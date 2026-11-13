#!/usr/bin/env python3
"""Retry *remaining balances* against a fresh on-chain snapshot.

Does not trust a historic SUCCESS as completion.  It verifies receipts and
transfer details before proposing another spend.  Existing journals and
plans are preserved.  One confirmation covers the resulting batch.
"""
from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from decimal import Decimal, InvalidOperation
from pathlib import Path
from datetime import datetime, timezone

import consolidator as core
from verify_transfers import tx_check

ROOT = Path(__file__).resolve().parent
WORKERS = 5
MEME_CONTRACT = core.Web3.to_checksum_address('0xb131f4a55907b10d1f0a50d8ab8fa09ec342cd74')
UNRESOLVED = {'prepared', 'uncertain', 'pending', 'broadcast'}
BLOCKED_REASONS = {'unpriced', 'invalid_contract', 'contract_not_allowlisted',
                   'unsupported_type', 'invalid_numeric_position', 'chain_id_mismatch',
                   'native_symbol_mismatch', 'incomplete_scan'}


def configs():
    nets = json.loads((ROOT / 'networks.json').read_text(encoding='utf-8'))
    extra = ROOT / 'extra_rpcs.json'
    if extra.exists():
        overrides = json.loads(extra.read_text(encoding='utf-8'))
        for net, urls in overrides.items():
            if net not in nets or not isinstance(urls, list):
                raise RuntimeError('Invalid extra_rpcs.json')
            nets[net]['rpcs'] = list(dict.fromkeys(urls + nets[net]['rpcs']))[:5]
    return nets


def decimal_price(original, action):
    try:
        x = Decimal(str(original.get('usd_price', '')))
        if not x.is_finite() or x <= 0:
            raise ValueError('Missing token USD price')
        return x
    except (InvalidOperation, ValueError):
        try:
            old_usd = Decimal(action['scan_usd'])
            old_raw = int(action['max_raw'])
            old_decimals = int(original['decimals'])
            if old_raw > 0 and old_usd > 0:
                return old_usd * (Decimal(10) ** old_decimals) / old_raw
        except (InvalidOperation, KeyError, ValueError):
            pass
        raise RuntimeError('Нет достоверной USD-цены')


def action_key(action):
    return (action['network'], action['from'].lower(),
            action['contract'].lower() if action['contract'] else 'native')


def scan_key(row):
    return (row['network'], row['address'].lower(),
            row['contract'].lower() if row.get('contract') else 'native')


def matching_event(e, action):
    return (str(e.get('network', '')).lower() == action['network'] and
            str(e.get('from', '')).lower() == action['from'].lower())


def verify_group_events(n, group, last_events, networks, recipient):
    """Verify every past terminal transaction for this source/chain.

    Any missing/mismatched receipt or pending broadcast blocks the whole
    account+network group, never silently treating it as a failed tx.
    """
    evs = [e for e in last_events if e.get('network') == n and
           str(e.get('from', '')).lower() == group[0]['from'].lower()]
    receipt_block = 0
    for e in evs:
        status = e.get('status')
        if status in UNRESOLVED or status not in ('success', 'failed'):
            raise RuntimeError('Старый перевод ещё не подтверждён; не повторяем')
        if not e.get('txhash') or e.get('to', '').lower() != recipient.lower():
            raise RuntimeError('Нет полного хеша или адрес получателя изменён')
        # Verify receipt, actual source/recipient and ERC20 Transfer log.
        row = {'network':n,'wallet':e['from'], 'recipient':recipient,
               'token':e.get('symbol',''), 'asset_type':'NATIVE' if not e.get('contract') else 'ERC20',
               'contract':e.get('contract') or '', 'amount_raw':str(e.get('amount_raw','')),
               'txhash':core.normalize_txhash(e['txhash']), 'status':'success'}
        result = tx_check(row, networks)
        if status == 'success' and result['onchain_status'] != 'VERIFIED':
            raise RuntimeError('Старый SUCCESS не подтверждён переводом в блокчейне: '+result['onchain_status'])
        if status == 'failed' and result['onchain_status'] != 'FAILED':
            raise RuntimeError('Старый FAILED не подтверждён блокчейном: '+result['onchain_status'])
        try:
            receipt_block = max(receipt_block, int(result.get('chain_block') or 0))
        except ValueError:
            pass
    return receipt_block


def provider_for_snapshot(network, cfg, account, min_block):
    failure = []
    for url in cfg['rpcs']:
        if not url.startswith('https://'):
            continue
        try:
            w3 = core.make_network_web3(url, network, timeout=12)
            if int(w3.eth.chain_id) != int(cfg['chain_id']):
                continue
            if int(w3.eth.block_number) < min_block:
                failure.append('RPC отстаёт от подтверждённых транзакций')
                continue
            # Do not create a fresh nonce while any other transaction is pending.
            confirmed = int(w3.eth.get_transaction_count(account, 'latest'))
            pending = int(w3.eth.get_transaction_count(account, 'pending'))
            if confirmed != pending:
                raise RuntimeError('Есть pending nonce; повтор с новым nonce заблокирован')
            return w3
        except Exception as exc:
            failure.append(type(exc).__name__)
    raise RuntimeError('Нет синхронизированного RPC: '+', '.join(failure[-3:]))


def live_asset(w3, action):
    if action['asset_type'] == 'NATIVE':
        return int(w3.eth.get_balance(action['from'])), 18
    contract = w3.eth.contract(address=core.Web3.to_checksum_address(action['contract']), abi=core.ERC20_ABI)
    balance = int(contract.functions.balanceOf(action['from']).call())
    dp = int(contract.functions.decimals().call())
    if not 0 <= dp <= 36:
        raise RuntimeError('Invalid token decimals')
    return balance, dp


def refresh_group(n, source, actions, last_events, networks, old_rows, settings, old_plan):
    try:
        min_block = verify_group_events(n, actions, last_events, networks, settings['recipient'])
        w3 = provider_for_snapshot(n, networks[n], source, min_block)
        new_actions, balances = [], []
        old_positions = {scan_key(r): r for r in old_rows if r.get('network') == n and r.get('address','').lower() == source.lower()}
        blocked_native = any(s.get('network') == n and str(s.get('from','')).lower() == source.lower()
                             and s.get('reason') in BLOCKED_REASONS for s in old_plan.get('skipped', []))
        # MEME was added outside the immutable scanner plan.  Only sweep ETH
        # if the live MEME balance is proven to be zero.
        if n == 'ethereum':
            meme = w3.eth.contract(address=MEME_CONTRACT, abi=core.ERC20_ABI)
            if int(meme.functions.balanceOf(source).call()) > 0:
                blocked_native = True
        for a in actions:
            raw, decimals = live_asset(w3, a)
            row = old_positions.get(action_key(a))
            label = {'network': n, 'wallet': source, 'token': a['symbol'], 'contract': a['contract'] or '',
                     'raw_balance': str(raw), 'balance':str(Decimal(raw) / (10**decimals)),
                     'status':'ZERO' if raw == 0 else 'LIVE', 'reason':''}
            balances.append(label)
            if raw == 0:
                continue
            if a['asset_type'] == 'NATIVE' and blocked_native:
                label['status'] = 'HELD'
                label['reason'] = 'Не подтверждена полнота ERC20/MEME; сохраняем газ'
                continue
            if row is None or row.get('status') != 'OK':
                raise RuntimeError('Нет подтверждённой исходной позиции для '+a['symbol'])
            if row.get('decimals') and int(row['decimals']) != decimals:
                raise RuntimeError('Изменились decimals у '+a['symbol'])
            price = decimal_price(row, a)
            worth = (Decimal(raw) / (10**decimals)) * price
            if worth < settings['min_usd']:
                label['status']='DUST'
                label['reason']='Ниже минимального порога USD'
                continue
            new = {k:v for k,v in a.items() if k != 'id'}
            new['max_raw'] = str(raw)
            new['scan_usd'] = str(worth)
            new['id'] = core.digest_json(new)[:24]
            new_actions.append(new)
        return new_actions, balances, ''
    except Exception as exc:
        return [], [], type(exc).__name__ + ': ' + str(exc)[:150]


def write_csv(path, records, columns):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8-sig', newline='') as fh:
        wr = csv.DictWriter(fh, fieldnames=columns, extrasaction='ignore')
        wr.writeheader()
        wr.writerows(records)


def snapshot_remaining(plan, networks, existing_rows):
    """Live remaining amounts for all eligible original plan positions."""
    out = []
    for group in group_actions(plan['actions']).values():
        net, wallet = group[0]['network'], group[0]['from']
        try:
            w3 = core.open_rpc(net, networks[net], timeout=12)
            for a in group:
                try:
                    raw, dp = live_asset(w3, a)
                    out.append({'network':net,'wallet':wallet,'token':a['symbol'],
                                'balance':str(Decimal(raw)/(10**dp)),
                                'state':'OK', 'reason':''})
                except Exception as exc:
                    out.append({'network':net,'wallet':wallet,'token':a['symbol'],
                                'balance':'','state':'RPC_ERROR','reason':type(exc).__name__})
        except Exception as exc:
            for a in group:
                out.append({'network':net,'wallet':wallet,'token':a['symbol'],
                            'balance':'','state':'RPC_ERROR','reason':type(exc).__name__})
    return out


def group_actions(actions):
    groups = defaultdict(list)
    for a in actions:
        groups[(a['network'], a['from'].lower())].append(a)
    return groups


def main():
    settings = core.load_settings(ROOT / 'settings.json')
    keys = core.load_plaintext_keys(ROOT / 'private_keys.txt', ROOT / 'addresses.txt')
    nets = configs()
    original = core.load_plan(ROOT / 'consolidation/plan.json')
    if original['destination'].lower() != settings['recipient'].lower():
        raise RuntimeError('Адрес получателя изменён: запуск остановлен')
    if original['networks_sha256'] != core.digest_json(nets):
        raise RuntimeError('Конфигурация RPC не соответствует старому плану')
    if original['scanner_csv_sha256'] != core.sha256_file(ROOT/'reports/balances_all.csv'):
        raise RuntimeError('Изменён старый отчёт сканера; запуск остановлен')
    if Decimal(original.get('min_usd', '0')) != settings['min_usd']:
        raise RuntimeError('Изменён минимальный порог после утверждения исходного плана')
    for field in ('max_fee_usd', 'max_fee_fraction', 'native_reserve'):
        if Decimal((original.get('fee_policy') or {}).get(field,'-1')) != settings[field]:
            raise RuntimeError('Изменены лимиты комиссий после утверждения исходного плана')
    old_rows = core.load_csv(ROOT / 'reports/balances_all.csv')
    candidates = [a for a in original['actions'] if a['network'] in core.PILOT_NETWORKS
                  and a['from'].lower() in keys]
    if not candidates:
        print('Нет позиций, доступных для повторной проверки.')
        return
    journal = ROOT/'consolidation/journal.jsonl'
    with core.exclusive_lock(journal):
        # First recheck unknown receipts without permitting a new spend.
        core.reconcile(journal, nets)
        latest = list(core.index_events(core.read_events(journal)).values())
        groups = group_actions(candidates)
        results, problems, snapshot = [], [], []
        print(f'Проверяю текущие остатки {len(groups)} групп адрес/сеть. Без отправки...', flush=True)
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            futures = {pool.submit(refresh_group,n,acts[0]['from'],acts,latest,nets,old_rows,settings,original):(n,addr)
                       for (n,addr),acts in groups.items()}
            for i, fut in enumerate(as_completed(futures), 1):
                n, addr = futures[fut]
                actions, balances, error = fut.result()
                if error:
                    problems.append({'network':n,'wallet':addr,'reason':error})
                else:
                    results.extend(actions)
                    snapshot.extend(balances)
                if i % 20 == 0 or i == len(groups):
                    print(f'Проверено групп: {i}/{len(groups)}', flush=True)
        results.sort(key=lambda a:(a['network'],a['from'].lower(),a['asset_type']=='NATIVE',a['symbol']))
        pending_amount = sum((Decimal(a['scan_usd']) for a in results),Decimal(0))
        print(f'Найдено {len(results)} позиций с остатками (~${pending_amount:.4f}, цены из старого скана).')
        print(f'Недоступно или заблокировано групп: {len(problems)}.')
        for item in problems[:12]:
            print('  ',item['network'],item['wallet'][:10],item['reason'])
        write_csv(ROOT/'consolidation/retry_preflight.csv',snapshot,
                  ['network','wallet','token','contract','raw_balance','balance','status','reason'])
        write_csv(ROOT/'consolidation/retry_blocked.csv',problems,['network','wallet','reason'])
        if not results:
            print('Подходящих к выводу остатков нет. Денег не отправлено.')
            return
        if not sys.stdin.isatty():
            raise RuntimeError('Реальные переводы требуют подтверждения в терминале')
        print('Получатель:',settings['recipient'])
        print('Будут отправляться только остатки с доступным газом и в пределах комиссии.')
        if input('Попробовать вывести эти остатки? [да/нет]: ').strip().casefold() not in ('да','yes'):
            print('Отменено, ничего не отправлено.')
            return
        # The immutable new plan is independently identifiable, never overwrite
        # an old approved plan used by prior transactions.
        base = dict(original)
        base.pop('approval_hash',None)
        base['generated_at'] = core.now()
        base['actions'] = results
        base['skipped'] = []
        base['retry_from'] = original['approval_hash']
        base['note'] = 'Additional on-chain verified remaining amounts; same recipient, fresh quote before signing'
        new_plan = {**base,'approval_hash':core.digest_json(base)}
        root = ROOT / 'consolidation/retry_plans'
        root.mkdir(parents=True, exist_ok=True)
        core.atomic_json(root / (new_plan['approval_hash']+'.json'),new_plan)
        print(f'Начинаю вывод оставшихся средств, параллельных групп: {WORKERS}.')
        totals = Counter()
        def task(actions):
            scoped = {**new_plan,'actions':actions}
            return core.work(scoped, old_rows, nets,mode='execute',network=None,source=None,
                             vault=ROOT/'private_keys.txt',journal=journal,
                             max_transfers=len(actions),approval=new_plan['approval_hash'],
                             reserve_native=settings['native_reserve'],
                             max_fee_usd=settings['max_fee_usd'], max_fee_fraction=settings['max_fee_fraction'],
                             auto_yes=True,batch=True,keyring_override=keys,buffered=True)
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            futures=[pool.submit(task,actions) for actions in group_actions(results).values()]
            for fut in as_completed(futures):
                res=fut.result()
                totals.update({k:v for k,v in res.items() if isinstance(v,int)})
        print('Подтверждено:',totals['confirmed'],'| неопределённых:',totals['unresolved'],
              '| ошибок:',totals['errors'])
        print('Перечитываю остатки после попытки вывода...')
        ending = snapshot_remaining(new_plan,nets,old_rows)
        write_csv(ROOT/'consolidation/retry_remaining.csv',ending,
                  ['network','wallet','token','balance','state','reason'])
        print('Отчёт по остаткам: consolidation/retry_remaining.csv')
        if totals['unresolved']:
            print('Неизвестные статусы сохранены в журнале; повтор с новым nonce не выполнялся.')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('ОСТАНОВКА:',type(exc).__name__,str(exc)[:220],file=sys.stderr)
        sys.exit(1)
