#!/usr/bin/env python3
"""MEME Ethereum add-on for existing v2 approved plans.

Does not change tokens.json, original scanner CSV, original plan.json, or prior
journal actions. Uses the SAME journal and nonce/receipt protections as core.
No private keys are logged. Actual transfers require a one-time batch approval
from start.py. Individual command without --execute is read-only.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from decimal import Decimal, InvalidOperation
from pathlib import Path

import consolidator as core

ROOT = Path(__file__).resolve().parent
CONTRACT = core.Web3.to_checksum_address('0xb131f4a55907b10d1f0a50d8ab8fa09ec342cd74')
TOKEN = 'MEME'
PRICE_KEY = f'ethereum:{CONTRACT.lower()}'
SCAN_PATH = ROOT / 'consolidation/meme_scan.csv'
PLAN_PATH = ROOT / 'consolidation/meme_plan.json'
FIELDS = ['address','network','chain_id','type','symbol','contract','balance',
          'raw_balance','decimals','usd_price','usd_value','status','error','block_tag']


def _price_lookup():
    """Return validated spot price or None. Network/API failure MUST NOT imply $0."""
    url = 'https://coins.llama.fi/prices/current/' + PRICE_KEY
    try:
        req = urllib.request.Request(url, headers={'User-Agent':'LocalPortfolioConsolidator/1.0'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            obj = json.load(resp)
        raw = (obj.get('coins') or {}).get(PRICE_KEY, {}).get('price')
        price = Decimal(str(raw))
        if price.is_finite() and price > 0:
            return price
    except (OSError, ValueError, InvalidOperation, TypeError, KeyError, TimeoutError):
        pass
    return None


def scan_one(address, network_config):
    """Read-only. Every RPC failing leaves UNKNOWN, never a fabricated zero."""
    issues=[]
    for url in network_config['rpcs']:
        if not isinstance(url, str) or not url.startswith('https://'):
            continue
        try:
            w3 = core.Web3(core.Web3.HTTPProvider(url, request_kwargs={'timeout':12}))
            if int(w3.eth.chain_id) != 1:
                raise RuntimeError('Wrong chain')
            if not w3.eth.get_code(CONTRACT):
                raise RuntimeError('Missing MEME contract')
            c = w3.eth.contract(address=CONTRACT, abi=core.ERC20_ABI)
            decimals = int(c.functions.decimals().call())
            if decimals != 18:
                raise RuntimeError('Unexpected MEME decimals')
            balance = int(c.functions.balanceOf(address).call())
            block = w3.eth.block_number
            return {'address':address,'network':'ethereum','chain_id':'1','type':'ERC20',
                    'symbol':TOKEN,'contract':CONTRACT,'raw_balance':str(balance),
                    'decimals':'18', 'balance':str(Decimal(balance) / Decimal(10**18)),
                    'usd_price':'','usd_value':'','status':'OK','error':'','block_tag':str(block)}
        except Exception as exc:
            issues.append(type(exc).__name__)
    return {'address':address,'network':'ethereum','chain_id':'1','type':'ERC20',
            'symbol':TOKEN,'contract':CONTRACT,'raw_balance':'','decimals':'',
            'balance':'','usd_price':'','usd_value':'','status':'ERROR',
            'error':','.join(issues[-5:]) or 'No usable RPC','block_tag':''}


def load_scan():
    if not SCAN_PATH.exists():
        return []
    with SCAN_PATH.open(encoding='utf-8-sig',newline='') as fh:
        return list(csv.DictReader(fh))


def save_scan(rows):
    SCAN_PATH.parent.mkdir(parents=True,exist_ok=True)
    tmp=SCAN_PATH.with_suffix('.tmp')
    with tmp.open('w',encoding='utf-8-sig',newline='') as fh:
        writer=csv.DictWriter(fh,fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
        fh.flush();os.fsync(fh.fileno())
    os.replace(tmp,SCAN_PATH)


def prepare(keyring, networks, settings, *, workers=5):
    """Return (plan, rows, blocked_wallets, safe_zero_wallets, summary).

    Existing immutable MEME plan is reused. No source wallets missing from it are
    silently added. This protects against bypassing old journal state.
    """
    # Scan only locally controlled source wallets. With a large addresses.txt,
    # scanning every public address here could block a five-wallet pilot for hours.
    active = {addr.lower() for addr in keyring}
    print(f'MEME: проверяю только участвующие кошельки ({len(active)} адресов)...', flush=True)
    if 'ethereum' not in networks:
        raise RuntimeError('Ethereum network missing')
    if PLAN_PATH.exists():
        plan = core.load_plan(PLAN_PATH)
        if plan['destination'].lower() != settings['recipient'].lower():
            raise RuntimeError('MEME plan recipient mismatch. Do not delete prior journal.')
        rows = load_scan()
        covered={r['address'].lower() for r in rows}
        missing=active-covered
        if missing:
            print('MEME: новые адреса ещё не включены в сохранённый дополнительный план:',len(missing))
        zero={r['address'].lower() for r in rows if r['status']=='OK' and int(r['raw_balance'] or 0)==0 and r['address'].lower() in active}
        excluded=({r['address'].lower() for r in rows if r['status']!='OK' or
                  (int(r.get('raw_balance') or 0)>0 and not r.get('usd_price'))} & active) | missing
        # If token discovery failed and NO operation from this supplementary
        # plan has ever reached the journal, retry without changing lineage.
        journal=ROOT/'consolidation/journal.jsonl'
        ever_attempted=any(e.get('plan_hash')==plan['approval_hash'] for e in core.read_events(journal))
        if not (excluded and not ever_attempted):
            return plan, rows, excluded, zero, {'reused':True,'missing_keys':len(missing)}
        print('MEME: повторяю неполную проверку (старых транзакций этого плана нет).')
    cfg=networks['ethereum']
    with ThreadPoolExecutor(max_workers=min(max(1,workers),5)) as pool:
        futures={pool.submit(scan_one, core.Web3.to_checksum_address(addr), cfg):addr for addr in active}
        rows=[f.result() for f in as_completed(futures)]
    rows.sort(key=lambda r:r['address'].lower())
    price = _price_lookup() if any(r['status']=='OK' and int(r['raw_balance'] or 0)>0 for r in rows) else None
    for r in rows:
        if r['status']=='OK' and int(r['raw_balance'] or 0)>0 and price is not None:
            r['usd_price']=str(price)
            r['usd_value']=str((Decimal(r['raw_balance']) / Decimal(10**18))*price)
    save_scan(rows)
    safe_zero={r['address'].lower() for r in rows if r['status']=='OK' and int(r['raw_balance'] or 0)==0 and r['address'].lower() in active}
    blocked={r['address'].lower() for r in rows if r['status']!='OK' or
             (int(r.get('raw_balance') or 0)>0 and not r.get('usd_price'))}
    plan = core.build_plan(rows,settings['recipient'],networks,
            {'ethereum':[{'symbol':TOKEN,'address':CONTRACT}]},
            min_usd=settings['min_usd'],source_digest=core.sha256_file(SCAN_PATH),
            network_digest=core.digest_json(networks),
            token_digest=core.digest_json({'ethereum':[{'symbol':TOKEN,'address':CONTRACT}]}),
            fee_policy={k:str(settings[k]) for k in ('max_fee_usd','max_fee_fraction','native_reserve')})
    core.atomic_json(PLAN_PATH,plan)
    print(f'MEME проверен: {len(rows)} кошельков; положительных: '
          f'{sum(r["status"]=="OK" and int(r["raw_balance"] or 0)>0 for r in rows)}; '
          f'ошибок: {sum(r["status"]!="OK" for r in rows)}; '
          f'цена: {"доступна" if price is not None else "не определена"}')
    return plan, rows, blocked, safe_zero, {'reused':False,'missing_keys':0}


def execute(plan, rows, keyring, networks, settings, journal, workers=5):
    """Called ONLY after start.py one-time user approval; same journal as base plan."""
    actions=[a for a in plan['actions'] if a['from'].lower() in keyring]
    if not actions:
        return {'sent':0,'confirmed':0,'unresolved':0,'errors':0, 'issues':[]}
    historical_rows=core.load_csv(ROOT/'reports/balances_all.csv')
    price_rows=[r for r in historical_rows if r['network']=='ethereum' and r['type'].lower()=='native']
    quote_rows=price_rows+rows
    def task(action):
        return core.work({**plan,'actions':[action]},quote_rows,networks,
            mode='execute', network=None, source=None,
            vault=ROOT/'private_keys.txt',journal=journal,max_transfers=1,
            approval=plan['approval_hash'],reserve_native=settings['native_reserve'],
            max_fee_usd=settings['max_fee_usd'],max_fee_fraction=settings['max_fee_fraction'],
            auto_yes=True,batch=True,keyring_override=keyring,buffered=True)
    out={'sent':0,'confirmed':0,'unresolved':0,'errors':0,'issues':[]}
    with ThreadPoolExecutor(max_workers=min(max(1,workers),5)) as pool:
        for f in as_completed([pool.submit(task,a) for a in actions]):
            result=f.result()
            for name in ('sent','confirmed','unresolved','errors'):
                out[name]+=result[name]
            out['issues'].extend(result['issues'])
    return out


def safe_for_native(plan, rows, blocked, safe_zero, journal):
    latest=core.index_events(core.read_events(journal))
    safe=set(safe_zero)
    for a in plan['actions']:
        if a['symbol']!='MEME':continue
        ev=latest.get((plan['approval_hash'],a['id']))
        if ev is not None and ev.get('status')=='success':
            safe.add(a['from'].lower())
    return safe-blocked


def main():
    parser=argparse.ArgumentParser(description='Read-only MEME scan, no token transfers')
    parser.add_argument('--workers',type=int,default=5)
    args=parser.parse_args()
    if not 1<=args.workers<=5:parser.error('workers must be 1..5')
    keyring=core.load_plaintext_keys(ROOT/'private_keys.txt',ROOT/'addresses.txt')
    settings=core.load_settings(ROOT/'settings.json')
    networks=json.loads((ROOT/'networks.json').read_text())
    plan, rows, blocked, zero, _=prepare(keyring,networks,settings,workers=args.workers)
    journal=ROOT/'consolidation/journal.jsonl'
    safe=safe_for_native(plan,rows,blocked,zero,journal)
    print(f'MEME: плановых позиций {len(plan["actions"])}; '
          f'защищённых от преждевременного вывода газа адресов: {len(set(keyring)-safe)}')
    print('Только проверка, ничего не отправлено. Для общего запуска: python start.py')

if __name__=='__main__':
    main()
