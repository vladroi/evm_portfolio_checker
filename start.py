#!/usr/bin/env python3
"""One-command batch launcher for locally controlled EVM wallets.

One explicit confirmation for the full batch. Keys are read directly from a local
private_keys.txt file (no password prompts). Every transaction is validated and journaled.
"""
from __future__ import annotations

import csv
import hashlib
import json
import subprocess
import sys
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import report as reporter
import meme as meme_addon
from decimal import Decimal
import consolidator as core
from pathlib import Path

ROOT = Path(__file__).resolve().parent
# Concurrent source-address+network workers. 5 keeps public RPC load moderate.
PARALLEL_WALLETS = 5

def group_by_wallet_chain(actions):
    """Keep each account/chain nonce sequence strictly serial."""
    groups = defaultdict(list)
    for a in actions:
        groups[(a['network'], a['from'].lower())].append(a)
    return groups

PILOT = tuple(sorted(core.PILOT_NETWORKS))
REQUIRED = ('consolidator.py', 'settings.json', 'private_keys.txt',
            'networks.json', 'tokens.json', 'addresses.txt', 'reports/balances_all.csv')


def run(*args):
    cmd = [sys.executable, *args]
    result = subprocess.run(cmd, cwd=ROOT, check=False)
    if result.returncode:
        raise RuntimeError(f"Команда завершилась с ошибкой: {args[0]} (код {result.returncode})")


def load_json(path):
    return json.loads((ROOT / path).read_text(encoding='utf-8'))


def sha256(path):
    return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()


def main():
    print('\nАвтоматический вывод из импортированных кошельков\n')
    missing = [p for p in REQUIRED if not (ROOT / p).is_file()]
    if missing:
        raise RuntimeError('Не найдены файлы: ' + ', '.join(missing) + '. Скопируй start.py в корень проекта, рядом с consolidator.py.')

    settings = load_json('settings.json')
    recipient = str(settings.get('recipient', '')).strip()
    if not (recipient.startswith('0x') and len(recipient) == 42):
        raise RuntimeError('Укажи полный адрес получателя в settings.json (recipient).')
    print('Получатель:', recipient)

    key_file = ROOT / 'private_keys.txt'
    keyring = core.load_plaintext_keys(key_file, ROOT / 'addresses.txt')
    keystores = set(keyring)
    print('Доступных исходных кошельков:', len(keystores))

    plan_path = ROOT / 'consolidation/plan.json'
    if not plan_path.exists():
        if (ROOT / 'consolidation/journal.jsonl').exists():
            raise RuntimeError('Есть журнал прежних транзакций, но план исчез. Не пересоздаю план автоматически.')
        print('\nСоздаю план из готового отчёта. Это не отправляет средства...')
        run('consolidator.py', 'plan')
    else:
        print('План переводов загружен.')
    plan = core.load_plan(plan_path)
    if plan.get('format_version') != 2:
        raise RuntimeError('План не версии v2. Не удаляй журнал транзакций; сначала разберись с ним.')
    if plan.get('destination', '').lower() != recipient.lower():
        raise RuntimeError('Получатель в плане отличается от settings.json! Останавливаю запуск.')
    if plan.get('scanner_csv_sha256') != sha256('reports/balances_all.csv'):
        raise RuntimeError('Сканерский отчёт изменён после утверждения плана. Останавливаю запуск, чтобы не потерять журнал переводов.')

    journal_path = ROOT / 'consolidation/journal.jsonl'
    latest = {}
    if journal_path.exists():
        for line in journal_path.read_text(encoding='utf-8').splitlines():
            if not line.strip():
                continue
            evt = json.loads(line)
            if evt.get('plan_hash') == plan['approval_hash'] and evt.get('action_id'):
                latest[evt['action_id']] = evt

    # Validate the unchanged registry and configurable fee limits, just like the CLI.
    networks = load_json('networks.json')
    extra_path = ROOT / 'extra_rpcs.json'
    extra = json.loads(extra_path.read_text(encoding='utf-8')) if extra_path.exists() else {}
    for slug, urls in extra.items():
        if slug not in networks or not isinstance(urls, list):
            raise RuntimeError('Некорректный extra_rpcs.json')
        networks[slug]['rpcs'] = list(dict.fromkeys(urls + networks[slug]['rpcs']))[:5]
    if plan['networks_sha256'] != core.digest_json(networks) or plan['tokens_sha256'] != sha256('tokens.json'):
        raise RuntimeError('Конфигурация RPC/токенов изменилась после составления плана.')
    config = core.load_settings(ROOT / 'settings.json')
    print('Проверяю MEME для участвующих кошельков. Деньги пока не отправляются...', flush=True)
    # Supplementary MEME scan and approved plan do not modify the original
    # scanner report, token registry, plan hash or prior journal history.
    try:
        meme_plan, meme_rows, meme_blocked, meme_zero, _ = meme_addon.prepare(
            keyring, networks, config, workers=PARALLEL_WALLETS)
    except Exception as exc:
        # Safest response to token-discovery failure: do not sweep Ethereum ETH,
        # but permit unrelated networks and wallet groups to continue.
        print('MEME: не удалось проверить токен:',type(exc).__name__)
        print('На всех этих кошельках временно заблокирован вывод нативного ETH в Ethereum.')
        meme_plan, meme_rows, meme_blocked, meme_zero = None, [], set(keystores), set()
    if Decimal(plan['min_usd']) != config['min_usd']:
        raise RuntimeError('Минимальный порог изменился после составления плана.')
    policy = plan.get('fee_policy') or {}
    for field in ('max_fee_usd','max_fee_fraction','native_reserve'):
        if field not in policy or Decimal(policy[field]) != config[field]:
            raise RuntimeError(f'Настройка {field} изменилась после составления плана.')

    journal_path = ROOT / 'consolidation/journal.jsonl'
    events = core.read_events(journal_path)
    latest = core.index_events(events)
    ours = [a for a in plan['actions'] if a['from'].lower() in keystores]
    eligible = [a for a in ours if a['network'] in PILOT]
    todo = [a for a in eligible if (plan['approval_hash'], a['id']) not in latest]
    meme_actions=[a for a in (meme_plan['actions'] if meme_plan else []) if a['from'].lower() in keystores]
    meme_todo=[a for a in meme_actions if (meme_plan['approval_hash'], a['id']) not in latest] if meme_plan else []
    unsupported = Counter(a['network'] for a in ours if a['network'] not in PILOT)
    by_network = Counter(a['network'] for a in todo)
    approximate_usd = sum((Decimal(a.get('scan_usd', '0')) for a in todo), Decimal(0))
    # A transaction in the journal is NOT necessarily complete. The old UI
    # misleadingly hid Base/Optimism because it only listed never-attempted actions.
    terminal = {'success', 'failed'}
    recovery_status = {'uncertain', 'prepared'}
    review_status = {'broadcast', 'pending'}
    can_recover = []
    to_review = []
    completed = Counter()
    already_recovered = []
    for a in eligible:
        key = (plan['approval_hash'], a['id'])
        ev = latest.get(key)
        if not ev:
            continue
        status = ev.get('status')
        if status == 'success':
            completed[a['network']] += 1
        elif status in recovery_status:
            # A prior rejected RPC broadcast does not permanently remove the
            # action: recovery may try again with the SAME nonce only after
            # independent RPC/receipt/nonce checks inside the core module.
            can_recover.append(a)
        elif status in review_status or status == 'failed':
            to_review.append(a)
    recover_counts = Counter(a['network'] for a in can_recover)
    pending_counts = Counter(a['network'] for a in to_review + already_recovered)
    print('\n================ ПЛАН ================')
    print('Получатель:', plan['destination'])
    print('Импортированных кошельков:', len(keystores))
    print('Новых переводов:', len(todo))
    print('Восстановление с прежним nonce:', len(can_recover))
    print('Требуют дополнительной сверки:', len(to_review) + len(already_recovered))
    print(f'Примерная стоимость НОВЫХ позиций по старому скану: ${approximate_usd:.4f}')
    print('Уже подтверждено по журналу:', sum(completed.values()))
    print('\nПо сетям (новые / восстановление / сверка / подтверждено):')
    networks_to_show = set(by_network) | set(recover_counts) | set(pending_counts) | set(completed)
    for network in sorted(networks_to_show):
        print(f'  {network:<12} {by_network[network]:>3} / {recover_counts[network]:>3} / '
              f'{pending_counts[network]:>3} / {completed[network]:>3}')
    if can_recover:
        print('\nBase и Optimism с прежним UNKNOWN не исключены из запуска:')
        for a in sorted(can_recover, key=lambda x:(x['network'],x['from'])):
            print(f'  {a["network"]:<12} {a["from"][:10]}… {a["symbol"]}: сверка + возможное восстановление с ТЕМ ЖЕ nonce')
    if to_review or already_recovered:
        print('Неопределённые/завершившиеся ошибкой записи НЕ отправляются новым nonce:')
        for a in sorted(to_review + already_recovered, key=lambda x:(x['network'],x['from'])):
            print(f'  {a["network"]:<12} {a["from"][:10]}… {a["symbol"]}: нужна сверка')
    print('MEME (Ethereum):',len(meme_todo),'позиций к проверке/выводу')
    if unsupported:
        print('НЕ будут отправлены (сети пока не поддерживаются):',
              ', '.join(f'{n} ({cnt})' for n, cnt in sorted(unsupported.items())))
    bad_scan = sum(x.get('reason') == 'incomplete_scan' and
                   str(x.get('from','')).lower() in keystores for x in plan.get('skipped', []))
    if bad_scan:
        print(f'Не включены в план из-за ошибок сканера: {bad_scan} групп адрес/сеть')
    print('Порядок: ERC-20 -> остаток нативной монеты; проверка газа перед отправкой.')
    if not todo and not meme_todo and not can_recover:
        print('Нет новых переводов для импортированных ключей. Строю актуальный отчёт...')
        reporter.generate(ROOT,live=True,addresses=keystores,workers=PARALLEL_WALLETS)
        print('Открой:',ROOT/'consolidation/report.html')
        return
    if not sys.stdin.isatty():
        raise RuntimeError('Для пакетной отправки требуется интерактивное подтверждение.')
    print('\nЭто реальные переводы. После подтверждения дополнительных вопросов по каждой операции не будет.')
    choice = input('Отправить ВСЕ доступные позиции на указанный адрес? [да/нет]: ').strip().casefold()
    if choice not in ('да','yes'):
        print('Отмена. Ничего не отправлено.')
        return
    rows = core.load_csv(ROOT / 'reports/balances_all.csv')
    # Same source+network never runs concurrently. Token actions precede NATIVE.
    groups = None  # Created after MEME preflight and Ethereum native gas guard.
    totals = Counter()
    issues = []
    with core.exclusive_lock(journal_path):
        # Recover the previous uncertain broadcasts safely using the RECORDED
        # account nonce. Never create a fresh nonce for an unresolved action.
        recovery = core.recover_uncertain_once(plan, rows, networks, keyring, config, journal_path)
        totals.update({k:v for k,v in recovery.items() if isinstance(v,int)})
        issues.extend(recovery['issues'])
        # MEME always precedes all Ethereum native-coin sweeps. Preserve the
        # ETH gas for MEME when balance or profitability cannot be verified.
        if meme_plan is not None and meme_todo:
            print(f'\nMEME: проверяю/отправляю {len(meme_todo)} позиций до нативного ETH...')
            meme_result = meme_addon.execute(meme_plan, meme_rows, keyring, networks,
                                            config, journal_path, workers=PARALLEL_WALLETS)
            totals.update({k:v for k,v in meme_result.items() if isinstance(v,int)})
            issues.extend(meme_result['issues'])
        meme_safe = (meme_addon.safe_for_native(meme_plan,meme_rows,meme_blocked,meme_zero,journal_path)
                     if meme_plan is not None else set())
        held=[a for a in eligible if a['network']=='ethereum' and a['asset_type']=='NATIVE'
              and a['from'].lower() not in meme_safe]
        if held:
            print('Ethereum: удерживаю нативный ETH на',len(held),
                  'адресах: MEME не проверен или не подтверждён.')
        eligible = [a for a in eligible if not (a['network']=='ethereum' and a['asset_type']=='NATIVE'
                          and a['from'].lower() not in meme_safe)]
        def run_wallet(actions):
            # Immutable approved plan and global journal; each worker owns a distinct
            # (chain, account) nonce sequence. A journal entry is written before broadcast.
            scoped = {**plan, 'actions':actions}
            return core.work(scoped, rows, networks, mode='execute', network=None, source=None,
                             vault=key_file, journal=journal_path,
                             max_transfers=len(actions), approval=plan['approval_hash'],
                             reserve_native=config['native_reserve'], max_fee_usd=config['max_fee_usd'],
                             max_fee_fraction=config['max_fee_fraction'], auto_yes=True, batch=True,
                             keyring_override=keyring, buffered=True)
        # Keys were already verified, so do not reread 900 private keys per worker.
        groups = group_by_wallet_chain(eligible)
        print(f'\nОбрабатываю {len(groups)} групп адрес/сеть, параллельно: {PARALLEL_WALLETS}.')
        with ThreadPoolExecutor(max_workers=PARALLEL_WALLETS) as pool:
            futures = [pool.submit(run_wallet, acts) for acts in groups.values()]
            for future in as_completed(futures):
                res = future.result()
                totals.update({k:v for k,v in res.items() if isinstance(v,int)})
                issues.extend(res['issues'])
    issue_path=ROOT/'consolidation/run_issues.csv'
    with issue_path.open('w',newline='',encoding='utf-8-sig') as out:
        writer=csv.DictWriter(out,fieldnames=['time','network','wallet','token','reason'])
        writer.writeheader()
        writer.writerows(issues)
    print('\nПакет завершён. Подтверждено:',totals['confirmed'],
          '| неизвестный статус:',totals['unresolved'],'| ошибок:',totals['errors'])
    # Reporting is READ-ONLY; errors here cannot cause another transfer.
    try:
        print('Проверяю оставшиеся балансы по RPC и создаю таблицы...')
        results = reporter.generate(ROOT, live=True, addresses=set(keyring), workers=PARALLEL_WALLETS)
        print('Готово:',ROOT/'consolidation/report.html')
        print('Таблицы:',ROOT/'consolidation/transfers.csv', 'и', ROOT/'consolidation/remaining_balances.csv')
    except Exception as exc:
        print('Отчёт не удалось построить:',type(exc).__name__)
        print('Повторить построение (без переводов): python report.py')
    print('Для проверки неопределённых переводов: python consolidator.py reconcile')

if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, json.JSONDecodeError) as exc:
        print('\nОСТАНОВКА:', exc, file=sys.stderr)
        sys.exit(1)
