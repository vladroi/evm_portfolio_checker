#!/usr/bin/env python3
"""READ-ONLY blockchain triage for Optimism, Base, BSC and Polygon.

Optionally reads the local plaintext key file to select ONLY owned addresses.
Never signs/broadcasts, and never changes the journal or plan.
"""
from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path
from decimal import Decimal
from collections import defaultdict

import consolidator as core

ROOT=Path(__file__).resolve().parent
TARGET={'optimism','base','bsc','polygon'}
PENDING={'prepared','uncertain','pending','broadcast'}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--preflight',action='store_true',help='Read-only gas/token checks for unconfirmed BSC and Polygon positions')
    p.add_argument('--all-sources', action='store_true', help='Check ALL addresses in the plan (very slow for 897 wallets)')
    args=p.parse_args()
    plan=core.load_plan(ROOT/'consolidation/plan.json')
    rows=core.load_csv(ROOT/'reports/balances_all.csv')
    events=core.read_events(ROOT/'consolidation/journal.jsonl')
    latest=core.index_events(events)
    cfg=json.loads((ROOT/'networks.json').read_text())
    override=ROOT/'extra_rpcs.json'
    if override.exists():
        extra=json.loads(override.read_text())
        for net,urls in extra.items():
            if net in cfg and isinstance(urls,list):
                cfg[net]['rpcs']=list(dict.fromkeys(urls+cfg[net]['rpcs']))[:5]
    settings=core.load_settings(ROOT/'settings.json')
    prices=core.get_price(rows,cfg)
    # The plan can include 897 scanned addresses while private_keys.txt has
    # only five test signers. A preflight of all unattempted items is misleading
    # and extremely costly. Filter to signers by default, without sending TXs.
    local_sources = None
    if args.preflight and not args.all_sources:
        key_file = ROOT / 'private_keys.txt'
        if not key_file.exists():
            raise SystemExit('private_keys.txt не найден. Для проверки всего плана используй --all-sources.')
        local_sources = set(core.load_plaintext_keys(key_file, ROOT / 'addresses.txt'))
        print(f'Проверка только кошельков из private_keys.txt: {len(local_sources)} адрес(ов).')
    summary=defaultdict(lambda:defaultdict(int))
    problems=[]
    for action in plan['actions']:
        if local_sources is not None and action['from'].lower() not in local_sources:
            continue
        if action['network'] not in TARGET:
            continue
        e=latest.get((plan['approval_hash'],action['id']))
        status=e['status'] if e else 'not_attempted'
        summary[action['network']][status]+=1
        if status in PENDING or status in ('failed','not_attempted'):
            problems.append({'network':action['network'],'wallet':action['from'],
                             'symbol':action['symbol'],'status':status,
                             'txhash':e.get('txhash','') if e else '',
                             'reason':'','asset_type':action['asset_type']})
    print('РЕЗУЛЬТАТ ПО ЖУРНАЛУ (не подтверждает статус в блокчейне)')
    for net in sorted(TARGET):
        counts=summary[net]
        print(net, ' | '.join(f'{k}:{v}' for k,v in sorted(counts.items())) or '(позиций нет)')
    print('\nНЕОПРЕДЕЛЁННЫЕ — не отправлять повторно без проверки receipt:')
    for r in problems:
        if r['status'] in PENDING:
            print(' ',r['network'],r['wallet'][:10],r['symbol'],r['status'],r['txhash'])

    if args.preflight:
        print('\nТЕСТЫ БЕЗ ОТПРАВКИ: Polygon и BSC (только действия без журнала)')
        cache={}
        problems_by_key={(p['network'],p['wallet'].lower(),p['symbol']):p for p in problems}
        for a in plan['actions']:
            if local_sources is not None and a['from'].lower() not in local_sources:
                continue
            if a['network'] not in ('polygon','bsc'):
                continue
            if a['asset_type']=='NATIVE':
                continue
            if latest.get((plan['approval_hash'],a['id'])):
                continue  # do not interfere with unknown broadcasts
            ref=problems_by_key.get((a['network'],a['from'].lower(),a['symbol']))
            if not ref:continue
            try:
                w3,q=core.quote_with_failover(a['network'],cfg[a['network']],cache,a,
                    prices.get(a['network']),int(settings['native_reserve']*Decimal(10**18)),
                    settings['max_fee_usd'],settings['max_fee_fraction'])
                if 'skip' in q:
                    reason='SKIP: '+q['skip']
                else:
                    reason='OK: gas quotation and ERC20 simulation passed'
            except Exception as e:
                # Only use sanitized locally-authored exception phases.
                reason=str(e)[:550] if isinstance(e,RuntimeError) and str(e).startswith('All read-only RPC preflights failed:') else type(e).__name__
            ref['reason']=reason
            print(' ',a['network'],a['from'][:10],a['symbol'],reason)
    target=ROOT/'consolidation/diagnostics.csv'
    with target.open('w',newline='',encoding='utf-8-sig') as out:
        w=csv.DictWriter(out,fieldnames=['network','wallet','symbol','status','txhash','reason','asset_type'])
        w.writeheader();w.writerows(problems)
    print('\nСохранено:',target)
    print('Никаких транзакций не отправлено.')

if __name__=='__main__':
    main()
