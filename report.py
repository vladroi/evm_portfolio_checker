#!/usr/bin/env python3
"""Read-only, post-transfer reconciliation report (NO signing, NO transfers).

Outputs CSV and a standalone offline HTML summary. Remaining balances are queried
live; RPC failures are marked UNKNOWN, never zero. Covers scanner-listed assets only.
"""
from __future__ import annotations

import argparse
import csv
import html
import json
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path

import consolidator as core

ROOT = Path(__file__).resolve().parent
STATES = {
    'success':'ПОДТВЕРЖДЕНО', 'failed':'ОТКЛОНЕНО СЕТЬЮ',
    'pending':'ОЖИДАЕТ / НЕЯСНО', 'uncertain':'НЕЯСНО: ОТПРАВКА',
    'broadcast':'ОЖИДАЕТ / НЕЯСНО', 'prepared':'НЕЯСНО: ПОДГОТОВЛЕНО',
}


def time_now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')


def fmt_decimal(value, precision=10):
    if value is None or value == '':
        return ''
    d = Decimal(value)
    return format(d.quantize(Decimal(1).scaleb(-precision)).normalize(), 'f')


def write_csv(path, fields, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8-sig', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        for r in rows:
            w.writerow(r)


def build_transfer_rows(plan, events, scan_rows=None):
    latest = core.index_events(events)
    rows = []
    lookup={}
    for r in scan_rows or []:
        lookup[(r['network'],r['address'].lower(),(r.get('contract') or '').lower(),r['type'].upper())]=r
    for a in plan['actions']:
        ev = latest.get((plan['approval_hash'], a['id']), {})
        status = ev.get('status', 'not_attempted')
        raw = ev.get('amount_raw')
        origin=lookup.get((a['network'],a['from'].lower(),(a.get('contract') or '').lower(),a['asset_type'])) or {}
        decimals=18 if a['asset_type']=='NATIVE' else int(origin.get('decimals') or 0)
        amount='' if raw in (None,'') or (a['asset_type']!='NATIVE' and not origin.get('decimals')) else format(Decimal(raw)/(Decimal(10)**decimals),'f')
        confirmed_usd=''
        if status == 'success' and amount and origin.get('usd_price'):
            try:
                confirmed_usd=format(Decimal(amount)*Decimal(origin['usd_price']),'f')
            except InvalidOperation:
                pass
        q = dict(network=a['network'], wallet=a['from'], recipient=a['to'],
                 token=a['symbol'], asset_type=a['asset_type'], contract=a.get('contract') or '',
                 status=status, description=STATES.get(status, 'НЕ ОТПРАВЛЕНО'),
                 amount_raw=raw or '', amount=amount, nonce=ev.get('nonce',''), txhash=ev.get('txhash',''),
                 scanned_usd_estimate=a.get('scan_usd',''), confirmed_usd_old_price=confirmed_usd, last_updated=ev.get('time',''))
        rows.append(q)
    return rows


def choose_addresses(plan, key_path, addr_path):
    if key_path.exists():
        keys = core.load_plaintext_keys(key_path, addr_path)
        return set(keys)
    # No private keys needed to make journal-only report. Empty live selection
    # avoids accidental 900-wallet scans when a key file is absent.
    return set()


def positions_for_live(rows, plan, allowed):
    # A planned action can have been sent already; its source must still be checked.
    groups = set()
    for a in plan['actions']:
        if a['from'].lower() in allowed:
            groups.add((a['network'],a['from'].lower()))
    for r in rows:
        if r['address'].lower() not in allowed:
            continue
        raw = r.get('raw_balance') or '0'
        if (r['status'] != 'OK' or (raw.isdigit() and int(raw) > 0)):
            groups.add((r['network'],r['address'].lower()))
    # Native balances must be queried too: tokens need native gas.
    group_rows=defaultdict(list)
    for r in rows:
        key=(r['network'],r['address'].lower())
        if key in groups and (r['type'].lower()=='native' or
                              r['status']!='OK' or int(r.get('raw_balance') or '0') > 0):
            group_rows[key].append(r)
    return group_rows


def _read_one_group(key, rows, networks):
    net, address = key
    outcome=[]
    cfg = networks.get(net)
    if not cfg:
        return [dict(network=net, wallet=address, token=r['symbol'], contract=r['contract'],
                     status='UNKNOWN', remaining='', usd_estimate='', rpc_error='No network config', checked_at=time_now()) for r in rows]
    # Each asset can fail on one provider while others succeed. Attempt up to all
    # configured RPCs per asset without ever turning errors into zero.
    for r in rows:
        checked_at=time_now()
        price = None
        try:
            price = Decimal(r['usd_price']) if r.get('usd_price') else None
        except InvalidOperation:
            pass
        result={'network':net,'wallet':r['address'],'token':r['symbol'],
                'asset_type':r['type'], 'contract':r.get('contract') or '',
                'remaining':'','remaining_raw':'','usd_estimate':'',
                'status':'UNKNOWN','rpc_error':'', 'checked_at':checked_at}
        errors=[]
        for url in cfg.get('rpcs',[]):
            if not isinstance(url,str) or not url.startswith('https://'):
                continue
            try:
                w3=core.Web3(core.Web3.HTTPProvider(url, request_kwargs={'timeout':10}))
                if w3.eth.chain_id != int(cfg['chain_id']):
                    raise RuntimeError('Incorrect chainId')
                if r['type'].lower() == 'native':
                    raw=int(w3.eth.get_balance(r['address']))
                    decimals=18
                else:
                    if not core.Web3.is_address(r.get('contract','')):
                        raise RuntimeError('Invalid token contract')
                    token=w3.eth.contract(address=core.Web3.to_checksum_address(r['contract']), abi=core.ERC20_ABI)
                    raw=int(token.functions.balanceOf(r['address']).call())
                    decimals=int(r['decimals']) if (r.get('decimals') or '').isdigit() else int(token.functions.decimals().call())
                    if decimals < 0 or decimals > 36:
                        raise RuntimeError('Invalid decimals')
                amount=Decimal(raw) / (Decimal(10)**decimals)
                result['remaining_raw']=str(raw)
                result['remaining']=format(amount,'f')
                if price is not None:
                    result['usd_estimate']=format(amount*price,'f')
                result['status']='OK'
                break
            except Exception as e:
                errors.append(type(e).__name__)
        if result['status']!='OK':
            result['rpc_error']=','.join(errors[-5:]) or 'No HTTPS RPC configured'
        outcome.append(result)
    return outcome


def live_balances(scan_rows, plan, networks, addresses, workers=5):
    selected=positions_for_live(scan_rows, plan, addresses)
    results=[]
    if not selected:
        return results
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs=[pool.submit(_read_one_group,key,rr,networks) for key,rr in selected.items()]
        for fut in as_completed(futs):
            results.extend(fut.result())
    return sorted(results,key=lambda x:(x['network'],x['wallet'].lower(),x['asset_type'].lower()!='erc20',x['token']))


def wallet_rows(transfers, remaining):
    grouped=defaultdict(lambda:dict(confirmed=0,uncertain=0,failed=0,not_sent=0,
                                     scan_usd=Decimal(0),confirmed_usd=Decimal(0), remaining_usd=Decimal(0),unknown_balances=0,live_positions=0))
    for t in transfers:
        v=grouped[(t['wallet'],t['network'])]
        if t['status']=='success': v['confirmed']+=1
        elif t['status'] in ('pending','uncertain','broadcast','prepared'): v['uncertain']+=1
        elif t['status']=='failed':v['failed']+=1
        else:v['not_sent']+=1
        if t.get('scanned_usd_estimate'):
            v['scan_usd']+=Decimal(t['scanned_usd_estimate'])
        if t.get('confirmed_usd_old_price'):
            v['confirmed_usd']+=Decimal(t['confirmed_usd_old_price'])
    for r in remaining:
        v=grouped[(r['wallet'],r['network'])]
        v['live_positions']+=1
        if r['status']!='OK':v['unknown_balances']+=1
        elif r['usd_estimate']:v['remaining_usd']+=Decimal(r['usd_estimate'])
        elif int(r.get('remaining_raw') or '0')>0:v['unknown_balances']+=1
    result=[]
    for (wallet,net),v in sorted(grouped.items(),key=lambda x:(x[0][1],x[0][0].lower())):
        result.append({'network':net,'wallet':wallet,'confirmed_transfers':v['confirmed'],
                       'unknown_transfers':v['uncertain'],'failed_transfers':v['failed'],
                       'not_attempted':v['not_sent'],
                       'original_scanned_usd':format(v['scan_usd'],'f'),
                       'confirmed_usd_using_old_prices':format(v['confirmed_usd'],'f'),
                       'remaining_live_usd_using_old_prices':format(v['remaining_usd'],'f') if v['live_positions'] else '',
                       'unavailable_live_positions':v['unknown_balances'],
                       'balance_checked': 'yes' if v['live_positions'] else 'no'})
    return result


def write_html(path, transfers, remaining, wallets, snapshot_time):
    def safe(s):return html.escape(str(s or ''))
    ok=sum(t['status']=='success' for t in transfers)
    unknown=sum(t['status'] in ('pending','uncertain','prepared','broadcast') for t in transfers)
    pending=sum(t['status'] in ('not_attempted','failed') for t in transfers)
    unavail=sum(r['status']!='OK' for r in remaining)
    # Embed plain JSON with '<' escaped to prevent any HTML/script injection.
    payload=json.dumps({'transfers':transfers,'remaining':remaining,'wallets':wallets},ensure_ascii=False).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
    page='''<!doctype html><html lang="ru"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>EVM — итоги переводов</title><style>
:root{font-family:Inter,system-ui,-apple-system,sans-serif;color-scheme:dark;background:#101217;color:#e8edf3}
body{max-width:1360px;margin:auto;padding:30px 22px 90px} h1{font-size:26px;margin:0 0 8px} h2{font-size:19px;margin:28px 0 12px}
small,.muted{color:#a4acb9} .metrics{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0}
.metric{flex:1;min-width:150px;border:1px solid #333946;border-radius:12px;padding:16px;background:#1b202a}.value{font-size:27px;font-weight:750}
.bar{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:13px} input,select{background:#1b202a;border:1px solid #3d4653;color:inherit;padding:11px;border-radius:8px;min-width:165px}
table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;background:#232936;position:sticky;top:0;z-index:1}
th,td{padding:10px;border-bottom:1px solid #303744;white-space:nowrap} .wrap{overflow:auto;border:1px solid #343c48;border-radius:10px;max-height:580px}
tr:nth-child(even){background:#191f28} .okay{color:#7bdfac}.bad{color:#ffb57d}.unknown{color:#ffd77d}
code{font-size:12px} a{color:#9bbaff}
</style></head><body>
<h1>Консолидация EVM — результаты</h1>
<p class="muted">Сформировано: __TIME__. Подтверждено означает receipt со статусом 1. Неопределённые операции нельзя повторять вслепую.</p>
<div class="metrics"><div class="metric"><div class="muted">Подтверждено</div><div class="value okay">__OK__</div></div>
<div class="metric"><div class="muted">Статус не выяснен</div><div class="value unknown">__UNKNOWN__</div></div>
<div class="metric"><div class="muted">Не выполнено / ошибка</div><div class="value bad">__PENDING__</div></div>
<div class="metric"><div class="muted">RPC не проверил остаток</div><div class="value unknown">__UNAVAIL__</div></div></div>
<p class="muted">Остатки взяты из сети на момент запроса, USD-переводы и цены — из старого сканирования. Отображаются только известные сканеру активы. Пустое значение не означает ноль.</p>
<h2>Кошельки по сетям</h2><div class="bar"><input id="walletSearch" placeholder="Адрес или сеть" oninput="render()"></div><div class="wrap"><table><thead><tr><th>Сеть</th><th>Кошелёк</th><th>Подтверждено</th><th>Неясно</th><th>Не отправлено</th><th>Отправлено, $ *</th><th>Осталось, $ *</th><th>Ошибок остатка</th></tr></thead><tbody id="walletRows"></tbody></table></div>
<h2>Что отправлено и что ожидает</h2><div class="bar"><input id="transferSearch" placeholder="Кошелёк, токен, хеш" oninput="render()"><select id="statusFilter" onchange="render()"><option value="">Все статусы</option><option value="success">Подтверждено</option><option value="pending">Неясный статус</option><option value="not_attempted">Не отправлено</option><option value="failed">Ошибка в сети</option></select></div>
<div class="wrap"><table><thead><tr><th>Сеть</th><th>Кошелёк</th><th>Токен</th><th>Статус</th><th>Сумма транзакции</th><th>Стоимость, $ *</th><th>Хеш</th><th>Причина</th></tr></thead><tbody id="transferRows"></tbody></table></div>
<h2>Текущие остатки по активам</h2><div class="bar"><input id="balanceSearch" placeholder="Адрес, сеть или токен" oninput="render()"></div>
<div class="wrap"><table><thead><tr><th>Сеть</th><th>Кошелёк</th><th>Монета</th><th>Осталось</th><th>USD по старой цене *</th><th>Проверка</th></tr></thead><tbody id="balanceRows"></tbody></table></div>
<p><small>* USD — только приблизительная оценка по старой цене сканера, не сумма полученного. Для позиций вне реестра токенов этот отчёт не гарантирует полноту.</small></p>
<script>const DATA=__DATA__;
function el(tag,content){let n=document.createElement(tag);n.textContent=content==null?'':String(content);return n}
function buildRow(fields){let tr=document.createElement('tr'); for(const f of fields){let td=el('td',f);tr.appendChild(td)}return tr}
function search(elId,parts){return parts.join(' ').toLowerCase().includes(document.getElementById(elId).value.trim().toLowerCase())}
function render(){
let wr=document.getElementById('walletRows');wr.replaceChildren();for(const x of DATA.wallets){if(!search('walletSearch',[x.network,x.wallet]))continue;
wr.appendChild(buildRow([x.network,x.wallet,x.confirmed_transfers,x.unknown_transfers,x.not_attempted,x.confirmed_usd_using_old_prices,x.balance_checked==='yes'?x.remaining_live_usd_using_old_prices:'не проверено',x.unavailable_live_positions]))}
let tr=document.getElementById('transferRows');tr.replaceChildren();for(const x of DATA.transfers){if(!search('transferSearch',[x.network,x.wallet,x.token,x.txhash]))continue;
let fil=document.getElementById('statusFilter').value;if(fil && !(fil==='pending'?['pending','uncertain','prepared','broadcast'].includes(x.status):fil===x.status))continue;
tr.appendChild(buildRow([x.network,x.wallet,x.token,x.description,x.amount?x.amount+' '+x.token:x.amount_raw,x.confirmed_usd_old_price,x.txhash,x.reason]))}
let br=document.getElementById('balanceRows');br.replaceChildren();for(const x of DATA.remaining){if(!search('balanceSearch',[x.network,x.wallet,x.token]))continue;
br.appendChild(buildRow([x.network,x.wallet,x.token,x.status==='OK'?x.remaining:'НЕИЗВЕСТНО',x.usd_estimate,x.status==='OK'?x.checked_at:'ОШИБКА RPC: '+x.rpc_error]))}
}render();</script></body></html>'''
    page=page.replace('__TIME__',safe(snapshot_time)).replace('__OK__',str(ok)).replace('__UNKNOWN__',str(unknown)).replace('__PENDING__',str(pending)).replace('__UNAVAIL__',str(unavail)).replace('__DATA__',payload)
    path.write_text(page,encoding='utf-8')


def generate(root=ROOT, *, live=True, addresses=None, workers=5):
    root=Path(root)
    plan=core.load_plan(root/'consolidation/plan.json')
    plans=[plan]
    meme_plan_file=root/'consolidation/meme_plan.json'
    if meme_plan_file.exists():
        plans.append(core.load_plan(meme_plan_file))
    events=core.read_events(root/'consolidation/journal.jsonl')
    selected=addresses
    if selected is None:
        selected=choose_addresses(plan,root/'private_keys.txt',root/'addresses.txt')
    # Include historical transfers even if their private keys were later removed.
    known_plan_hashes={p['approval_hash'] for p in plans}
    historical={str(e.get('from','')).lower() for e in events if e.get('plan_hash') in known_plan_hashes}
    active={a.lower() for a in selected}|historical
    # Delayed until scanner CSV is loaded to provide human-readable token amounts.
    transfers=[]
    networks=json.loads((root/'networks.json').read_text())
    extras=root/'extra_rpcs.json'
    if extras.exists():
        for net,urls in json.loads(extras.read_text()).items():
            if net in networks and isinstance(urls,list):
                networks[net]['rpcs']=list(dict.fromkeys(urls+networks[net]['rpcs']))[:5]
    scan_rows=core.load_csv(root/'reports/balances_all.csv')
    meme_scan_path=root/'consolidation/meme_scan.csv'
    if meme_scan_path.exists():
        with meme_scan_path.open(newline='', encoding='utf-8-sig') as fh:
            scan_rows.extend(csv.DictReader(fh))
    # Sum actions from the original immutable plan AND the independent MEME plan;
    # never rewrite the original approval hash or the journal.
    combined_plan={**plan,'actions':[a for p in plans for a in p['actions']]}
    issue_map={}
    issues_path=root/'consolidation/run_issues.csv'
    if issues_path.exists():
        with issues_path.open(newline='',encoding='utf-8-sig') as f:
            for issue in csv.DictReader(f):
                issue_map[(issue['network'],issue['wallet'].lower(),issue['token'])]=issue.get('reason','')
    transfers=[t for p in plans for t in build_transfer_rows(p,events,scan_rows)
               if t['wallet'].lower() in active]
    for t in transfers:
        t['reason']=issue_map.get((t['network'],t['wallet'].lower(),t['token']),'') if t['status']=='not_attempted' else (
            'Не повторять до сверки по хешу' if t['status'] in ('uncertain','prepared','pending','broadcast') else '')
    remaining=live_balances(scan_rows,combined_plan,networks,active,workers) if live else []
    wallets=wallet_rows(transfers,remaining)
    folder=root/'consolidation'
    write_csv(folder/'transfers.csv', ['network','wallet','recipient','token','asset_type','contract','status','description','amount','amount_raw','nonce','txhash','scanned_usd_estimate','confirmed_usd_old_price','last_updated','reason'],transfers)
    write_csv(folder/'remaining_balances.csv',['network','wallet','token','asset_type','contract','remaining','remaining_raw','usd_estimate','status','rpc_error','checked_at'],remaining)
    write_csv(folder/'wallets_summary.csv',['network','wallet','confirmed_transfers','unknown_transfers','failed_transfers','not_attempted','original_scanned_usd','confirmed_usd_using_old_prices','remaining_live_usd_using_old_prices','unavailable_live_positions','balance_checked'],wallets)
    write_csv(folder/'needs_attention.csv',['network','wallet','recipient','token','asset_type','contract','status','description','amount','amount_raw','nonce','txhash','scanned_usd_estimate','confirmed_usd_old_price','last_updated','reason'],[r for r in transfers if r['status']!='success'])
    write_html(folder/'report.html',transfers,remaining,wallets,time_now())
    return {'transfers':transfers,'remaining':remaining,'wallets':wallets}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--no-refresh',action='store_true',help='Use journal only; live balances not checked')
    p.add_argument('--workers',type=int,default=5)
    args=p.parse_args()
    if args.workers < 1 or args.workers > 10:
        p.error('workers must be 1..10')
    out=generate(live=not args.no_refresh,workers=args.workers)
    counts=Counter(t['status'] for t in out['transfers'])
    print('Отчёт:',ROOT/'consolidation/report.html')
    print('Подтверждено:',counts['success'],'| неопределённых:',sum(counts[s] for s in ('pending','uncertain','broadcast','prepared')))
    print('Проверено активов в сети:',len(out['remaining']), '| не удалось проверить:',sum(r['status']!='OK' for r in out['remaining']))
    print('CSV: transfers.csv, remaining_balances.csv, wallets_summary.csv, needs_attention.csv')

if __name__ == '__main__':
    main()
