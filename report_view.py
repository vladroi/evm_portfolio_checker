"""Offline, dependency-free wallet tables and human-readable HTML dashboard.

Balances are scanned in checker.py; this module only displays public addresses and
already collected results. It does not make requests or handle private keys.
"""
from __future__ import annotations

import csv
import json
from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal
from html import escape
from pathlib import Path


def _sum_usd(records: list[dict]) -> str:
    return format(sum((Decimal(r['usd_value']) for r in records if r['usd_value'] != ''), Decimal(0)), 'f')


def _csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    with path.open('w', encoding='utf-8-sig', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)


def write_wallet_tables(out: Path, rows: list[dict], cfg: dict,
                        addresses: list[str], usd: bool) -> None:
    """Add three easy-to-browse reports, without touching previous CSV reports."""
    out.mkdir(parents=True, exist_ok=True)
    grouped = defaultdict(list)
    for r in rows:
        grouped[(r['address'].lower(), r['network'])].append(r)

    overview = []
    per_network = []
    holdings = []
    wallets = []
    for addr in addresses:
        wallet_nz, wallet_errors, network_info = [], [], []
        columns = {'address': addr}
        for slug, conf in cfg.items():
            display = conf.get('name', slug)
            subset = grouped.get((addr.lower(), slug), [])
            nz = [r for r in subset if r['status'] == 'OK' and r['raw_balance'] not in ('', None) and int(r['raw_balance']) > 0]
            errors = [r for r in subset if r['status'] != 'OK']
            wallet_nz.extend(nz)
            wallet_errors.extend(errors)
            unpriced = sum(r['usd_value'] == '' for r in nz) if usd else 0
            net_usd = _sum_usd(nz) if usd else ''

            columns[f'{slug}_assets'] = '; '.join(f"{r['balance']} {r['symbol']}" for r in nz)
            columns[f'{slug}_usd_known'] = net_usd if nz else ('' if not usd else '0')
            columns[f'{slug}_errors'] = len(errors)

            per_network.append({
                'address': addr, 'network': display,
                'assets': columns[f'{slug}_assets'], 'usd_known': net_usd,
                'nonzero_assets': len(nz), 'unpriced_assets': unpriced,
                'errors': len(errors),
            })
            for r in nz:
                holdings.append({
                    'address': addr, 'network': display, 'asset': r['symbol'],
                    'balance': r['balance'], 'usd_value': r['usd_value'],
                    'type': r['type'], 'contract': r['contract'],
                })
            if nz or errors:
                network_info.append({
                    'slug': slug, 'name': display, 'known_usd': net_usd,
                    'unpriced': unpriced,
                    'holdings': [{
                        'symbol': r['symbol'], 'balance': r['balance'],
                        'usd': r['usd_value'], 'contract': r['contract'],
                        'type': r['type'],
                    } for r in nz],
                    'errors': [{'symbol': r['symbol'], 'message': r['error']} for r in errors],
                })
        priced_total = _sum_usd(wallet_nz) if usd else ''
        missing = sum(r['usd_value'] == '' for r in wallet_nz) if usd else 0
        net_count = sum(bool(n['holdings']) for n in network_info)
        columns.update({
            'usd_known': priced_total, 'nonzero_assets': len(wallet_nz),
            'networks_with_assets': net_count, 'unpriced_assets': missing,
            'errors': len(wallet_errors),
        })
        overview.append(columns)
        wallets.append({
            'address': addr, 'usd_known': priced_total,
            'assets': len(wallet_nz), 'networks': net_count,
            'unpriced': missing, 'errors': len(wallet_errors),
            'details': network_info,
        })

    first = ['address', 'usd_known', 'nonzero_assets', 'networks_with_assets', 'unpriced_assets', 'errors']
    for slug in cfg:
        first.extend([f'{slug}_assets', f'{slug}_usd_known', f'{slug}_errors'])
    _csv(out/'wallets_table.csv', overview, first)
    _csv(out/'wallets_by_network.csv', per_network,
         ['address', 'network', 'assets', 'usd_known', 'nonzero_assets', 'unpriced_assets', 'errors'])
    _csv(out/'wallet_assets.csv', holdings,
         ['address', 'network', 'asset', 'balance', 'usd_value', 'type', 'contract'])

    payload = {
        'wallets': wallets,
        'networks': [{'slug': slug, 'name': conf.get('name', slug)} for slug, conf in cfg.items()],
        'usd': usd,
        'generated_at': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
        'total_usd': _sum_usd([r for r in rows if r['status']=='OK' and r['raw_balance'] not in ('',None) and int(r['raw_balance'])>0]) if usd else '',
        'total_positions': len(holdings),
        'total_errors': sum(w['errors'] for w in wallets),
        'total_unpriced': sum(w['unpriced'] for w in wallets),
    }
    html = _HTML.replace('__REPORT_JSON__', json.dumps(payload, ensure_ascii=False).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026'))
    (out/'portfolio.html').write_text(html, encoding='utf-8')


_HTML = r'''<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Портфель кошельков · EVM Checker</title>
<style>
:root { color-scheme:light; --bg:#f5f7fb; --paper:#fff; --ink:#172337; --muted:#65728a; --line:#e3e8f0; --blue:#315fe9; --red:#ba3d34; }
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif}
.wrap{max-width:1380px;margin:auto;padding:36px 25px 60px}header{display:flex;justify-content:space-between;align-items:end;gap:15px;flex-wrap:wrap}
h1{font-size:29px;letter-spacing:-.9px;margin:0 0 3px}.sub,.muted{color:var(--muted)}.sub{margin:0}.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:25px 0 16px}
.stat,.panel{background:var(--paper);border:1px solid var(--line);border-radius:12px}.stat{padding:19px 20px}.stat .k{display:block;color:var(--muted);font-size:12px;margin-bottom:8px}.stat strong{font-size:25px;font-variant-numeric:tabular-nums}
.warn{background:#fff7e8;border:1px solid #efddb4;border-radius:10px;padding:13px 17px;margin-bottom:16px;color:#6f4d1b}.warn.hidden{display:none}
.toolbar{display:flex;gap:10px;padding:15px;flex-wrap:wrap;align-items:center}input,select{border:1px solid #d7dfec;border-radius:8px;background:#fff;padding:10px 11px;color:var(--ink);font:inherit;min-height:41px}input{width:330px;max-width:100%}select{max-width:100%}
.table-scroll{overflow:auto}.main{width:100%;border-collapse:collapse;text-align:left}.main thead{position:sticky;top:0;z-index:2}.main th{background:#f8fafd;color:var(--muted);font-weight:650;font-size:12px;padding:12px 16px;border-bottom:1px solid var(--line);white-space:nowrap}.main td{padding:12px 16px;border-bottom:1px solid #edf0f5;vertical-align:middle}
.main tr.wallet{cursor:pointer}.main tr.wallet:hover{background:#f5f8ff}.main tr.open{background:#f5f8ff}.main tr:last-child td{border-bottom:0}
.wallet-id{font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;color:#263247}.ticker{background:#eff3fc;color:#425372;padding:3px 7px;border-radius:5px;font-size:11px;display:inline-block;margin:2px 4px 2px 0;white-space:nowrap}
.money{font-variant-numeric:tabular-nums;font-weight:700;white-space:nowrap}.err{font-weight:650;color:var(--red)}.count{font-variant-numeric:tabular-nums}.zero{color:#9ca7b8}
.detail-cell{background:#fafbff!important;padding:20px 22px!important}.detail-head{display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap;border-bottom:1px solid var(--line);padding-bottom:13px;margin-bottom:14px}.full-id{font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}.blocks{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
.chain{background:#fff;border:1px solid var(--line);border-radius:10px;padding:14px 15px}.chain h3{font-size:14px;margin:0 0 11px}.chain small{color:var(--muted)}.asset-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;padding:8px 0;border-bottom:1px solid #f0f2f7}.asset-row:last-child{border:0}.asset-qty{font-variant-numeric:tabular-nums;overflow-wrap:anywhere}.asset-price{text-align:right;white-space:nowrap}.asset-name{font-weight:600}.unknown{color:#9b6d28}.problem{font-size:12px;color:var(--red);margin-top:8px}details{margin-top:8px}summary{cursor:pointer;font-weight:600}ul{padding-left:18px;margin:8px 0 0}li{overflow-wrap:anywhere;margin:5px 0}
.links{padding:14px 17px;color:var(--muted);display:flex;gap:16px;flex-wrap:wrap}.links a{color:var(--blue);text-decoration:none}.links a:hover{text-decoration:underline}.empty{padding:30px;color:var(--muted);text-align:center}.foot{margin-top:18px;color:var(--muted);font-size:12px}
@media(max-width:720px){.wrap{padding:20px 12px}.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.stat{padding:13px}.stat strong{font-size:20px}.toolbar{align-items:stretch}.toolbar input,.toolbar select{width:100%}.main th,.main td{padding:10px 8px}.hidden-mobile{display:none}}
</style>
</head>
<body>
<div class="wrap">
<header><div><h1>Портфель кошельков</h1><p class="sub">EVM Checker · публичные адреса · <span id="generated"></span></p></div><span class="muted" id="shown"></span></header>
<div class="stats">
<div class="stat"><span class="k">Кошельков</span><strong id="wallet-count"></strong></div>
<div class="stat"><span class="k">Известная стоимость, USD</span><strong id="usd-total"></strong></div>
<div class="stat"><span class="k">Ненулевых позиций</span><strong id="positions-total"></strong></div>
<div class="stat"><span class="k">Ошибок проверки</span><strong id="error-total"></strong></div>
</div>
<div class="warn hidden" id="warning"></div>
<div class="panel">
<div class="toolbar">
<input id="search" placeholder="Поиск по адресу 0x…" aria-label="Поиск адреса">
<select id="network" aria-label="Фильтр по сети"></select>
<select id="status" aria-label="Фильтр кошельков"><option value="all">Все кошельки</option><option value="funded">С балансом</option><option value="errors">С ошибками</option><option value="clean">Без ошибок</option></select>
<select id="sort" aria-label="Сортировка"><option value="usd">Сначала по USD ↓</option><option value="assets">Сначала по числу активов ↓</option><option value="errors">Сначала по ошибкам ↓</option><option value="address">По адресу A–Z</option></select>
</div>
<div class="table-scroll"><table class="main"><thead><tr><th>№</th><th>Кошелёк</th><th>Известно USD</th><th>Активов</th><th>Сетей</th><th>Ошибок</th><th class="hidden-mobile">Найденные сети</th></tr></thead><tbody id="wallet-body"></tbody></table></div>
<div class="links">CSV-таблицы: <a href="wallets_table.csv">Кошельки × сети</a><a href="wallet_assets.csv">Все ненулевые токены</a><a href="wallets_by_network.csv">Кошелёк × сеть</a><a href="errors.csv">Ошибки</a></div>
</div>
<div class="foot">Сумма USD отражает только найденные активы с доступной ценой. Токены вне настроенного списка не обнаруживаются автоматически; при ошибках RPC стоимость может быть занижена. Для деталей нажмите на строку кошелька. Файл работает без интернета.</div>
</div>
<script type="application/json" id="report-data">__REPORT_JSON__</script>
<script>
'use strict';
const data=JSON.parse(document.getElementById('report-data').textContent);
const $=id=>document.getElementById(id);
const escapeHtml=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const nfmt=new Intl.NumberFormat('ru-RU',{maximumFractionDigits:2});
function price(value){if(value===''||value===null||value===undefined)return '—';let n=Number(value);if(!Number.isFinite(n))return '—';if(n>0&&n<0.01)return '< $0,01';return '$'+nfmt.format(n);}
function quant(value){const n=Number(value);if(!Number.isFinite(n))return escapeHtml(value);if(n!==0&&Math.abs(n)<0.00000001)return n.toExponential(5);if(Math.abs(n)>=0.00000001&&Math.abs(n)<1e12)return new Intl.NumberFormat('ru-RU',{maximumSignificantDigits:10}).format(n);return escapeHtml(value);}
function detailHtml(w){
 const sections=w.details.map(net=>{
   const tokens=net.holdings.map(a=>`<div class="asset-row"><div><div class="asset-name">${escapeHtml(a.symbol)}</div><div class="asset-qty">${quant(a.balance)} <small>${escapeHtml(a.symbol)}</small></div></div><div class="asset-price">${a.usd===''?'<span class="unknown">нет цены</span>':price(a.usd)}</div></div>`).join('');
   const er=net.errors.length?`<details><summary class="problem">${net.errors.length} ошибок проверки — показать</summary><ul>${net.errors.map(e=>`<li>${escapeHtml(e.symbol)}: ${escapeHtml(e.message)}</li>`).join('')}</ul></details>`:'';
   const msg=!net.holdings.length?'<small>Ненулевые активы не подтверждены.</small>':'';
   return `<section class="chain"><h3>${escapeHtml(net.name)} · ${net.holdings.length} активов</h3>${tokens}${msg}${er}</section>`;
 }).join('');
 return `<div class="detail-head"><span class="full-id">${escapeHtml(w.address)}</span><span class="muted">${w.unpriced?escapeHtml(w.unpriced)+' актив(ов) без цены · ':''}${w.errors?escapeHtml(w.errors)+' ошибок':''}</span></div><div class="blocks">${sections||'<span class="muted">Из проверенных токенов ненулевых балансов нет.</span>'}</div>`;
}
const opened=new Set();
function render(){
 const q=$('search').value.trim().toLowerCase(), net=$('network').value, status=$('status').value, sort=$('sort').value;
 const arr=data.wallets.filter(w=>{
   if(q&&!w.address.toLowerCase().includes(q))return false;
   if(net!=='all'&&!w.details.some(d=>d.slug===net&&(d.holdings.length||d.errors.length)))return false;
   if(status==='funded'&&!w.assets)return false;
   if(status==='errors'&&!w.errors)return false;
   if(status==='clean'&&w.errors)return false;
   return true;
 });
 arr.sort((a,b)=>{let d=0;if(sort==='usd')d=Number(b.usd_known||0)-Number(a.usd_known||0);else if(sort==='assets')d=b.assets-a.assets;else if(sort==='errors')d=b.errors-a.errors;return d||a.address.localeCompare(b.address);});
 $('shown').textContent=`Показано ${arr.length} из ${data.wallets.length}`;
 const tb=$('wallet-body');tb.innerHTML='';if(!arr.length){tb.innerHTML='<tr><td class="empty" colspan="7">Нет кошельков по выбранным фильтрам</td></tr>';return;}
 const fragment=document.createDocumentFragment();
 arr.forEach((w,i)=>{
   const isOpen=opened.has(w.address),tr=document.createElement('tr');tr.className='wallet'+(isOpen?' open':'');tr.tabIndex=0;tr.setAttribute('role','button');tr.setAttribute('aria-expanded',String(isOpen));
   const nets=w.details.filter(d=>d.holdings.length).map(d=>`<span class="ticker">${escapeHtml(d.name)} · ${d.holdings.length}</span>`).join('');
   tr.innerHTML=`<td class="count muted">${i+1}</td><td><span class="wallet-id" title="${escapeHtml(w.address)}">${escapeHtml(w.address.slice(0,9)+'…'+w.address.slice(-6))}</span></td><td class="money">${data.usd?price(w.usd_known):'<span class="muted">нет оценки</span>'}${w.unpriced?' <span title="Есть токены без USD-цены" class="unknown">*</span>':''}</td><td class="count">${w.assets}</td><td class="count">${w.networks}</td><td class="count ${w.errors?'err':'zero'}">${w.errors}</td><td class="hidden-mobile">${nets||'<span class="zero">—</span>'}</td>`;
   const toggle=()=>{if(opened.has(w.address))opened.delete(w.address);else opened.add(w.address);render();};
   tr.addEventListener('click',toggle);tr.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();toggle();}});fragment.appendChild(tr);
   if(isOpen){const dtr=document.createElement('tr');const cell=document.createElement('td');cell.colSpan=7;cell.className='detail-cell';cell.innerHTML=detailHtml(w);dtr.appendChild(cell);fragment.appendChild(dtr);}
 });tb.appendChild(fragment);
}
$('generated').textContent=data.generated_at;
$('wallet-count').textContent=nfmt.format(data.wallets.length);
$('usd-total').textContent=data.usd?price(data.total_usd):'—';
$('positions-total').textContent=nfmt.format(data.total_positions);
$('error-total').textContent=nfmt.format(data.total_errors);
const warning=[];
if(data.total_errors)warning.push(`${data.total_errors} проверок завершились ошибкой. Часть балансов неизвестна, итог в USD может быть занижен.`);
if(data.total_unpriced)warning.push(`${data.total_unpriced} ненулевых позиций не имеют цены в USD.`);
if(!data.usd)warning.push('Запуск без --usd: USD-оценка не выполнялась.');
if(warning.length){$('warning').classList.remove('hidden');$('warning').textContent=warning.join(' ');}
$('network').innerHTML='<option value="all">Все сети</option>'+data.networks.map(n=>`<option value="${escapeHtml(n.slug)}">${escapeHtml(n.name)}</option>`).join('');
['search','network','status','sort'].forEach(id=>$(id).addEventListener(id==='search'?'input':'change',render));
render();
</script>
</body>
</html>'''
