#!/usr/bin/env python3
"""Read-only independent on-chain verification for EVM Consolidator.

NEVER reads private_keys.txt, signs or sends any transactions.
Checks receipt status AND the actual transfer details. Also checks current
balances for tracked wallet/network/token positions. Original journal unchanged.
"""
import argparse
import csv
import html
import json
import re
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from decimal import Decimal
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

ERC20_TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
TRANSFER_SELECTOR = 'a9059cbb'
BALANCE_OF_SELECTOR = '70a08231'
DECIMALS_SELECTOR = '313ce567'

_tls = threading.local()


def lower(value):
    return str(value or '').lower()


def int_hex(value):
    if value is None: raise ValueError('Missing hex quantity')
    return int(value, 16) if isinstance(value, str) and value.startswith('0x') else int(value)


def valid_addr(value):
    return bool(re.fullmatch(r'0x[0-9a-fA-F]{40}', value or ''))


def load_csv(path):
    with open(path, newline='', encoding='utf-8-sig') as f:
        return list(csv.DictReader(f))


def load_networks(path, override):
    configs = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    if Path(override).exists():
        extra = json.loads(Path(override).read_text(encoding='utf-8-sig'))
        for network, rpcs in extra.items():
            if network in configs and isinstance(rpcs, list):
                configs[network]['rpcs'] = list(dict.fromkeys(
                    [u for u in rpcs if isinstance(u, str) and u.startswith('https://')] + configs[network]['rpcs']))
    return configs


def rpc(url, method, params, timeout=12):
    payload = json.dumps({'jsonrpc':'2.0','id':1,'method':method,'params':params},separators=(',',':')).encode()
    req = Request(url, data=payload, headers={'Content-Type':'application/json','User-Agent':'evm-readonly-audit/1.0'})
    with urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read(3_000_000))
    if not isinstance(data, dict): raise RuntimeError('Malformed JSON-RPC response')
    if data.get('error'): raise RuntimeError('RPC returned an error')
    if 'result' not in data: raise RuntimeError('Missing RPC result')
    return data['result']


def obtain(network, cfg, fn):
    """Use same chain for all calls in a verification attempt."""
    errors = []
    matches = []
    for url in cfg.get('rpcs', []):
        if not isinstance(url, str) or not url.startswith('https://'):
            continue
        try:
            if int_hex(rpc(url,'eth_chainId',[])) != int(cfg['chain_id']):
                errors.append('chain id mismatch'); continue
            result = fn(url)
            return result, ''
        except (RuntimeError,ValueError,URLError,HTTPError,TimeoutError,KeyError,TypeError) as exc:
            errors.append(type(exc).__name__)
        except Exception as exc:
            errors.append(type(exc).__name__)
    return None, ('RPC_UNAVAILABLE: ' + ', '.join(errors[:5]) if errors else 'NO_RPC')


def tx_check(row, configs):
    net = row.get('network','')
    result = {
        'network':net, 'wallet':row.get('wallet',''), 'recipient':row.get('recipient',''),
        'token':row.get('token',''), 'asset_type':row.get('asset_type',''),
        'contract':row.get('contract',''), 'expected_amount_raw':row.get('amount_raw',''),
        'txhash':row.get('txhash',''), 'journal_status':row.get('status',''),
        'onchain_status':'', 'details':'', 'chain_block':'', 'actual_amount_raw':'',
    }
    if row.get('status') != 'success':
        result.update(onchain_status='NOT_ATTEMPTED',details=row.get('reason',''))
        return result
    if net not in configs:
        result.update(onchain_status='UNVERIFIED', details='Network absent from config')
        return result
    h = row.get('txhash','')
    if not re.fullmatch(r'0x[0-9a-fA-F]{64}',h):
        result.update(onchain_status='UNVERIFIED',details='Invalid or missing transaction hash')
        return result
    # A missing receipt on one RPC must not stop the check: ask other RPCs.
    receipt, tx = None, None
    checked = 0
    fail_classes = []
    for url in configs[net].get('rpcs', []):
        if not isinstance(url, str) or not url.startswith('https://'):
            continue
        try:
            if int_hex(rpc(url,'eth_chainId',[])) != int(configs[net]['chain_id']):
                fail_classes.append('WrongChainId'); continue
            r = rpc(url,'eth_getTransactionReceipt',[h])
            t = rpc(url,'eth_getTransactionByHash',[h])
            checked += 1
            if r is not None:
                receipt, tx = r, t
                if tx is not None:break
        except Exception as exc:
            fail_classes.append(type(exc).__name__)
    if receipt is None:
        if checked:
            result.update(onchain_status='NOT_FOUND',details=f'No receipt on {checked} validated RPC(s); not proof of failure')
        else:
            result.update(onchain_status='RPC_UNAVAILABLE',details='All endpoints failed: '+', '.join(fail_classes[:5]))
        return result
    result['chain_block'] = str(int_hex(receipt.get('blockNumber'))) if receipt.get('blockNumber') else ''
    if int_hex(receipt.get('status')) != 1:
        result.update(onchain_status='FAILED',details='Receipt status != 1')
        return result
    if not tx:
        result.update(onchain_status='UNVERIFIED',details='Successful receipt but transaction body unavailable')
        return result
    if lower(receipt.get('transactionHash')) != lower(h) or lower(tx.get('hash')) != lower(h):
        result.update(onchain_status='MISMATCH',details='Receipt/transaction hash mismatch')
        return result
    if lower(tx.get('from')) != lower(row.get('wallet')) or lower(receipt.get('from')) != lower(row.get('wallet')):
        result.update(onchain_status='MISMATCH',details='Sender does not match wallet')
        return result
    try:
        expected = int(row['amount_raw'])
    except (ValueError,TypeError):
        result.update(onchain_status='UNVERIFIED',details='Missing expected raw amount in CSV')
        return result
    typ = row.get('asset_type','').upper()
    if typ == 'NATIVE':
        actual = int_hex(tx.get('value'))
        result['actual_amount_raw'] = str(actual)
        if lower(tx.get('to')) != lower(row.get('recipient')):
            result.update(onchain_status='MISMATCH', details='Native tx sent to another recipient')
        elif actual != expected:
            result.update(onchain_status='MISMATCH',details='Native tx amount differs from journal')
        else:
            result.update(onchain_status='VERIFIED',details='Native transfer verified: recipient and amount')
        return result
    if typ != 'ERC20' or not valid_addr(row.get('contract','')):
        result.update(onchain_status='UNVERIFIED',details='Missing ERC20 contract information')
        return result
    if lower(tx.get('to')) != lower(row.get('contract')):
        result.update(onchain_status='MISMATCH',details='ERC20 tx called another contract')
        return result
    if int_hex(tx.get('value')) != 0:
        result.update(onchain_status='MISMATCH',details='ERC20 tx unexpectedly contains native value')
        return result
    calldata = lower(tx.get('input') or tx.get('data'))
    if not calldata.startswith('0x'+TRANSFER_SELECTOR) or len(calldata) < 138:
        result.update(onchain_status='MISMATCH',details='Contract call is not ERC20 transfer(address,uint256)')
        return result
    input_recipient = '0x'+calldata[34:74]
    call_value = int(calldata[74:138],16)
    if lower(input_recipient) != lower(row['recipient']) or call_value != expected:
        result.update(onchain_status='MISMATCH',details='ERC20 call destination or amount differs')
        return result
    total_received = 0
    for log in receipt.get('logs',[]):
        topics = log.get('topics') or []
        if lower(log.get('address')) != lower(row['contract']) or len(topics) < 3:continue
        if lower(topics[0]) != ERC20_TRANSFER_TOPIC:continue
        source = '0x'+topics[1][-40:]
        dest = '0x'+topics[2][-40:]
        if lower(source) == lower(row['wallet']) and lower(dest) == lower(row['recipient']):
            total_received += int_hex(log.get('data'))
    result['actual_amount_raw'] = str(total_received)
    if total_received != expected:
        result.update(onchain_status='MISMATCH',details='Missing or different ERC20 Transfer event (received: '+str(total_received)+')')
    else:
        result.update(onchain_status='VERIFIED',details='Token Transfer event verified: recipient and amount')
    return result


def balances(rows, networks, max_workers):
    # Deliberately only checks assets mentioned in transfers.csv; not unknown tokens.
    positions = {}
    for row in rows:
        net = row['network']; wallet = row['wallet']; token = row['token']; contract = row.get('contract','')
        if not valid_addr(wallet) or net not in networks:continue
        typ = row.get('asset_type','').upper()
        key = (net, lower(wallet),lower(contract) if typ == 'ERC20' else 'native')
        positions[key] = {'network':net,'wallet':wallet,'token':token,'asset_type':typ,'contract':contract}
    def check(position):
        net, wallet, typ, contract = position['network'],position['wallet'],position['asset_type'],position['contract']
        def read(url):
            block = rpc(url,'eth_blockNumber',[])
            if typ == 'NATIVE':
                return int_hex(rpc(url,'eth_getBalance',[wallet,'latest'])),18,int_hex(block)
            payload = {'to':contract,'data':'0x'+BALANCE_OF_SELECTOR + lower(wallet)[2:].rjust(64,'0')}
            value = int_hex(rpc(url,'eth_call',[payload,'latest']))
            dp = {'to':contract,'data':'0x'+DECIMALS_SELECTOR}
            decimals = int_hex(rpc(url,'eth_call',[dp,'latest']))
            return value, decimals,int_hex(block)
        v,err=obtain(net,networks[net],read)
        if err:return {**position,'raw_balance':'','balance':'','block':'','state':'RPC_ERROR','reason':err}
        amount,dp,block=v
        if dp < 0 or dp > 36:
            return {**position,'raw_balance':'','balance':'','block':str(block),'state':'ERROR','reason':'Invalid token decimals'}
        return {**position,'raw_balance':str(amount),'balance':str(Decimal(amount)/Decimal(10**dp)),
                'block':str(block),'state':'OK','reason':''}
    out=[]
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures=[pool.submit(check, p) for p in positions.values()]
        for i,f in enumerate(as_completed(futures),1):
            try:out.append(f.result())
            except Exception as exc:out.append({'network':'','wallet':'','token':'','asset_type':'',
                'contract':'','raw_balance':'','balance':'','block':'','state':'ERROR','reason':type(exc).__name__})
            if i%100 == 0:print(f'Current-balance checks: {i}/{len(futures)}',flush=True)
    return sorted(out,key=lambda v:(v['network'],lower(v['wallet']),v['token']))


def dump_csv(path, rows, cols):
    with open(path,'w',newline='',encoding='utf-8-sig') as f:
        w=csv.DictWriter(f,fieldnames=cols,extrasaction='ignore')
        w.writeheader();w.writerows(rows)


def page(path, txrows, balances_rows):
    ct=Counter(x['onchain_status'] for x in txrows)
    remaining=sum(1 for x in balances_rows if x.get('state')=='OK' and Decimal(x.get('balance') or '0')>0)
    def trlist(rows,fields):
        return ''.join('<tr>'+''.join('<td>'+html.escape(str(row.get(k,'')))+'</td>' for k in fields)+'</tr>' for row in rows)
    txcols=['network','wallet','token','onchain_status','expected_amount_raw','actual_amount_raw','txhash','details']
    bcols=['network','wallet','token','balance','state','reason']
    body=f'''<!doctype html><html lang="ru"><meta charset="utf-8"><title>Проверка переводов</title>
<style>body{{font-family:system-ui,Arial,sans-serif;margin:24px;background:#f7f8fa;color:#20242b}}h1,h2{{letter-spacing:-.04em}}.stat{{display:inline-block;background:white;padding:15px;border-radius:9px;margin:4px}}input{{padding:12px;width:95%;border:1px solid #ccc;border-radius:7px;margin:14px 0}}.scroll{{overflow:auto;max-height:520px;border:1px solid #ddd;background:#fff}}table{{border-collapse:collapse;font-size:12px;width:100%}}th,td{{border-bottom:1px solid #eee;padding:9px;text-align:left;white-space:nowrap}}th{{position:sticky;top:0;background:#edf0f4}} .warn{{color:#9a4d0c}}</style>
<h1>Проверка переводов по блокчейну</h1><p>Только чтение. VERIFIED = квитанция + настоящий получатель + точная сумма/событие Transfer. Старое SUCCESS не является доказательством.</p>
<div class="stat">Подтверждено переводов: <strong>{ct['VERIFIED']}</strong></div><div class="stat">Не подтверждено/не совпало: <strong>{sum(v for k,v in ct.items() if k not in ('VERIFIED','NOT_ATTEMPTED'))}</strong></div><div class="stat">Осталось ненулевых известных позиций: <strong>{remaining}</strong></div>
<h2>Аудит транзакций</h2><input placeholder="Поиск по адресу / сети / токену / статусу" oninput="filter('txs',this.value)"><div class="scroll"><table id="txs"><thead><tr>{''.join('<th>'+c+'</th>' for c in txcols)}</tr></thead><tbody>{trlist(txrows,txcols)}</tbody></table></div>
<h2>Текущие остатки известных активов</h2><p class="warn">Ненулевой баланс не всегда означает неудавшийся перевод: средства могли поступить позже сканирования или остаться из-за комиссии. Неизвестные токены вне списка не проверялись.</p><input placeholder="Поиск по кошельку / сети" oninput="filter('balances',this.value)"><div class="scroll"><table id="balances"><thead><tr>{''.join('<th>'+c+'</th>' for c in bcols)}</tr></thead><tbody>{trlist(balances_rows,bcols)}</tbody></table></div>
<script>function filter(id,q){{q=q.toLowerCase();for(let tr of document.querySelectorAll('#'+id+' tbody tr'))tr.style.display=tr.textContent.toLowerCase().includes(q)?'':'none';}}</script></html>'''
    Path(path).write_text(body,encoding='utf-8')


def main():
    p=argparse.ArgumentParser(description='Read-only verification: no keys, no broadcast')
    p.add_argument('--csv', default='consolidation/transfers.csv')
    p.add_argument('--networks',default='networks.json')
    p.add_argument('--extra-rpcs',default='extra_rpcs.json')
    p.add_argument('--only',default='',help='Network slug e.g. optimism')
    p.add_argument('--workers',type=int,default=5)
    p.add_argument('--skip-balances',action='store_true')
    p.add_argument('--out',default='consolidation/audit')
    args=p.parse_args()
    args.workers=max(1,min(args.workers,10))
    rows=load_csv(args.csv)
    if args.only: rows=[r for r in rows if r.get('network')==args.only]
    if not rows:raise SystemExit('No report entries match filters')
    cfgs=load_networks(args.networks,args.extra_rpcs)
    destination=Counter(lower(r.get('recipient')) for r in rows)
    print('Recipients in report:', ', '.join(destination))
    print('Auditing',len(rows),'rows, including',sum(r.get('status')=='success' for r in rows),'journal SUCCESS; read-only')
    report=[]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        fs=[pool.submit(tx_check,row,cfgs) for row in rows]
        for i,f in enumerate(as_completed(fs),1):
            try:report.append(f.result())
            except Exception as exc:report.append({'onchain_status':'AUDIT_ERROR','details':type(exc).__name__})
            if i%100==0:print('Transaction checks:',i,'/',len(fs),flush=True)
    report.sort(key=lambda x:(x.get('network',''),lower(x.get('wallet')),x.get('token','')))
    print('On-chain transfer verification:',dict(Counter(x['onchain_status'] for x in report)))
    rest=[] if args.skip_balances else balances(rows,cfgs,args.workers)
    out=Path(args.out);out.mkdir(parents=True,exist_ok=True)
    txfields=['network','wallet','recipient','token','asset_type','contract','journal_status','onchain_status',
              'expected_amount_raw','actual_amount_raw','txhash','chain_block','details']
    dump_csv(out/'transactions_verified.csv',report,txfields)
    balfields=['network','wallet','token','asset_type','contract','raw_balance','balance','block','state','reason']
    dump_csv(out/'remaining_live.csv',rest,balfields)
    page(out/'report.html',report,rest)
    print('Saved:',out/'transactions_verified.csv',out/'remaining_live.csv',out/'report.html')
    print('No keys read; no transactions sent; journal unchanged.')


if __name__=='__main__':main()
