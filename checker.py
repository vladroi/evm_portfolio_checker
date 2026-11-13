#!/usr/bin/env python3
"""Read-only EVM portfolio checker: native balances + configured ERC-20/BEP-20 tokens.
No private keys, signing, approvals, or transfers.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import random
import sys
import time
import shutil
from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from urllib.parse import urlparse

import aiohttp
from web3 import Web3
from report_view import write_wallet_tables

HERE = Path(__file__).resolve().parent
BALANCE_OF = '0x70a08231'
DECIMALS = '0x313ce567'
HEADERS = ['address','network','chain_id','type','symbol','contract','balance',
           'raw_balance','decimals','usd_price','usd_value','status','error','block_tag']

class RPCError(Exception):
    pass

class FatalContractError(RPCError):
    """A contract-specific problem, not a provider outage."""

class TransientRPCError(RPCError):
    pass

class UnsupportedRPCMethod(TransientRPCError):
    """Method is unavailable on this endpoint, not on the whole blockchain."""


def short_error(err: Exception) -> str:
    msg = str(err).replace('\n', ' ').strip()
    # Don't accidentally export key-bearing URL strings in reports.
    return (msg[:160] if msg else type(err).__name__)


def rpc_host(url: str) -> str:
    return urlparse(url).hostname or '(invalid)'


class RPCPool:
    def __init__(self, slug: str, cfg: dict, session: aiohttp.ClientSession,
                 global_limiter: asyncio.Semaphore, per_network: int = 3):
        self.slug, self.cfg, self.session = slug, cfg, session
        self.limit, self.global_limiter = asyncio.Semaphore(per_network), global_limiter
        self.endpoints = [{'url': url, 'host': rpc_host(url), 'valid': None,
                           'failures': 0, 'until': 0.0, 'last_error': '',
                           'probe_lock': asyncio.Lock(), 'calls': 0,
                           'unsupported_methods': set()}
                          for url in dict.fromkeys(cfg['rpcs'])]
        self.round_robin = 0

    async def _post(self, url: str, method: str, params: list):
        body = {'jsonrpc': '2.0', 'method': method, 'params': params, 'id': 1}
        try:
            async with self.global_limiter:
                async with self.session.post(url, json=body) as response:
                    if response.status in (401, 403, 408, 409, 425, 429) or response.status >= 500:
                        raise TransientRPCError(f'HTTP {response.status}')
                    if response.status != 200:
                        raise TransientRPCError(f'HTTP {response.status}')
                    payload = await response.json(content_type=None)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as e:
            raise TransientRPCError(type(e).__name__) from e
        if not isinstance(payload, dict):
            raise TransientRPCError('Unexpected JSON response')
        if payload.get('error') is not None:
            err = payload['error']
            msg = str(err.get('message', 'RPC application error')) if isinstance(err, dict) else 'RPC application error'
            code = err.get('code') if isinstance(err, dict) else None
            lower = msg.lower()
            unsupported = ('method not supported', 'method is not supported',
                           'method not found', 'unsupported method', 'not available',
                           'method eth_call is not supported')
            if code == -32601 or any(word in lower for word in unsupported):
                raise UnsupportedRPCMethod(f'RPC {code}: {msg[:80]}')
            # -32603 ('Internal error') and other generic node errors can be
            # provider-specific. Try different RPCs before declaring a failure.
            transient_words = ('rate limit', 'too many', 'timeout', 'busy', 'temporarily',
                               'upstream', 'unavailable', 'overload', '429', 'limit exceeded')
            if code in (-32603, -32000, -32005, -32016) or any(s in lower for s in transient_words):
                if 'execution reverted' not in lower and 'invalid opcode' not in lower:
                    raise TransientRPCError(f'RPC {code}: {msg[:80]}')
            # A real EVM revert is contract-specific; changing RPC usually won't fix it.
            if 'execution reverted' in lower or 'invalid opcode' in lower:
                raise FatalContractError(f'RPC {code}: {msg[:80]}')
            # Unknown provider errors must not silently appear as zero balances.
            raise TransientRPCError(f'RPC {code}: {msg[:80]}')
        value = payload.get('result')
        if not isinstance(value, str) or not value.startswith('0x'):
            raise TransientRPCError('Missing/invalid hex result')
        return value

    async def _validate(self, ep: dict):
        if ep['valid'] is True:
            return
        async with ep['probe_lock']:
            if ep['valid'] is True:
                return
            chain_hex = await self._post(ep['url'], 'eth_chainId', [])
            actual = int(chain_hex, 16)
            if actual != self.cfg['chain_id']:
                ep['valid'] = False  # permanently disable incorrect chain
                raise TransientRPCError(f'chainId mismatch: {actual}')
            ep['valid'] = True

    def _failure(self, ep: dict, exc: Exception):
        ep['failures'] += 1
        ep['last_error'] = short_error(exc)
        ep['until'] = time.monotonic() + min(60, 2 ** min(6, ep['failures']))

    async def call(self, method: str, params: list) -> str:
        if not self.endpoints:
            raise RPCError('No endpoints configured')
        async with self.limit:
            # Round-robin prevents pushing every balanceOf query through one public RPC.
            failures = []
            for attempt in range(3):
                order = self.endpoints[self.round_robin:] + self.endpoints[:self.round_robin]
                self.round_robin = (self.round_robin + 1) % len(self.endpoints)
                for ep in order:
                    if (ep['valid'] is False or method in ep['unsupported_methods']
                            or time.monotonic() < ep['until']):
                        continue
                    try:
                        await self._validate(ep)
                        result = await self._post(ep['url'], method, params)
                        ep['failures'], ep['until'], ep['last_error'] = 0, 0, ''
                        ep['calls'] += 1
                        return result
                    except FatalContractError:
                        # Contract execution revert is not caused by a throttled endpoint.
                        raise
                    except UnsupportedRPCMethod as e:
                        ep['unsupported_methods'].add(method)
                        ep['last_error'] = short_error(e)
                        failures.append(f'{ep["host"]}: {short_error(e)}')
                    except (TransientRPCError, ValueError) as e:
                        self._failure(ep, e)
                        failures.append(f'{ep["host"]}: {short_error(e)}')
                # If all public endpoints are temporarily throttled, allow cooldown
                # instead of instantly declaring every remaining token inaccessible.
                available_later = [ep['until'] for ep in self.endpoints if ep['valid'] is not False]
                if attempt < 2 and available_later:
                    delay = max(0.2, min(5.0, min(available_later)-time.monotonic()))
                    await asyncio.sleep(delay + random.uniform(0, 0.2))
            if not failures:
                if all(method in ep['unsupported_methods'] or ep['valid'] is False for ep in self.endpoints):
                    raise RPCError(f'No usable RPC endpoint supports {method}')
                raise RPCError('All RPC endpoints are unavailable/cooling down')
            raise RPCError('All RPC attempts failed: ' + '; '.join(failures[-3:]))

    async def probe_all(self, sample_token: dict | None = None):
        async def one(ep):
            try:
                # eth_chainId/eth_blockNumber are NOT proof that eth_call works.
                await self._validate(ep)
                bn = await self._post(ep['url'], 'eth_blockNumber', [])
                status = {'provider': ep['host'], 'status': 'ok', 'block': int(bn,16)}
                if sample_token:
                    try:
                        val = await self._post(ep['url'], 'eth_call',
                                               [{'to': sample_token['address'], 'data': DECIMALS}, 'latest'])
                        if val == '0x' or not (0 <= int(val, 16) <= 36):
                            raise TransientRPCError('Invalid decimals() response')
                        status['eth_call'] = 'ok'
                    except Exception as e:
                        status['eth_call'] = 'failed'
                        status['eth_call_error'] = short_error(e)
                        if isinstance(e, UnsupportedRPCMethod):
                            ep['unsupported_methods'].add('eth_call')
                        # A usable RPC for native balances may still reject eth_call.
                return status
            except Exception as e:
                self._failure(ep, e)
                return {'provider': ep['host'], 'status': 'failed', 'error': short_error(e)}
        return await asyncio.gather(*(one(ep) for ep in self.endpoints))

    def health(self):
        return {'network': self.slug, 'chain_id': self.cfg['chain_id'], 'providers': [
            {'host': ep['host'], 'validated': ep['valid'], 'calls': ep['calls'],
             'failures': ep['failures'], 'error': ep['last_error'],
             'unsupported_methods': sorted(ep['unsupported_methods'])} for ep in self.endpoints]}


def read_addresses(path: Path) -> list[str]:
    result, seen = [], set()
    with path.open(encoding='utf-8-sig') as f:
        for i, raw in enumerate(f, 1):
            value = raw.strip()
            if not value or value.startswith('#') or value.startswith('//'):
                continue
            if not Web3.is_address(value):
                print(f'Warning: line {i}: invalid EVM address, skipped', file=sys.stderr)
                continue
            checksum = Web3.to_checksum_address(value)
            if checksum.lower() in seen:
                continue
            result.append(checksum)
            seen.add(checksum.lower())
    return result


def load_settings(networks_path: Path, tokens_path: Path, extra_rpc_path: Path | None):
    cfg = json.loads(networks_path.read_text(encoding='utf-8'))
    tokens = json.loads(tokens_path.read_text(encoding='utf-8'))
    extra = json.loads(extra_rpc_path.read_text(encoding='utf-8')) if extra_rpc_path and extra_rpc_path.exists() else {}
    for slug, values in extra.items():
        if slug not in cfg or not isinstance(values, list):
            raise ValueError(f'Unknown network or invalid extra RPC list: {slug}')
        cfg[slug]['rpcs'] = list(dict.fromkeys(values + cfg[slug]['rpcs']))[:5]
    for slug, chain in cfg.items():
        if len(chain['rpcs']) != len(set(chain['rpcs'])):
            raise ValueError(f'Duplicate RPC endpoints for {slug}')
        chain['rpcs'] = chain['rpcs'][:5]
        for url in chain['rpcs']:
            if not url.startswith('https://') or 'YOUR_' in url:
                raise ValueError(f'Invalid RPC candidate in {slug} (must be a real HTTPS URL)')
    for slug, collection in tokens.items():
        if slug not in cfg:
            raise ValueError(f'Tokens configured for unknown network {slug}')
        seen = set()
        for token in collection:
            if not Web3.is_address(token['address']):
                raise ValueError(f'Invalid token contract for {slug}: {token["symbol"]}')
            address = token['address'].lower()
            if address in seen:
                raise ValueError(f'Duplicate token contract for {slug}: {address}')
            seen.add(address)
    return cfg, tokens


def empty_record(address: str, slug: str, cfg: dict, kind: str,
                 symbol: str, contract: str = '') -> dict:
    return {'address': address, 'network': slug, 'chain_id': cfg['chain_id'],
            'type': kind, 'symbol': symbol, 'contract': contract, 'balance': '',
            'raw_balance': '', 'decimals': '', 'usd_price': '', 'usd_value': '',
            'status': 'ERROR', 'error': '', 'block_tag': 'latest'}


def scale(raw: int, decimals: int) -> str:
    return format(Decimal(raw) / (Decimal(10) ** decimals), 'f')


def record_success(row: dict, raw: int, decimals: int):
    row['raw_balance'] = str(raw)
    row['decimals'] = decimals
    row['balance'] = scale(raw, decimals)
    row['status'], row['error'] = 'OK', ''


async def metadata(pool: RPCPool, token: dict) -> tuple[int | None, str]:
    try:
        val = await pool.call('eth_call', [{'to': token['address'], 'data': DECIMALS}, 'latest'])
        if val == '0x':
            raise FatalContractError('No decimals() response: wrong contract or unsupported token')
        dec = int(val, 16)
        if not (0 <= dec <= 36):
            raise FatalContractError('Invalid decimals() value')
        return dec, ''
    except Exception as e:
        return None, short_error(e)


async def get_balances_for_address(pool: RPCPool, slug: str, cfg: dict,
                                   address: str, token_meta: list) -> list[dict]:
    records = []
    native = empty_record(address, slug, cfg, 'native', cfg['native_symbol'])
    try:
        raw = int(await pool.call('eth_getBalance', [address,'latest']),16)
        record_success(native, raw, 18)
    except Exception as e:
        native['error'] = short_error(e)
    records.append(native)
    for token, decimals, meta_error in token_meta:
        row = empty_record(address, slug, cfg, 'ERC20', token['symbol'], token['address'])
        if meta_error:
            row['error'] = f'Token metadata unavailable: {meta_error}'[:160]
        else:
            try:
                # balanceOf(address) selector + 32-byte ABI-encoded argument.
                data = BALANCE_OF + address[2:].lower().rjust(64, '0')
                raw_hex = await pool.call('eth_call', [{'to':token['address'], 'data':data}, 'latest'])
                if raw_hex == '0x':
                    raise FatalContractError('Empty balanceOf() result')
                record_success(row, int(raw_hex,16), decimals)
            except Exception as e:
                row['error'] = short_error(e)
        records.append(row)
    return records


async def scan_network(slug: str, cfg: dict, tokens: list, addresses: list[str],
                       pool: RPCPool, address_parallelism: int) -> list[dict]:
    # Query decimals once per token per network. Don't silently assume USDT is 6 decimals.
    token_meta = []
    for tok in tokens:
        decimals, error = await metadata(pool, tok)
        token_meta.append((tok, decimals, error))
    sem = asyncio.Semaphore(address_parallelism)
    async def one(addr):
        async with sem:
            return await get_balances_for_address(pool, slug, cfg, addr, token_meta)
    # As-completed means a slow address doesn't hold up other addresses.
    out = await asyncio.gather(*(one(addr) for addr in addresses))
    return [row for batch in out for row in batch]


async def retry_failed_rows(pool: RPCPool, slug: str, cfg: dict,
                            rows: list[dict], concurrency: int) -> tuple[int, int]:
    """Update ONLY failed observations, retaining successful historical rows verbatim."""
    candidates = [r for r in rows if r['network'] == slug and r['status'] != 'OK']
    if not candidates:
        return 0, 0
    print(f'{slug}: retrying {len(candidates)} ERROR rows only')
    meta_cache = {}
    # A valid decimals value from an earlier successful observation is sufficient
    # to skip re-querying decimals() for the same ERC-20 contract.
    for row in rows:
        if (row['network'] == slug and row['type'] == 'ERC20' and row['status'] == 'OK'
                and row['decimals'] not in ('', None)):
            meta_cache[row['contract'].lower()] = (int(row['decimals']), '')
    failed_contracts = {r['contract'].lower(): r['contract'] for r in candidates
                        if r['type'] == 'ERC20' and r['contract'].lower() not in meta_cache}
    for contract in failed_contracts.values():
        dec, err = await metadata(pool, {'address': contract})
        meta_cache[contract.lower()] = (dec, err)
    sem = asyncio.Semaphore(concurrency)
    async def one(row):
        async with sem:
            attempt = dict(row)
            attempt['status'], attempt['error'] = 'ERROR', ''
            if row['type'] == 'native':
                try:
                    raw = int(await pool.call('eth_getBalance', [row['address'], 'latest']),16)
                    record_success(attempt, raw, 18)
                except Exception as e:
                    attempt['error'] = short_error(e)
            elif row['type'] == 'ERC20':
                dec, meta_err = meta_cache.get(row['contract'].lower(), (None, 'Metadata unavailable'))
                if dec is None:
                    attempt['error'] = f'Token metadata unavailable: {meta_err}'[:160]
                else:
                    try:
                        data = BALANCE_OF + row['address'][2:].lower().rjust(64, '0')
                        val = await pool.call('eth_call',
                                              [{'to': row['contract'], 'data': data}, 'latest'])
                        if val == '0x':
                            raise FatalContractError('Empty balanceOf() result')
                        record_success(attempt, int(val,16), dec)
                    except Exception as e:
                        attempt['error'] = short_error(e)
            else:
                attempt['error'] = f'Unknown asset type: {row["type"]}'
            if attempt['status'] == 'OK':
                # Re-price only newly resolved assets, never overwrite existing values.
                attempt['usd_price'], attempt['usd_value'] = '', ''
            return attempt
    results = await asyncio.gather(*(one(row) for row in candidates))
    by_identity = {(r['address'].lower(), r['network'], r['type'], r['contract'].lower()):r
                   for r in results}
    recovered = 0
    for i, row in enumerate(rows):
        if row['network'] != slug or row['status'] == 'OK':
            continue
        identity = (row['address'].lower(), row['network'], row['type'], row['contract'].lower())
        result = by_identity[identity]
        if result['status'] == 'OK':
            recovered += 1
        rows[i] = result
    return recovered, len(candidates)


def previous_rows(out: Path, known_networks: dict) -> tuple[list[dict], list[str]]:
    source = out / 'balances_all.csv'
    with source.open('r', encoding='utf-8-sig', newline='') as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None or not set(HEADERS) <= set(reader.fieldnames):
            raise ValueError('balances_all.csv: missing required columns')
        rows = list(reader)
    if not rows:
        raise ValueError('balances_all.csv: no rows to retry')
    seen, addresses = set(), []
    identifiers = set()
    for row in rows:
        if row['network'] not in known_networks:
            raise ValueError(f'Unknown network in balances_all.csv: {row["network"]}')
        if not Web3.is_address(row['address']):
            raise ValueError('Invalid address in previous report')
        if row['status'] not in ('OK', 'ERROR'):
            raise ValueError(f'Unexpected status in previous report: {row["status"]}')
        if row['type'] not in ('native', 'ERC20'):
            raise ValueError('Unexpected asset type in previous report')
        key = (row['address'].lower(), row['network'], row['type'], row['contract'].lower())
        if key in identifiers:
            raise ValueError('Duplicate observation in previous report')
        identifiers.add(key)
        if row['address'].lower() not in seen:
            seen.add(row['address'].lower())
            addresses.append(row['address'])
    return rows, addresses


async def add_usd_prices(session: aiohttp.ClientSession, results: list[dict], cfg: dict):
    # DefiLlama is optional. Empty price is UNKNOWN, never $0.
    keys = {}
    for row in results:
        if row['status'] != 'OK' or int(row['raw_balance']) <= 0:
            continue
        chain = cfg[row['network']]
        key = ('coingecko:' + chain['native_price_id'] if row['type'] == 'native'
               else chain['price_chain'] + ':' + row['contract'].lower())
        keys.setdefault(key, []).append(row)
    key_list = list(keys)
    for offset in range(0, len(key_list), 18):
        group = key_list[offset:offset + 18]
        url = 'https://coins.llama.fi/prices/current/' + ','.join(group)
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=12)) as response:
                if response.status != 200:
                    raise RPCError(f'Price API HTTP {response.status}')
                items = (await response.json(content_type=None)).get('coins', {})
            for key in group:
                data = items.get(key, {})
                price = data.get('price')
                if price is None:
                    continue
                rate = Decimal(str(price))
                if not rate.is_finite() or rate <= 0:
                    continue
                for row in keys[key]:
                    row['usd_price'] = format(rate, 'f')
                    row['usd_value'] = format(Decimal(row['balance']) * rate, 'f')
        except (aiohttp.ClientError, asyncio.TimeoutError, RPCError, ValueError,
                TypeError, InvalidOperation) as e:
            print(f'Price API unavailable for batch {offset//18 + 1}: {short_error(e)}', file=sys.stderr)


def write_csv(path: Path, rows: list[dict], headers: list[str]):
    tmp = path.with_name(path.name + '.tmp')
    with tmp.open('w', encoding='utf-8-sig', newline='') as f:
        wr = csv.DictWriter(f, fieldnames=headers, extrasaction='ignore')
        wr.writeheader()
        wr.writerows(rows)
    tmp.replace(path)


def write_reports(out: Path, rows: list[dict], cfg: dict, addresses: list[str],
                  health: list[dict], usd: bool):
    out.mkdir(parents=True, exist_ok=True)
    write_csv(out/'balances_all.csv', rows, HEADERS)
    nonzero = [r for r in rows if r['status']=='OK' and int(r['raw_balance'])>0]
    errors = [r for r in rows if r['status']!='OK']
    write_csv(out/'balances_nonzero.csv', nonzero, HEADERS)
    write_csv(out/'errors.csv', errors, HEADERS)
    by_addr, by_net, by_token = [], [], []
    for addr in addresses:
        sub = [r for r in rows if r['address']==addr]
        nz = [r for r in sub if r['status']=='OK' and int(r['raw_balance'])>0]
        by_addr.append({'address':addr, 'usd_known':format(sum((Decimal(r['usd_value']) for r in nz if r['usd_value']!=''),Decimal(0)), 'f') if usd else '',
                        'unpriced_nonzero':sum(not r['usd_value'] for r in nz) if usd else '',
                        'nonzero_assets':len(nz), 'networks_with_balance':len({r['network'] for r in nz}),
                        'errors':sum(r['status']!='OK' for r in sub)})
    for slug in cfg:
        sub = [r for r in rows if r['network']==slug]
        nz = [r for r in sub if r['status']=='OK' and int(r['raw_balance'])>0]
        by_net.append({'network':slug, 'usd_known':format(sum((Decimal(r['usd_value']) for r in nz if r['usd_value']!=''),Decimal(0)), 'f') if usd else '',
                       'nonzero_assets':len(nz), 'wallets_with_balance':len({r['address'] for r in nz}),
                       'errors':sum(r['status']!='OK' for r in sub),
                       'rpc_candidates':len(cfg[slug]['rpcs'])})
    buckets = defaultdict(list)
    for row in nonzero:
        buckets[(row['network'],row['symbol'],row['contract'])].append(row)
    for (slug, symbol, contract), chunk in sorted(buckets.items()):
        by_token.append({'network':slug,'symbol':symbol,'contract':contract,
                         'total_balance':format(sum((Decimal(r['balance']) for r in chunk),Decimal(0)),'f'),
                         'usd_known':format(sum((Decimal(r['usd_value']) for r in chunk if r['usd_value']!=''),Decimal(0)),'f') if usd else '',
                         'wallets':len(chunk)})
    write_csv(out/'summary_by_address.csv',by_addr,['address','usd_known','unpriced_nonzero','nonzero_assets','networks_with_balance','errors'])
    write_csv(out/'summary_by_network.csv',by_net,['network','usd_known','nonzero_assets','wallets_with_balance','errors','rpc_candidates'])
    write_csv(out/'summary_by_asset.csv',by_token,['network','symbol','contract','total_balance','usd_known','wallets'])
    write_wallet_tables(out, rows, cfg, addresses, usd)
    (out/'rpc_health.json').write_text(json.dumps(health,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    summary={'generated_at':datetime.now(timezone.utc).isoformat(),
             'wallets':len(addresses),'evm_networks':len(cfg),'observations':len(rows),
             'nonzero_assets':len(nonzero),'errors':len(errors),
             'prices_requested':usd,
             'known_usd_total': format(sum((Decimal(r['usd_value']) for r in nonzero if r['usd_value']!=''),Decimal(0)),'f') if usd else None,
             'unpriced_nonzero_assets':sum(not r['usd_value'] for r in nonzero) if usd else None,
             'important':'US dollar total is PARTIAL if any nonzero asset has unknown price. Scan only covers native assets and configured token contract addresses.'}
    (out/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return summary


def print_wallet_preview(rows: list[dict], addresses: list[str], usd: bool, max_rows: int = 15):
    """Compact console preview; detailed holdings are in portfolio.html."""
    wallet = {addr.lower(): {'address': addr, 'usd': Decimal(0), 'assets': 0,
                             'networks': set(), 'errors': 0} for addr in addresses}
    for r in rows:
        item = wallet.get(r['address'].lower())
        if item is None:
            continue
        if r['status'] != 'OK':
            item['errors'] += 1
        elif r['raw_balance'] not in ('', None) and int(r['raw_balance']) > 0:
            item['assets'] += 1
            item['networks'].add(r['network'])
            if r['usd_value'] != '':
                item['usd'] += Decimal(r['usd_value'])
    ordered = sorted(wallet.values(), key=lambda w: (-w['usd'] if usd else -w['assets'],
                                                     -w['assets'], w['address'].lower()))
    print('\nКОШЕЛЬКИ — ТОП', min(len(ordered),max_rows), 'ПО', 'ИЗВЕСТНОЙ СТОИМОСТИ USD' if usd else 'КОЛИЧЕСТВУ АКТИВОВ')
    print(f"{'#':>3}  {'Адрес':<21} {'USD (известно)':>16} {'Активов':>8} {'Сетей':>6} {'Ошибок':>7}")
    print('-'*72)
    for i, w in enumerate(ordered[:max_rows], 1):
        short = w['address'][:10] + '…' + w['address'][-6:]
        price = format(w['usd'], ',.2f') if usd else '—'
        print(f"{i:>3}  {short:<21} {price:>16} {w['assets']:>8} {len(w['networks']):>6} {w['errors']:>7}")
    if len(ordered) > max_rows:
        print(f'... ещё {len(ordered)-max_rows} кошельков — см. portfolio.html')
    if usd:
        print('USD — только оценённые активы. Ошибки RPC и неоценённые токены в сумму не входят.')


async def run(args):
    cfg, tokens = load_settings(args.networks,args.tokens,args.extra_rpcs)
    all_cfg = cfg
    if args.only:
        keep = set(args.only.split(','))
        if not keep <= set(cfg):
            raise ValueError('Unknown --only network: '+','.join(sorted(keep-set(cfg))))
        cfg = {k:v for k,v in cfg.items() if k in keep}
    if args.report_only:
        # Rebuild the wallet dashboard from the most recent scan: no RPC calls.
        source = args.out/'balances_all.csv'
        with source.open('r', encoding='utf-8-sig', newline='') as f:
            rows = list(csv.DictReader(f))
        rows = [r for r in rows if r['network'] in cfg]
        if not rows:
            raise ValueError(f'No scan rows found in {source}')
        seen = set()
        addresses = []
        for r in rows:
            if r['address'].lower() not in seen:
                addresses.append(r['address'])
                seen.add(r['address'].lower())
        summary_path = args.out/'summary.json'
        old_summary = json.loads(summary_path.read_text(encoding='utf-8')) if summary_path.exists() else {}
        priced = bool(old_summary.get('prices_requested')) if 'prices_requested' in old_summary else any(r['usd_value'] for r in rows)
        write_wallet_tables(args.out, rows, cfg, addresses, priced)
        print_wallet_preview(rows, addresses, priced)
        print(f'Created wallet dashboard from existing {source} (no RPC requests)')
        print('Open in browser:', (args.out/'portfolio.html').resolve())
        return
    addresses=[] if (args.probe_only or args.retry_errors) else read_addresses(args.addresses)
    if not (args.probe_only or args.retry_errors) and not addresses:
        raise ValueError(f'No valid addresses in {args.addresses}')
    timeout = aiohttp.ClientTimeout(total=args.timeout, connect=min(args.timeout,6))
    connector = aiohttp.TCPConnector(limit=40, ttl_dns_cache=120)
    async with aiohttp.ClientSession(timeout=timeout,connector=connector,headers={'User-Agent':'ReadOnlyEVMChecker/1.0'}) as session:
        limiter = asyncio.Semaphore(args.global_concurrency)
        pools = {slug:RPCPool(slug,entry,session,limiter,args.network_concurrency) for slug,entry in cfg.items()}
        if args.probe_only:
            limit = asyncio.Semaphore(8)
            async def probe(slug,pool):
                async with limit:
                    sample = tokens.get(slug, [])
                    return slug, await pool.probe_all(sample[0] if sample else None)
            results = await asyncio.gather(*(probe(slug,pool) for slug,pool in pools.items()))
            args.out.mkdir(parents=True,exist_ok=True)
            (args.out/'rpc_probes.json').write_text(json.dumps(dict(results),ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
            for slug, p in results:
                ok=sum(x['status']=='ok' for x in p)
                call_ok=sum(x.get('eth_call')=='ok' for x in p)
                tested=sum('eth_call' in x for x in p)
                print(f'{slug:<12} {ok}/{len(p)} RPC responding; eth_call {call_ok}/{tested} tested OK')
            print('Saved:',args.out/'rpc_probes.json')
            return
        if args.retry_errors:
            rows, previous_addresses = previous_rows(args.out, all_cfg)
            before = sum(r['status'] != 'OK' for r in rows)
            to_retry = sum(r['status'] != 'OK' and r['network'] in cfg for r in rows)
            if to_retry == 0:
                print(f'No failed observations to retry in chosen networks. Existing errors: {before}')
                return
            print(f'Retrying {to_retry} failed positions (other successful observations preserved).')
            selected = [slug for slug in cfg if any(r['network']==slug and r['status']!='OK' for r in rows)]
            for slug in selected:
                fixed, attempted = await retry_failed_rows(pools[slug], slug, cfg[slug], rows,
                                                           args.address_concurrency)
                print(f'{slug}: recovered {fixed}/{attempted}; remaining {attempted-fixed}')
            summary_path = args.out / 'summary.json'
            old_summary = json.loads(summary_path.read_text(encoding='utf-8')) if summary_path.exists() else {}
            priced = args.usd or bool(old_summary.get('prices_requested'))
            if priced:
                newly_resolved = [r for r in rows if r['network'] in cfg and r['status']=='OK'
                                  and r['usd_value']=='' and int(r['raw_balance'])>0]
                await add_usd_prices(session, newly_resolved, all_cfg)
            # Prevent accidental loss of the previous full scan on an interrupted write.
            timestamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
            backup = args.out / f'balances_all.before_retry_{timestamp}.csv'
            if backup.exists():
                backup = args.out / f'balances_all.before_retry_{timestamp}_{time.time_ns()}.csv'
            shutil.copy2(args.out / 'balances_all.csv', backup)
            old_health_path = args.out / 'rpc_health.json'
            previous_health = (json.loads(old_health_path.read_text(encoding='utf-8'))
                               if old_health_path.exists() else [])
            health_by_slug = {r['network']: r for r in previous_health if r.get('network') in all_cfg}
            health_by_slug.update({slug: pools[slug].health() for slug in selected})
            summary = write_reports(args.out, rows, all_cfg, previous_addresses,
                                    list(health_by_slug.values()), priced)
            print_wallet_preview(rows, previous_addresses, priced)
            print(f'Recovered {before-summary["errors"]} checks; {summary["errors"]} errors remain.')
            if priced:
                print('Known USD subtotal:', summary['known_usd_total'],
                      '— unpriced:', summary['unpriced_nonzero_assets'])
            print('Previous scan backed up:', backup.resolve())
            print('Updated dashboard:', (args.out/'portfolio.html').resolve())
            return
        print(f'Checking {len(addresses)} EVM address(es) across {len(cfg)} networks...')
        tasks = {asyncio.create_task(scan_network(slug,entry,tokens.get(slug,[]),addresses,pools[slug],args.address_concurrency)):slug
                 for slug,entry in cfg.items()}
        rows=[]
        for completed in asyncio.as_completed(tasks):
            # Network workers normally return records; unexpected crashes are not fake zero balances.
            try:
                batch=await completed
                rows.extend(batch)
                slug=batch[0]['network'] if batch else '(empty)'
                nz=sum(r['status']=='OK' and int(r['raw_balance'])>0 for r in batch)
                errs=sum(r['status']!='OK' for r in batch)
                print(f'{slug:<12}: {nz} nonzero positions, {errs} errors')
            except Exception as e:
                print(f'Unexpected network failure: {short_error(e)}',file=sys.stderr)
                raise
        if args.usd:
            await add_usd_prices(session,rows,cfg)
        rows.sort(key=lambda r:(r['address'].lower(),list(cfg).index(r['network']),r['type']!='native',r['symbol']))
        summary=write_reports(args.out,rows,cfg,addresses,[p.health() for p in pools.values()],args.usd)
        print_wallet_preview(rows, addresses, args.usd)
        print('Total nonzero positions:',summary['nonzero_assets'])
        print('Errors (not counted as zero):',summary['errors'])
        if args.usd:
            print('Known USD subtotal:',summary['known_usd_total'],'\u2014 unpriced:',summary['unpriced_nonzero_assets'])
        print('Reports saved to',args.out.resolve())
        print('Wallet table (open in browser):', (args.out/'portfolio.html').resolve())


def main():
    parser=argparse.ArgumentParser(description='Read-only EVM native + selected ERC20 portfolio checker')
    parser.add_argument('--addresses',type=Path,default=HERE/'addresses.txt')
    parser.add_argument('--networks',type=Path,default=HERE/'networks.json')
    parser.add_argument('--tokens',type=Path,default=HERE/'tokens.json')
    parser.add_argument('--extra-rpcs',type=Path,default=HERE/'extra_rpcs.json')
    parser.add_argument('--out',type=Path,default=HERE/'reports')
    parser.add_argument('--only',help='Comma-separated network slugs, e.g. ethereum,base,bsc')
    parser.add_argument('--usd',action='store_true',help='Attempt DefiLlama USD prices; missing prices remain unknown')
    parser.add_argument('--probe-only',action='store_true',help='Validate chain ID and live block on each RPC; no addresses needed')
    parser.add_argument('--report-only',action='store_true',help='Create wallet tables from previous reports/balances_all.csv without RPC calls')
    parser.add_argument('--retry-errors',action='store_true',help='Retry only ERROR rows in existing reports/balances_all.csv; keep successful rows untouched')
    parser.add_argument('--timeout',type=float,default=8.0)
    parser.add_argument('--global-concurrency',type=int,default=12)
    parser.add_argument('--network-concurrency',type=int,default=2)
    parser.add_argument('--address-concurrency',type=int,default=2)
    args=parser.parse_args()
    if sum((args.report_only,args.probe_only,args.retry_errors)) > 1:
        parser.error('--report-only, --probe-only and --retry-errors are mutually exclusive')
    if min(args.timeout,args.global_concurrency,args.network_concurrency,args.address_concurrency)<=0:
        parser.error('Timeout and concurrency options must be positive')
    try:
        asyncio.run(run(args))
    except (OSError,ValueError,json.JSONDecodeError) as e:
        print('ERROR:',e,file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print('Interrupted; no funds were transferred',file=sys.stderr)
        sys.exit(130)

if __name__=='__main__':
    main()
