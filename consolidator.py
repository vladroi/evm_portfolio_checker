#!/usr/bin/env python3
"""Conservative, explicitly approved local EVM fund consolidator.

Reads scanner CSV and network/token registries. Reads private keys from a local
plaintext file (user selected this mode). Never prints or journals keys.
Never repeats an ambiguous broadcast.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import time
import fcntl
import re
import subprocess
from contextlib import contextmanager
from collections import defaultdict
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path

try:
    from web3 import Web3
    from eth_account import Account
except ImportError:
    print('Install dependencies in the checker venv: pip install "web3>=7,<8"', file=sys.stderr)
    raise

HERE = Path(__file__).resolve().parent
DEFAULT_SETTINGS = {
    'recipient': '',
    'min_usd': '0',
    'max_fee_usd': '2',
    'max_fee_fraction': '1.0',
    'native_reserve': '0',
}


def load_settings(path):
    """Read user-editable config; never store secrets in this file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f'Settings file missing: {path}. Copy settings.example.json to settings.json')
    data = json.loads(path.read_text(encoding='utf-8-sig'))
    if not isinstance(data, dict):
        raise ValueError('settings.json must be a JSON object')
    if any(k in data for k in ('private_key', 'private_keys', 'seed', 'mnemonic')):
        raise ValueError('Never place private keys or seed phrases in settings.json')
    unknown = set(data) - set(DEFAULT_SETTINGS)
    if unknown:
        raise ValueError('Unknown settings: ' + ', '.join(sorted(unknown)))
    settings = {**DEFAULT_SETTINGS, **data}
    if not Web3.is_address(settings['recipient']):
        raise ValueError('Set recipient to a valid 0x address inside settings.json')
    settings['recipient'] = Web3.to_checksum_address(settings['recipient'])
    for key in ('min_usd', 'max_fee_usd', 'max_fee_fraction', 'native_reserve'):
        try:
            settings[key] = Decimal(str(settings[key]))
        except (InvalidOperation, ValueError) as exc:
            raise ValueError(f'Invalid decimal setting: {key}') from exc
    if any(not settings[key].is_finite() for key in ('min_usd', 'max_fee_usd', 'max_fee_fraction', 'native_reserve')):
        raise ValueError('Fee and threshold settings must be finite decimal values')
    if settings['min_usd'] < 0:
        raise ValueError('min_usd must be >= 0')
    if settings['max_fee_usd'] <= 0 or not 0 < settings['max_fee_fraction'] <= 1 or settings['native_reserve'] < 0:
        raise ValueError('Invalid fee settings: max_fee_usd > 0, 0 < max_fee_fraction <= 1, native_reserve >= 0')
    return settings

# Pilot scope: EOA-only legacy / EIP-1559 transfers.
# ZKsync Era requires EOA preflight; smart contract accounts are refused.
# These networks can expose proof-of-authority extraData larger than 32 bytes.
# Middleware is required on EVERY read-only, quote and reconciliation provider.
POA_NETWORKS = {'bsc', 'polygon', 'opbnb', 'gnosis'}
# OP Stack charges an additional L1 data fee (and, after Isthmus, an
# operator fee).  Both must be reserved BEFORE sweeping a native balance.
OP_STACK_NETWORKS = {'base', 'optimism'}
OP_GAS_ORACLE = Web3.to_checksum_address('0x420000000000000000000000000000000000000F')
OP_GAS_ABI = [
    {'type':'function','name':'getL1FeeUpperBound','stateMutability':'view',
     'inputs':[{'name':'_unsignedTxSize','type':'uint256'}],
     'outputs':[{'name':'','type':'uint256'}]},
    {'type':'function','name':'getOperatorFee','stateMutability':'view',
     'inputs':[{'name':'_gasUsed','type':'uint256'}],
     'outputs':[{'name':'','type':'uint256'}]},
]


def op_stack_extra_fee_cap(w3, gas_limit, asset_type):
    """Reserve the OP L1-data and operator fees, with headroom.

    getL1FeeUpperBound accepts estimated unsigned transaction size.  320
    bytes for plain native transfers / 512 for ERC20 are deliberately larger
    than the usual corresponding transaction payloads.  Extra x1.5 headroom
    allows for changing L1 prices between quote and submission.  Fail closed
    if either fee component cannot be established.
    """
    oracle = w3.eth.contract(address=OP_GAS_ORACLE, abi=OP_GAS_ABI)
    size = 512 if asset_type == 'ERC20' else 320
    try:
        l1 = int(oracle.functions.getL1FeeUpperBound(size).call())
        operator = int(oracle.functions.getOperatorFee(gas_limit).call())
    except Exception as exc:
        raise RuntimeError('OP Stack L1/operator fee estimate unavailable') from exc
    if l1 < 0 or operator < 0:
        raise RuntimeError('OP Stack returned negative extra fee')
    return (3 * (l1 + operator) + 1) // 2


def rpc_broadcast_reason(exc):
    """Report useful, non-secret rejection categories without RPC URLs."""
    msg = str(exc).lower()
    for phrase, label in (
        ('insufficient funds','INSUFFICIENT_FUNDS (balance incl. L1 fees)'),
        ('insufficient balance','INSUFFICIENT_BALANCE'),
        ('nonce too low','NONCE_ALREADY_USED'),
        ('already known','ALREADY_KNOWN'),
        ('replacement transaction underpriced','REPLACEMENT_UNDERPRICED'),
        ('transaction underpriced','TRANSACTION_UNDERPRICED'),
        ('max fee per gas less than block base fee','FEE_TOO_LOW'),
        ('fee cap less than block base fee','FEE_TOO_LOW'),
        ('intrinsic gas too low','GAS_LIMIT_TOO_LOW'),
        ('exceeds block gas limit','GAS_LIMIT_TOO_HIGH'),
        ('rate limit','RPC_RATE_LIMIT'),
        ('too many requests','RPC_RATE_LIMIT'),
        ('429','RPC_RATE_LIMIT'),
        ('timeout','RPC_TIMEOUT'),
        ('connection reset','RPC_CONNECTION'),
        ('invalid sender','INVALID_SIGNATURE'),
        ('invalid chain id','WRONG_CHAIN'),
    ):
        if phrase in msg:
            return label
    return type(exc).__name__

PILOT_NETWORKS = {'ethereum', 'bsc', 'polygon', 'arbitrum', 'optimism', 'base', 'avalanche', 'zksync', 'linea', 'mantle', 'scroll'}
ERC20_ABI = [
    {"type": "function", "name": "balanceOf", "stateMutability": "view",
     "inputs": [{"name": "owner", "type": "address"}],
     "outputs": [{"name": "", "type": "uint256"}]},
    {"type": "function", "name": "decimals", "stateMutability": "view",
     "inputs": [], "outputs": [{"name": "", "type": "uint8"}]},
    {"type": "function", "name": "transfer", "stateMutability": "nonpayable",
     "inputs": [{"name": "to", "type": "address"}, {"name": "value", "type": "uint256"}],
     "outputs": [{"name": "", "type": "bool"}]}
]


@contextmanager
def exclusive_lock(journal):
    """Prevent concurrent reconcilers/executors across the whole lifetime."""
    lockfile = Path(str(journal) + '.lock')
    lockfile.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lockfile, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as e:
            raise RuntimeError('Another consolidator process holds this journal lock') from e
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)

def now():
    return datetime.now(timezone.utc).isoformat()


def normalize_txhash(value):
    """Return a 0x-prefixed 32-byte hash for both old and new journal entries."""
    if isinstance(value, (bytes,bytearray)):
        raw=bytes(value).hex()
    else:
        raw=str(value)
        raw=raw[2:] if raw.startswith(('0x','0X')) else raw
    if not re.fullmatch(r'[0-9a-fA-F]{64}', raw):
        raise ValueError('Invalid transaction hash in journal or signed transaction')
    return '0x'+raw.lower()


def digest_json(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def sha256_file(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    with tmp.open('w', encoding='utf-8') as f:
        os.chmod(tmp, 0o600)
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def load_csv(path):
    with Path(path).open(newline='', encoding='utf-8-sig') as f:
        rows = list(csv.DictReader(f))
    required = {'address','network','chain_id','type','symbol','contract','raw_balance','status','usd_value'}
    if not rows or not required.issubset(rows[0]):
        raise ValueError('Not a compatible balances_all.csv (missing fields)')
    return rows


def build_plan(rows, recipient, network_cfg, tokens_cfg, *, min_usd=Decimal('0'), source_digest='', network_digest='', token_digest='', fee_policy=None):
    if not Web3.is_address(recipient):
        raise ValueError('Invalid recipient address')
    if min_usd < 0 or not min_usd.is_finite():
        raise ValueError('min_usd must be finite and >= 0')
    dest = Web3.to_checksum_address(recipient)
    allowed = {net: {Web3.to_checksum_address(t['address']).lower() for t in ts}
               for net, ts in tokens_cfg.items()}
    grouped = defaultdict(list)
    for r in rows:
        if not Web3.is_address(r['address']):
            raise ValueError('Unexpected invalid source address in scanner report')
        grouped[(r['network'], Web3.to_checksum_address(r['address']))].append(r)
    actions, skipped = [], []
    for (network, source), positions in sorted(grouped.items()):
        if network not in network_cfg:
            skipped.append({'network': network, 'from': source, 'reason': 'unknown_network'})
            continue
        cfg = network_cfg[network]
        if any(p['status'] != 'OK' for p in positions):
            skipped.append({'network': network, 'from': source, 'reason': 'incomplete_scan'})
            continue
        if source.lower() == dest.lower():
            skipped.append({'network': network, 'from': source, 'reason': 'recipient_is_source'})
            continue
        for p in positions:
            try:
                raw = int(p['raw_balance'] or '0')
                usd = Decimal(p['usd_value']) if p['usd_value'] else None
                chain_id = int(p['chain_id'])
            except (ValueError, InvalidOperation):
                skipped.append({'network': network, 'from': source, 'reason': 'invalid_numeric_position'})
                continue
            if raw <= 0:
                continue
            if chain_id != int(cfg['chain_id']):
                skipped.append({'network': network, 'from': source, 'reason': 'chain_id_mismatch'})
                continue
            if usd is None:
                skipped.append({'network': network, 'from': source, 'asset': p['symbol'], 'reason': 'unpriced'})
                continue
            if usd < min_usd:
                skipped.append({'network': network, 'from': source, 'asset': p['symbol'], 'reason': 'below_min_usd'})
                continue
            is_native = p['type'].lower() == 'native'
            is_erc20 = p['type'].upper() == 'ERC20'
            if not (is_native or is_erc20):
                skipped.append({'network': network, 'from': source, 'asset': p['symbol'], 'reason': 'unsupported_type'})
                continue
            contract = None
            if is_erc20:
                if not Web3.is_address(p['contract']):
                    skipped.append({'network': network, 'from': source, 'asset': p['symbol'], 'reason': 'invalid_contract'})
                    continue
                contract = Web3.to_checksum_address(p['contract'])
                if contract.lower() not in allowed.get(network, set()):
                    skipped.append({'network': network, 'from': source, 'asset': p['symbol'], 'reason': 'contract_not_allowlisted'})
                    continue
            else:
                if p['symbol'] != cfg['native_symbol']:
                    skipped.append({'network': network, 'from': source, 'asset': p['symbol'], 'reason': 'native_symbol_mismatch'})
                    continue
            obj = {'network':network,'chain_id':chain_id,'from':source,'to':dest,
                   'asset_type':'NATIVE' if is_native else 'ERC20',
                   'symbol':p['symbol'],'contract':contract,'max_raw':str(raw),
                   'scan_usd':str(usd)}
            obj['id'] = digest_json(obj)[:24]
            actions.append(obj)
    actions.sort(key=lambda a: (a['network'], a['from'].lower(), a['asset_type']=='NATIVE', a['symbol']))
    base = {'format_version':2, 'generated_at':now(), 'destination':dest,
            'min_usd':str(min_usd), 'fee_policy':fee_policy, 'scanner_csv_sha256':source_digest,
            'networks_sha256':network_digest, 'tokens_sha256':token_digest,
            'actions':actions, 'skipped':skipped,
            'note':'Plan is not a gas quote; every action is rechecked on-chain before sending.'}
    base['approval_hash'] = digest_json(base)
    return base


def export_plan_csv(plan, plan_path):
    parent = Path(plan_path).parent
    parent.mkdir(parents=True, exist_ok=True)
    actions_path = parent / 'plan_table.csv'
    with actions_path.open('w', newline='', encoding='utf-8-sig') as fh:
        fields = ['network', 'chain_id', 'from', 'to', 'asset_type', 'symbol', 'contract',
                  'max_raw', 'scan_usd', 'execution', 'id']
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for action in plan['actions']:
            writer.writerow({**action,'execution': 'PILOT' if action['network'] in PILOT_NETWORKS else 'PLAN_ONLY'})
    skipped_path = parent / 'skipped.csv'
    with skipped_path.open('w', newline='', encoding='utf-8-sig') as fh:
        fields = ['network','from','asset','reason']
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for row in plan['skipped']:
            writer.writerow(row)
    return actions_path, skipped_path


def load_plan(path):
    plan = json.loads(Path(path).read_text(encoding='utf-8'))
    check = dict(plan)
    given = check.pop('approval_hash')
    if digest_json(check) != given:
        raise ValueError('Plan has been changed since approval: hash mismatch')
    if plan.get('format_version') != 2:
        raise ValueError('Unsupported plan format')
    return plan


def append_event(journal_path, event):
    journal_path = Path(journal_path)
    journal_path.parent.mkdir(parents=True, exist_ok=True)
    event = {'time':now(), **event}
    fd = os.open(journal_path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, (json.dumps(event, ensure_ascii=False, sort_keys=True) + '\n').encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def read_events(path):
    path = Path(path)
    if not path.exists():
        return []
    with path.open(encoding='utf-8') as f:
        return [json.loads(line) for line in f if line.strip()]


def index_events(events):
    latest = {}
    for e in events:
        if e.get('action_id'):
            latest[(e.get('plan_hash'), e['action_id'])] = e
    return latest


def make_network_web3(url, network, timeout=15):
    """Build a network-aware RPC client; never use a bare Web3() elsewhere.

    In web3.py v7, ExtraDataToPOAMiddleware normalizes PoA-style block
    extraData, preventing BSC/Polygon get_block() and fee-quote failures.
    """
    w3 = Web3(Web3.HTTPProvider(url, request_kwargs={'timeout': timeout}))
    if network in POA_NETWORKS:
        from web3.middleware import ExtraDataToPOAMiddleware
        w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    return w3


def open_rpc(network, cfg, timeout=15):
    messages = []
    for url in cfg['rpcs']:
        if not url.startswith('https://'):
            continue
        try:
            w3 = make_network_web3(url, network, timeout=timeout)
            if w3.eth.chain_id != int(cfg['chain_id']):
                messages.append('wrong chain id')
                continue
            _ = w3.eth.block_number
            return w3
        except Exception as e:
            messages.append(type(e).__name__)
    raise RuntimeError(f'No working RPC for {network}; failure classes: {", ".join(messages[-5:])}')


def broadcast_identical_signed_transaction(network, cfg, first_provider, raw_transaction,
                                           expected_hash, max_providers=4):
    """Broadcast EXACT SAME signed bytes to fallback RPCs; no re-signing/nonce change.

    A broadcast timeout is ambiguous, so we must never interpret it as an
    authorization to create a fresh transaction. Repeating identical raw bytes
    cannot produce a different transfer hash or consume a second nonce.
    Returns (acknowledged, provider, failure_classes), no secrets or raw RPC
    errors included in diagnostic output.
    """
    expected_hash = normalize_txhash(expected_hash)
    candidates = [first_provider]
    used = {getattr(getattr(first_provider, 'provider', None), 'endpoint_uri', None)}
    for url in cfg.get('rpcs', []):
        if len(candidates) >= max_providers:
            break
        if not isinstance(url, str) or not url.startswith('https://') or url in used:
            continue
        used.add(url)
        candidates.append(make_network_web3(url, network, timeout=15))
    failures = []
    for provider in candidates:
        try:
            if int(provider.eth.chain_id) != int(cfg['chain_id']):
                failures.append('WrongChainId')
                continue
            result = normalize_txhash(provider.eth.send_raw_transaction(raw_transaction))
            if result != expected_hash:
                failures.append('UnexpectedTransactionHash')
                continue
            return True, provider, failures
        except Exception as exc:
            failures.append(rpc_broadcast_reason(exc))
            # Some nodes return "already known" even though the signed tx is
            # in their pool. This is not a reason to allocate another nonce.
            try:
                if provider.eth.get_transaction(expected_hash):
                    return True, provider, failures
            except Exception:
                pass
            try:
                if provider.eth.get_transaction_receipt(expected_hash):
                    return True, provider, failures
            except Exception:
                pass
    return False, first_provider, failures


def quote_with_failover(network, cfg, cache, action, native_price, reserve_wei,
                        max_fee_usd, max_fee_fraction):
    """Try a different validated RPC when eth_call/estimation fails.

    Never used for broadcast retries; it only retries READ-ONLY preflight work.
    """
    failures = []
    candidates = []
    cached = cache.get(network)
    if cached is not None:
        candidates.append(cached)
    for url in cfg['rpcs']:
        if not url.startswith('https://'):
            continue
        if cached is not None and getattr(cached.provider, 'endpoint_uri', None) == url:
            continue
        candidates.append(make_network_web3(url, network, timeout=15))
    for w3 in candidates:
        try:
            if int(w3.eth.chain_id) != int(cfg['chain_id']):
                failures.append('WrongChainId')
                continue
            q = make_quote(w3, action, native_price, reserve_wei, max_fee_usd, max_fee_fraction)
            cache[network] = w3
            return w3, q
        except Exception as e:
            # Token contract explicitly returned false: trying another provider will
            # not change a deterministic contract rejection.
            if 'returned false during simulation' in str(e):
                raise
            # Only expose safe, locally-authored failure phases. Raw exception text
            # may contain API tokens embedded in RPC URLs and must not be logged.
            details = str(e)
            known_phases = (
                'Cannot validate token balance and decimals on-chain',
                'Token transfer simulation failed',
                'Gas estimate rejected',
                'Contract has no bytecode',
                'Mantle gas price is not positive',
                'Linea RPC lacks linea_estimateGas',
                'Scroll L1 gas oracle returned a non-positive fee',
                'OP Stack L1/operator fee estimate unavailable',
            )
            phase = next((phrase for phrase in known_phases if details.startswith(phrase)), 'RPC preflight')
            cause = type(e.__cause__).__name__ if e.__cause__ is not None else type(e).__name__
            failures.append(f'{phase} [{cause}]')
    raise RuntimeError('All read-only RPC preflights failed: '+'; '.join(failures[-5:]))


# Scroll's L1 fee is on top of L2 gas and depends on the FULL signed tx bytes.
# An offline surrogate signature is used for the preliminary quote only.  The
# actual signature is checked against the reserved cap immediately before send.
SCROLL_GAS_ORACLE = Web3.to_checksum_address('0x5300000000000000000000000000000000000002')
SCROLL_L1_ABI = [{
    'type': 'function', 'name': 'getL1Fee', 'stateMutability': 'view',
    'inputs': [{'name': '_data', 'type': 'bytes'}],
    'outputs': [{'name': '', 'type': 'uint256'}],
}]
# Deterministic dummy key for offline BYTE-SIZE ESTIMATION ONLY, never broadcast.
# The actual key is exclusively read from the local plaintext key file.
SCROLL_DUMMY_SIGNING_KEY = '0x' + '11' * 32


def scroll_l1_fee(w3, raw_signed):
    oracle = w3.eth.contract(address=SCROLL_GAS_ORACLE, abi=SCROLL_L1_ABI)
    fee = int(oracle.functions.getL1Fee(bytes(raw_signed)).call())
    if fee <= 0:
        raise RuntimeError('Scroll L1 gas oracle returned a non-positive fee')
    return fee


def scroll_l1_reservation(w3, action, data, fee_fields, gas_limit):
    tx = {**{k: v for k, v in data.items() if k != 'from'}, **fee_fields,
          'gas':gas_limit, 'chainId':int(action['chain_id']),
          'nonce':int(w3.eth.get_transaction_count(action['from'], 'pending'))}
    # Signing locally only creates a representative RLP byte string; no network send.
    surrogate = Account.sign_transaction(tx, SCROLL_DUMMY_SIGNING_KEY)
    quoted = scroll_l1_fee(w3, surrogate.raw_transaction)
    # Margin for RLP size/compression differences and gas-oracle drift.
    return (quoted * 2) + 1


def linea_gas_quote(w3, call):
    # Linea's official endpoint includes the L1 data cost in the priority fee.
    # When a provider cannot perform this method, skip instead of undercharging.
    payload = {k: (hex(v) if isinstance(v, int) else v) for k,v in call.items()}
    result = w3.provider.make_request('linea_estimateGas', [payload])
    if not isinstance(result, dict) or result.get('error') or not isinstance(result.get('result'), dict):
        raise RuntimeError('Linea RPC lacks linea_estimateGas: cannot quote safe fee')
    values = result['result']
    try:
        estimate = int(values['gasLimit'], 16) if isinstance(values['gasLimit'], str) else int(values['gasLimit'])
        base = int(values['baseFeePerGas'], 16) if isinstance(values['baseFeePerGas'], str) else int(values['baseFeePerGas'])
        priority = int(values['priorityFeePerGas'], 16) if isinstance(values['priorityFeePerGas'], str) else int(values['priorityFeePerGas'])
    except (TypeError, ValueError, KeyError) as e:
        raise RuntimeError('Linea RPC returned incomplete gas quote') from e
    if estimate <= 0 or base < 0 or priority < 0:
        raise RuntimeError('Linea RPC returned invalid gas quote')
    gas_limit = (estimate*125 + 99)//100
    fee_per_gas = max(2*base+priority, base+priority)
    if fee_per_gas <= 0:
        raise RuntimeError('Linea RPC returned zero gas price')
    return gas_limit, {'type':2, 'maxFeePerGas':fee_per_gas,
                       'maxPriorityFeePerGas':priority}, gas_limit*fee_per_gas


def fee_quote(w3, gas, network=''):
    # Max charged fee cap. Conservative, not an exact final fee, and L2 DA costs
    # may not be accounted for by gas*price. Never promise an exact zero remainder.
    block = w3.eth.get_block('latest')
    base_fee = block.get('baseFeePerGas')
    if base_fee is not None:
        if network == 'zksync':
            priority = 0  # ZKsync Era does not use Ethereum tip bidding.
        else:
            try:
                priority = int(w3.eth.max_priority_fee)
            except Exception:
                priority = max(1_000_000, int(w3.eth.gas_price)//10)
            priority = min(max(1_000_000, priority), 100_000_000_000)
        max_fee = max(2*int(base_fee)+priority, int(w3.eth.gas_price))
        return {'maxFeePerGas':max_fee,'maxPriorityFeePerGas':priority, 'type':2}, gas*max_fee
    gas_price = (int(w3.eth.gas_price)*12 + 9)//10
    return {'gasPrice':gas_price}, gas*gas_price


def make_quote(w3, action, native_price, reserve_wei, max_fee_usd, max_fee_fraction):
    source, destination = action['from'], action['to']
    asset_type = action['asset_type']
    if action['network'] == 'zksync' and w3.eth.get_code(source):
        return {'skip': 'ZKSYNC_SMART_ACCOUNT: requires EIP-712 wallet flow'}
    live_native = int(w3.eth.get_balance(source, 'latest'))
    data = {'from':source, 'to':destination}
    if asset_type == 'ERC20':
        contract_addr = action['contract']
        if not w3.eth.get_code(contract_addr):
            raise RuntimeError('Contract has no bytecode; refusing transfer')
        token = w3.eth.contract(address=contract_addr, abi=ERC20_ABI)
        try:
            live_token = int(token.functions.balanceOf(source).call())
            decimal_places = int(token.functions.decimals().call())
        except Exception as e:
            raise RuntimeError('Cannot validate token balance and decimals on-chain') from e
        if not 0 <= decimal_places <= 36:
            raise RuntimeError('Unreasonable token decimals')
        amount = min(live_token, int(action['max_raw']))
        if amount <= 0:
            return {'skip':'token balance is now zero', 'skip_code':'zero_balance'}
        data['to'] = contract_addr
        # ERC-20 transfer(address,uint256) selector + two ABI words.
        data['data'] = '0xa9059cbb' + destination[2:].lower().rjust(64, '0') + format(amount, '064x')
        data['value'] = 0
        # A contract may return ABI false without reverting. Check the current
        # transfer path with an eth_call and refuse an explicit false response.
        try:
            simulated = w3.eth.call(data)
            if len(simulated) == 32 and int.from_bytes(simulated, 'big') == 0:
                raise RuntimeError('Token transfer() returned false during simulation')
        except RuntimeError:
            raise
        except Exception as e:
            raise RuntimeError(f'Token transfer simulation failed: {type(e).__name__}') from e
    else:
        # Native sweep value calculated from LIVE balance only after gas quote.
        amount = 1
        data['value'] = 1
    network = action['network']
    if network == 'linea':
        gas_limit, fee_fields, fee_cap = linea_gas_quote(w3, data)
    else:
        try:
            estimated = int(w3.eth.estimate_gas(data))
        except Exception as e:
            raise RuntimeError(f'Gas estimate rejected: {type(e).__name__}') from e
        # Mantle's eth_estimateGas includes L1 and L2 charges; do not apply
        # a generic EIP-1559 tip model. Extra margin covers estimate variation.
        multiplier = 150 if network == 'mantle' else 130 if network == 'scroll' else 125
        gas_limit = (estimated*multiplier+99)//100
        if network == 'mantle':
            gas_price = (int(w3.eth.gas_price)*130+99)//100
            if gas_price <= 0:
                raise RuntimeError('Mantle gas price is not positive')
            fee_fields = {'gasPrice': gas_price}   # Legacy EOA tx
            fee_cap = gas_price*gas_limit
        elif network == 'scroll':
            gas_price = (int(w3.eth.gas_price)*130+99)//100
            if gas_price <= 0:
                raise RuntimeError('Scroll gas price is not positive')
            fee_fields = {'gasPrice':gas_price}    # Scroll L2 execution
            fee_cap = gas_price*gas_limit
            l1_reserve = scroll_l1_reservation(w3, action, data, fee_fields, gas_limit)
            fee_cap += l1_reserve
        else:
            fee_fields, fee_cap = fee_quote(w3, gas_limit, network)
    max_gas = 2_000_000 if network == 'zksync' else 300_000
    if gas_limit > max_gas:
        raise RuntimeError(f'Gas estimate exceeds {max_gas} safety limit')
    # On Base and Optimism, the execution gas alone is NOT the whole fee.
    # In particular a full-balance ETH sweep may fail to broadcast unless
    # L1 data + operator fee is also kept on the sending account.
    if network in OP_STACK_NETWORKS:
        fee_cap += op_stack_extra_fee_cap(w3, gas_limit, asset_type)
    if asset_type == 'NATIVE':
        amount = min(int(action['max_raw']), live_native - fee_cap - reserve_wei)
        if amount <= 0:
            return {'skip':'insufficient native balance after gas cap and reserve'}
        data['value'] = amount
    elif live_native < fee_cap + reserve_wei:
        return {'skip':'NEEDS_GAS: insufficient native gas balance'}
    if native_price is None:
        return {'skip':'native USD price unavailable; fee budget cannot be verified'}
    fee_usd = (Decimal(fee_cap) / Decimal(10**18))*native_price
    # A partial live balance may be worth less than the originally scanned position.
    # For a native sweep, compare gas to the source's spendable gross value,
    # not just the net transfer after subtracting that same gas; otherwise
    # a $0.03 balance with a $0.02 fee would be wrongly rejected.
    if asset_type == 'NATIVE':
        action_usd = (Decimal(min(live_native, int(action['max_raw']))) /
                      Decimal(10**18)) * native_price
    else:
        action_usd = Decimal(action['scan_usd']) * Decimal(amount) / Decimal(action['max_raw'])
    if fee_usd > max_fee_usd:
        return {'skip':f'fee cap ${fee_usd:.4f} > max ${max_fee_usd}'}
    if fee_usd > action_usd*max_fee_fraction:
        return {'skip':f'fee cap ${fee_usd:.4f} too high versus asset ${action_usd}',
                'skip_code':'uneconomic_token'}
    return {'tx_body':data,'gas_limit':gas_limit,'decimals': (18 if asset_type == 'NATIVE' else decimal_places),'fee_fields':fee_fields,
            'fee_cap_wei':fee_cap,'fee_usd':str(fee_usd),'amount_raw':amount,
            'live_native_wei':live_native, 'native_price':str(native_price),
            'l1_cap_wei':(l1_reserve if network == 'scroll' else 0)}


def prices_from_csv(rows, networks):
    # Match the native token price from the scanner's own USD-priced rows.
    prices = {}
    for r in rows:
        n = r['network']
        if n not in networks:
            continue
        if r['type'].lower() != 'native' or r['status'] != 'OK':
            continue
        if r.get('symbol') != networks[n]['native_symbol'] or not r.get('usd_price'):
            continue
        try:
            x = Decimal(r['usd_price'])
            if x > 0:
                prices[n] = x
        except InvalidOperation:
            continue
    return prices


def selected_actions(plan, network, source):
    arr = plan['actions']
    if network:
        arr = [a for a in arr if a['network'] == network]
    if source:
        arr = [a for a in arr if a['from'].lower() == source.lower()]
    return arr


def check_native_after_tokens(action, plan, events, safe_skipped_tokens=None):
    if action['asset_type'] != 'NATIVE':
        return None
    # Preserve gas when even one scanned token was not included in the plan.
    unsafe = {'unpriced','invalid_contract','contract_not_allowlisted',
              'unsupported_type','invalid_numeric_position','chain_id_mismatch',
              'native_symbol_mismatch','incomplete_scan'}
    if any(s.get('network') == action['network'] and
           str(s.get('from','')).lower() == action['from'].lower() and
           s.get('reason') in unsafe for s in plan.get('skipped', [])):
        return 'native sweep blocked: excluded or unverified asset may require gas'
    siblings = [a for a in plan['actions'] if a['network'] == action['network'] and
                a['from'] == action['from'] and a['asset_type'] == 'ERC20']
    latest = index_events(events)
    safe_skipped_tokens = safe_skipped_tokens or set()
    for token_action in siblings:
        # This token was checked LIVE in this very run and either had a zero
        # balance or cost more to transfer than the approved fee policy allows.
        # Preserve this decision only in memory, never mark it as 'success' in
        # the journal: a later run must re-evaluate economics on-chain.
        if token_action['id'] in safe_skipped_tokens:
            continue
        evt = latest.get((plan['approval_hash'], token_action['id']))
        if not evt or evt.get('status') != 'success':
            return 'native sweep blocked: token planned but not yet confirmed'
    return None


class LocalKeysError(RuntimeError):
    """Invalid/insecure local key file. Messages never contain private key material."""


def protect_local_keys_file(path):
    """Reject tracked/unignored plaintext keys; enforce owner-only local file access."""
    path = Path(path)
    if not path.is_file() or path.is_symlink():
        raise LocalKeysError('Не найден обычный файл private_keys.txt (ссылки запрещены).')
    # Do not alter content. Set owner-only permissions automatically, without asking
    # the user to run chmod in the terminal.
    try:
        path.chmod(0o600)
    except OSError as exc:
        raise LocalKeysError('Не удалось ограничить доступ к private_keys.txt.') from exc

    # If this directory is in a Git repository, ensure no secrets can be committed.
    try:
        repo = subprocess.run(['git', '-C', str(path.parent), 'rev-parse', '--show-toplevel'],
                              capture_output=True, text=True, check=False)
    except OSError:
        # Not a dependency for standalone (non-Git) local use.
        return
    if repo.returncode != 0:
        return
    # git ls-files lists already tracked files even when they are gitignored.
    tracked = subprocess.run(['git', '-C', str(path.parent), 'ls-files', '--error-unmatch', '--', path.name],
                             capture_output=True, check=False)
    if tracked.returncode == 0:
        raise LocalKeysError('ОПАСНО: private_keys.txt уже отслеживается Git. '
                             'Прекращаю работу. Удали файл из индекса Git без удаления локального файла.')
    ignored = subprocess.run(['git', '-C', str(path.parent), 'check-ignore', '-q', '--', path.name],
                             capture_output=True, check=False)
    if ignored.returncode != 0:
        # User should not have to edit .gitignore by hand. Block if Git still
        # doesn't ignore it after the local-only rule is added.
        ignore_path = path.parent / '.gitignore'
        try:
            existing = ignore_path.read_text(encoding='utf-8') if ignore_path.exists() else ''
            with ignore_path.open('a', encoding='utf-8') as out:
                out.write(('' if not existing or existing.endswith('\n') else '\n') + '/private_keys.txt\n')
        except OSError as exc:
            raise LocalKeysError('Не могу защитить private_keys.txt через .gitignore.') from exc
        ignored = subprocess.run(['git', '-C', str(path.parent), 'check-ignore', '-q', '--', path.name],
                                 capture_output=True, check=False)
        if ignored.returncode != 0:
            raise LocalKeysError('private_keys.txt всё ещё доступен для добавления в Git. Остановка.')


def load_plaintext_keys(path, addresses_path=None):
    """Read local private keys once. No passwords, no decryption, no secret logging."""
    path = Path(path)
    protect_local_keys_file(path)
    allowed = None
    if addresses_path is not None:
        addresses_path = Path(addresses_path)
        if not addresses_path.is_file():
            raise LocalKeysError('Не найден addresses.txt для сверки исходных адресов.')
        allowed = set()
        for raw in addresses_path.read_text(encoding='utf-8-sig').splitlines():
            addr = raw.strip()
            if not addr or addr.startswith(('#', '//')):
                continue
            if Web3.is_address(addr):
                allowed.add(addr.lower())
    keys = {}
    with path.open('r', encoding='utf-8-sig') as fh:
        for line_no, raw in enumerate(fh, 1):
            val = raw.strip()
            if not val or val.startswith(('#', '//')):
                continue
            if not re.fullmatch(r'(?:0x)?[0-9a-fA-F]{64}', val):
                raise LocalKeysError(f'Некорректный формат приватного ключа в строке {line_no}.')
            try:
                account = Account.from_key('0x' + val.removeprefix('0x'))
            except Exception as exc:
                raise LocalKeysError(f'Невозможно прочитать ключ в строке {line_no}.') from exc
            address = account.address.lower()
            if allowed is not None and address not in allowed:
                raise LocalKeysError(f'Адрес из строки {line_no} отсутствует в addresses.txt.')
            if address in keys:
                raise LocalKeysError(f'Дубликат приватного ключа (строка {line_no}).')
            keys[address] = account
    if not keys:
        raise LocalKeysError('В private_keys.txt нет приватных ключей.')
    return keys


def get_price(rows, networks):
    return prices_from_csv(rows, networks)


def inspect_plan(plan, rows, networks, *, network=None, source=None):
    prices = prices_from_csv(rows, networks)
    actions = selected_actions(plan, network, source)
    summary = defaultdict(lambda: [0, Decimal(0)])
    for a in actions:
        summary[a['network']][0] += 1
        summary[a['network']][1] += Decimal(a['scan_usd'])
    print('Recipient:',plan['destination'])
    print('Approval hash:',plan['approval_hash'])
    print(f'Included actions: {len(actions)}; excluded entries: {len(plan["skipped"])}')
    print('These are historical scanner USD estimates, NOT a live balance or gas quote.')
    for n, (cnt, usd) in sorted(summary.items()):
        gate = 'pilot execute' if n in PILOT_NETWORKS else 'plan-only / requires adapter'
        suffix = '' if n in prices else '; native gas USD price missing'
        print(f'  {n:12} {cnt:5} positions  ${usd:.4f}  [{gate}{suffix}]')


def prepare_rpc(network, configs, cache):
    if network not in cache:
        cache[network] = open_rpc(network, configs[network])
    return cache[network]


def work(plan, scan_rows, configs, *, mode, network, source, vault, journal, max_transfers,
         approval, reserve_native, max_fee_usd, max_fee_fraction, auto_yes, batch=False, keyring_override=None, buffered=False):
    if mode == 'execute':
        if not approval or approval != plan['approval_hash']:
            raise ValueError('Execution requires exact full --approve hash shown by `plan`')
        if batch:
            if not auto_yes:
                raise ValueError('Batch requires one-time approval from start.py')
            if network is not None and network not in PILOT_NETWORKS:
                raise ValueError('Unsupported network selected for batch')
        elif not network or network not in PILOT_NETWORKS:
            raise ValueError('A supported pilot network must be selected for single execution')
        if max_transfers <= 0:
            raise ValueError('Specify --max-transfers explicitly (start with 1)')
        if not auto_yes and not sys.stdin.isatty():
            raise ValueError('Interactive confirmation required unless --yes is supplied')
    prices = get_price(scan_rows, configs)
    actions = selected_actions(plan, network, source)
    events = read_events(journal)
    latest = index_events(events)
    cache = {}
    sent = 0
    confirmed = 0
    unresolved = 0
    errors = 0
    lines = []
    issues = []
    # Only read-only, live-validated dust skips from THIS run can unlock a
    # native sweep; transient RPC failures never do.
    safe_skipped_tokens = set()
    active_action = None
    def emit(*items):
        if active_action is not None and len(items)>1 and any(w in str(items[1]).upper() for w in ('SKIP:', 'ERROR:')):
            issues.append({'time': now(),'network':active_action['network'],
                           'wallet':active_action['from'],'token':active_action['symbol'],
                           'reason':' '.join(str(x) for x in items[1:])})
        if buffered:
            lines.append(' '.join(str(x) for x in items))
        else:
            print(*items)
    keyring = (keyring_override if keyring_override is not None else
               (load_plaintext_keys(vault, HERE / 'addresses.txt')
                if mode == 'execute' and actions else None))
    for a in actions:
        active_action = a
        if mode == 'execute' and sent >= max_transfers:
            break
        tag = f'{a["network"]}/{a["from"][:8]}…/{a["symbol"]}'
        if a['network'] not in PILOT_NETWORKS:
            emit(tag, 'SKIP: execution not enabled for this network')
            continue
        if mode == 'execute':
            last = latest.get((plan['approval_hash'],a['id']))
            if last:
                emit(tag, 'SKIP: journal already contains action; reconcile rather than resend')
                continue
            # Do not sign while any transaction from this account+chain has unresolved state.
            pending = [e for e in index_events(events).values() if e.get('network') == a['network']
                       and e.get('from') == a['from'] and e.get('status') not in ('success','failed')]
            if pending:
                emit(tag, 'SKIP: another action unresolved for this source; reconcile first')
                continue
            blocked = check_native_after_tokens(a, plan, events, safe_skipped_tokens)
            if blocked:
                emit(tag, 'SKIP:', blocked)
                continue
        if a['network'] not in prices:
            emit(tag, 'SKIP: missing native token USD price')
            continue
        try:
            reserve_wei = int(reserve_native*Decimal(10**18))
            w3, q = quote_with_failover(a['network'], configs[a['network']], cache,
                                        a, prices[a['network']], reserve_wei,
                                        max_fee_usd, max_fee_fraction)
            if 'skip' in q:
                if (mode == 'execute' and a['asset_type'] == 'ERC20' and
                        q.get('skip_code') in {'uneconomic_token', 'zero_balance'}):
                    safe_skipped_tokens.add(a['id'])
                    emit(tag, 'SKIP: невыгодный или пустой токен; нативная монета не блокируется:', q['skip'])
                else:
                    emit(tag, 'SKIP:', q['skip'])
                continue
            units = Decimal(q['amount_raw']) / (Decimal(10) ** q.get('decimals', 18))
            units_label = format(units.normalize(), 'f')
            emit('\n---------------- ПЕРЕВОД ----------------')
            emit('Сеть:      ', a['network'])
            emit('Отправитель:', a['from'])
            emit('Получатель: ', a['to'])
            emit(f'Сумма:       {units_label} {a["symbol"]}')
            emit(f'Комиссия:    не более ~${Decimal(q["fee_usd"]):.4f} по текущей оценке')
            emit('-----------------------------------------')
            if mode != 'execute':
                continue
            if not auto_yes:
                answer = input('Отправить этот перевод? [да/нет]: ').strip().casefold()
                if answer not in ('да', 'yes', 'send'):
                    emit('Отменено. Ничего не отправлено.')
                    continue
            account = keyring.get(a['from'].lower())
            if account is None:
                emit(tag, 'SKIP: исходный адрес отсутствует в private_keys.txt')
                continue
            latest_nonce = w3.eth.get_transaction_count(a['from'], 'latest')
            pending_nonce = w3.eth.get_transaction_count(a['from'], 'pending')
            if latest_nonce != pending_nonce:
                emit(tag, 'SKIP: pending nonce differs from confirmed nonce')
                continue
            # Re-evaluate quote after interactive approval and before signing.
            q = make_quote(w3, a, prices[a['network']], reserve_wei, max_fee_usd, max_fee_fraction)
            if 'skip' in q:
                if (a['asset_type'] == 'ERC20' and
                        q.get('skip_code') in {'uneconomic_token', 'zero_balance'}):
                    safe_skipped_tokens.add(a['id'])
                    emit(tag, 'SKIP after fresh quote: невыгодный или пустой токен; BNB/другая нативная монета не блокируется:', q['skip'])
                else:
                    emit(tag, 'SKIP after fresh quote:',q['skip'])
                continue
            tx = {**q['tx_body'], **q['fee_fields'], 'gas':q['gas_limit'],
                  'nonce':latest_nonce, 'chainId':a['chain_id']}
            # Sign without the UI-only 'from' field (source is derived from the keystore).
            signed = account.sign_transaction({k:v for k,v in tx.items() if k != 'from'})
            txhash = normalize_txhash(signed.hash)
            if a['network'] == 'scroll':
                # Re-check oracle using the *actual* signed transaction bytes.
                # This must run before journaling and broadcasting. Never spend
                # a native balance if additional L1 data fee exceeds the reserve.
                real_l1_fee = scroll_l1_fee(w3, signed.raw_transaction)
                if real_l1_fee > q['l1_cap_wei']:
                    emit(tag, 'SKIP: Scroll L1 fee rose above reserved amount')
                    continue
                if q['live_native_wei'] < q['amount_raw'] + q['gas_limit'] * q['fee_fields']['gasPrice'] + real_l1_fee + reserve_wei:
                    emit(tag, 'SKIP: Scroll insufficient gas after final signed quote')
                    continue
            ev = {'plan_hash':plan['approval_hash'],'action_id':a['id'],
                  'network':a['network'],'chain_id':a['chain_id'],'from':a['from'],
                  'to':a['to'],'symbol':a['symbol'],'contract':a['contract'],
                  'amount_raw':str(q['amount_raw']),'nonce':latest_nonce,
                  'txhash':txhash, 'status':'prepared'}
            # CRUCIAL: write hash before the first broadcast. A timeout after broadcast
            # is ambiguous; NEVER blindly re-send or reuse this nonce.
            append_event(journal, ev)
            events.append(ev)
            ack, confirmed_provider, failure_classes = broadcast_identical_signed_transaction(
                a['network'], configs[a['network']], w3, signed.raw_transaction, txhash)
            if not ack:
                ev = {**ev,'status':'uncertain',
                      'broadcast_failures':failure_classes[:4]}
                append_event(journal, ev); events.append(ev)
                emit(tag,'UNKNOWN: несколько RPC не подтвердили отправку; nonce сохранён')
                unresolved += 1
                if batch:
                    continue
                break
            w3 = confirmed_provider
            ev = {**ev, 'status':'broadcast'}
            append_event(journal, ev); events.append(ev)
            sent += 1
            try:
                receipt = w3.eth.wait_for_transaction_receipt(txhash, timeout=180, poll_latency=3)
                status = 'success' if int(receipt['status']) == 1 else 'failed'
                ev = {**ev,'status':status,'block':int(receipt['blockNumber']),
                      'gas_used':int(receipt.get('gasUsed') or 0),
                      'effective_gas_price':int(receipt.get('effectiveGasPrice') or 0)}
                append_event(journal, ev); events.append(ev)
                emit(tag, status.upper(), txhash)
                if status == 'success':
                    confirmed += 1
                elif not batch:
                    break
            except Exception:
                ev = {**ev,'status':'pending'}
                append_event(journal, ev); events.append(ev)
                emit(tag,'PENDING or RPC failure',txhash,': no automatic resend')
                unresolved += 1
                if not batch:
                    break
        except Exception as e:
            # RPC exception messages may accidentally include credentialed URLs.
            # Show safe phase-level preflight reasons in bulk mode. Never reveal
            # raw RPC messages, provider credentials or any private key material.
            if batch:
                detail = str(e)
                if isinstance(e, RuntimeError) and detail.startswith('All read-only RPC preflights failed:'):
                    label = detail[:460]
                elif isinstance(e, RuntimeError) and detail.startswith('Token transfer() returned false'):
                    label = 'Token transfer simulation returned false'
                else:
                    label = type(e).__name__
            else:
                label = f'{type(e).__name__}: {str(e)[:160]}'
            emit(tag, 'ERROR:', label)
            errors += 1
            # Stop single execution on error; never retry ambiguous broadcasts.
            if mode == 'execute' and (not batch or isinstance(e, (LocalKeysError, OSError))):
                break
    emit(f'Completed {mode}. Broadcasts initiated: {sent}; confirmed: {confirmed}; '
          f'unresolved: {unresolved}; errors: {errors}; journal: {journal}')
    if buffered:
        # One atomic console block per account+network worker.
        print('\n'.join(lines), flush=True)
    return {'sent':sent, 'confirmed':confirmed, 'unresolved':unresolved, 'errors':errors, 'issues':issues}




def recover_uncertain_once(plan, scan_rows, configs, keyring, settings, journal):
    """One guarded recovery attempt for journaled ambiguous broadcasts.

    Called only after the user's normal batch confirmation, under the same
    cross-process journal lock used by the batch runner. Reuses the recorded
    account nonce, NEVER allocates a fresh one. Two independent RPC endpoints
    must agree no previous tx is visible and nonce is still unconsumed.
    Any uncertainty leaves the action blocked. This does not recover transactions
    from other users or wallets not in the current approved plan.
    """
    results = {'confirmed': 0, 'unresolved': 0, 'errors': 0, 'sent': 0, 'issues': []}
    events = read_events(journal)
    latest = index_events(events)
    approved = {(plan['approval_hash'], a['id']): a for a in plan['actions']}
    prices = prices_from_csv(scan_rows, configs)
    candidates = [(k, e, approved[k]) for k, e in latest.items()
                  if k in approved and e.get('status') in ('uncertain', 'prepared')
                  and e.get('network') in PILOT_NETWORKS and
                  str(e.get('from', '')).lower() in keyring]
    if not candidates:
        return results
    print(f'\nПроверяю {len(candidates)} ранее неопределённых операций (без нового nonce)...', flush=True)
    for k, ev, action in candidates:
        network = action['network']
        short = f'{network}/{action["from"][:10]}/{action["symbol"]}'
        try:
            # Retries across different launches are allowed only with the
            # ORIGINAL account nonce. The validation below insists that at
            # least 2 RPCs see that nonce as free AND no previous hash is
            # visible. A later attempt cannot execute a second withdrawal
            # with a new nonce.
            history = [e for e in events if (e.get('plan_hash'), e.get('action_id')) == k]
            previous_attempts = max((int(e.get('recovery_attempts', 0) or 0)
                                     for e in history), default=0)
            if not (action['from'].lower() == str(ev.get('from', '')).lower()
                    and action['to'].lower() == str(ev.get('to', '')).lower()
                    and int(action['chain_id']) == int(ev.get('chain_id', -1))
                    and 0 <= int(ev['nonce']) and action['id'] == ev.get('action_id')):
                print(short, 'ОЖИДАЕТ: данные журнала не совпадают с утверждённым планом')
                results['unresolved'] += 1
                continue
            original_nonce = int(ev['nonce'])
            old_hashes = list(dict.fromkeys(normalize_txhash(e['txhash']) for e in history
                                                if e.get('txhash')))
            cfg = configs[network]
            checked = []
            previous_receipt = None
            visible = False
            for url in list(dict.fromkeys(cfg['rpcs'])):
                if not isinstance(url, str) or not url.startswith('https://'):
                    continue
                try:
                    w3 = make_network_web3(url, network, timeout=10)
                    if int(w3.eth.chain_id) != int(action['chain_id']):
                        continue
                    receipts_on_this_node = []
                    pending_on_this_node = False
                    for h in old_hashes:
                        try:
                            found_receipt = w3.eth.get_transaction_receipt(h)
                            if found_receipt is not None:
                                receipts_on_this_node.append((h, found_receipt))
                                break
                        except Exception:
                            pass
                        try:
                            pending_tx = w3.eth.get_transaction(h)
                            if pending_tx:
                                pending_on_this_node = True
                        except Exception:
                            pass
                    if receipts_on_this_node:
                        previous_receipt = receipts_on_this_node[0]
                        break
                    if pending_on_this_node:
                        visible = True
                    confirmed_nonce = int(w3.eth.get_transaction_count(action['from'], 'latest'))
                    pending_nonce = int(w3.eth.get_transaction_count(action['from'], 'pending'))
                    checked.append((w3, confirmed_nonce, pending_nonce))
                except Exception:
                    continue
                if len(checked) >= 3:
                    break
            if previous_receipt is not None:
                found_hash, receipt = previous_receipt
                final_status = 'success' if int(receipt['status']) == 1 else 'failed'
                record = {**ev, 'txhash': found_hash, 'status':final_status,
                          'block':int(receipt['blockNumber']), 'recovery_note':'old transaction receipt found'}
                append_event(journal, record)
                events.append(record)
                if final_status == 'success':
                    results['confirmed'] += 1
                else:
                    results['errors'] += 1
                print(short, 'НАЙДЕНА РАНЕЕ:', final_status.upper())
                continue
            if visible:
                print(short, 'ОЖИДАЕТ: транзакция видна в mempool')
                results['unresolved'] += 1
                continue
            if len(checked) < 2:
                print(short, 'ОЖИДАЕТ: недостаточно независимых RPC для проверки')
                results['unresolved'] += 1
                continue
            if any(confirmed != original_nonce or pending != original_nonce
                   for _, confirmed, pending in checked):
                print(short, 'ОЖИДАЕТ: nonce изменился или RPC не согласны')
                results['unresolved'] += 1
                continue
            if network not in prices:
                print(short, 'ОЖИДАЕТ: цена монеты для комиссии не определена')
                results['unresolved'] += 1
                continue
            # Quote is freshly calculated from actual balances, not scanner balances.
            reserve_wei = int(settings['native_reserve'] * Decimal(10**18))
            provider, quote = quote_with_failover(network, cfg, {}, action,
                              prices[network], reserve_wei,
                              settings['max_fee_usd'], settings['max_fee_fraction'])
            if 'skip' in quote:
                print(short, 'ПРОПУЩЕНО:', quote['skip'])
                results['unresolved'] += 1
                continue
            # Re-check on this provider immediately before signing; never use
            # a new nonce or attempt to bypass a pending transaction.
            if int(provider.eth.get_transaction_count(action['from'], 'latest')) != original_nonce or \
               int(provider.eth.get_transaction_count(action['from'], 'pending')) != original_nonce:
                print(short, 'ОЖИДАЕТ: nonce изменился перед отправкой')
                results['unresolved'] += 1
                continue
            tx = {**quote['tx_body'], **quote['fee_fields'], 'gas': quote['gas_limit'],
                  'nonce': original_nonce, 'chainId': action['chain_id']}
            signed = keyring[action['from'].lower()].sign_transaction({n:v for n,v in tx.items() if n != 'from'})
            signed_hash = normalize_txhash(signed.hash)
            if network == 'scroll':
                l1 = scroll_l1_fee(provider, signed.raw_transaction)
                if l1 > quote['l1_cap_wei'] or \
                    quote['live_native_wei'] < quote['amount_raw'] + quote['gas_limit'] * quote['fee_fields']['gasPrice'] + l1 + reserve_wei:
                    print(short, 'ОЖИДАЕТ: Scroll L1-комиссия изменилась')
                    results['unresolved'] += 1
                    continue
            prepared = {**ev, 'status':'prepared', 'txhash':signed_hash,
                        'prior_txhashes':old_hashes, 'nonce':original_nonce,
                        'amount_raw':str(quote['amount_raw']), 'recovery_attempts':previous_attempts+1}
            append_event(journal, prepared)  # durable BEFORE RPC broadcast
            events.append(prepared)
            ack, provider, fail_classes = broadcast_identical_signed_transaction(
                network, cfg, provider, signed.raw_transaction, signed_hash)
            if not ack:
                event = {**prepared, 'status':'uncertain',
                         'broadcast_failures':fail_classes[:4]}
                append_event(journal,event); events.append(event)
                print(short, 'RPC ОТКЛОНИЛИ ОТПРАВКУ: '+', '.join(dict.fromkeys(fail_classes))+'; nonce сохранён')
                results['unresolved'] += 1
                continue
            event = {**prepared, 'status':'broadcast'}
            append_event(journal,event); events.append(event)
            results['sent'] += 1
            try:
                receipt = provider.eth.wait_for_transaction_receipt(signed_hash, timeout=90, poll_latency=3)
                status = 'success' if int(receipt['status']) == 1 else 'failed'
                event = {**event, 'status':status, 'block':int(receipt['blockNumber']),
                         'gas_used':int(receipt.get('gasUsed') or 0),
                         'effective_gas_price':int(receipt.get('effectiveGasPrice') or 0)}
                append_event(journal,event); events.append(event)
                results['confirmed' if status == 'success' else 'errors'] += 1
                print(short, status.upper(), signed_hash)
            except Exception:
                event = {**event,'status':'pending'}
                append_event(journal,event); events.append(event)
                results['unresolved'] += 1
                print(short, 'ОЖИДАЕТ: отправлена, подтверждение не получено', signed_hash)
        except Exception as exc:
            # A local/provider exception is not permission to resend.
            results['errors'] += 1
            results['issues'].append({'time':now(),'network':network,'wallet':action['from'],
                                      'token':action['symbol'],'reason':'recovery '+type(exc).__name__})
            print(short, 'ОШИБКА ПРОВЕРКИ:', type(exc).__name__)
    return results


def reconcile(journal, configs):
    """Read-only status check across different RPCs. Never resends a transaction.

    A missing receipt is NOT failure: it may be pending, invisible to one RPC,
    dropped, or replaced. Only an actual receipt can confirm success/failure.
    """
    events = read_events(journal)
    current = index_events(events)
    found = unknown = failed = visible = 0
    for e in current.values():
        if e['status'] in ('success','failed'):
            continue
        network = e.get('network','')
        cfg = configs.get(network)
        if not cfg or not e.get('txhash'):
            unknown += 1
            print(network, e.get('from','')[:10], 'UNKNOWN: missing network/hash')
            continue
        try:
            hashes = list(dict.fromkeys(
                normalize_txhash(h) for h in [e['txhash'], *(e.get('prior_txhashes') or [])]))
        except ValueError:
            unknown += 1
            print(network, e.get('from','')[:10], 'ОШИБКА ФОРМАТА ХЕША')
            continue
        txhash = hashes[0]
        seen_tx = False
        good_rpc = False
        receipt = None
        # A replacement uses the SAME nonce and may have a different hash.
        # Check both the first hash and every replacement hash.
        for url in cfg.get('rpcs',[]):
            if not isinstance(url,str) or not url.startswith('https://'):
                continue
            try:
                w3=make_network_web3(url, network, timeout=12)
                if int(w3.eth.chain_id) != int(cfg['chain_id']):
                    continue
                good_rpc = True
                for candidate in hashes:
                    try:
                        receipt = w3.eth.get_transaction_receipt(candidate)
                        if receipt is not None:
                            txhash = candidate
                            break
                    except Exception:
                        pass
                    try:
                        tx = w3.eth.get_transaction(candidate)
                        if tx:
                            seen_tx=True
                    except Exception:
                        pass
                if receipt is not None:
                    break
            except Exception:
                continue
        if receipt is not None:
            status='success' if int(receipt['status'])==1 else 'failed'
            append_event(journal,{**e,'status':status,'txhash':txhash,'block':int(receipt['blockNumber']),
                                  'gas_used':int(receipt.get('gasUsed') or 0),
                                  'effective_gas_price':int(receipt.get('effectiveGasPrice') or 0)})
            found += 1
            if status=='failed':failed += 1
            print(network,e['from'][:10],e['symbol'],status.upper(),txhash)
        else:
            unknown += 1
            if seen_tx:
                visible += 1
                explanation='В СЕТИ, ОЖИДАЕТ ПОДТВЕРЖДЕНИЯ'
            elif good_rpc:
                explanation='TX НЕ НАЙДЕНА НА ДОСТУПНЫХ RPC, СТАТУС НЕИЗВЕСТЕН'
            else:
                explanation='ОШИБКА ВСЕХ RPC, СТАТУС НЕИЗВЕСТЕН'
            print(network, e['from'][:10],e.get('symbol',''), explanation, txhash)
    print(f'Reconciled: {found}; unresolved: {unknown} ({visible} visible pending); failed: {failed}')
    if unknown:
        print('Не отправляй их повторно: отсутствие receipt не доказывает отмену транзакции.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['plan','review','execute','reconcile'])
    p.add_argument('--csv', default='reports/balances_all.csv', help='Original scanner CSV')
    p.add_argument('--networks', default='networks.json')
    p.add_argument('--tokens', default='tokens.json')
    p.add_argument('--extra-rpcs', default='extra_rpcs.json', help='Optional RPC overrides as in checker')
    p.add_argument('--plan', default='consolidation/plan.json')
    p.add_argument('--journal', default='consolidation/journal.jsonl')
    p.add_argument('--settings', default='settings.json', help='Editable local settings JSON (recipient and fee rules)')
    p.add_argument('--to', help='Override settings recipient (not needed for normal use)')
    p.add_argument('--min-usd', default=None, help='Override settings min_usd')
    p.add_argument('--network', help='Network slug, REQUIRED for execution')
    p.add_argument('--source', help='Restrict to one source address for first test')
    p.add_argument('--vault', default='private_keys.txt', help='Local plaintext keys file (NOT encrypted)')
    p.add_argument('--approve', help='Full immutable plan hash, REQUIRED for execute')
    p.add_argument('--max-transfers', type=int, default=0, help='Explicit ceiling for execute; start with 1')
    p.add_argument('--max-fee-usd', type=Decimal, default=None)
    p.add_argument('--max-fee-fraction', type=Decimal, default=None)
    p.add_argument('--native-reserve', type=Decimal, default=None)
    p.add_argument('--yes', action='store_true', help='Disable per-transaction SEND prompt; still requires full plan hash')
    args = p.parse_args()
    if args.command != 'reconcile':
        settings = load_settings(args.settings)
        args.to = args.to or settings['recipient']
        args.min_usd = args.min_usd if args.min_usd is not None else str(settings['min_usd'])
        args.max_fee_usd = args.max_fee_usd if args.max_fee_usd is not None else settings['max_fee_usd']
        args.max_fee_fraction = args.max_fee_fraction if args.max_fee_fraction is not None else settings['max_fee_fraction']
        args.native_reserve = args.native_reserve if args.native_reserve is not None else settings['native_reserve']
    cfg_path, tok_path, csv_path = Path(args.networks),Path(args.tokens),Path(args.csv)
    networks = json.loads(cfg_path.read_text())
    extra_path = Path(args.extra_rpcs)
    extra = json.loads(extra_path.read_text()) if extra_path.exists() else {}
    for slug, urls in extra.items():
        if slug not in networks or not isinstance(urls, list):
            raise ValueError('Invalid extra RPC config')
        networks[slug]['rpcs'] = list(dict.fromkeys(urls + networks[slug]['rpcs']))[:5]
    # Plan binds to effective RPC config, not just the default settings file.
    effective_network_digest = digest_json(networks)
    if args.command == 'reconcile':
        with exclusive_lock(args.journal):
            reconcile(args.journal, networks)
        try:
            import report as reporter
            reporter.generate(HERE, live=True, workers=5)
            print('Итоговая таблица:', HERE/'consolidation/report.html')
        except Exception as exc:
            print('Не удалось обновить отчёт:', type(exc).__name__)
        return
    tokens = json.loads(tok_path.read_text())
    rows = load_csv(csv_path)
    if args.command == 'plan':
        if not args.to:
            p.error('Set recipient inside settings.json')
        plan = build_plan(rows,args.to,networks,tokens,min_usd=Decimal(args.min_usd),
                          source_digest=sha256_file(csv_path),network_digest=effective_network_digest,
                          token_digest=sha256_file(tok_path),
                          fee_policy={'max_fee_usd':str(args.max_fee_usd),
                                      'max_fee_fraction':str(args.max_fee_fraction),
                                      'native_reserve':str(args.native_reserve)})
        atomic_json(args.plan, plan)
        export_plan_csv(plan, args.plan)
        print('Plan written:',args.plan)
        inspect_plan(plan, rows, networks, network=args.network, source=args.source)
        print('Carefully review plan.json and confirm recipient address BEFORE execute.')
        return
    plan = load_plan(args.plan)
    if plan['destination'].lower() != args.to.lower():
        raise ValueError('Recipient in settings.json differs from the approved plan; create a new plan')
    if Decimal(plan['min_usd']) != Decimal(args.min_usd):
        raise ValueError('min_usd changed since plan approval; create a new plan')
    fee_policy = plan.get('fee_policy') or {}
    for field, expected in [('max_fee_usd',args.max_fee_usd),
                            ('max_fee_fraction',args.max_fee_fraction),
                            ('native_reserve',args.native_reserve)]:
        if field not in fee_policy or Decimal(fee_policy[field]) != expected:
            raise ValueError(f'{field} changed since plan approval; create a new plan')
    # Prevent using a plan with a silently changed registry; source report can be old,
    # but its sha is bound and also checked here to avoid accidental report mixing.
    if plan['scanner_csv_sha256'] != sha256_file(csv_path) or plan['networks_sha256'] != effective_network_digest or plan['tokens_sha256'] != sha256_file(tok_path):
        raise ValueError('Scanner report or registry changed; create and review a new plan')
    if args.command == 'review':
        inspect_plan(plan, rows, networks, network=args.network, source=args.source)
    if args.command in ('review','execute'):
        if args.max_fee_usd <= 0 or not (Decimal(0)<args.max_fee_fraction <=Decimal(1)) or args.native_reserve < 0:
            raise ValueError('Invalid gas safety limits')
        if args.command == 'execute':
            with exclusive_lock(args.journal):
                work(plan, rows, networks, mode=args.command, network=args.network, source=args.source,
                     vault=args.vault, journal=args.journal, max_transfers=args.max_transfers,
                     approval=args.approve, reserve_native=args.native_reserve,
                     max_fee_usd=args.max_fee_usd, max_fee_fraction=args.max_fee_fraction,
                     auto_yes=args.yes)
        else:
            work(plan, rows, networks, mode=args.command, network=args.network, source=args.source,
                 vault=args.vault, journal=args.journal, max_transfers=args.max_transfers,
                 approval=args.approve, reserve_native=args.native_reserve,
                 max_fee_usd=args.max_fee_usd, max_fee_fraction=args.max_fee_fraction,
                 auto_yes=args.yes)


if __name__ == '__main__':
    main()
