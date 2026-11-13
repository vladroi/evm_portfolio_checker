import asyncio
import importlib.util
import json
import re
import sys
import tempfile
import types
import unittest
from pathlib import Path

# Test offline without installing web3; installed web3 performs checksum validation.
if importlib.util.find_spec('web3') is None:
    shim = types.ModuleType('web3')
    shim.Web3 = type('Web3', (), {
        'is_address': staticmethod(lambda s: bool(re.fullmatch(r'0x[0-9a-fA-F]{40}',s))),
        'to_checksum_address': staticmethod(lambda s: '0x'+s[2:].lower())})
    sys.modules['web3'] = shim

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import checker

class CheckerTests(unittest.TestCase):
    def test_config(self):
        p=Path(checker.__file__).parent
        networks,tokens=checker.load_settings(p/'networks.json',p/'tokens.json',None)
        self.assertEqual(len(networks),18)
        self.assertEqual(sum(len(x) for x in tokens.values()),65)
        self.assertEqual(networks['bsc']['chain_id'],56)
        self.assertTrue(all(1 <= len(n['rpcs']) <= 5 for n in networks.values()))

    def test_one_token_and_zero_native(self):
        class FakePool:
            async def call(self,method,params):
                if method=='eth_getBalance':return '0x0'
                if params[0]['data']==checker.DECIMALS:return hex(18)
                if method=='eth_call':return hex(5*10**18)
                raise AssertionError(method)
        async def scan():
            cfg={'chain_id':56,'native_symbol':'BNB'}
            addr='0x'+'1'*40
            return await checker.scan_network('bsc',cfg,[{'symbol':'USDT','address':'0x'+'2'*40}],[addr],FakePool(),2)
        rows=asyncio.run(scan())
        self.assertEqual(rows[0]['balance'],'0')
        self.assertEqual(rows[0]['status'],'OK')
        self.assertEqual(rows[1]['balance'],'5')
        self.assertEqual(rows[1]['status'],'OK')

    def test_reports_and_error_not_zero(self):
        cfg={'ethereum':{'chain_id':1,'rpcs':['https://example.com']}}
        address='0x'+'1'*40
        r=checker.empty_record(address,'ethereum',cfg['ethereum'],'native','ETH')
        r['error']='RPC unavailable'
        with tempfile.TemporaryDirectory() as d:
            summary=checker.write_reports(Path(d),[r],cfg,[address],[],False)
            self.assertEqual(summary['errors'],1)
            self.assertEqual(summary['nonzero_assets'],0)
            self.assertEqual((Path(d)/'balances_nonzero.csv').read_text(encoding='utf-8-sig').count('\n'),1)
            self.assertIn('ERROR',(Path(d)/'errors.csv').read_text(encoding='utf-8-sig'))

    def test_rpc_fallback(self):
        async def scenario():
            cfg={'chain_id':1,'rpcs':['https://broken.invalid','https://good.invalid']}
            pool=checker.RPCPool('ethereum',cfg,None,asyncio.Semaphore(3))
            async def post(url,method,params):
                if 'broken' in url:raise checker.TransientRPCError('timeout')
                return '0x1' if method=='eth_chainId' else '0x2a'
            pool._post=post
            return await pool.call('eth_getBalance',['0x'+'1'*40,'latest'])
        self.assertEqual(asyncio.run(scenario()),'0x2a')

if __name__=='__main__': unittest.main()

class ReportViewTests(unittest.TestCase):
    def test_wallet_dashboard_and_tables(self):
        import csv
        from report_view import write_wallet_tables
        a1 = '0x' + '1'*40
        a2 = '0x' + '2'*40
        cfg = {
            'ethereum': {'name':'Ethereum','chain_id':1,'rpcs':['https://example.org']},
            'base': {'name':'Base','chain_id':8453,'rpcs':['https://example.org']},
        }
        r1 = checker.empty_record(a1, 'ethereum', cfg['ethereum'], 'native', 'ETH')
        checker.record_success(r1, 10**18, 18)
        r1['usd_value'] = '2000.25'
        r2 = checker.empty_record(a1, 'base', cfg['base'], 'ERC20', 'USDC', '0x'+'3'*40)
        checker.record_success(r2, 12*10**6, 6)
        r2['usd_value'] = '12.0'
        r3 = checker.empty_record(a2, 'ethereum', cfg['ethereum'], 'native', 'ETH')
        r3['error'] = 'RPC unavailable'
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            write_wallet_tables(out, [r1,r2,r3], cfg, [a1,a2], True)
            with (out/'wallets_table.csv').open(encoding='utf-8-sig', newline='') as f:
                wallets = list(csv.DictReader(f))
            self.assertEqual(len(wallets),2)
            self.assertEqual(wallets[0]['usd_known'], '2012.25')
            self.assertEqual(wallets[0]['networks_with_assets'], '2')
            self.assertEqual(wallets[0]['base_assets'], '12 USDC')
            self.assertEqual(wallets[1]['errors'], '1')
            self.assertEqual(wallets[1]['usd_known'], '0')
            with (out/'wallet_assets.csv').open(encoding='utf-8-sig', newline='') as f:
                assets = list(csv.DictReader(f))
            self.assertEqual(len(assets),2)
            with (out/'wallets_by_network.csv').open(encoding='utf-8-sig', newline='') as f:
                by_network = list(csv.DictReader(f))
            self.assertEqual(len(by_network),4)
            html = (out/'portfolio.html').read_text(encoding='utf-8')
            self.assertIn('Портфель кошельков', html)
            self.assertIn('RPC unavailable', html)
            self.assertIn('wallets_table.csv', html)
            self.assertIn('2000.25', html)
            self.assertIn('"total_errors": 1', html)

    def test_unpriced_and_no_usd_are_not_zero(self):
        from report_view import write_wallet_tables
        a1 = '0x'+'1'*40
        cfg = {'base': {'name':'Base','chain_id':8453,'rpcs':['https://example.org']}}
        r = checker.empty_record(a1, 'base', cfg['base'], 'ERC20', 'UNKNOWN', '0x'+'3'*40)
        checker.record_success(r, 12345, 3)
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            write_wallet_tables(out,[r],cfg,[a1],True)
            html = (out/'portfolio.html').read_text(encoding='utf-8')
            self.assertIn('"total_unpriced": 1',html)
            self.assertIn('"usd": ""',html)
            write_wallet_tables(out,[r],cfg,[a1],False)
            self.assertIn('"usd": false', (out/'portfolio.html').read_text(encoding='utf-8'))


class ExistingScanReportOnlyTests(unittest.TestCase):
    def test_report_only_no_rpc(self):
        import contextlib
        import csv
        import io
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d)
            addr = '0x' + '1'*40
            src = checker.empty_record(addr, 'ethereum', {'chain_id': 1}, 'native', 'ETH')
            checker.record_success(src, 10**18, 18)
            src['usd_value'] = '2000'
            checker.write_csv(dest/'balances_all.csv', [src], checker.HEADERS)
            (dest/'summary.json').write_text('{"prices_requested":true}',encoding='utf8')
            args = types.SimpleNamespace(
                networks=Path(checker.__file__).parent/'networks.json',
                tokens=Path(checker.__file__).parent/'tokens.json',
                extra_rpcs=None, only=None, report_only=True, out=dest)
            with contextlib.redirect_stdout(io.StringIO()) as captured:
                asyncio.run(checker.run(args))
            self.assertTrue((dest/'portfolio.html').exists())
            self.assertIn('no RPC requests',captured.getvalue())


class EthereumErrorFixTests(unittest.TestCase):
    def test_rpc_unsupported_eth_call_fallback_and_method_specific_skip(self):
        async def scenario():
            cfg={'chain_id':1,'rpcs':['https://bad.invalid','https://good.invalid']}
            pool=checker.RPCPool('ethereum',cfg,None,asyncio.Semaphore(3))
            calls=[]
            async def fake_post(url, method, params):
                calls.append((url,method))
                if method=='eth_chainId':return '0x1'
                if method=='eth_call' and 'bad' in url:
                    raise checker.UnsupportedRPCMethod('RPC -32000: The method eth_call is not supported.')
                return '0x2a'
            pool._post=fake_post
            first=await pool.call('eth_call',[{'to':'0x'+'1'*40,'data':checker.DECIMALS},'latest'])
            second=await pool.call('eth_call',[{'to':'0x'+'1'*40,'data':checker.DECIMALS},'latest'])
            native=await pool.call('eth_getBalance',['0x'+'1'*40,'latest'])
            return first,second,native,calls,pool.health()
        first,second,native,calls,health=asyncio.run(scenario())
        self.assertEqual((first,second,native),('0x2a',)*3)
        self.assertEqual(sum('bad' in url and method=='eth_call' for url,method in calls),1)
        self.assertEqual(health['providers'][0]['unsupported_methods'],['eth_call'])

    def test_internal_error_response_is_retryable(self):
        class Response:
            status=200
            async def __aenter__(self):return self
            async def __aexit__(self,*args):return False
            async def json(self,**kwargs):return {'jsonrpc':'2.0','id':1,'error':{'code':-32603,'message':'Internal error'}}
        class Session:
            def post(self,*a,**kw):return Response()
        async def scenario():
            pool=checker.RPCPool('ethereum',{'chain_id':1,'rpcs':['https://bad.invalid']},
                                 Session(),asyncio.Semaphore(1))
            await pool._post('https://bad.invalid','eth_call',[])
        with self.assertRaises(checker.TransientRPCError):
            asyncio.run(scenario())

    def test_provider_unsupported_response_is_retryable(self):
        class Response:
            status=200
            async def __aenter__(self):return self
            async def __aexit__(self,*args):return False
            async def json(self,**kwargs):return {'jsonrpc':'2.0','id':1,'error':{'code':-32000,'message':'The method eth_call is not supported.'}}
        class Session:
            def post(self,*a,**kw):return Response()
        async def scenario():
            pool=checker.RPCPool('ethereum',{'chain_id':1,'rpcs':['https://bad.invalid']},
                                 Session(),asyncio.Semaphore(1))
            await pool._post('https://bad.invalid','eth_call',[])
        with self.assertRaises(checker.UnsupportedRPCMethod):
            asyncio.run(scenario())

    def test_retry_only_failed_observations(self):
        addr='0x'+'1'*40
        token='0x'+'2'*40
        cfg={'ethereum':{'chain_id':1,'native_symbol':'ETH'},'base':{'chain_id':8453,'native_symbol':'ETH'}}
        succeeded=checker.empty_record(addr,'ethereum',cfg['ethereum'],'native','ETH')
        checker.record_success(succeeded,1234567,18)
        failed=checker.empty_record(addr,'ethereum',cfg['ethereum'],'ERC20','DAI',token)
        failed['error']='Token metadata unavailable: RPC -32603: Internal error'
        other=checker.empty_record(addr,'base',cfg['base'],'native','ETH')
        checker.record_success(other,777,18)
        rows=[succeeded,failed,other]
        original_native=dict(succeeded)
        original_base=dict(other)
        class FakePool:
            calls=[]
            async def call(self,method,params):
                self.calls.append(method)
                if method=='eth_call' and params[0]['data']==checker.DECIMALS:
                    return '0x12'
                if method=='eth_call' and params[0]['data'].startswith(checker.BALANCE_OF):
                    return hex(200*10**18)
                raise AssertionError('Successful rows must not be queried')
        recovered,attempted=asyncio.run(checker.retry_failed_rows(FakePool(), 'ethereum',cfg['ethereum'],rows,2))
        self.assertEqual((recovered,attempted),(1,1))
        self.assertEqual(rows[1]['balance'],'200')
        self.assertEqual(rows[1]['status'],'OK')
        self.assertEqual(rows[0],original_native)
        self.assertEqual(rows[2],original_base)

    def test_extra_rpcs_are_prioritized(self):
        root=Path(checker.__file__).parent
        with tempfile.TemporaryDirectory() as d:
            extra=Path(d)/'extra_rpcs.json'
            extra.write_text(json.dumps({'ethereum':['https://my-node.example.com']}))
            networks,_=checker.load_settings(root/'networks.json',root/'tokens.json',extra)
        self.assertEqual(networks['ethereum']['rpcs'][0],'https://my-node.example.com')
        self.assertEqual(len(networks['ethereum']['rpcs']),5)
