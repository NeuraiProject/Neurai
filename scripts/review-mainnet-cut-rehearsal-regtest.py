#!/usr/bin/env python3
"""Rehearse a future mainnet activation between old-rule and new-rule nodes.

The reset testnet cannot show this: its new magic drops old nodes on the first
message. Here both nodes share the network identity (regtest magic and genesis)
and run the same binary; the "old" node keeps every new rule unscheduled
through the regtest height overrides, the "new" node activates them at H.

For each rule, a fresh pair of nodes reaches H-1 together and one node mines
block H with a single probe transaction. The report classifies the rule:
  * hard fork: the old node rejects a block the new node accepts;
  * restrictive (soft fork): the new node rejects a block the old node accepts.

Usage: review-mainnet-cut-rehearsal-regtest.py [--bindir DIR]
"""
import argparse
import base64
import importlib.util
import json
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

spec = importlib.util.spec_from_file_location('h10', Path(__file__).with_name('review-testnet-reset-h10.py'))
h10 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h10)

H = 130
MAX = 2147483647
HEIGHT_ARGS = ['optinfeaturesheight', 'strictauthscriptheight', 'signatureopcodesheight', 'txhashheight',
               'assetmessageheight', 'inputfieldheight', 'merkleposeidonheight', 'authscripttreeheight',
               'nip040height', 'depinstateheight']
DISABLE_ARGS = ['zkverifyheight', 'poseidonworkheight', 'authscriptbudgetheight']  # -1 disables


def schedule(height):
    if height is None:
        return [f'-{a}={MAX}' for a in HEIGHT_ARGS] + [f'-{a}=-1' for a in DISABLE_ARGS]
    return [f'-{a}={height}' for a in HEIGHT_ARGS + DISABLE_ARGS]


class RegtestNode:
    def __init__(self, bindir, directory, extra_args=()):
        self.directory = directory
        directory.mkdir(parents=True)
        self.rpc_port = h10.free_port()
        self.p2p_port = h10.free_port()
        self.log = (directory / 'process.log').open('w')
        self.proc = subprocess.Popen([
            str(Path(bindir) / 'neuraid'), '-regtest', '-server', '-listen=1', '-bind=127.0.0.1',
            f'-port={self.p2p_port}', '-dnsseed=0', '-discover=0', '-txindex=1', '-fallbackfee=0.01',
            '-acceptnonstdtxn=1', '-rpcuser=review', '-rpcpassword=disposable-regtest',
            f'-rpcport={self.rpc_port}', f'-datadir={directory}', *extra_args],
            stdout=self.log, stderr=subprocess.STDOUT)

    def rpc(self, method, *params):
        payload = json.dumps({'jsonrpc': '1.0', 'id': 'cut', 'method': method, 'params': params}).encode()
        auth = base64.b64encode(b'review:disposable-regtest').decode()
        request = urllib.request.Request(f'http://127.0.0.1:{self.rpc_port}', payload,
                                         {'Authorization': 'Basic ' + auth})
        try:
            response = urllib.request.urlopen(request, timeout=120)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            reply = json.load(response)
        if reply.get('error'):
            raise h10.RPCError(reply['error'].get('message', str(reply['error'])))
        return reply['result']

    def ready(self):
        for _ in range(600):
            if self.proc.poll() is not None:
                raise RuntimeError(f'node exited; see {self.directory}/process.log')
            try:
                self.rpc('getblockcount')
                return
            except (OSError, h10.RPCError):
                time.sleep(0.1)
        raise RuntimeError('node startup timed out')

    def stop(self):
        if self.proc.poll() is None:
            try:
                self.rpc('stop')
                self.proc.wait(timeout=60)
            except Exception:
                self.proc.kill()
        self.log.close()


def wait(predicate, tries=300):
    for _ in range(tries):
        if predicate():
            return True
        time.sleep(0.1)
    return False


def rehearse(bindir, root, rule):
    """Returns (classification, detail) for one rule on a fresh node pair."""
    old = RegtestNode(bindir, root / rule / 'old', schedule(None) + ['-connect=0'])
    new = RegtestNode(bindir, root / rule / 'new', schedule(H) + ['-connect=0'])
    nodes = [old, new]
    try:
        for node in nodes:
            node.ready()
        new.rpc('addnode', f'127.0.0.1:{old.p2p_port}', 'onetry')
        if not wait(lambda: len(old.rpc('getpeerinfo')) == 1):
            return 'error', 'nodes did not connect'
        miner = new.rpc('getnewaddress')

        def spk(address):
            return bytes.fromhex(new.rpc('validateaddress', address)['scriptPubKey'])

        def synced():
            return wait(lambda: old.rpc('getbestblockhash') == new.rpc('getbestblockhash'))

        new.rpc('generatetoaddress', 101, miner)
        if not synced():
            return 'error', 'initial sync failed'

        # Common setup that is valid under both rule sets, before H.
        cat_coin = None
        if rule == 'op_cat_p2sh':
            p2sh = new.rpc('decodescript', h10.CAT_REDEEM.hex())['p2sh']
            txid = new.rpc('sendtoaddress', p2sh, 1)
            tx = new.rpc('getrawtransaction', txid, True)
            cat_coin = (txid, next(o['n'] for o in tx['vout'] if o['scriptPubKey'].get('addresses') == [p2sh]))
        if rule == 'nip040_xna_marker':
            new.rpc('issue', 'CUTPROBE', 1000, miner)
        new.rpc('generatetoaddress', H - 1 - new.rpc('getblockcount'), miner)
        if not synced() or new.rpc('getblockcount') != H - 1:
            return 'error', 'nodes did not reach H-1 together'

        # Probe transaction for block H.
        miner_node = new
        if rule == 'tx_v3':
            coin = next(u for u in new.rpc('listunspent', 1) if u['amount'] > 2)
            unsigned = h10.raw_tx([(coin['txid'], coin['vout'], b'')],
                                  [(h10.sats(coin['amount']) - 1_000_000, spk(miner))], version=3)
            new.rpc('sendrawtransaction', new.rpc('signrawtransaction', unsigned.hex())['hex'])
        elif rule == 'op_cat_p2sh':
            raw = h10.raw_tx([(cat_coin[0], cat_coin[1], h10.CAT_SCRIPTSIG)], [(99_000_000, spk(miner))])
            new.rpc('sendrawtransaction', raw.hex())
        elif rule == 'nip040_xna_marker':
            new.rpc('transfer', 'CUTPROBE', 1, new.rpc('getnewaddress'))
        elif rule == 'strict_xna_placement':
            # Legacy-valid, strict-invalid output: OP_XNA_ASSET OP_TRUE. Mined by the
            # old node; the new node enforces the strict rule from H.
            miner_node = old
            old_miner = old.rpc('getnewaddress')
            coin_txid = new.rpc('sendtoaddress', old_miner, 5)
            if not wait(lambda: coin_txid in old.rpc('getrawmempool')):
                return 'error', 'funding did not reach the old node'
            tx = old.rpc('getrawtransaction', coin_txid, True)
            vout = next(o['n'] for o in tx['vout'] if o['scriptPubKey'].get('addresses') == [old_miner])
            raw = h10.raw_tx([(coin_txid, vout, b'')],
                             [(400_000_000, bytes([0xc0, 0x51])),
                              (99_000_000, bytes.fromhex(old.rpc('validateaddress', old_miner)['scriptPubKey']))])
            old.rpc('sendrawtransaction', old.rpc('signrawtransaction', raw.hex())['hex'])
        else:
            return 'error', f'unknown rule {rule}'

        block = miner_node.rpc('generatetoaddress', 1, miner if miner_node is new else old.rpc('getnewaddress'))[0]
        other = old if miner_node is new else new
        accepted = wait(lambda: other.rpc('getbestblockhash') == block, 100)
        mined_tx_count = len(miner_node.rpc('getblock', block)['tx'])
        if mined_tx_count < 2:
            return 'error', f'probe transaction not mined (block has {mined_tx_count} tx)'
        peers = len(old.rpc('getpeerinfo'))
        if accepted:
            return 'compatible', f'{"old" if other is old else "new"} node accepted block H; peers={peers}'
        chain = [c for c in other.rpc('getchaintips') if c['hash'] == block]
        status = chain[0]['status'] if chain else 'not received'
        classification = 'hard fork' if other is old else 'restrictive (soft fork)'
        return classification, f'{"old" if other is old else "new"} node left block H as {status}; peers={peers}'
    finally:
        for node in nodes:
            node.stop()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bindir', default='/root/Neurai/src')
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix='mainnet-cut-rehearsal-'))
    expected = {'tx_v3': 'hard fork', 'op_cat_p2sh': 'hard fork', 'nip040_xna_marker': 'hard fork',
                'strict_xna_placement': 'restrictive (soft fork)'}
    report = {'directory': str(root), 'H': H, 'results': []}
    for rule, want in expected.items():
        try:
            got, detail = rehearse(args.bindir, root, rule)
        except Exception as error:  # keep the other rules running
            got, detail = 'error', repr(error)
        passed = got == want
        report['results'].append({'rule': rule, 'classification': got, 'expected': want,
                                  'detail': detail, 'passed': passed})
        print(('PASS ' if passed else 'FAIL ') + f'{rule}: {got} ({detail})', flush=True)
    (root / 'report.json').write_text(json.dumps(report, indent=2))
    failed = [r for r in report['results'] if not r['passed']]
    print(f"\n{len(report['results']) - len(failed)}/{len(report['results'])} as expected; report: {root}/report.json")
    if failed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
