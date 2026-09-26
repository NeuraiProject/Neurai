#!/usr/bin/env python3
"""Rehearse the reset testnet activation boundary (plan 2026-09-26 v2).

Runs isolated nodes with the real -testnet parameters of the current binary
(fresh data directories, no seeds) and checks, on both sides of the opt-in
activation height H:
  * legacy spends, tx v3, an OP_CAT P2SH spend and the NIP-040 asset marker;
  * strict wallet addresses handed out before H but not payable until H;
  * -addresstype (legacy, pq, ecdsa): default family on each side of H, the
    ecdsa wallet never handing out Legacy, and the error when an existing
    wallet is opened with a different -addresstype;
  * mempool eviction and continued mining after a reorg from above H back to H-2;
  * a reorg down to the genesis block (assets are a pure rule from genesis);
  * P2P separation from a node of the previous testnet (optional old binary).

Each check prints PASS/FAIL; a JSON report is written next to the data.
Usage: review-testnet-reset-h10.py [--bindir DIR] [--old-bindir DIR]
"""
import argparse
import base64
import glob
import json
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

GENESIS = '0000008b384aeffecdab182575dc4e86c9f07f90318c65088532660ed9a8a021'  # reset testnet, 2026-09-26
H = 10                       # opt-in activation height of the reset testnet
MATURITY = 5                 # COINBASE_MATURITY_TESTNET
MARKER_RVN = '72766e'        # "rvn" asset marker
MARKER_XNA = '786e61'        # "xna" asset marker
ASSET = 'RVNPROBE'


class RPCError(Exception):
    pass


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class TestnetNode:
    def __init__(self, bindir, directory, extra_args=()):
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)   # exist_ok: restarts reuse the data directory
        self.rpc_port = free_port()
        self.p2p_port = free_port()
        self.log = (directory / 'process.log').open('w')
        self.proc = subprocess.Popen([
            str(Path(bindir) / 'neuraid'), '-testnet', '-server', '-listen=1', '-bind=127.0.0.1',
            f'-port={self.p2p_port}', '-connect=0', '-dnsseed=0', '-discover=0', '-txindex=1',
            '-fallbackfee=0.01', '-keypool=5', '-rpcuser=review', '-rpcpassword=disposable-testnet',
            f'-rpcport={self.rpc_port}', f'-datadir={directory}', *extra_args],
            stdout=self.log, stderr=subprocess.STDOUT)

    def rpc(self, method, *params):
        payload = json.dumps({'jsonrpc': '1.0', 'id': 'h10', 'method': method, 'params': params}).encode()
        auth = base64.b64encode(b'review:disposable-testnet').decode()
        request = urllib.request.Request(f'http://127.0.0.1:{self.rpc_port}', payload,
                                         {'Authorization': 'Basic ' + auth})
        try:
            response = urllib.request.urlopen(request, timeout=120)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            reply = json.load(response)
        if reply.get('error'):
            raise RPCError(reply['error'].get('message', str(reply['error'])))
        return reply['result']

    def ready(self):
        for _ in range(600):
            if self.proc.poll() is not None:
                raise RuntimeError(f'node exited; see {self.directory}/process.log')
            try:
                self.rpc('getblockcount')
                return
            except (OSError, RPCError):
                time.sleep(0.1)
        raise RuntimeError('node startup timed out')

    def debug_log(self):
        text = ''
        for path in glob.glob(str(self.directory / '**' / 'debug.log'), recursive=True):
            text += Path(path).read_text(errors='replace')
        return text

    def stop(self):
        if self.proc.poll() is None:
            try:
                self.rpc('stop')
                self.proc.wait(timeout=60)
            except Exception:
                self.proc.kill()
        self.log.close()


def init_error(bindir, directory, extra_args):
    """Starts neuraid expecting it to refuse to start; returns (exit code, output)."""
    directory.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run([str(Path(bindir) / 'neuraid'), '-testnet', '-server=0', '-listen=0', '-connect=0',
                           '-dnsseed=0', '-discover=0', '-txindex=1', f'-datadir={directory}', *extra_args],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
    return proc.returncode, proc.stdout


# --- minimal transaction serialization ------------------------------------

def compact(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    return b'\xfe' + struct.pack('<I', n)


def push(data):
    assert 1 < len(data) < 0x4c or (len(data) == 1 and data[0] > 0x10)
    return bytes([len(data)]) + data


def raw_tx(inputs, outputs, version=2, locktime=0):
    """inputs: [(txid_hex, vout, scriptSig)]; outputs: [(sats, scriptPubKey)]."""
    raw = struct.pack('<I', version) + compact(len(inputs))
    for txid, vout, script_sig in inputs:
        raw += bytes.fromhex(txid)[::-1] + struct.pack('<I', vout)
        raw += compact(len(script_sig)) + script_sig + struct.pack('<I', 0xffffffff)
    raw += compact(len(outputs))
    for value, spk in outputs:
        raw += struct.pack('<q', value) + compact(len(spk)) + spk
    if version == 3:
        raw += compact(0)  # NIP-014: empty vrefin
    return raw + struct.pack('<I', locktime)


def sats(amount):
    return int(round(float(amount) * 100_000_000))


# --- bech32m (BIP 350) for AuthScript v1 test addresses --------------------

BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'


def bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def convertbits(data, frombits, tobits):
    acc, bits, ret, maxv = 0, 0, [], (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def bech32m_address(hrp, version, program):
    data = [version] + convertbits(program, 8, 5)
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    polymod = bech32_polymod(expanded + data + [0] * 6) ^ 0x2bc830a3
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + '1' + ''.join(BECH32_CHARSET[d] for d in data + checksum)


V1_PROGRAM = bytes([0x11] * 32)
V1_SCRIPT = bytes([0x51, 0x20]) + V1_PROGRAM           # witness v1 (AuthScript)
V1_ADDRESS = bech32m_address('tnc', 1, V1_PROGRAM)       # testnet AuthScript HRP


# OP_CAT redeem script: <0x41> <0x42> OP_CAT <0x4142> OP_EQUAL
CAT_REDEEM = bytes([0x7e]) + push(bytes([0x41, 0x42])) + bytes([0x87])
CAT_SCRIPTSIG = push(bytes([0x41])) + push(bytes([0x42])) + push(CAT_REDEEM)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bindir', default='/root/Neurai/src')
    parser.add_argument('--old-bindir', default='', help='binary of the previous testnet for the P2P check')
    args = parser.parse_args()

    directory = Path(tempfile.mkdtemp(prefix='testnet-reset-h10-'))
    report = {'directory': str(directory), 'results': []}
    nodes = []
    used = set()           # coins taken by hand-built transactions
    pending_coins = []     # coins of the transaction being submitted

    def check(label, condition, observed=None):
        report['results'].append({'case': label, 'passed': bool(condition), 'observed': observed})
        print(('PASS ' if condition else 'FAIL ') + label + ('' if condition else f'  -> {observed}'), flush=True)

    def expect_error(label, fn, fragment):
        try:
            result = fn()
        except RPCError as error:
            # A rejected transaction did not spend its coin: make it reusable.
            used.difference_update(pending_coins)
            pending_coins.clear()
            check(label, fragment in str(error), str(error))
            return
        check(label, False, f'accepted: {result}')

    def wait(predicate, what, tries=900):
        for _ in range(tries):
            if predicate():
                return
            time.sleep(0.1)
        raise RuntimeError('timeout: ' + what)

    try:
        a = TestnetNode(args.bindir, directory / 'a')                     # legacy wallet, main actor
        b = TestnetNode(args.bindir, directory / 'b', ['-addresstype=pq'])    # PQ wallet, rival chain
        c = TestnetNode(args.bindir, directory / 'c', ['-addresstype=ecdsa'])  # strict ECDSA wallet
        nodes += [a, b, c]
        for node in nodes:
            node.ready()

        info = a.rpc('getblockchaininfo')
        check('network is testnet', info['chain'] == 'test', info['chain'])
        check('chain starts at the reset-testnet genesis', a.rpc('getblockhash', 0) == GENESIS, a.rpc('getblockhash', 0))


        def tip():
            return a.rpc('getblockcount')

        def mine(n, node=None):
            return (node or a).rpc('generatetoaddress', n, miner)

        def spk(address):
            return bytes.fromhex(a.rpc('validateaddress', address)['scriptPubKey'])

        def take_coin():
            # Unconfirmed change is included: before H only the coinbase of
            # block 1 is mature for the wallet, and every probe needs a coin.
            for u in a.rpc('listunspent', 0):
                key = (u['txid'], u['vout'])
                if key not in used and u['amount'] > 2 and not u.get('asset_name') and 'assetName' not in u:
                    used.add(key)
                    pending_coins.append(key)
                    return u
            raise RuntimeError('no spendable coin left')

        def send_raw(raw_hex):
            txid = a.rpc('sendrawtransaction', raw_hex)
            pending_coins.clear()
            return txid

        def fund_p2sh(redeem):
            p2sh = a.rpc('decodescript', redeem.hex())['p2sh']
            txid = a.rpc('sendtoaddress', p2sh, 1)
            tx = a.rpc('getrawtransaction', txid, True)
            vout = next(o['n'] for o in tx['vout'] if o['scriptPubKey'].get('addresses') == [p2sh])
            used.add((txid, vout))
            return txid, vout

        def cat_spend(coin):
            return raw_tx([(coin[0], coin[1], CAT_SCRIPTSIG)], [(99_000_000, spk(miner))]).hex()

        def v3_payment():
            coin = take_coin()
            unsigned = raw_tx([(coin['txid'], coin['vout'], b'')],
                              [(sats(coin['amount']) - 1_000_000, spk(miner))], version=3)
            signed = a.rpc('signrawtransaction', unsigned.hex())
            if not signed.get('complete'):
                raise RuntimeError(f'v3 signing incomplete: {signed}')
            return signed['hex']

        def v1_output_payment():
            coin = take_coin()
            unsigned = raw_tx([(coin['txid'], coin['vout'], b'')],
                              [(100_000_000, V1_SCRIPT), (sats(coin['amount']) - 101_000_000, spk(miner))])
            signed = a.rpc('signrawtransaction', unsigned.hex())
            if not signed.get('complete'):
                raise RuntimeError(f'v1 output signing incomplete: {signed}')
            return signed['hex']

        def asset_output(txid, marker):
            tx = a.rpc('getrawtransaction', txid, True)
            for out in tx['vout']:
                script = out['scriptPubKey']['hex']
                if marker in script and ASSET.encode().hex() in script:
                    return out['n'], script, sats(out['value'])
            raise RuntimeError(f'no {marker} output of {ASSET} in {txid}')

        def asset_respend(txid, marker_from, marker_to):
            """Spend the asset output of `txid`, re-emitting it with the other marker."""
            n, script, value = asset_output(txid, marker_from)
            coin = take_coin()
            unsigned = raw_tx([(txid, n, b''), (coin['txid'], coin['vout'], b'')],
                              [(value, bytes.fromhex(script.replace(marker_from, marker_to))),
                               (sats(coin['amount']) - 1_000_000, spk(miner))])
            signed = a.rpc('signrawtransaction', unsigned.hex())
            if not signed.get('complete'):
                raise RuntimeError(f'asset signing incomplete: {signed}')
            return signed['hex']

        # ---- blocks 1..H-1: rules that predate the new NIPs --------------------
        miner = a.rpc('getnewaddress')
        check('legacy wallet hands out a legacy address', not miner.startswith('tnc1'), miner)
        mine(MATURITY + 1)                               # tip 6: coinbase of block 1 is mature
        check('tip before probes', tip() == MATURITY + 1, tip())

        # Addresses are handed out before H; paying to them is what is refused.
        b_early = b.rpc('getnewaddress')
        check('PQ wallet hands out its default (strict v2) address before H', b_early.startswith('tpq1z'), b_early)
        expect_error('wallet never hands out generic AuthScript v1 (contract) addresses',
                     lambda: b.rpc('getnewaddress', '', 'authscript'), 'Unknown address type')
        types = [n.rpc('getwalletinfo')['addresstype'] for n in (a, b, c)]
        check('wallets report the -addresstype they were created with', types == ['legacy', 'pq', 'ecdsa'], types)
        c_early = c.rpc('getnewaddress')
        check('ecdsa wallet hands out its default (strict v3) address before H', c_early.startswith('tnq1r'), c_early)
        expect_error('ecdsa wallet never hands out Legacy (no fallback before H)',
                     lambda: c.rpc('getnewaddress', '', 'legacy'), 'strict ECDSA wallet')
        expect_error('payment to a strict address handed out before H is refused before H',
                     lambda: a.rpc('sendtoaddress', c_early, 1), 'Invalid')
        expect_error('ecdsa wallet does not mine to strict v3 before H',
                     lambda: c.rpc('generate', 1), 'not active yet')

        legacy_txid = a.rpc('sendtoaddress', a.rpc('getnewaddress'), 1)
        check('legacy payment accepted before H', legacy_txid in a.rpc('getrawmempool'), legacy_txid)
        expect_error('tx v3 rejected before H', lambda: send_raw(v3_payment()), 'version-v3-not-active')
        expect_error('output to an AuthScript v1 program refused before H (policy)',
                     lambda: send_raw(v1_output_payment()), 'authscript-output-not-active')
        expect_error('generatetoaddress to an AuthScript address refused before H',
                     lambda: a.rpc('generatetoaddress', 1, V1_ADDRESS), 'not active yet')
        cat_coin = fund_p2sh(CAT_REDEEM)
        issue_txid = a.rpc('issue', ASSET, 1000, miner)[0]
        mine(1)                                          # tip 7
        expect_error('OP_CAT spend rejected before H', lambda: send_raw(cat_spend(cat_coin)), 'disabled')

        issue_hex = a.rpc('getrawtransaction', issue_txid)
        check('asset issued before H carries the rvn marker',
              MARKER_RVN in issue_hex and MARKER_XNA not in issue_hex, issue_hex[-160:])
        pre = a.rpc('transfer', ASSET, 10, a.rpc('getnewaddress'))[0]
        check('transfer before H produces an rvn output', MARKER_RVN in a.rpc('getrawtransaction', pre))
        mine(1)                                          # tip 8 (next block 9)
        expect_error('xna-marker output rejected before H',
                     lambda: send_raw(asset_respend(pre, MARKER_RVN, MARKER_XNA)),
                     'bad-txns-asset-marker-before-nip040')
        mine(1)                                          # tip 9 (next block 10 = H)
        check('tip is H-1', tip() == H - 1, tip())

        # ---- next block is H: every new rule applies --------------------------
        post = a.rpc('transfer', ASSET, 5, a.rpc('getnewaddress'))[0]
        post_hex = a.rpc('getrawtransaction', post)
        check('rvn UTXO spent for block H produces xna outputs only',
              MARKER_XNA in post_hex and MARKER_RVN not in post_hex, post_hex[-160:])
        v3_txid = send_raw(v3_payment())
        check('tx v3 accepted for block H', v3_txid in a.rpc('getrawmempool'), v3_txid)
        v1_txid = send_raw(v1_output_payment())
        check('output to an AuthScript v1 program accepted for block H', v1_txid in a.rpc('getrawmempool'), v1_txid)
        cat_txid = send_raw(cat_spend(cat_coin))
        check('OP_CAT spend accepted for block H', cat_txid in a.rpc('getrawmempool'), cat_txid)
        mine(1)                                          # block 10 = H
        block_h = a.rpc('getblock', a.rpc('getbestblockhash'))
        check('block H contains the v3, OP_CAT and xna transactions',
              {v3_txid, cat_txid, post} <= set(block_h['tx']), block_h['tx'])
        expect_error('rvn-marker output rejected from H',
                     lambda: send_raw(asset_respend(post, MARKER_XNA, MARKER_RVN)),
                     'bad-txns-legacy-asset-marker-after-nip040')
        mine(1)                                          # block 11
        check('tip is H+1', tip() == H + 1, tip())

        # ---- reorg back to H-2: new-rule transactions must leave the mempool --
        cat_coin2 = fund_p2sh(CAT_REDEEM)
        mine(1)                                          # block 12
        pending = {send_raw(v3_payment()), send_raw(cat_spend(cat_coin2)),
                   a.rpc('transfer', ASSET, 1, a.rpc('getnewaddress'))[0]}
        check('new-rule transactions pending before the reorg', pending <= set(a.rpc('getrawmempool')),
              sorted(pending))
        block9 = a.rpc('getblockhash', H - 1)
        a.rpc('invalidateblock', block9)
        check('reorg back to H-2', tip() == H - 2, tip())
        leftover = []
        for txid in a.rpc('getrawmempool'):
            raw = a.rpc('getrawtransaction', txid)
            if (raw.startswith('03000000') or MARKER_XNA in raw or CAT_SCRIPTSIG.hex() in raw
                    or V1_SCRIPT.hex() in raw):
                leftover.append(txid)
        check('no new-rule transaction survives in the mempool at H-2', not leftover, leftover)
        check('the reverted block-H transactions are not in the mempool',
              not ({v3_txid, cat_txid, post, v1_txid} & set(a.rpc('getrawmempool'))), a.rpc('getrawmempool'))
        try:
            # Pay the coinbase to a fresh address: an otherwise identical header
            # would reproduce the invalidated block H-1 and be refused as such.
            a.rpc('generatetoaddress', 1, a.rpc('getnewaddress'))
            check('mining still works for block H-1 after the reorg', tip() == H - 1, tip())
        except RPCError as error:
            check('mining still works for block H-1 after the reorg', False, str(error))
        a.rpc('reconsiderblock', block9)
        wait(lambda: tip() >= H + 2, 'original chain restored')
        check('original chain restored after reconsiderblock', tip() >= H + 2, tip())
        check('assets still active across the reorg', ASSET in a.rpc('listassets'), a.rpc('listassets'))

        # ---- reorg down to genesis: rival chain mined by b ---------------------
        b.rpc('generatetoaddress', tip() + 5, miner)
        a.rpc('addnode', f'127.0.0.1:{b.p2p_port}', 'onetry')
        wait(lambda: a.rpc('getbestblockhash') == b.rpc('getbestblockhash'), 'reorg to the rival chain')
        check('reorg to a rival chain forked at genesis', a.rpc('getblockhash', 1) == b.rpc('getblockhash', 1),
              [a.rpc('getblockhash', 1), b.rpc('getblockhash', 1)])
        version1 = b.rpc('getblock', b.rpc('getblockhash', 1))['versionHex']
        check('rival block 1 already carries the asset version bits', int(version1, 16) >= 0x30000000, version1)
        b_address = b.rpc('getnewaddress')
        check('PQ wallet hands out a strict PQ (v2) address once H is reached', b_address.startswith('tpq1'), b_address)
        check('wallet does not own a generic v1 contract address', not b.rpc('validateaddress', V1_ADDRESS)['ismine'],
              b.rpc('validateaddress', V1_ADDRESS))
        check('legacy wallet keeps handing out Legacy after H', not a.rpc('getnewaddress').startswith('tnq1'), 'legacy')

        # ---- -addresstype=ecdsa above H, and the fixed wallet type -----------
        c.rpc('addnode', f'127.0.0.1:{a.p2p_port}', 'onetry')
        wait(lambda: c.rpc('getbestblockhash') == a.rpc('getbestblockhash'), 'ecdsa node sync')
        c_address = c.rpc('getnewaddress')
        check('ecdsa wallet hands out a strict ECDSA (v3) address once H is reached', c_address.startswith('tnq1r'), c_address)
        check('ecdsa wallet owns its v3 address', c.rpc('validateaddress', c_address)['ismine'], c_address)
        c_change = c.rpc('getrawchangeaddress')
        check('ecdsa wallet change is strict v3', c_change.startswith('tnq1r'), c_change)
        expect_error('ecdsa wallet refuses Legacy after H', lambda: c.rpc('getnewaddress', '', 'legacy'), 'strict ECDSA wallet')
        expect_error('ecdsa wallet has no PQ addresses', lambda: c.rpc('getnewaddress', '', 'pq'), '-addresstype=pq')
        # Mining and spending from the ecdsa wallet: coinbase and change are v3.
        c_mined = c.rpc('generate', 1)[0]
        coinbase = c.rpc('getrawtransaction', c.rpc('getblock', c_mined)['tx'][0], True)
        check('ecdsa wallet mines to a strict v3 output',
              coinbase['vout'][0]['scriptPubKey']['hex'].startswith('5320'), coinbase['vout'][0]['scriptPubKey'])
        a.rpc('sendtoaddress', c_address, 5)
        a.rpc('sendtoaddress', c_early, 1)
        wait(lambda: len(c.rpc('getrawmempool')) > 1, 'payments to the ecdsa wallet')
        c.rpc('generatetoaddress', 1, c.rpc('getnewaddress'))
        check('address handed out before H receives once H is reached',
              c.rpc('getreceivedbyaddress', c_early) == 1, c.rpc('getreceivedbyaddress', c_early))
        spend = c.rpc('sendtoaddress', miner, 1)
        spend_tx = c.rpc('getrawtransaction', spend, True)
        change_spks = [o['scriptPubKey']['hex'] for o in spend_tx['vout'] if o['scriptPubKey'].get('addresses') != [miner]]
        check('ecdsa wallet spend sends its change to strict v3',
              bool(change_spks) and all(x.startswith('5320') for x in change_spks), change_spks)
        c.stop()
        nodes.remove(c)
        code, output = init_error(args.bindir, directory / 'c', ['-addresstype=legacy'])
        check('existing ecdsa wallet refuses to open with -addresstype=legacy',
              code != 0 and 'was created with -addresstype=ecdsa' in output, output[-400:])
        c = TestnetNode(args.bindir, directory / 'c')
        nodes.append(c)
        c.ready()
        check('without -addresstype the wallet keeps its stored type',
              c.rpc('getwalletinfo')['addresstype'] == 'ecdsa' and c.rpc('getnewaddress').startswith('tnq1r'),
              c.rpc('getwalletinfo')['addresstype'])
        code, output = init_error(args.bindir, directory / 'fresh-pqwallet', ['-pqwallet=1'])
        check('-pqwallet is refused (replaced by -addresstype=pq)',
              code != 0 and '-addresstype=pq' in output, output[-400:])
        code, output = init_error(args.bindir, directory / 'fresh-unknown', ['-addresstype=authscript'])
        check('unknown -addresstype is refused', code != 0 and 'Unknown -addresstype' in output, output[-400:])
        code, output = init_error(args.bindir, directory / 'fresh-nobip44', ['-addresstype=ecdsa', '-bip44=0'])
        check('-addresstype=ecdsa requires -bip44=1', code != 0 and 'requires -bip44=1' in output, output[-400:])

        # ---- P2P separation from the previous testnet ---------------------------
        if args.old_bindir:
            old = TestnetNode(args.old_bindir, directory / 'old')
            nodes.append(old)
            old.ready()
            a.rpc('addnode', f'127.0.0.1:{old.p2p_port}', 'onetry')
            time.sleep(5)
            peers = [p['addr'] for p in a.rpc('getpeerinfo')]
            check('new node keeps no peer from the previous testnet', f'127.0.0.1:{old.p2p_port}' not in peers, peers)
            check('previous-testnet node has no peers', old.rpc('getpeerinfo') == [], old.rpc('getpeerinfo'))
            check('previous-testnet node logged the foreign message start',
                  'MESSAGESTART' in old.debug_log().upper(), 'see old/*/debug.log')
    finally:
        for node in nodes:
            node.stop()
        (directory / 'report.json').write_text(json.dumps(report, indent=2))
        failed = [r['case'] for r in report['results'] if not r['passed']]
        print(f"\n{len(report['results']) - len(failed)}/{len(report['results'])} passed; report: {directory}/report.json")
        if failed:
            raise SystemExit(1)


if __name__ == '__main__':
    main()
