#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Scan a chain for an opcode byte in every script the consensus code parses.

Used before activating a previously unassigned opcode retroactively (NIP-060
OP_CHECKSIG_P256 at testnet block 10): once the opcode is assigned, every
occurrence outside a push starts counting sigops, so a historical block could
change validity. The scan follows the same paths as the consensus sigop
counters (GetLegacySigOpCount, GetP2SHSigOpCount, CountWitnessSigOps and the
bare-output charge at spend time) and is deliberately over-inclusive: a script
that might be counted is scanned. Each script is walked like
CScript::GetSigOpCount, stopping at the first malformed push.

Blocks are read with `getblock <hash> 3`, which carries the spent output of
every input (needs undo data, so the node must not be pruned).

The scan is incremental: the state file keeps height, hash and hits per block.
On a new run the stored hashes are checked against the active chain and the
scan resumes from the last common block.

Usage:
  scan_opcode.py --datadir /root/tn [--opcode 0xe0] [--state scan.json] [--start N]
  scan_opcode.py --self-test

Exit status: 0 when the range was scanned with no hits, 1 when there are hits,
2 when the range is empty (--start above the tip): nothing was examined.
"""

import argparse
import base64
import http.client
import json
import os
import sys

OP_0 = 0x00
OP_PUSHDATA1 = 0x4c
OP_PUSHDATA2 = 0x4d
OP_PUSHDATA4 = 0x4e
OP_1 = 0x51
OP_16 = 0x60
OP_HASH160 = 0xa9
OP_EQUAL = 0x87
OP_XNA_ASSET = 0xc0


def iter_ops(script):
    """Yield (opcode, data) like CScript::GetOp; data is None for non-pushes.

    Stops silently at the first malformed push, as GetSigOpCount does.
    """
    i = 0
    n = len(script)
    while i < n:
        op = script[i]
        i += 1
        if op <= OP_PUSHDATA4:
            if op < OP_PUSHDATA1:
                size = op
            elif op == OP_PUSHDATA1:
                if i + 1 > n:
                    return
                size = script[i]
                i += 1
            elif op == OP_PUSHDATA2:
                if i + 2 > n:
                    return
                size = int.from_bytes(script[i:i + 2], 'little')
                i += 2
            else:
                if i + 4 > n:
                    return
                size = int.from_bytes(script[i:i + 4], 'little')
                i += 4
            if i + size > n:
                return
            yield op, script[i:i + size]
            i += size
        else:
            yield op, None


def count_opcode(script, opcode):
    return sum(1 for op, data in iter_ops(script) if data is None and op == opcode)


def is_push_only(script):
    return all(data is not None or op <= OP_16 for op, data in iter_ops(script))


def last_push(script):
    data = b''
    for op, d in iter_ops(script):
        if d is not None:
            data = d
        elif OP_1 <= op <= OP_16 or op == 0x4f:
            data = b''
    return data


def witness_program(script):
    """(version, program) of a plain witness program, or None."""
    if len(script) < 4 or len(script) > 42:
        return None
    if script[0] != OP_0 and not (OP_1 <= script[0] <= OP_16):
        return None
    if script[1] + 2 != len(script):
        return None
    version = 0 if script[0] == OP_0 else script[0] - OP_1 + 1
    return version, script[2:]


def asset_witness_program(script):
    """(version, program) of `OP_n <32 bytes> OP_XNA_ASSET ...`, or None.

    Over-inclusive version of GetAssetScriptWitnessProgram: any 32-byte
    witness program followed by OP_XNA_ASSET.
    """
    if len(script) > 35 and OP_1 <= script[0] <= OP_16 and script[1] == 0x20 and script[34] == OP_XNA_ASSET:
        return script[0] - OP_1 + 1, script[2:34]
    return None


def is_p2sh(script):
    """P2SH prefix, with or without an asset suffix (over-inclusive)."""
    return len(script) >= 23 and script[0] == OP_HASH160 and script[1] == 0x14 and script[22] == OP_EQUAL


def witness_scripts(version, program, witness):
    """Scripts that WitnessSigOps parses for this program and witness."""
    if version == 0 and len(program) == 32 and witness:
        return [('witness_script', witness[-1])]
    if version == 1 and len(program) == 32 and witness:
        first = witness[0]
        if len(first) == 1 and 0x10 <= first[0] <= 0x12:
            if len(witness) >= 2:
                return [('authscript_leaf', witness[-2])]
            return []
        if len(witness) > 1:
            return [('authscript_witness_script', witness[-1])]
    # Strict v2/v3 and unknown versions carry no evaluated script.
    return []


def scan_tx(tx, opcode):
    """Return a list of hits: dicts with the path and the count."""
    hits = []

    def check(path, script):
        c = count_opcode(script, opcode)
        if c:
            hits.append({'txid': tx.get('txid'), 'path': path, 'count': c, 'script': script.hex()})

    for out in tx.get('vout', []):
        check('vout[%d].scriptPubKey' % out.get('n', -1), bytes.fromhex(out['scriptPubKey']['hex']))

    for i, txin in enumerate(tx.get('vin', [])):
        if 'coinbase' in txin:
            check('vin[%d].coinbase' % i, bytes.fromhex(txin['coinbase']))
            continue
        script_sig = bytes.fromhex(txin.get('scriptSig', {}).get('hex', ''))
        check('vin[%d].scriptSig' % i, script_sig)
        witness = [bytes.fromhex(w) for w in txin.get('txinwitness', [])]
        prevout = txin.get('prevout')
        if prevout is None:
            hits.append({'txid': tx.get('txid'), 'path': 'vin[%d]' % i, 'count': 0,
                         'error': 'missing prevout (getblock verbosity 3 needed)'})
            continue
        spk = bytes.fromhex(prevout['scriptPubKey']['hex'])
        check('vin[%d].prevout.scriptPubKey' % i, spk)

        redeem = None
        if is_p2sh(spk) and is_push_only(script_sig):
            redeem = last_push(script_sig)
            check('vin[%d].redeemScript' % i, redeem)

        program = witness_program(spk) or asset_witness_program(spk)
        route = 'witness'
        if program is None and redeem is not None:
            program = witness_program(redeem)
            route = 'p2sh_witness'
        if program is not None:
            for name, script in witness_scripts(program[0], program[1], witness):
                check('vin[%d].%s.%s' % (i, route, name), script)
    return hits


# --- RPC -------------------------------------------------------------------

class Rpc:
    def __init__(self, datadir, network, port):
        cookie = os.path.join(datadir, network, '.cookie') if network else os.path.join(datadir, '.cookie')
        if os.path.exists(cookie):
            with open(cookie) as f:
                userpass = f.read().strip()
        else:
            # Fall back to rpcuser/rpcpassword in neurai.conf.
            conf = {}
            with open(os.path.join(datadir, 'neurai.conf')) as f:
                for line in f:
                    if '=' in line and not line.lstrip().startswith('#'):
                        key, value = line.strip().split('=', 1)
                        conf[key.strip()] = value.strip()
            userpass = '%s:%s' % (conf.get('rpcuser', ''), conf.get('rpcpassword', ''))
        self.auth = base64.b64encode(userpass.encode()).decode()
        self.port = port
        self.conn = http.client.HTTPConnection('127.0.0.1', port, timeout=600)

    def call(self, method, *params):
        body = json.dumps({'jsonrpc': '1.0', 'id': 1, 'method': method, 'params': list(params)})
        self.conn.request('POST', '/', body, {'Authorization': 'Basic ' + self.auth,
                                              'Content-Type': 'application/json'})
        resp = json.loads(self.conn.getresponse().read())
        if resp.get('error'):
            raise RuntimeError('%s: %s' % (method, resp['error']))
        return resp['result']


def _resume_height(hash_at, blocks, start, tip):
    """Height to resume from: one past the highest stored block that is in the
    active chain and linked, through `prev`, to every stored block below it.

    Hash linkage plus an active top imply the whole stored chain is active, so
    a state that mixes two branches (a reorganization during an earlier run)
    is detected even when its last hash is still valid. Anything above the
    resume point is dropped.
    """
    heights = sorted(int(k) for k in blocks)
    # Longest linked prefix starting at `start`.
    linked = start - 1
    for h in heights:
        if h != linked + 1:
            break
        entry = blocks[str(h)]
        if h > start and entry.get('prev') != blocks[str(h - 1)]['hash']:
            break
        linked = h
    # Highest linked block still in the active chain. The chain may have become
    # shorter than the stored state: never ask for a height above the tip.
    height = start
    for h in range(min(linked, tip), start - 1, -1):
        if hash_at(h) == blocks[str(h)]['hash']:
            height = h + 1
            break
    for h in [int(k) for k in blocks if int(k) >= height]:
        del blocks[str(h)]
    return height


def scan_chain(rpc, opcode, state_path, start):
    state = {'opcode': opcode, 'start': start, 'blocks': {}}
    if state_path and os.path.exists(state_path):
        with open(state_path) as f:
            stored = json.load(f)
        if stored.get('opcode') != opcode:
            raise SystemExit('state file was made for another opcode')
        # A state made from another start height is not reused: its blocks
        # below the new start would be reported, maybe from another branch.
        # State files without the field were made from height 0.
        if stored.get('start', 0) == start:
            state = dict(stored, start=start)
        else:
            print('state file was made from height %d, not %d: starting again'
                  % (stored.get('start', 0), start), file=sys.stderr)
    blocks = state['blocks']

    def hash_at(h):
        """Hash of the active block at height h, or None when the chain has
        become shorter than h (it can shrink at any moment during the scan)."""
        try:
            return rpc.call('getblockhash', h)
        except RuntimeError:
            if h <= rpc.call('getblockcount'):
                raise
            return None

    def save():
        if state_path:
            with open(state_path, 'w') as f:
                json.dump(state, f)

    while True:
        tip = rpc.call('getblockcount')
        height = _resume_height(hash_at, blocks, start, tip)
        reorg = False
        for h in range(height, tip + 1):
            bhash = hash_at(h)
            if bhash is None:
                print('the chain became shorter than height %d, resuming' % h, file=sys.stderr)
                reorg = True
                break
            block = rpc.call('getblock', bhash, 3)
            prev = block.get('previousblockhash')
            # The chain moved to another branch during the scan: resume from
            # the common ancestor instead of storing blocks of two branches.
            if h > start and (block['hash'] != bhash or prev != blocks.get(str(h - 1), {}).get('hash')):
                print('reorganization at height %d, resuming' % h, file=sys.stderr)
                reorg = True
                break
            hits = []
            for tx in block['tx']:
                hits.extend(scan_tx(tx, opcode))
            blocks[str(h)] = {'hash': bhash, 'prev': prev, 'hits': hits}
            if h % 1000 == 0 or h == tip:
                print('height %d/%d' % (h, tip), file=sys.stderr)
                save()
        # A reorganization above the last block read is caught here.
        if not reorg and (not blocks or hash_at(tip) == blocks[str(tip)]['hash']):
            break
    save()
    all_hits = [dict(hit, height=int(k)) for k, v in blocks.items() for hit in v['hits']]
    # The tip hash returned is the one validated with the hits, never asked
    # for again: the chain may have moved since.
    tip_hash = blocks[str(tip)]['hash'] if blocks else None
    return tip, tip_hash, sorted(all_hits, key=lambda x: x['height'])


# --- Self-test -------------------------------------------------------------

def self_test(opcode):
    """Fixtures for every path; each must be found, and the controls not."""
    op = bytes([opcode])
    key33 = bytes(33)
    prog32 = bytes(range(32))
    p2sh_spk = bytes([OP_HASH160, 0x14]) + bytes(20) + bytes([OP_EQUAL])
    if_branch = bytes([0x00, 0x63]) + op + bytes([0x68, 0x51])  # 0 IF <op> ENDIF 1
    asset_suffix = bytes([OP_XNA_ASSET, 0x05]) + b'rvnt\x00' + bytes([0x75])

    def tx(vin, vout=()):
        return {'txid': 'fixture', 'vin': list(vin),
                'vout': [{'n': n, 'scriptPubKey': {'hex': s.hex()}} for n, s in enumerate(vout)]}

    def spend(spk, script_sig=b'', witness=()):
        return {'scriptSig': {'hex': script_sig.hex()}, 'txinwitness': [w.hex() for w in witness],
                'prevout': {'scriptPubKey': {'hex': spk.hex()}}}

    def push(data):
        return (bytes([len(data)]) if len(data) < OP_PUSHDATA1 else bytes([OP_PUSHDATA1, len(data)])) + data

    p2wsh_redeem = bytes([OP_0, 0x20]) + prog32
    cases = [
        ('coinbase scriptSig', tx([{'coinbase': (b'\x03\x01\x02\x03' + op).hex()}]), 'vin[0].coinbase'),
        ('coinbase output', tx([{'coinbase': '0101'}], [op]), 'vout[0].scriptPubKey'),
        ('bare output', tx([], [bytes([0x51]) + op]), 'vout[0].scriptPubKey'),
        ('OP_RETURN raw bytes', tx([], [bytes([0x6a]) + op]), 'vout[0].scriptPubKey'),
        ('bare output spent', tx([spend(bytes([0x51]) + op)]), 'vin[0].prevout.scriptPubKey'),
        ('P2SH redeemScript', tx([spend(p2sh_spk, push(if_branch))]), 'vin[0].redeemScript'),
        ('P2WSH', tx([spend(bytes([OP_0, 0x20]) + prog32, b'', [key33, if_branch])]),
         'vin[0].witness.witness_script'),
        ('P2SH-P2WSH', tx([spend(p2sh_spk, push(p2wsh_redeem), [key33, if_branch])]),
         'vin[0].p2sh_witness.witness_script'),
        ('AuthScript v1', tx([spend(bytes([0x51, 0x20]) + prog32, b'', [b'\x00', if_branch])]),
         'vin[0].witness.authscript_witness_script'),
        ('AuthScript v1 with asset suffix',
         tx([spend(bytes([0x51, 0x20]) + prog32 + asset_suffix, b'', [b'\x00', if_branch])]),
         'vin[0].witness.authscript_witness_script'),
        ('NIP-044 leaf', tx([spend(bytes([0x51, 0x20]) + prog32, b'', [b'\x10', if_branch, b'\x01' * 33])]),
         'vin[0].witness.authscript_leaf'),
    ]
    controls = [
        ('opcode inside a push', tx([], [push(op * 3)])),
        ('opcode in a signature and key in the witness',
         tx([spend(bytes([OP_0, 0x14]) + bytes(20), b'', [op * 71, op * 33])])),
        ('opcode in a strict v3 witness', tx([spend(bytes([0x53, 0x20]) + prog32, b'', [b'\x02', op * 64, op * 33, b'\x51'])])),
        ('opcode after a malformed push', tx([], [bytes([0x4d, 0xff]) + op])),
        ('opcode after a truncated push', tx([], [bytes([0x05, 0x01]) + op])),
        ('NIP-044 tree: opcode in the control block, not the leaf',
         tx([spend(bytes([0x51, 0x20]) + prog32, b'', [b'\x10', bytes([0x51]), op * 33])])),
    ]
    failures = 0
    for name, t, path in cases:
        hits = scan_tx(t, opcode)
        ok = any(h['path'] == path and h['count'] >= 1 for h in hits)
        print('%-4s found    %-40s %s' % ('ok' if ok else 'FAIL', name, [h['path'] for h in hits]))
        failures += not ok
    for name, t in controls:
        hits = [h for h in scan_tx(t, opcode) if h['count']]
        ok = not hits
        print('%-4s ignored  %-40s %s' % ('ok' if ok else 'FAIL', name, [h['path'] for h in hits]))
        failures += not ok
    failures += not reorg_self_test(opcode)
    print('self-test: %s' % ('PASS' if failures == 0 else '%d FAILURES' % failures))
    return failures == 0


class FakeChain:
    """getblockhash / getblock / getblockcount over branches that can switch
    after a number of calls, to test reorganizations during a scan."""

    def __init__(self, opcode):
        self.op = opcode
        self.calls = 0
        self.switch_after = None
        self.branch = 'a'
        self.tips = {'a': 9, 'b': 9}

    def block_hash(self, h, branch):
        # Branches share blocks 0..4 and differ from height 5.
        return ('a' if h < 5 else branch) + '%04d' % h

    def call(self, method, *params):
        self.calls += 1
        if self.switch_after is not None and self.calls > self.switch_after:
            self.branch = 'b'
        if method == 'getblockcount':
            return self.tips[self.branch]
        if method == 'getblockhash':
            if params[0] > self.tips[self.branch]:
                raise RuntimeError('Block height out of range')
            return self.block_hash(params[0], self.branch)
        if method == 'getblock':
            bhash = params[0]
            h = int(bhash[1:])
            branch = bhash[0] if h >= 5 else self.branch
            # Branch a carries the opcode at height 6; branch b at height 7.
            spk = bytes([0x51, self.op]) if (branch, h) in (('a', 6), ('b', 7)) else bytes([0x51])
            tx = {'txid': bhash, 'vin': [{'coinbase': '00'}],
                  'vout': [{'n': 0, 'scriptPubKey': {'hex': spk.hex()}}]}
            block = {'hash': bhash, 'tx': [tx]}
            if h > 0:
                block['previousblockhash'] = self.block_hash(h - 1, branch)
            return block
        raise ValueError(method)


def reorg_self_test(opcode):
    """A reorganization during the scan must not leave blocks of two branches."""
    import tempfile
    ok = True
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, 'state.json')
        chain = FakeChain(opcode)
        chain.switch_after = 16  # switches while reading heights 5..9 of branch a
        _, tip_hash, hits = scan_chain(chain, opcode, path, 0)
        stored = json.load(open(path))['blocks']
        active = all(v['hash'] == chain.block_hash(int(k), 'b') for k, v in stored.items())
        heights = sorted(h['height'] for h in hits)
        good = active and heights == [7] and tip_hash == chain.block_hash(9, 'b')
        print('%-4s reorg      %-40s hits at %s' % ('ok' if good else 'FAIL', 'during the scan', heights))
        ok &= good
        # A state file that already mixes two branches is repaired on resume.
        mixed = {'opcode': opcode, 'blocks': {}}
        for h in range(10):
            branch = 'a' if h < 8 else 'b'
            mixed['blocks'][str(h)] = {'hash': chain.block_hash(h, branch),
                                       'prev': chain.block_hash(h - 1, branch) if h else None,
                                       'hits': [{'txid': 'x', 'path': 'p', 'count': 1}] if (branch, h) == ('a', 6) else []}
        json.dump(mixed, open(path, 'w'))
        chain = FakeChain(opcode)
        chain.branch = 'b'
        _, tip_hash, hits = scan_chain(chain, opcode, path, 0)
        heights = sorted(h['height'] for h in hits)
        good = heights == [7] and tip_hash == chain.block_hash(9, 'b')
        print('%-4s reorg      %-40s hits at %s' % ('ok' if good else 'FAIL', 'mixed state file on resume', heights))
        ok &= good
        # The chain becomes shorter than the stored state (branch b ends at 6).
        chain = FakeChain(opcode)
        chain.branch = 'b'
        chain.tips['b'] = 6
        try:
            tip, tip_hash, hits = scan_chain(chain, opcode, path, 0)
            stored = json.load(open(path))['blocks']
            good = tip == 6 and max(int(k) for k in stored) == 6 and tip_hash == chain.block_hash(6, 'b') and not hits
        except RuntimeError as error:
            good, hits = False, str(error)
        print('%-4s reorg      %-40s %s' % ('ok' if good else 'FAIL', 'shorter chain on resume', hits))
        ok &= good
        # The chain becomes shorter during the scan, after getblockcount:
        # branch b (tip 6) replaces branch a while heights 7..9 are read.
        os.remove(path)
        chain = FakeChain(opcode)
        chain.switch_after = 16
        chain.tips['b'] = 6
        try:
            tip, tip_hash, hits = scan_chain(chain, opcode, path, 0)
            stored = json.load(open(path))['blocks']
            good = (tip == 6 and tip_hash == chain.block_hash(6, 'b') and not hits and
                    sorted(int(k) for k in stored) == list(range(7)) and
                    all(v['hash'] == chain.block_hash(int(k), 'b') for k, v in stored.items()))
        except RuntimeError as error:
            good, hits = False, str(error)
        print('%-4s reorg      %-40s %s' % ('ok' if good else 'FAIL', 'shorter chain during the scan', hits))
        ok &= good
        # A state file made from another start height is not reused. Branch a
        # is stored from 0 (opcode at 6); branch b is then scanned from 8.
        os.remove(path)
        scan_chain(FakeChain(opcode), opcode, path, 0)
        chain = FakeChain(opcode)
        chain.branch = 'b'
        _, _, hits = scan_chain(chain, opcode, path, 8)
        state = json.load(open(path))
        good = (not hits and state['start'] == 8 and sorted(int(k) for k in state['blocks']) == [8, 9])
        print('%-4s reorg      %-40s %s' % ('ok' if good else 'FAIL', 'state of another start height',
                                            [h['height'] for h in hits]))
        ok &= good
    return ok


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--opcode', default='0xe0')
    parser.add_argument('--datadir')
    parser.add_argument('--network', default='testnet', help='subdirectory with the .cookie ("" for mainnet)')
    parser.add_argument('--rpcport', type=int, default=19101)
    parser.add_argument('--state', help='JSON state file for incremental runs')
    parser.add_argument('--start', type=int, default=0)
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    opcode = int(args.opcode, 0)
    if args.self_test:
        sys.exit(0 if self_test(opcode) else 1)
    if not args.datadir:
        parser.error('--datadir is required')
    rpc = Rpc(args.datadir, args.network, args.rpcport)
    tip, tip_hash, hits = scan_chain(rpc, opcode, args.state, args.start)
    if tip < args.start:
        # Not the same as a range scanned with no hits: no block was examined.
        print(json.dumps({'opcode': hex(opcode), 'start': args.start, 'tip': tip, 'empty_range': True},
                         indent=1))
        print('empty range: --start %d is above the tip %d' % (args.start, tip), file=sys.stderr)
        sys.exit(2)
    print(json.dumps({'opcode': hex(opcode), 'start': args.start, 'tip': tip, 'tip_hash': tip_hash,
                      'hits': hits}, indent=1))
    sys.exit(1 if hits else 0)


if __name__ == '__main__':
    main()
