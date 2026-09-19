#!/usr/bin/env python3
"""Exact transaction-policy and aggregate block-weight boundaries, isolated regtest.

Twenty-five individually standard two-input transactions fill each boundary block.
Padding is witness argument data, not script, and stays below per-input limits.
Signatures are generated once, so ECDSA/PQ signature randomness cannot move a
boundary. Both synchronous and worker validators check the handcrafted blocks.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
from review_auth_envelope import Envelope, options

spec = importlib.util.spec_from_file_location('blocks', Path(__file__).with_name('review-csfs-block-limit-regtest.py'))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
h = b.h


def merkle(leaves):
    while len(leaves) > 1:
        if len(leaves) % 2:
            leaves = leaves + [leaves[-1]]
        leaves = [b.hash256(leaves[i] + leaves[i + 1]) for i in range(0, len(leaves), 2)]
    return leaves[0]


def block(template, txs):
    commitment = b.hash256(merkle([bytes(32)] + [b.hash256(t[1]) for t in txs]) + bytes(32))
    height = template['height']
    height_bytes = height.to_bytes((height.bit_length() + 7) // 8, 'little')
    if height_bytes[-1] & 128:
        height_bytes += b'\x00'
    script = h.push(height_bytes) + b'\x00'
    vin = b'\x01' + bytes(32) + b'\xff' * 4 + h.compact(len(script)) + script + b'\xff' * 4
    outs = b'\x02' + b.output(template['coinbasevalue'], b'\x51') + b.output(0, b'\x6a\x24\xaa\x21\xa9\xed' + commitment)
    stripped = struct.pack('<I', 2) + vin + outs + bytes(4)
    wire = struct.pack('<I', 2) + b'\x00\x01' + vin + outs + b'\x01\x20' + bytes(32) + bytes(4)
    bits = int(template['bits'], 16)
    prefix = struct.pack('<I', template['version']) + bytes.fromhex(template['previousblockhash'])[::-1]
    prefix += merkle([b.hash256(stripped)] + [b.hash256(t[0]) for t in txs]) + struct.pack('<II', template['curtime'], bits)
    target = (bits & 0x007fffff) << (8 * ((bits >> 24) - 3))
    for nonce in range(1_000_000):
        header = prefix + struct.pack('<I', nonce)
        if int.from_bytes(b.hash256(header), 'little') <= target:
            raw = header + h.compact(1 + len(txs)) + wire + b''.join(t[1] for t in txs)
            base = 80 + len(h.compact(1 + len(txs))) + len(stripped) + sum(len(t[0]) for t in txs)
            return raw, b.hash256(header)[::-1].hex(), 3 * base + len(raw)
    raise RuntimeError('PoW search exhausted')


class Spend:
    def __init__(self, env, inputs, script, destination):
        seq = b'\xff' * 4
        prevouts = b''.join(h.outpoint(*p) for p in inputs)
        out = b.output(1_900_000_000, destination)  # two 10-XNA inputs; fee 1 XNA
        redeem = h.push(b'\x51\x20' + env.program(script)) if env.wrapped else b''
        vin = h.compact(2) + b''.join(h.outpoint(*p) + h.compact(len(redeem)) + redeem + seq for p in inputs)
        self.prefix = struct.pack('<I', 2)
        self.body = vin + b'\x01' + out
        self.stripped = self.prefix + self.body + bytes(4)
        self.script = script
        self.stacks = []
        for p in inputs:
            stack = [bytes([env.auth])]
            if env.auth:
                pre = self.prefix + b.hash256(prevouts) + b.hash256(seq * 2) + h.outpoint(*p)
                pre += h.compact(len(script)) + script + struct.pack('<Q', 1_000_000_000) + seq
                pre += b.hash256(out) + bytes(4) + bytes([env.auth]) + struct.pack('<I', 1)
                stack += [env.sign(b.hash256(pre)), env.pub]
            self.stacks.append(stack)

    def serialize(self, extra):
        witnesses = b''
        for stack in self.stacks:
            args = []
            for _ in range(80):
                added = min(extra, 3072 - 253)
                extra -= added
                args.append(b'B' * (253 + added))
            items = stack + args + [self.script]
            witnesses += h.compact(len(items)) + b''.join(h.compact(len(x)) + x for x in items)
        if extra:
            raise ValueError('padding exceeds per-input capacity')
        wire = self.prefix + b'\x00\x01' + self.body + witnesses + bytes(4)
        return self.stripped, wire

    def at_weight(self, target):
        base = self.serialize(0)
        extra = target - (3 * len(base[0]) + len(base[1]))
        if extra < 0:
            raise ValueError('weight too small')
        tx = self.serialize(extra)
        assert 3 * len(tx[0]) + len(tx[1]) == target
        return tx


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    options(parser)
    args = parser.parse_args()
    env = Envelope(args.auth, args.wrapped, args.signer)
    directory = Path(tempfile.mkdtemp(prefix='weight-limits-'))
    files = [Path(__file__), Path(__file__).with_name('review_auth_envelope.py'), Path(b.__file__), Path(h.__file__), Path(__file__).with_name('generate_authscript_vectors.py')]
    report = dict(results=[], auth=args.auth, wrapped=args.wrapped,
                  binary_sha256=h.digest_file(args.bindir / 'neuraid'), signer_sha256=h.digest_file(args.signer),
                  source_sha256={p.name: h.digest_file(p) for p in files})
    nodes = []

    def check(label, passed, observed):
        report['results'].append(dict(case=label, passed=bool(passed), observed=observed))
        print(('PASS ' if passed else 'FAIL ') + label, flush=True)
        if not passed:
            raise RuntimeError(f'{label}: {observed}')

    try:
        source = h.Node(args.bindir, directory / 'source', ['-bypassdownload=1', '-acceptnonstdtxn=0'])
        nodes.append(source)
        source.ready()
        miner = source.rpc('getnewaddress')
        source.rpc('generatetoaddress', 110, miner)
        destination = bytes.fromhex(source.rpc('validateaddress', miner)['scriptPubKey'])
        script = b'\x6d' * 40 + b'\x51'  # consume all 80 padding arguments
        spk = env.output(env.program(script))
        raw = struct.pack('<I', 2) + b'\x00' + h.compact(52) + b.output(1_000_000_000, spk) * 52 + bytes(4)
        signed = source.rpc('signrawtransaction', source.rpc('fundrawtransaction', raw.hex())['hex'])
        check('funding/signed', signed['complete'], signed['complete'])
        funding = source.rpc('sendrawtransaction', signed['hex'])
        source.rpc('generatetoaddress', 1, miner)
        indices = [o['n'] for o in source.rpc('getrawtransaction', funding, True)['vout'] if o['scriptPubKey']['hex'] == spk.hex()]
        check('funding/coins', len(indices) == 52, len(indices))
        spends = [Spend(env, [(funding, n) for n in indices[i:i+2]], script, destination) for i in range(0, 52, 2)]
        # Policy is exclusive at 400000; consensus allows these transactions.
        for target in (399999, 400000, 400001):
            tx = spends[0].at_weight(target)
            decoded = source.rpc('decoderawtransaction', tx[1].hex())
            check(f'tx{target}/node_weight', decoded['vsize'] == (target + 3) // 4 and decoded['size'] == len(tx[1]), decoded['vsize'])
            result = source.rpc('testmempoolaccept', [tx[1].hex()])[0]
            check(f'tx{target}/policy', result.get('allowed') == 1 if target < 400000 else
                  result.get('allowed') == 0 and 'tx-size' in str(result), result)
        template = source.rpc('getblocktemplate', {'rules': ['segwit']})
        txs = [spend.at_weight(320000) for spend in spends[1:]]
        overhead = block(template, txs)[2] - 320000 * 25
        candidates = {}
        limit = template['weightlimit']
        check('block/active_limit', limit == 8_000_000, limit)
        for target in (limit - 1, limit, limit + 1):
            last_weight = target - overhead - 320000 * 24
            current = txs[:-1] + [spends[-1].at_weight(last_weight)]
            check(f'block{target}/individual_policy', all(source.rpc('testmempoolaccept', [t[1].hex()])[0].get('allowed') == 1 for t in current), last_weight)
            candidate = block(template, current)
            check(f'block{target}/exact_weight', candidate[2] == target, candidate[2])
            candidates[target] = candidate
        policy_block = block(template, [spends[0].at_weight(400001)])
        tip = source.rpc('getbestblockhash')
        history = [source.rpc('getblock', source.rpc('getblockhash', n), False) for n in range(1, 112)]
        for par in (1, 2):
            node = h.Node(args.bindir, directory / f'validator{par}', ['-disablewallet=1', f'-par={par}', '-assumevalid=0'])
            nodes.append(node)
            node.ready()
            for raw in history:
                result = node.rpc('submitblock', raw)
                if result is not None:
                    raise RuntimeError(f'funding replay: {result}')
            check(f'par{par}/threads', f'Using {0 if par == 1 else 2} threads for script verification' in (node.directory / 'regtest/debug.log').read_text(), par)
            result = node.rpc('submitblock', candidates[limit + 1][0].hex())
            check(f'par{par}/overweight_rejected', result == 'bad-blk-weight' and node.rpc('getbestblockhash') == tip and node.rpc('gettxout', funding, indices[2]) is not None, result)
            for label, candidate in [('policy_only', policy_block), ('below', candidates[limit - 1]), ('exact', candidates[limit])]:
                raw, blockhash, weight = candidate
                result = node.rpc('submitblock', raw.hex())
                check(f'par{par}/{label}/accepted', result is None and node.rpc('getbestblockhash') == blockhash, result)
                check(f'par{par}/{label}/node_weight', node.rpc('getblock', blockhash)['weight'] == weight, weight)
                used = indices[:2] if label == 'policy_only' else indices[2:]
                check(f'par{par}/{label}/spent', all(node.rpc('gettxout', funding, i, False) is None for i in used), len(used))
                node.rpc('invalidateblock', blockhash)
                check(f'par{par}/{label}/restored', node.rpc('getbestblockhash') == tip and all(node.rpc('gettxout', funding, i, False) is not None for i in used), tip)
        report['block_transaction_count'] = 25
        report['block_weights'] = list(candidates)
    except Exception as error:
        report['error'] = str(error)
        print('ERROR:', error, flush=True)
    finally:
        for node in reversed(nodes):
            node.close()
        report['passed'] = sum(r['passed'] for r in report['results'])
        report['failed'] = sum(not r['passed'] for r in report['results']) + int('error' in report)
        (directory / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print('Report:', directory / 'report.json', flush=True)
    return int(report['failed'] != 0)


if __name__ == '__main__':
    raise SystemExit(main())
