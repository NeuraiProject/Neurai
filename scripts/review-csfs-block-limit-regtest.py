#!/usr/bin/env python3
"""Submit handcrafted signature-opcode blocks at 80000/80001 sigops to fresh regtest nodes.

Static signature instructions sit in unexecuted branches: this tests accounting,
not crypto throughput. Coinbase and spend outputs contribute zero sigops.
No mempool admission, block-template selection or PoW bypass for test blocks.

With --auth every authenticated v1 input adds one sigop of its own (WitnessSigOps),
so the number of inputs is chosen to keep each total exactly at the boundary.
--wrapped spends the same programs through P2SH.
"""
import argparse
from review_auth_envelope import Envelope, options

ENVELOPE = Envelope()
import importlib.util
import json
from pathlib import Path
import struct
import tempfile

_spec = importlib.util.spec_from_file_location('helpers', Path(__file__).with_name('review-introspection-regtest.py'))
h = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(h)
from generate_authscript_vectors import bech32m, sha256

COIN = 100_000_000
BASE_COUNT = 199
EXTRA_COUNTS = (2, 3, 80, 81, 199, 200)


def hash256(data):
    return sha256(sha256(data))


def output(value, script):
    return struct.pack('<q', value) + h.compact(len(script)) + script


def spend(funding, indices, scripts, natives, chosen, env):
    """Spend the chosen funded scripts into one output; fee is one XNA."""
    sequence = b'\xff' * 4
    prevouts = b''.join(h.outpoint(funding, indices[i]) for i in chosen)
    outputs = b'\x01' + output((len(chosen) - 1) * COIN, b'\x53\x20' + bytes(range(32)))
    inputs = h.compact(len(chosen))
    witness = b''
    for i in chosen:
        sigscript = h.push(natives[i]) if env.wrapped else b''
        inputs += h.outpoint(funding, indices[i]) + h.compact(len(sigscript)) + sigscript + sequence
        stack = [bytes([env.auth])]
        if env.auth:
            preimage = (struct.pack('<I', 2) + hash256(prevouts) + hash256(sequence * len(chosen)) +
                        h.outpoint(funding, indices[i]) + h.compact(len(scripts[i])) + scripts[i] +
                        struct.pack('<Q', COIN) + sequence + hash256(outputs[1:]) + bytes(4) +
                        bytes([env.auth]) + struct.pack('<I', 1))
            stack += [env.sign(hash256(preimage)), env.pub]
        stack.append(scripts[i])
        witness += h.compact(len(stack)) + b''.join(h.compact(len(x)) + x for x in stack)
    version, locktime = struct.pack('<I', 2), bytes(4)
    stripped = version + inputs + outputs + locktime
    return stripped, version + b'\x00\x01' + inputs + outputs + witness + locktime


def block(template, tx):
    stripped, wire = tx
    # Two leaves: coinbase witness hash is zero by definition.
    witness_root = hash256(bytes(32) + hash256(wire))
    commitment = hash256(witness_root + bytes(32))
    height = template['height']
    height_bytes = height.to_bytes((height.bit_length() + 7) // 8, 'little')
    if height_bytes[-1] & 128:
        height_bytes += b'\x00'
    script_sig = h.push(height_bytes) + b'\x00'
    inputs = b'\x01' + bytes(32) + b'\xff' * 4 + h.compact(len(script_sig)) + script_sig + b'\xff' * 4
    # Claim the template subsidy only; leaving the transaction fee unclaimed is valid.
    outputs = b'\x02' + output(template['coinbasevalue'], b'\x51')
    outputs += output(0, b'\x6a\x24\xaa\x21\xa9\xed' + commitment)
    cb_stripped = struct.pack('<I', 2) + inputs + outputs + bytes(4)
    cb_wire = struct.pack('<I', 2) + b'\x00\x01' + inputs + outputs + b'\x01\x20' + bytes(32) + bytes(4)
    root = hash256(hash256(cb_stripped) + hash256(stripped))
    bits = int(template['bits'], 16)
    prefix = struct.pack('<I', template['version']) + bytes.fromhex(template['previousblockhash'])[::-1]
    prefix += root + struct.pack('<II', template['curtime'], bits)
    target = (bits & 0x007fffff) << (8 * ((bits >> 24) - 3))
    for nonce in range(1_000_000):
        header = prefix + struct.pack('<I', nonce)
        if int.from_bytes(hash256(header), 'little') <= target:
            raw = header + b'\x02' + cb_wire + wire
            size_stripped = 80 + 1 + len(cb_stripped) + len(stripped)
            return raw, hash256(header)[::-1].hex(), size_stripped * 3 + len(raw)
    raise RuntimeError('regtest proof of work search exhausted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    parser.add_argument('--opcode', choices=['csfs', 'checksigadd', 'ed25519'], default='csfs')
    options(parser)
    args = parser.parse_args()
    global ENVELOPE
    ENVELOPE = env = Envelope(args.auth, args.wrapped, args.signer)
    opcode = {'csfs': 0xb4, 'checksigadd': 0xde, 'ed25519': 0xdd}[args.opcode]
    extra = 1 if env.auth else 0
    directory = Path(tempfile.mkdtemp(prefix='csfs-block-limit-'))
    report = {'opcode': args.opcode, 'results': [], 'auth': args.auth, 'wrapped': args.wrapped,
              'envelope_sha256': h.digest_file(Path(__file__).with_name('review_auth_envelope.py')),
              'accounting': {'sigops_per_authenticated_input': extra, 'selections': {}},
              'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'source_sha256': {p.name: h.digest_file(p) for p in (Path(__file__),
                  Path(__file__).with_name('review-introspection-regtest.py'),
                  Path(__file__).with_name('generate_authscript_vectors.py'))}}
    nodes = []

    def check(case, passed, observed):
        report['results'].append({'case': case, 'passed': bool(passed), 'observed': observed})
        print(('PASS ' if passed else 'FAIL ') + case, flush=True)
        if not passed:
            raise RuntimeError(f'{case}: {observed}')

    def selection(target):
        # Plain: 402/80 base inputs of 199 plus a small last script. Authenticated:
        # each input costs 200, so 399/79 base inputs plus a last script of 199/200.
        last = ({80000: 2, 80001: 3, 16000: 80, 16001: 81} if not extra else
                {80000: 199, 80001: 200, 16000: 199, 16001: 200})[target]
        base = (target - (last + extra)) // (BASE_COUNT + extra)
        if base * (BASE_COUNT + extra) + last + extra != target:
            raise RuntimeError('boundary not representable: ' + str(target))
        report['accounting']['selections'][str(target)] = {'base_inputs': base, 'last_count': last}
        return list(range(base)) + [402 + EXTRA_COUNTS.index(last)]

    try:
        source = h.Node(args.bindir, directory / 'source', ['-bypassdownload=1'])
        nodes.append(source)
        source.ready()
        miner = source.rpc('getnewaddress')
        source.rpc('generatetoaddress', 110, miner)
        scripts, natives, spks, payments = [], [], [], {}
        for i, count in enumerate([BASE_COUNT] * 402 + list(EXTRA_COUNTS)):
            # Extra scripts: 2/3 and 80/81 for the plain boundaries, 199/200 for authenticated ones.
            script = b'\x00\x63' + h.push(struct.pack('<I', i)) + bytes([opcode]) * count + b'\x68\x51'
            program = env.program(script)
            scripts.append(script)
            natives.append(b'\x51\x20' + program)
            spks.append(env.output(program))
            payments[env.address(source, program)] = 1
        funding = source.rpc('sendmany', '', payments)
        source.rpc('generatetoaddress', 1, miner)
        funded = source.rpc('getrawtransaction', funding, True)
        lookup = {o['scriptPubKey']['hex']: o['n'] for o in funded['vout']}
        indices = [lookup[spk.hex()] for spk in spks]
        # Test admission only: never put these spends into the source mempool.
        for cost in (16000, 16001):
            _, wire = spend(funding, indices, scripts, natives, selection(cost), env)
            result = source.rpc('testmempoolaccept', [wire.hex()])[0]
            if cost == 16000:
                check('mempool/16000_allowed', result.get('allowed') == 1, result)
            else:
                check('mempool/16001_rejected', result.get('allowed') != 1 and
                      'bad-txns-too-many-sigops' in str(result), result)
        template = source.rpc('getblocktemplate', {'rules': ['segwit']})
        check('source/empty_template', template['transactions'] == [], len(template['transactions']))
        candidates = {}
        for cost in (80000, 80001):
            tx = spend(funding, indices, scripts, natives, selection(cost), env)
            raw, block_hash, weight = block(template, tx)
            check(f'block{cost}/weight_below_limit', weight < template['weightlimit'], weight)
            (directory / f'block-{cost}.hex').write_text(raw.hex() + '\n')
            candidates[cost] = raw.hex(), block_hash, hash256(tx[0])[::-1].hex()
            report['accounting']['selections'][str(cost)]['block_weight'] = weight
        check('blocks/distinct_hashes', candidates[80000][1] != candidates[80001][1],
              [candidates[c][1] for c in (80000, 80001)])
        tip = source.rpc('getbestblockhash')
        history = [source.rpc('getblock', source.rpc('getblockhash', i), False)
                   for i in range(1, template['height'])]
        for par in (1, 2):
            node = h.Node(args.bindir, directory / f'validator{par}', ['-disablewallet=1', f'-par={par}'])
            nodes.append(node)
            node.ready()
            log = (node.directory / 'regtest' / 'debug.log').read_text()
            expected_threads = 0 if par == 1 else 2
            thread_line = next((line for line in log.splitlines() if 'threads for script verification' in line), '')
            check(f'par{par}/verification_threads', f'Using {expected_threads} threads for script verification' in thread_line, thread_line)
            for raw in history:
                result = node.rpc('submitblock', raw)
                if result is not None:
                    raise RuntimeError(f'history rejected: {result}')
            check(f'par{par}/funded_tip', node.rpc('getbestblockhash') == tip, tip)
            check(f'par{par}/empty_mempool', node.rpc('getrawmempool') == [], node.rpc('getrawmempool'))
            raw, bad_hash, _ = candidates[80001]
            result = node.rpc('submitblock', raw)
            check(f'par{par}/80001_rejected', result == 'bad-blk-sigops', result)
            check(f'par{par}/rejected_tip_unchanged', node.rpc('getbestblockhash') == tip, node.rpc('getbestblockhash'))
            check(f'par{par}/rejected_utxo_unspent', node.rpc('gettxout', funding, indices[0]) is not None, funding)
            raw, good_hash, txid = candidates[80000]
            result = node.rpc('submitblock', raw)
            check(f'par{par}/80000_accepted', result is None, result)
            check(f'par{par}/accepted_tip', node.rpc('getbestblockhash') == good_hash, node.rpc('getbestblockhash'))
            check(f'par{par}/confirmed_spend', node.rpc('getrawtransaction', txid, True).get('confirmations') == 1, txid)
            check(f'par{par}/accepted_utxo_spent', node.rpc('gettxout', funding, indices[0]) is None, funding)
        report['height'] = template['height']
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
