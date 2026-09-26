#!/usr/bin/env python3
"""R4 witness limits with real root-asset transfers; policy and block consensus."""
import argparse
import json
from pathlib import Path
import struct
import tempfile
import importlib.util
from review_auth_envelope import Envelope, compact, hash160

def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

r3 = load('r4_r3', 'review-opcode-assets-r3-regtest.py')
limits = load('r4_limits', 'review-witness-limits-regtest.py')
h, b, sig = r3.h, r3.b, r3.sig
COIN = 100_000_000

def transaction(env, inputs, script, arguments, outputs, locktime=0, sequence=0xffffffff):
    prev = b''.join(h.outpoint(*p) for p in inputs)
    seq, lock = struct.pack('<I', sequence), struct.pack('<I', locktime)
    out = b''.join(struct.pack('<Q', value) + compact(len(spk)) + spk for value, spk in outputs)
    scriptsig = h.push(b'\x51\x20' + env.program(script)) if env.wrapped else b''
    stack = [bytes([env.auth])]
    if env.auth:
        preimage = (struct.pack('<I', 3) + b.hash256(prev) + b.hash256(seq * len(inputs)) +
                    h.outpoint(*inputs[0]) + compact(len(script)) + script + struct.pack('<Q', 10 * COIN) +
                    seq + b.hash256(out) + b.hash256(b'') + lock + bytes([env.auth]) + struct.pack('<I', 1))
        stack += [env.sign(b.hash256(preimage)), env.pub]
    stack += list(arguments) + [script]
    vin = b''
    for i, p in enumerate(inputs):
        script_sig = scriptsig if i == 0 else b''
        vin += h.outpoint(*p) + compact(len(script_sig)) + script_sig + seq
    witness = compact(len(stack)) + b''.join(compact(len(x)) + x for x in stack)
    witness += b'\x00' * (len(inputs) - 1)
    return (struct.pack('<I', 3) + b'\x00\x01' + compact(len(inputs)) + vin +
            compact(len(outputs)) + out + b'\x00' + witness + lock).hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    parser.add_argument('--output', type=Path)
    parser.add_argument('--signer', type=Path, default=Path('/tmp/authscript-review-signer'))
    args = parser.parse_args()
    directory = args.output or Path(tempfile.mkdtemp(prefix='r4-witness-assets-'))
    if args.output:
        directory.mkdir(parents=True, exist_ok=False)
    files = list(Path(__file__).parent.glob('review*.py')) + [Path(__file__).with_name('generate_authscript_vectors.py')]
    report = {'results': [], 'matrix': [], 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'source_sha256': {p.name: h.digest_file(p) for p in files}}
    nodes = []
    def check(label, ok, observed):
        report['results'].append({'case': label, 'passed': bool(ok), 'observed': observed})
        print(('PASS ' if ok else 'FAIL ') + label, flush=True)
        if not ok:
            raise RuntimeError(label + ': ' + str(observed))
    try:
        source = h.Node(args.bindir, directory / 'source',
                        ['-addresstype=pq', '-par=1', '-acceptnonstdtxn=0', '-bypassdownload=1'])
        nodes.append(source)
        source.ready()
        miner = source.rpc('getnewaddress')
        source.rpc('generatetoaddress', 500, miner)
        legacy = Envelope(2, False, args.signer)
        legacy_spk = b'\x76\xa9\x14' + hash160(legacy.pub) + b'\x88\xac'
        addresses = [source.rpc('decodescript', legacy_spk.hex())['addresses'][0], miner]
        addresses += [source.rpc('getnewaddress', '', kind) for kind in ('pq', 'ecdsa')]
        destinations = [bytes.fromhex(source.rpc('validateaddress', x)['scriptPubKey']) for x in addresses]
        def mine():
            return source.rpc('generatetoaddress', 1, miner)[0]
        def confirm(result):
            txid = result[0] if isinstance(result, list) else result
            mine()
            return source.rpc('getrawtransaction', txid, True)
        def locate(tx, prefix, asset=False):
            out = next(o for o in tx['vout'] if o['scriptPubKey']['hex'].startswith(prefix.hex()) and
                       (len(o['scriptPubKey']['hex']) > len(prefix.hex())) == asset)
            point = tx['txid'], out['n']
            source.rpc('lockunspent', False, [{'txid': point[0], 'vout': point[1]}])
            return point
        confirm(source.rpc('issue', 'R4LIMITS', 100000, miner))
        validators = []
        for par in (1, 2):
            worker = h.Node(args.bindir, directory / f'validator{par}',
                            ['-disablewallet=1', f'-par={par}', '-assumevalid=0'])
            nodes.append(worker)
            worker.ready()
            validators.append((par, worker))
            log = (worker.directory / 'regtest/debug.log').read_text()
            check(f'par{par}/threads', f'Using {0 if par == 1 else 2} threads for script verification' in log, par)
        def sync():
            for par, worker in validators:
                for height in range(worker.rpc('getblockcount') + 1, source.rpc('getblockcount') + 1):
                    result = worker.rpc('submitblock', source.rpc('getblock', source.rpc('getblockhash', height), False))
                    if result is not None:
                        raise RuntimeError(f'par{par}/history: {result}')
        def asset_script(prefix):
            payload = b'xnat\x08R4LIMITS' + struct.pack('<q', 5 * COIN)
            return prefix + b'\xc0' + h.push(payload) + b'\x75'
        for auth in (0, 1, 2):
            for wrapped in (False, True):
                env = Envelope(auth, wrapped, args.signer)
                for name, script, operands, error, v0_policy in limits.cases():
                    for family in range(4):
                        label = f'{name}/auth{auth}/p2sh{int(wrapped)}/family{family}'
                        source_family = 2 + family % 2
                        asset = locate(confirm(source.rpc('transfer', 'R4LIMITS', 5, addresses[source_family])),
                                       destinations[source_family], True)
                        program = env.program(script)
                        funding = locate(confirm(source.rpc('sendtoaddress', env.address(source, program), 10)), env.output(program))
                        outs = [(0, asset_script(destinations[family])), (9 * COIN, destinations[1])]
                        wire = bytes.fromhex(source.rpc('signrawtransaction',
                            transaction(env, [funding, asset], script, operands, outs))['hex'])
                        stripped = sig.strip(wire)
                        txid = source.rpc('decoderawtransaction', wire.hex())['txid']
                        check(label + '/txid', b.hash256(stripped)[::-1].hex() == txid, txid)
                        result = source.rpc('testmempoolaccept', [wire.hex()])[0]
                        check(label + '/mempool', (result.get('allowed') == 1) == (error is None) and
                              (error is None or error.lower() in str(result).lower()), result)
                        sync()
                        template = source.rpc('getblocktemplate', {'rules': ['segwit']})
                        check(label + '/empty_template', not template['transactions'], len(template['transactions']))
                        raw, blockhash, weight = b.block(template, (stripped, wire))
                        for par, worker in validators:
                            tip = worker.rpc('getbestblockhash')
                            result = worker.rpc('submitblock', raw.hex())
                            if error:
                                expected = f'non-mandatory-script-verify-flag ({error})' if par == 1 else 'block-validation-failed'
                                check(label + f'/par{par}/rejected', result == expected, result)
                                check(label + f'/par{par}/unchanged', worker.rpc('getbestblockhash') == tip and
                                      worker.rpc('gettxout', *asset) is not None and worker.rpc('gettxout', *funding) is not None, tip)
                            else:
                                check(label + f'/par{par}/accepted', result is None and worker.rpc('getbestblockhash') == blockhash, result)
                                created = worker.rpc('gettxout', txid, 0)
                                check(label + f'/par{par}/asset_moved', worker.rpc('gettxout', *asset) is None and
                                      created is not None and created['scriptPubKey']['hex'] == outs[0][1].hex(), created)
                        if not error:
                            check(label + '/source_block', source.rpc('submitblock', raw.hex()) is None, blockhash)
                            source.rpc('invalidateblock', blockhash)
                            check(label + '/rollback', source.rpc('gettxout', *asset, False) is not None and
                                  txid in source.rpc('getrawmempool'), txid)
                            source.rpc('reconsiderblock', blockhash)
                            check(label + '/restored', source.rpc('getbestblockhash') == blockhash and
                                  source.rpc('gettxout', *asset) is None, blockhash)
                        report['matrix'].append({'case': label, 'error': error, 'weight': weight})
        report['height'] = source.rpc('getblockcount')
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
