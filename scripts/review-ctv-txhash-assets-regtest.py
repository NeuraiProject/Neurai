#!/usr/bin/env python3
"""R2: real asset transfers under CTV/TXHASH, six authenticated envelopes.

Digests are fixed in the script except CTV/P2SH, which uses an unbound witness
digest to avoid the self-reference from committing redeemScript in scriptSig.
A changed-output plus changed-digest control distinguishes these policies.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import tempfile

from review_auth_envelope import Envelope, compact, hash160
from generate_authscript_vectors import sha256

spec = importlib.util.spec_from_file_location('txhash_review', Path(__file__).with_name('review-txhash-regtest.py'))
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
h, c = t.h, t._ctv
COIN = 100_000_000


def transaction(env, inputs, script, expected, outputs, refs):
    prev = b''.join(h.outpoint(*p) for p in inputs)
    seq = b'\xff' * 4
    out = b''.join(struct.pack('<Q', value) + compact(len(spk)) + spk for value, spk in outputs)
    scriptsig = h.push(b'\x51\x20' + env.program(script)) if env.wrapped else b''
    stack = [bytes([env.auth])]
    if env.auth:
        preimage = (struct.pack('<I', 3) + t.double_sha(prev) + t.double_sha(seq * len(inputs)) +
                    h.outpoint(*inputs[0]) + compact(len(script)) + script + struct.pack('<Q', COIN) +
                    seq + t.double_sha(out) + t.double_sha(b''.join(h.outpoint(*p) for p in refs)) +
                    bytes(4) + bytes([env.auth]) + struct.pack('<I', 1))
        stack += [env.sign(t.double_sha(preimage)), env.pub]
    stack += [expected, script]
    vin = b''
    for i, p in enumerate(inputs):
        sig = scriptsig if i == 0 else b''
        vin += h.outpoint(*p) + compact(len(sig)) + sig + seq
    witness = compact(len(stack)) + b''.join(compact(len(x)) + x for x in stack)
    witness += b'\x00' * (len(inputs) - 1)
    return (struct.pack('<I', 3) + b'\x00\x01' + compact(len(inputs)) + vin +
            compact(len(outputs)) + out + compact(len(refs)) +
            b''.join(h.outpoint(*p) for p in refs) + witness + bytes(4)).hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    parser.add_argument('--output', type=Path)
    parser.add_argument('--signer', type=Path, default=Path('/tmp/authscript-review-signer'))
    args = parser.parse_args()
    directory = args.output or Path(tempfile.mkdtemp(prefix='r2-assets-'))
    if args.output:
        directory.mkdir(parents=True, exist_ok=False)
    report = {'results': [], 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'source_sha256': {p.name: h.digest_file(p) for p in
                [Path(__file__)] + [Path(__file__).with_name(x) for x in
                ('review_auth_envelope.py', 'review-txhash-regtest.py', 'review-ctv-regtest.py',
                 'review-introspection-regtest.py', 'generate_authscript_vectors.py')]}}
    node = None
    def check(label, ok, observed):
        report['results'].append({'case': label, 'passed': bool(ok), 'observed': observed})
        print(('PASS ' if ok else 'FAIL ') + label, flush=True)
        if not ok:
            raise RuntimeError(label + ': ' + str(observed))
    try:
        node = h.Node(args.bindir, directory / 'node', ['-pqwallet=1'])
        node.ready()
        miner = node.rpc('getnewaddress')
        node.rpc('generatetoaddress', 500, miner)
        legacy_key = Envelope(2, False, args.signer)
        legacy_script = b'\x76\xa9\x14' + hash160(legacy_key.pub) + b'\x88\xac'
        legacy_address = node.rpc('decodescript', legacy_script.hex())['addresses'][0]
        addresses = [legacy_address, miner] + [node.rpc('getnewaddress', '', kind) for kind in ('pq', 'ecdsa')]
        destinations = [bytes.fromhex(node.rpc('validateaddress', a)['scriptPubKey']) for a in addresses]
        def mine():
            return node.rpc('generatetoaddress', 1, miner)[0]
        def confirm(result):
            txid = result[0] if isinstance(result, list) else result
            mine()
            return node.rpc('getrawtransaction', txid, True)
        def locate(tx, prefix, asset=False):
            out = next(o for o in tx['vout'] if o['scriptPubKey']['hex'].startswith(prefix.hex()) and
                       (len(o['scriptPubKey']['hex']) > len(prefix.hex())) == asset)
            point = (tx['txid'], out['n'])
            node.rpc('lockunspent', False, [{'txid': point[0], 'vout': point[1]}])
            return point
        refs = [locate(confirm(node.rpc('sendtoaddress', miner, 1)), destinations[1]) for _ in range(2)]
        contracts = []
        for auth in (0, 1, 2):
            for wrapped in (False, True):
                env = Envelope(auth, wrapped, args.signer)
                for opcode in ('ctv', 'txhash'):
                    for family in range(4):
                        label = f'{opcode}/auth{auth}/p2sh{int(wrapped)}/family{family}'
                        name = f'R2{opcode.upper()}{auth}{int(wrapped)}{family}'
                        source = 2 + family % 2
                        confirm(node.rpc('issue', name, 5, miner))
                        asset = locate(confirm(node.rpc('transfer', name, 5, addresses[source])), destinations[source], True)
                        def asset_script(prefix, amount):
                            payload = b'xnat' + compact(len(name)) + name.encode() + struct.pack('<q', amount * COIN)
                            return prefix + b'\xc0' + h.push(payload) + b'\x75'
                        def outputs(target=family, amount=3):
                            return [(0, asset_script(destinations[target], amount)),
                                    (0, asset_script(destinations[0], 5 - amount)),
                                    (90_000_000, destinations[1])]
                        good_outputs = outputs()
                        fixed = not (opcode == 'ctv' and wrapped)
                        literal = (c.ctv(3, 0, [0xffffffff] * 2, good_outputs, 0, refs)
                                   if opcode == 'ctv' else
                                   t.field_hash(16, 3, 0, [bytes(36)] * 2, [0xffffffff] * 2, good_outputs, 0))
                        script = b'\xb3\x75\x51' if opcode == 'ctv' else h.push(b'\x10\x00') + b'\xb5\x87'
                        if fixed:
                            script = b'\x76' + h.push(literal) + b'\x88' + script
                        program = env.program(script)
                        funding = locate(confirm(node.rpc('sendtoaddress', env.address(node, program), 1)), env.output(program))
                        inputs = [funding, asset]
                        sigs = [h.push(b'\x51\x20' + program) if wrapped else b'', b'']
                        digest = (c.ctv(3, 0, [0xffffffff] * 2, good_outputs, 0, refs, sigs)
                                  if opcode == 'ctv' else
                                  t.field_hash(16, 3, 0, [h.outpoint(*p) for p in inputs],
                                               [0xffffffff] * 2, good_outputs, 0))
                        def signed(outs, references, expected=digest):
                            return node.rpc('signrawtransaction', transaction(env, inputs, script, expected, outs, references))['hex']
                        good = signed(good_outputs, refs)
                        result = node.rpc('testmempoolaccept', [good])[0]
                        check(label + '/admit', result.get('allowed') == 1, result)
                        for suffix, outs, expected in (
                                ('destination', outputs((family + 1) % 4), digest),
                                ('quantity_balanced', outputs(amount=4), digest),
                                ('wrong_digest', good_outputs, bytes([digest[0] ^ 1]) + digest[1:])):
                            result = node.rpc('testmempoolaccept', [signed(outs, refs, expected)])[0]
                            reason = ('equalverify' if suffix == 'wrong_digest' and fixed else
                                      'checktemplateverify' if opcode == 'ctv' else 'false')
                            check(label + '/' + suffix, result.get('allowed') != 1 and reason in str(result).lower(), result)
                        changed = outputs((family + 1) % 4)
                        rebound = (c.ctv(3, 0, [0xffffffff] * 2, changed, 0, refs, sigs)
                                   if opcode == 'ctv' else
                                   t.field_hash(16, 3, 0, [h.outpoint(*p) for p in inputs],
                                                [0xffffffff] * 2, changed, 0))
                        result = node.rpc('testmempoolaccept', [signed(changed, refs, rebound)])[0]
                        check(label + '/digest_rebinding', (result.get('allowed') == 1) == (not fixed) and
                              (not fixed or 'equalverify' in str(result).lower()), result)
                        result = node.rpc('testmempoolaccept', [signed(good_outputs, refs[::-1])])[0]
                        check(label + '/reference_order', (result.get('allowed') == 1) == (opcode == 'txhash'), result)
                        txid = node.rpc('sendrawtransaction', good)
                        block = mine()
                        check(label + '/mined', node.rpc('getrawtransaction', txid, True).get('confirmations', 0) > 0, txid)
                        node.rpc('invalidateblock', block)
                        check(label + '/reorg_readmission', txid in node.rpc('getrawmempool'), txid)
                        check(label + '/source_restored', node.rpc('gettxout', *asset, False) is not None, asset)
                        node.rpc('reconsiderblock', block)
                        check(label + '/reconfirmed', node.rpc('getrawtransaction', txid, True).get('confirmations', 0) > 0, txid)
                        contracts.append(txid)
        height = node.rpc('getblockcount')
        blocks = [node.rpc('getblock', node.rpc('getblockhash', i), False) for i in range(1, height + 1)]
        for par in (1, 2):
            validator = h.Node(args.bindir, directory / f'validator{par}', ['-disablewallet=1', f'-par={par}'])
            try:
                validator.ready()
                for block in blocks:
                    result = validator.rpc('submitblock', block)
                    if result is not None:
                        raise RuntimeError(f'validator{par}: {result}')
                check(f'validator{par}/same_tip', validator.rpc('getbestblockhash') == node.rpc('getbestblockhash'), height)
                for txid in contracts:
                    check(f'validator{par}/{txid}', validator.rpc('getrawtransaction', txid, True).get('confirmations', 0) > 0, txid)
            finally:
                validator.close()
        report['height'] = height
    except Exception as error:
        report['error'] = str(error)
        print('ERROR:', error, flush=True)
    finally:
        if node:
            node.close()
        report['passed'] = sum(r['passed'] for r in report['results'])
        report['failed'] = sum(not r['passed'] for r in report['results']) + int('error' in report)
        (directory / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print('Report:', directory / 'report.json', flush=True)
    return int(report['failed'] != 0)


if __name__ == '__main__':
    raise SystemExit(main())
