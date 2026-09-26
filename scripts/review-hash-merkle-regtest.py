#!/usr/bin/env python3
"""Mine v1 hash/Poseidon/Merkle contracts and validate good/bad blocks on fresh workers.
Fixed expectations are the independently generated literals from phases 11-13.
Destinations are synthetic: tests payment constraints, not signing their later spends.
"""
import argparse
from review_auth_envelope import Envelope, options

ENVELOPE = Envelope()
import importlib.util
import json
from pathlib import Path
import re
import struct
import tempfile


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

h = load('hash_review_helpers', 'review-introspection-regtest.py')
b = load('hash_review_blocks', 'review-csfs-block-limit-regtest.py')
from generate_authscript_vectors import bech32m, sha256


def transaction(utxo, script, arguments, output, amount=90_000_000):
    return ENVELOPE.transaction(utxo, script, arguments, output, amount=amount)


def cases(vectors):
    text = vectors.read_text()
    opcodes = {'KECCAK256': 0xba, 'BLAKE2B': 0xbb, 'BLAKE3': 0xc8, 'SHA3_256': 0xca, 'SHA512': 0xcb}
    result = []
    for name, opcode in opcodes.items():
        found = re.findall(r'\{33, OP_' + name + r', "([0-9a-f]+)"\}', text)
        if len(found) != 1:
            raise ValueError('missing or ambiguous independent vector: ' + name)
        script = bytes([opcode]) + h.push(bytes.fromhex(found[0])) + b'\x88'
        result.append((name, script, [bytes(range(33))]))
    result.append(('POSEIDON', b'\xc9' + h.push(bytes.fromhex(
        '19a31753d0b32445ade8c7fe5158568be0182b5fb7756fd0229ed62257e5df2b')) + b'\x88', [b'hello']))
    for scheme in (1, 2, 3, 4):
        roots = re.findall(r'\{' + str(scheme) + r', 32, 2, "([0-9a-f]+)"\}', text)
        if len(roots) != 1:
            raise ValueError('missing Merkle vector')
        destination = bytes([2]) + bytes(range(32))
        leaf = sha256(destination) if scheme == 1 else destination
        proof = bytes([32]) + bytes((37 * level + j) % 256 for level in range(32) for j in range(32)) + b'\xa5' * 4
        # Witness supplies leaf and proof; SWAP inserts the fixed scheme below proof.
        script = h.push(bytes([scheme])) + b'\x7c' + h.push(bytes.fromhex(roots[0])) + b'\xc1\x69'
        result.append((f'MERKLE{scheme}', script, [leaf, proof]))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    parser.add_argument('--vectors', type=Path, default=Path(__file__).resolve().parents[1] / 'src/test/reversebytes_tests.cpp')
    options(parser)
    args = parser.parse_args()
    global ENVELOPE
    ENVELOPE = Envelope(args.auth, args.wrapped, args.signer)
    directory = Path(tempfile.mkdtemp(prefix='hash-merkle-regtest-'))
    report = {'results': [], 'auth': args.auth, 'wrapped': args.wrapped, 'envelope_sha256': h.digest_file(Path(__file__).with_name('review_auth_envelope.py')), 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'vectors_sha256': h.digest_file(args.vectors),
              'source_sha256': {p.name: h.digest_file(p) for p in (Path(__file__),
                  Path(__file__).with_name('review-introspection-regtest.py'),
                  Path(__file__).with_name('review-csfs-block-limit-regtest.py'),
                  Path(__file__).with_name('generate_authscript_vectors.py'))}}
    nodes = []
    def check(label, passed, observed):
        report['results'].append({'case': label, 'passed': bool(passed), 'observed': observed})
        print(('PASS ' if passed else 'FAIL ') + label, flush=True)
        if not passed:
            raise RuntimeError(f'{label}: {observed}')
    try:
        source = h.Node(args.bindir, directory / 'source', ['-bypassdownload=1', '-par=1'])
        nodes.append(source)
        source.ready()
        miner = source.rpc('getnewaddress')
        source.rpc('generatetoaddress', 110, miner)
        destinations = [bytes.fromhex(source.rpc('validateaddress', miner)['scriptPubKey'])]
        destinations += [bytes([0x50 + version, 32]) + bytes(range(32)) for version in (1, 2, 3)]
        contracts, payments = [], {}
        for name, verification, arguments in cases(args.vectors):
            for family, output in enumerate(destinations):
                script = verification + b'\x00\xcd' + h.push(output) + b'\x87'
                tag = sha256(b'NeuraiAuthScript')
                program = ENVELOPE.program(script)
                payments[ENVELOPE.address(source, program)] = 1
                contracts.append((f'{name}/family{family}', script, arguments, output, program, family))
        funding = source.rpc('sendmany', '', payments)
        source.rpc('generatetoaddress', 1, miner)
        funded = source.rpc('getrawtransaction', funding, True)
        indices = {o['scriptPubKey']['hex']: o['n'] for o in funded['vout']}
        history = [source.rpc('getblock', source.rpc('getblockhash', i), False) for i in range(1, 112)]
        validators = []
        for par in (1, 2):
            node = h.Node(args.bindir, directory / f'validator{par}', ['-disablewallet=1', f'-par={par}', '-assumevalid=0'])
            nodes.append(node)
            validators.append(node)
            node.ready()
            for raw in history:
                if node.rpc('submitblock', raw) is not None:
                    raise RuntimeError('validator rejected funding history')
            log = (node.directory / 'regtest/debug.log').read_text()
            expected = 0 if par == 1 else 2
            check(f'par{par}/threads', f'Using {expected} threads for script verification' in log, expected)
            check(f'par{par}/funded_tip', node.rpc('getbestblockhash') == source.rpc('getbestblockhash'), 111)
        for label, script, arguments, output, program, family in contracts:
            utxo = funding, indices[ENVELOPE.output(program).hex()]
            invalid_args = list(arguments)
            invalid_args[-1] = bytes([invalid_args[-1][0] ^ 1]) + invalid_args[-1][1:]
            bad = transaction(utxo, script, invalid_args, output)
            wrong_output = transaction(utxo, script, arguments, destinations[(family + 1) % 4])
            for kind, tx in [('bad_argument', bad), ('wrong_output', wrong_output)]:
                try:
                    source.rpc('sendrawtransaction', tx[1].hex())
                    check(label + '/' + kind, False, 'accepted')
                except h.RPCError as error:
                    expected = 'OP_VERIFY' if label.startswith('MERKLE') and kind == 'bad_argument' else ('OP_EQUALVERIFY' if kind == 'bad_argument' else 'false')
                    check(label + '/' + kind, error.code == -26 and expected in str(error), str(error))
            template = source.rpc('getblocktemplate', {'rules': ['segwit']})
            check(label + '/empty_template', not template['transactions'], len(template['transactions']))
            raw_bad, _, _ = b.block(template, bad)
            (directory / (label.replace('/', '-') + '-bad.hex')).write_text(raw_bad.hex())
            for par, validator in zip((1, 2), validators):
                tip = validator.rpc('getbestblockhash')
                result = validator.rpc('submitblock', raw_bad.hex())
                expected = 'non-mandatory-script-verify-flag (' + ('Script failed an OP_VERIFY operation' if label.startswith('MERKLE') else 'Script failed an OP_EQUALVERIFY operation') + ')'
                check(label + f'/par{par}/invalid_block', result == (expected if par == 1 else 'block-validation-failed'), result)
                check(label + f'/par{par}/state_preserved', validator.rpc('getbestblockhash') == tip and validator.rpc('gettxout', *utxo) is not None, tip)
            good = transaction(utxo, script, arguments, output)
            txid = source.rpc('sendrawtransaction', good[1].hex())
            blockhash = source.rpc('generatetoaddress', 1, miner)[0]
            raw = source.rpc('getblock', blockhash, False)
            check(label + '/mined', source.rpc('getrawtransaction', txid, True).get('confirmations') == 1, txid)
            for par, validator in zip((1, 2), validators):
                check(label + f'/par{par}/empty_mempool', validator.rpc('getrawmempool') == [], [])
                result = validator.rpc('submitblock', raw)
                check(label + f'/par{par}/valid_block', result is None and validator.rpc('getbestblockhash') == blockhash, result)
                check(label + f'/par{par}/utxo', validator.rpc('gettxout', *utxo) is None and validator.rpc('gettxout', txid, 0)['scriptPubKey']['hex'] == output.hex(), txid)
        report['height'] = source.rpc('getblockcount')
        report['contracts'] = len(contracts)
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
