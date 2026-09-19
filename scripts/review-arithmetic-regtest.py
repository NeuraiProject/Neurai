#!/usr/bin/env python3
"""Mine arithmetic v1 contracts over real input/output amounts; validate bad/good blocks.
Synthetic payment destinations are not subsequently spent. No production changes.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import tempfile


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

h = load('arithmetic_review_helpers', 'review-introspection-regtest.py')
b = load('arithmetic_review_blocks', 'review-csfs-block-limit-regtest.py')
from generate_authscript_vectors import bech32m, sha256


def transaction(utxo, script, arguments, output, amount=99_000_000):
    inputs = b'\x01' + h.outpoint(*utxo) + b'\x00' + b'\xff' * 4
    outputs = b'\x01' + b.output(amount, output)
    witness = [b'\x00', *arguments, script]
    serialized = h.compact(len(witness)) + b''.join(h.compact(len(x)) + x for x in witness)
    version, locktime = struct.pack('<I', 2), bytes(4)
    return version + inputs + outputs + locktime, version + b'\x00\x01' + inputs + outputs + serialized + locktime


def number(n):
    if not n:
        return b''
    raw = abs(n).to_bytes((abs(n).bit_length() + 7) // 8, 'little')
    if raw[-1] & 128:
        return raw + bytes([128 if n < 0 else 0])
    return raw[:-1] + bytes([raw[-1] | (128 if n < 0 else 0)])


def cases():
    # All contracts require exactly 0.01 XNA fee from a real 1 XNA input.
    fee = b'\x00\xd6\x00\xcc\x94' + h.push(number(1_000_000)) + b'\x9d'
    # A witness operand is combined with the actual output value (99M sat).
    # Expected integers are independently computed here, without node arithmetic.
    for name, opcode, operand, bad, error in [
        ('MUL', 0x95, 100, 2**63-1, 'OP_MUL overflowed the 64-bit numeric domain'),
        ('DIV', 0x96, -7, 0, 'OP_DIV attempted division by zero'),
        ('MOD', 0x97, -7, 0, 'OP_MOD attempted division by zero'),
        ('ADD', 0x93, 2**63-1-99_000_000, 2**63-1,
         'Numeric addition overflowed the 64-bit numeric domain'),
    ]:
        value = 99_000_000
        q = -(value // 7)
        expected = {'MUL': value * operand, 'DIV': q,
                    'MOD': value - q * operand, 'ADD': value + operand}[name]
        # fee leaves witness operand intact; SWAP puts it after OUTPUTVALUE.
        script = fee + b'\x00\xcc\x7c' + bytes([opcode]) + h.push(number(expected)) + b'\x9d'
        yield name, script, [number(operand)], [number(bad)], error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='arithmetic-regtest-'))
    report = {'results': [], 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
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
        for name, verification, arguments, bad_arguments, failure in cases():
            for family, output in enumerate(destinations):
                script = verification + b'\x00\xcd' + h.push(output) + b'\x87'
                tag = sha256(b'NeuraiAuthScript')
                program = sha256(tag + tag + b'\x01\x00' + sha256(script))
                payments[bech32m('tnq', 1, program)] = 1
                contracts.append((f'{name}/family{family}', script, arguments, output, program, family, bad_arguments, failure))
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
        for label, script, arguments, output, program, family, bad_arguments, failure in contracts:
            utxo = funding, indices[(b'\x51\x20' + program).hex()]
            negatives = [
                ('bad_argument', transaction(utxo, script, bad_arguments, output), failure),
                ('wrong_amount', transaction(utxo, script, arguments, output, 98_999_999),
                 'Script failed an OP_NUMEQUALVERIFY operation'),
                ('wrong_output', transaction(utxo, script, arguments, destinations[(family + 1) % 4]),
                 'Script evaluated without error but finished with a false/empty top stack element'),
            ]
            for kind, tx, error_text in negatives:
                try:
                    source.rpc('sendrawtransaction', tx[1].hex())
                    check(label + '/' + kind, False, 'accepted')
                except h.RPCError as error:
                    check(label + '/' + kind, error.code == -26 and error_text in str(error), str(error))
                template = source.rpc('getblocktemplate', {'rules': ['segwit']})
                check(label + '/' + kind + '/empty_template', not template['transactions'], len(template['transactions']))
                raw_bad, _, _ = b.block(template, tx)
                (directory / (label.replace('/', '-') + '-' + kind + '.hex')).write_text(raw_bad.hex())
                for par, validator in zip((1, 2), validators):
                    tip = validator.rpc('getbestblockhash')
                    result = validator.rpc('submitblock', raw_bad.hex())
                    expected = 'non-mandatory-script-verify-flag (' + error_text + ')'
                    check(label + f'/{kind}/par{par}/invalid_block',
                          result == (expected if par == 1 else 'block-validation-failed'), result)
                    check(label + f'/{kind}/par{par}/state_preserved',
                          validator.rpc('getbestblockhash') == tip and validator.rpc('gettxout', *utxo) is not None, tip)
            good = transaction(utxo, script, arguments, output)
            txid = source.rpc('sendrawtransaction', good[1].hex())
            blockhash = source.rpc('generatetoaddress', 1, miner)[0]
            raw = source.rpc('getblock', blockhash, False)
            check(label + '/mined', source.rpc('getrawtransaction', txid, True).get('confirmations') == 1, txid)
            for par, validator in zip((1, 2), validators):
                check(label + f'/par{par}/empty_mempool', validator.rpc('getrawmempool') == [], [])
                result = validator.rpc('submitblock', raw)
                check(label + f'/par{par}/valid_block', result is None and validator.rpc('getbestblockhash') == blockhash, result)
                check(label + f'/par{par}/utxo', validator.rpc('gettxout', *utxo) is None and validator.rpc('gettxout', txid, 0)['scriptPubKey']['hex'] == output.hex() and validator.rpc('gettxout', txid, 0)['value'] == 0.99, txid)
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
