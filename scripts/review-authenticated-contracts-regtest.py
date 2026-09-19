#!/usr/bin/env python3
"""Mine externally signed v1 contracts: PQ/ECDSA, native/P2SH, four output families.
Commitment/sighash/transaction encoding is independent Python; crypto uses pinned test helper.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('authenticated_helpers', Path(__file__).with_name('review-arithmetic-regtest.py'))
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
h, b = a.h, a.b


def hash160(x):
    return hashlib.new('ripemd160', a.sha256(x)).digest()


def sighash(utxo, script, output, auth):
    prevout = h.outpoint(*utxo)
    sequence = b'\xff' * 4
    out = b.output(900_000_000, output)
    preimage = (struct.pack('<I', 2) + b.hash256(prevout) + b.hash256(sequence) + prevout +
                h.compact(len(script)) + script + struct.pack('<Q', 1_000_000_000) + sequence +
                b.hash256(out) + bytes(4) + bytes([auth]) + struct.pack('<I', 1))
    return b.hash256(preimage)


def transaction(utxo, sigscript, stack, output):
    inputs = b'\x01' + h.outpoint(*utxo) + h.compact(len(sigscript)) + sigscript + b'\xff' * 4
    outputs = b'\x01' + b.output(900_000_000, output)
    witness = h.compact(len(stack)) + b''.join(h.compact(len(x)) + x for x in stack)
    prefix, lock = struct.pack('<I', 2), bytes(4)
    return prefix + inputs + outputs + lock, prefix + b'\x00\x01' + inputs + outputs + witness + lock


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    parser.add_argument('--signer', type=Path, default=Path('/tmp/authscript-review-signer'))
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='authenticated-contracts-'))
    files = [Path(__file__), *[Path(__file__).with_name(f) for f in (
        'authscript-review-signer.cpp', 'review-arithmetic-regtest.py',
        'review-introspection-regtest.py', 'review-csfs-block-limit-regtest.py', 'generate_authscript_vectors.py')]]
    report = {'results': [], 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'signer_sha256': h.digest_file(args.signer),
              'source_sha256': {p.name: h.digest_file(p) for p in files}}
    nodes, validators = [], []

    def check(label, passed, observed):
        report['results'].append({'case': label, 'passed': bool(passed), 'observed': observed})
        print(('PASS ' if passed else 'FAIL ') + label, flush=True)
        if not passed:
            raise RuntimeError(f'{label}: {observed}')

    try:
        source = h.Node(args.bindir, directory / 'source', ['-bypassdownload=1', '-acceptnonstdtxn=0', '-par=1'])
        nodes.append(source)
        source.ready()
        miner = source.rpc('getnewaddress')
        source.rpc('generatetoaddress', 110, miner)
        destinations = [bytes.fromhex(source.rpc('validateaddress', miner)['scriptPubKey'])]
        destinations += [bytes([0x50 + v, 32]) + bytes(range(32)) for v in (1, 2, 3)]
        argument = b'contract-preimage'
        contracts, outputs = [], []
        for family, auth in [('pq', 1), ('ecdsa', 2)]:
            # Disposable secrets stay in memory/stdin and are not recorded in the report.
            pubhex, secret = subprocess.check_output([str(args.signer), 'keygen', family], text=True).splitlines()
            pub = bytes.fromhex(pubhex)
            for dest, output in enumerate(destinations):
                script = b'\xa8' + h.push(a.sha256(argument)) + b'\x88\x00\xcd' + h.push(output) + b'\x87'
                tag = a.sha256(b'NeuraiAuthScript')
                commitment = a.sha256(tag + tag + b'\x01' + bytes([auth]) + hash160(pub) + a.sha256(script))
                native = b'\x51\x20' + commitment
                for wrapped in (False, True):
                    spk = b'\xa9\x14' + hash160(native) + b'\x87' if wrapped else native
                    outputs.append(b.output(1_000_000_000, spk))
                    contracts.append((f'{family}/dest{dest}/p2sh{int(wrapped)}', family, auth, pub, secret,
                                      script, output, spk, h.push(native) if wrapped else b''))
        raw = struct.pack('<I', 2) + b'\x00' + h.compact(len(outputs)) + b''.join(outputs) + bytes(4)
        funded = source.rpc('fundrawtransaction', raw.hex())
        signed = source.rpc('signrawtransaction', funded['hex'])
        check('funding_signed', signed['complete'], signed['complete'])
        funding = source.rpc('sendrawtransaction', signed['hex'])
        source.rpc('generatetoaddress', 1, miner)
        coins = source.rpc('getrawtransaction', funding, True)['vout']
        for par in (1, 2):
            node = h.Node(args.bindir, directory / f'validator{par}', ['-disablewallet=1', f'-par={par}', '-assumevalid=0'])
            nodes.append(node)
            node.ready()
            validators.append((par, node))
            for height in range(1, 112):
                result = node.rpc('submitblock', source.rpc('getblock', source.rpc('getblockhash', height), False))
                if result is not None:
                    raise RuntimeError('funding rejected: ' + str(result))
            log = (node.directory / 'regtest/debug.log').read_text()
            check(f'par{par}/threads', f'Using {0 if par == 1 else 2} threads for script verification' in log, par)
        for label, family, auth, pub, secret, script, output, spk, sigscript in contracts:
            index = next(o['n'] for o in coins if o['scriptPubKey']['hex'] == spk.hex())
            utxo = funding, index
            def sign(destination):
                digest = sighash(utxo, script, destination, auth)
                result = subprocess.check_output([str(args.signer), 'sign', family],
                    input=secret + '\n' + digest.hex() + '\n', text=True)
                return bytes.fromhex(result.strip())
            signature = sign(output)
            stack = [bytes([auth]), signature, pub, argument, script]
            wrong_arg = list(stack)
            wrong_arg[3] = b'wrong-preimage'
            empty_sig = list(stack)
            empty_sig[1] = b''
            wrong_output = b'\x6a'
            resigned = list(stack)
            resigned[1] = sign(wrong_output)
            negatives = [
                ('wrong_argument', transaction(utxo, sigscript, wrong_arg, output), 'Script failed an OP_EQUALVERIFY operation'),
                ('empty_signature', transaction(utxo, sigscript, empty_sig, output), 'Witness program hash mismatch'),
                ('wrong_output', transaction(utxo, sigscript, stack, wrong_output), 'Witness program hash mismatch'),
                ('resigned_wrong_output', transaction(utxo, sigscript, resigned, wrong_output),
                 'Script evaluated without error but finished with a false/empty top stack element'),
            ]
            for name, tx, error_text in negatives:
                try:
                    source.rpc('sendrawtransaction', tx[1].hex())
                    check(label + '/' + name + '/mempool', False, 'accepted')
                except h.RPCError as error:
                    check(label + '/' + name + '/mempool', error.code == -26 and error_text in str(error), str(error))
                template = source.rpc('getblocktemplate', {'rules': ['segwit']})
                check(label + '/' + name + '/empty_template', not template['transactions'], len(template['transactions']))
                raw_block, _, _ = b.block(template, tx)
                (directory / (label.replace('/', '-') + '-' + name + '.hex')).write_text(raw_block.hex())
                for par, validator in validators:
                    tip = validator.rpc('getbestblockhash')
                    result = validator.rpc('submitblock', raw_block.hex())
                    expected = f'non-mandatory-script-verify-flag ({error_text})' if par == 1 else 'block-validation-failed'
                    check(label + '/' + name + f'/par{par}/block', result == expected, result)
                    check(label + '/' + name + f'/par{par}/unchanged', validator.rpc('getbestblockhash') == tip and validator.rpc('gettxout', *utxo) is not None, tip)
            good = transaction(utxo, sigscript, stack, output)
            txid = source.rpc('sendrawtransaction', good[1].hex())
            blockhash = source.rpc('generatetoaddress', 1, miner)[0]
            raw_block = source.rpc('getblock', blockhash, False)
            check(label + '/mined', source.rpc('getrawtransaction', txid, True).get('confirmations') == 1, txid)
            for par, validator in validators:
                check(label + f'/par{par}/empty_mempool', validator.rpc('getrawmempool') == [], [])
                result = validator.rpc('submitblock', raw_block)
                created = validator.rpc('gettxout', txid, 0)
                check(label + f'/par{par}/block', result is None and validator.rpc('getbestblockhash') == blockhash, result)
                check(label + f'/par{par}/utxo', validator.rpc('gettxout', *utxo) is None and created is not None and
                      created['value'] == 9 and created['scriptPubKey']['hex'] == output.hex(), txid)
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
