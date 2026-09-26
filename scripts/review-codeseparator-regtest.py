#!/usr/bin/env python3
"""Review CODESEPARATOR and internal signature opcodes in authenticated v1 contracts.
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
    directory = Path(tempfile.mkdtemp(prefix='codeseparator-contracts-'))
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
        output = bytes.fromhex(source.rpc('validateaddress', miner)['scriptPubKey'])
        keys = {}
        for family in ('pq', 'ecdsa'):
            pubhex, secret = subprocess.check_output([str(args.signer), 'keygen', family], text=True).splitlines()
            keys[family] = bytes.fromhex(pubhex), secret
        contracts, outputs = [], []
        for family in ('pq', 'ecdsa'):
            pub, secret = keys[family]
            tails = {
                'CHECKSIG': h.push(pub) + b'\xac',
                'CHECKSIGVERIFY': h.push(pub) + b'\xad\x51',
                'CHECKSIGADD': b'\x00' + h.push(pub) + b'\xde\x51\x9c',
                'CHECKMULTISIG': b'\x00\x7c\x51' + h.push(pub) + b'\x51\xae',
                'CHECKMULTISIGVERIFY': b'\x00\x7c\x51' + h.push(pub) + b'\x51\xaf\x51',
            }
            for opcode, tail in tails.items():
                # The scriptCode keeps separators after the last EXECUTED one.
                shapes = [
                    ('executed', b'\x51\x75\xab' + tail, tail),
                    ('skipped', b'\x00\x63\xab\x68' + tail, b'\x00\x63\xab\x68' + tail),
                    ('executed_and_later', b'\x51\x63\xab\x68' + tail + b'\xab', b'\x68' + tail + b'\xab'),
                ]
                for shape, script, script_code in shapes:
                    for auth in (0, 1, 2):
                        authfamily = 'pq' if auth == 1 else 'ecdsa'
                        authpub = keys[authfamily][0] if auth else b''
                        descriptor = bytes([auth]) + (hash160(authpub) if auth else b'')
                        tag = a.sha256(b'NeuraiAuthScript')
                        commitment = a.sha256(tag + tag + b'\x01' + descriptor + a.sha256(script))
                        native = b'\x51\x20' + commitment
                        for wrapped in (False, True):
                            spk = b'\xa9\x14' + hash160(native) + b'\x87' if wrapped else native
                            outputs.append(b.output(1_000_000_000, spk))
                            contracts.append((f'{family}/{opcode}/{shape}/auth{auth}/p2sh{int(wrapped)}',
                                              family, auth, authfamily, authpub, script, script_code, spk,
                                              h.push(native) if wrapped else b''))
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
        for label, family, auth, authfamily, authpub, script, script_code, spk, sigscript in contracts:
            index = next(o['n'] for o in coins if o['scriptPubKey']['hex'] == spk.hex())
            utxo = funding, index
            def sign(sign_family, code, domain):
                digest = sighash(utxo, code, output, domain)
                result = subprocess.check_output([str(args.signer), 'sign', sign_family],
                    input=keys[sign_family][1] + '\n' + digest.hex() + '\n', text=True)
                return bytes.fromhex(result.strip())
            envelope = [bytes([auth])]
            if auth:
                envelope += [sign(authfamily, script, auth), authpub]
            stack = envelope + [sign(family, script_code, 0), script]
            wrong_code = script if script_code != script else script[4:]
            wrong_internal = envelope + [sign(family, wrong_code, 0), script]
            negatives = [('wrong_internal_scriptcode', transaction(utxo, sigscript, wrong_internal, output),
                          'Signature must be zero for failed CHECK(MULTI)SIG operation')]
            if auth:
                wrong_outer = list(stack)
                wrong_outer[1] = sign(authfamily, script_code if script_code != script else script[4:], auth)
                negatives.append(('wrong_outer_scriptcode', transaction(utxo, sigscript, wrong_outer, output),
                                  'Witness program hash mismatch'))
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
                    # NULLFAIL is policy here; block validation reports the opcode's false result.
                    block_error = error_text
                    if name == 'wrong_internal_scriptcode':
                        block_error = ('Script failed an OP_CHECKSIGVERIFY operation' if '/CHECKSIGVERIFY/' in label else
                                       'Script failed an OP_CHECKMULTISIGVERIFY operation' if '/CHECKMULTISIGVERIFY/' in label else
                                       'Script evaluated without error but finished with a false/empty top stack element')
                    expected = f'non-mandatory-script-verify-flag ({block_error})' if par == 1 else 'block-validation-failed'
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
