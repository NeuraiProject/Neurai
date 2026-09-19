#!/usr/bin/env python3
"""Fund and spend P2SH-witness v0/v1/v2/v3; reject malformed scriptSig in full blocks."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile

spec = importlib.util.spec_from_file_location('p2sh_helpers', Path(__file__).with_name('review-arithmetic-regtest.py'))
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
h, b = a.h, a.b


def spend(utxo, script_sig, witness, output):
    inputs = b'\x01' + h.outpoint(*utxo) + h.compact(len(script_sig)) + script_sig + b'\xff' * 4
    outputs = b'\x01' + b.output(900_000_000, output)
    stack = h.compact(len(witness)) + b''.join(h.compact(len(x)) + x for x in witness)
    prefix, lock = struct.pack('<I', 2), bytes(4)
    return prefix + inputs + outputs + lock, prefix + b'\x00\x01' + inputs + outputs + stack + lock


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    parser.add_argument('--keys-first', action='store_true', help='Import keys before redeem scripts to exercise owned P2SH registration')
    parser.add_argument('--importmulti', action='store_true', help='Register redeem scripts through importmulti')
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='p2sh-witness-regtest-'))
    files = [Path(__file__), *[Path(__file__).with_name(f) for f in (
        'review-arithmetic-regtest.py', 'review-introspection-regtest.py',
        'review-csfs-block-limit-regtest.py', 'generate_authscript_vectors.py')]]
    report = {'import_rpc': 'importmulti' if args.importmulti else 'importaddress', 'keys_before_scripts': args.keys_first, 'results': [], 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'source_sha256': {p.name: h.digest_file(p) for p in files}}
    nodes, validators = [], []

    def check(label, passed, observed):
        report['results'].append({'case': label, 'passed': bool(passed), 'observed': observed})
        print(('PASS ' if passed else 'FAIL ') + label, flush=True)
        if not passed:
            raise RuntimeError(f'{label}: {observed}')

    try:
        source = h.Node(args.bindir, directory / 'source',
                        ['-bypassdownload=1', '-acceptnonstdtxn=0', '-pqwallet=1', '-par=1'])
        nodes.append(source)
        source.ready()
        miner = source.rpc('getnewaddress')
        source.rpc('generatetoaddress', 110, miner)
        output = bytes.fromhex(source.rpc('validateaddress', miner)['scriptPubKey'])
        tag = a.sha256(b'NeuraiAuthScript')
        redeems = [b'\x00\x20' + a.sha256(b'\x51'),
                   b'\x51\x20' + a.sha256(tag + tag + b'\x01\x00' + a.sha256(b'\x51'))]
        # Import redeem scripts before their private keys: importaddress is a watch-only RPC.
        keys = h.Node(args.bindir, directory / 'keys', ['-pqwallet=1'])
        nodes.append(keys)
        keys.ready()
        secrets = []
        for family in ('pq', 'ecdsa'):
            address = keys.rpc('getnewaddress', '', family)
            redeems.append(bytes.fromhex(keys.rpc('validateaddress', address)['scriptPubKey']))
            secrets.append(keys.rpc('dumpprivkey', address))
        if args.keys_first:
            for secret in secrets:
                source.rpc('importprivkey', secret, '', False)
        outputs = []
        for redeem in redeems:
            if args.importmulti:
                address = source.rpc('decodescript', redeem.hex())['p2sh']
                result = source.rpc('importmulti', [{'scriptPubKey': {'address': address},
                    'redeemscript': redeem.hex(), 'timestamp': 'now', 'label': 'review'}], {'rescan': False})
                check(f'importmulti/v{len(outputs)}', result[0].get('success') is True, result)
            else:
                source.rpc('importaddress', redeem.hex(), '', False, True)
            digest = hashlib.new('ripemd160', a.sha256(redeem)).digest()
            outputs.append(b'\xa9\x14' + digest + b'\x87')
        if not args.keys_first:
            for secret in secrets:
                source.rpc('importprivkey', secret, '', False)
        raw = struct.pack('<I', 2) + b'\x00' + h.compact(4) + b''.join(b.output(1_000_000_000, p) for p in outputs) + bytes(4)
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
                    raise RuntimeError('validator rejected funding: ' + str(result))
            log = (node.directory / 'regtest/debug.log').read_text()
            check(f'par{par}/threads', f'Using {0 if par == 1 else 2} threads for script verification' in log, par)
        for version, (redeem, p2sh) in enumerate(zip(redeems, outputs)):
            label = f'v{version}'
            index = next(o['n'] for o in coins if o['scriptPubKey']['hex'] == p2sh.hex())
            utxo = funding, index
            canonical = h.push(redeem)
            witness = [b'\x51'] if version == 0 else [b'\x00', b'\x51']
            if version >= 2:
                unsigned = spend(utxo, b'', [], output)[0]
                signed = source.rpc('signrawtransaction', unsigned.hex())
                check(label + '/wallet_signed', signed['complete'], signed.get('errors', []))
                decoded = source.rpc('decoderawtransaction', signed['hex'])
                check(label + '/canonical_scriptsig', decoded['vin'][0]['scriptSig']['hex'] == canonical.hex(), decoded['vin'][0]['scriptSig']['hex'])
                witness = [bytes.fromhex(x) for x in decoded['vin'][0]['txinwitness']]
                check(label + '/strict_template', len(witness) == 4 and witness[0] == bytes([version - 1]) and
                      witness[-1] == b'\x51' and len(witness[1]) > 0, [len(x) for x in witness])
            good = spend(utxo, canonical, witness, output)
            mutated = redeem[:-1] + bytes([redeem[-1] ^ 1])
            negatives = [
                ('extra_push', b'\x00' + canonical, 'Witness requires only-redeemscript scriptSig', 'Witness requires only-redeemscript scriptSig'),
                ('nonminimal_push', b'\x4c' + bytes([len(redeem)]) + redeem, 'Data push larger than necessary', 'Witness requires only-redeemscript scriptSig'),
                ('wrong_redeem', h.push(mutated), 'Script evaluated without error but finished with a false/empty top stack element', 'Script evaluated without error but finished with a false/empty top stack element'),
            ]
            for name, sig, policy_error, consensus_error in negatives:
                tx = spend(utxo, sig, witness, output)
                try:
                    source.rpc('sendrawtransaction', tx[1].hex())
                    check(label + '/' + name + '/mempool', False, 'accepted')
                except h.RPCError as error:
                    check(label + '/' + name + '/mempool', error.code == -26 and policy_error in str(error), str(error))
                check(label + '/' + name + '/empty_mempool', source.rpc('getrawmempool') == [], [])
                template = source.rpc('getblocktemplate', {'rules': ['segwit']})
                raw_block, _, _ = b.block(template, tx)
                (directory / f'{label}-{name}.hex').write_text(raw_block.hex())
                for par, validator in validators:
                    tip = validator.rpc('getbestblockhash')
                    result = validator.rpc('submitblock', raw_block.hex())
                    prefix = 'mandatory-script-verify-flag-failed' if name == 'wrong_redeem' else 'non-mandatory-script-verify-flag'
                    expected = f'{prefix} ({consensus_error})' if par == 1 else 'block-validation-failed'
                    check(label + '/' + name + f'/par{par}/block', result == expected, result)
                    check(label + '/' + name + f'/par{par}/unchanged', validator.rpc('getbestblockhash') == tip and validator.rpc('gettxout', *utxo) is not None, tip)
            txid = source.rpc('sendrawtransaction', good[1].hex())
            check(label + '/admitted', txid in source.rpc('getrawmempool'), txid)
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
