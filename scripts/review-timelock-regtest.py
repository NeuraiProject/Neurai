#!/usr/bin/env python3
"""CLTV/CSV maturity boundaries on real v1 UTXOs; synchronous/threaded block validation.
Synthetic destination programs test constrained payments, not their later spending.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import tempfile


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


h = load('timelock_helpers', 'review-introspection-regtest.py')
b = load('timelock_blocks', 'review-csfs-block-limit-regtest.py')
a = load('timelock_numbers', 'review-arithmetic-regtest.py')
from generate_authscript_vectors import bech32m, sha256


def transaction(utxo, script, output, locktime, sequence):
    inputs = b'\x01' + h.outpoint(*utxo) + b'\x00' + struct.pack('<I', sequence)
    outputs = b'\x01' + b.output(99_000_000, output)
    witness = b'\x02\x01\x00' + h.compact(len(script)) + script
    version, lock = struct.pack('<I', 2), struct.pack('<I', locktime)
    return version + inputs + outputs + lock, version + b'\x00\x01' + inputs + outputs + witness + lock


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='timelock-regtest-'))
    report = {'results': [], 'boundaries': [], 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'source_sha256': {p.name: h.digest_file(p) for p in (Path(__file__), *[
                  Path(__file__).with_name(f) for f in ['review-introspection-regtest.py',
                  'review-csfs-block-limit-regtest.py', 'review-arithmetic-regtest.py',
                  'generate_authscript_vectors.py']])}}
    nodes, validators = [], []

    def check(label, passed, observed):
        report['results'].append({'case': label, 'passed': bool(passed), 'observed': observed})
        print(('PASS ' if passed else 'FAIL ') + label, flush=True)
        if not passed:
            raise RuntimeError(f'{label}: {observed}')

    try:
        source = h.Node(args.bindir, directory / 'source', ['-bypassdownload=1', '-par=1'])
        nodes.append(source)
        source.ready()
        source.rpc('setmocktime', 1800000000)
        miner = source.rpc('getnewaddress')
        source.rpc('generatetoaddress', 110, miner)
        for par in (1, 2):
            node = h.Node(args.bindir, directory / f'validator{par}',
                          ['-disablewallet=1', f'-par={par}', '-assumevalid=0'])
            nodes.append(node)
            node.ready()
            node.rpc('setmocktime', 1801000000)
            validators.append((par, node))
            for height in range(1, 111):
                raw = source.rpc('getblock', source.rpc('getblockhash', height), False)
                if node.rpc('submitblock', raw) is not None:
                    raise RuntimeError('funding history rejected')
            log = (node.directory / 'regtest/debug.log').read_text()
            count = 0 if par == 1 else 2
            check(f'par{par}/threads', f'Using {count} threads for script verification' in log, count)

        def mine(count=1):
            hashes = source.rpc('generatetoaddress', count, miner)
            for blockhash in hashes:
                raw = source.rpc('getblock', blockhash, False)
                for par, validator in validators:
                    result = validator.rpc('submitblock', raw)
                    check(f'advance/{blockhash}/par{par}', result is None and
                          validator.rpc('getbestblockhash') == blockhash, result)
            return hashes

        def mtp():
            return source.rpc('getblockchaininfo')['mediantime']

        destinations = [bytes.fromhex(source.rpc('validateaddress', miner)['scriptPubKey'])]
        destinations += [bytes([0x50 + v, 32]) + bytes(range(32)) for v in (1, 2, 3)]
        for kind in ('CLTV_HEIGHT', 'CSV_HEIGHT', 'CLTV_TIME', 'CSV_TIME'):
            absolute = kind.startswith('CLTV')
            temporal = kind.endswith('TIME')
            funding_height = source.rpc('getblockcount') + 1
            coin_mtp = mtp()
            target = coin_mtp + 512 if temporal else funding_height + 2
            operand = target if absolute else (0x400001 if temporal else 3)
            locktime = target if absolute else 0
            sequence = 0xfffffffe if absolute else operand
            payments, contracts = {}, []
            for family, output in enumerate(destinations):
                script = h.push(a.number(operand)) + bytes([0xb1 if absolute else 0xb2, 0x75])
                script += b'\x00\xcd' + h.push(output) + b'\x87'
                tag = sha256(b'NeuraiAuthScript')
                program = sha256(tag + tag + b'\x01\x00' + sha256(script))
                payments[bech32m('tnq', 1, program)] = 1
                contracts.append((family, output, script, program))
            funding = source.rpc('sendmany', '', payments)
            mine()
            funded = source.rpc('getrawtransaction', funding, True)
            indices = {o['scriptPubKey']['hex']: o['n'] for o in funded['vout']}
            spends = []
            for family, output, script, program in contracts:
                utxo = funding, indices[(b'\x51\x20' + program).hex()]
                spends.append((family, utxo, output, script, transaction(utxo, script, output, locktime, sequence)))

            def reject_all(stage):
                for family, utxo, output, script, tx in spends:
                    label = f'{kind}/{stage}/family{family}'
                    try:
                        source.rpc('sendrawtransaction', tx[1].hex())
                        check(label + '/mempool', False, 'accepted')
                    except h.RPCError as error:
                        reason = 'non-final' if absolute else 'non-BIP68-final'
                        check(label + '/mempool', error.code == -26 and reason in str(error), str(error))
                    template = source.rpc('getblocktemplate', {'rules': ['segwit']})
                    check(label + '/empty_template', not template['transactions'], len(template['transactions']))
                    raw, _, _ = b.block(template, tx)
                    (directory / (label.replace('/', '-') + '.hex')).write_text(raw.hex())
                    for par, validator in validators:
                        tip = validator.rpc('getbestblockhash')
                        result = validator.rpc('submitblock', raw.hex())
                        check(label + f'/par{par}/block', result == 'bad-txns-nonfinal', result)
                        check(label + f'/par{par}/unchanged', validator.rpc('getbestblockhash') == tip and
                              validator.rpc('gettxout', *utxo) is not None, tip)

            reject_all('early')
            if temporal:
                source.rpc('setmocktime', target - 1)
                mine(6)
                check(kind + '/last_mtp_before', mtp() == target - 1, mtp())
                reject_all('last_before')
                source.rpc('setmocktime', target)
                mine(6)
                check(kind + '/equal_mtp', mtp() == target, mtp())
                if absolute:
                    reject_all('equality')
                    source.rpc('setmocktime', target + 1)
                    mine(6)
                check(kind + '/first_valid_mtp', mtp() == target + int(absolute), mtp())
            else:
                mine()
                check(kind + '/last_invalid_height', source.rpc('getblockcount') + 1 == target, target)
                reject_all('last_before')
                mine()
                check(kind + '/first_valid_height', source.rpc('getblockcount') + 1 == target + 1, target + 1)
            report['boundaries'].append({'kind': kind, 'funding_height': funding_height, 'coin_mtp': coin_mtp,
                'operand': operand, 'candidate_height': source.rpc('getblockcount') + 1, 'mtp': mtp()})
            # A mature UTXO must not allow weakening the contract's own lock.
            for family, utxo, output, script, tx in spends:
                bypass = transaction(utxo, script, output, locktime - 1 if absolute else 0,
                                     sequence if absolute else sequence - 1)
                label = f'{kind}/family{family}/weakened_lock'
                try:
                    source.rpc('sendrawtransaction', bypass[1].hex())
                    check(label + '/mempool', False, 'accepted')
                except h.RPCError as error:
                    check(label + '/mempool', error.code == -26 and
                          'Locktime requirement not satisfied' in str(error), str(error))
                template = source.rpc('getblocktemplate', {'rules': ['segwit']})
                check(label + '/empty_template', not template['transactions'], len(template['transactions']))
                raw, _, _ = b.block(template, bypass)
                (directory / (label.replace('/', '-') + '.hex')).write_text(raw.hex())
                for par, validator in validators:
                    tip = validator.rpc('getbestblockhash')
                    result = validator.rpc('submitblock', raw.hex())
                    expected = ('non-mandatory-script-verify-flag (Locktime requirement not satisfied)'
                                if par == 1 else 'block-validation-failed')
                    check(label + f'/par{par}/block', result == expected, result)
                    check(label + f'/par{par}/unchanged', validator.rpc('getbestblockhash') == tip and
                          validator.rpc('gettxout', *utxo) is not None, tip)
            # All four admitted at the exact boundary, before any further block.
            txids = []
            for family, utxo, output, script, tx in spends:
                txids.append(source.rpc('sendrawtransaction', tx[1].hex()))
                check(f'{kind}/family{family}/admitted_at_boundary', txids[-1] in source.rpc('getrawmempool'), txids[-1])
            for par, validator in validators:
                check(f'{kind}/par{par}/empty_mempool', validator.rpc('getrawmempool') == [], [])
            mine()
            for txid, (family, utxo, output, script, tx) in zip(txids, spends):
                check(f'{kind}/family{family}/mined', source.rpc('getrawtransaction', txid, True).get('confirmations') == 1, txid)
                for par, validator in validators:
                    created = validator.rpc('gettxout', txid, 0)
                    check(f'{kind}/family{family}/par{par}/utxo', validator.rpc('gettxout', *utxo) is None and
                          created is not None and created['scriptPubKey']['hex'] == output.hex() and created['value'] == 0.99, created)
        report['height'] = source.rpc('getblockcount')
        report['contracts'] = 16
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
