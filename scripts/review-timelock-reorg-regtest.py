#!/usr/bin/env python3
"""Roll CLTV/CSV height/time maturity back with pending and confirmed descendants.
Runs independent wallet nodes with zero/two script verification threads.
"""
import argparse
import importlib.util
import json
import struct
from pathlib import Path
import tempfile

spec = importlib.util.spec_from_file_location('timelock_review', Path(__file__).with_name('review-timelock-regtest.py'))
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
h = t.h


def program(script):
    tag = t.sha256(b'NeuraiAuthScript')
    return t.sha256(tag + tag + b'\x01\x00' + t.sha256(script))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='timelock-reorg-'))
    files = [Path(__file__), *[Path(__file__).with_name(f) for f in (
        'review-timelock-regtest.py', 'review-introspection-regtest.py',
        'review-csfs-block-limit-regtest.py', 'review-arithmetic-regtest.py', 'generate_authscript_vectors.py')]]
    report = {'results': [], 'boundaries': [], 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'source_sha256': {p.name: h.digest_file(p) for p in files}}
    nodes = []

    def check(label, passed, observed):
        report['results'].append({'case': label, 'passed': bool(passed), 'observed': observed})
        print(('PASS ' if passed else 'FAIL ') + label, flush=True)
        if not passed:
            raise RuntimeError(f'{label}: {observed}')

    try:
        for par in (1, 2):
            node = h.Node(args.bindir, directory / f'node{par}', ['-bypassdownload=1', f'-par={par}', '-assumevalid=0'])
            nodes.append(node)
            node.ready()
            node.rpc('setmocktime', 1800000000)
            miner = node.rpc('getnewaddress')
            legacy = bytes.fromhex(node.rpc('validateaddress', miner)['scriptPubKey'])
            node.rpc('generatetoaddress', 110, miner)
            log = (node.directory / 'regtest/debug.log').read_text()
            check(f'par{par}/threads', f'Using {0 if par == 1 else 2} threads for script verification' in log, par)
            for kind in ('CLTV_HEIGHT', 'CSV_HEIGHT', 'CLTV_TIME', 'CSV_TIME'):
                label = f'par{par}/{kind}'
                absolute, temporal = kind.startswith('CLTV'), kind.endswith('TIME')
                height = node.rpc('getblockcount') + 1
                coin_mtp = node.rpc('getblockchaininfo')['mediantime']
                target = coin_mtp + 512 if temporal else height + 2
                operand = target if absolute else (0x400001 if temporal else 3)
                locktime, sequence = (target, 0xfffffffe) if absolute else (0, operand)
                # The parent pays a spendable NoAuth OP_TRUE output, used only in isolated regtest.
                child_script = b'\x51'
                destination = b'\x51\x20' + program(child_script)
                contract = h.push(t.a.number(operand)) + bytes([0xb1 if absolute else 0xb2, 0x75])
                contract += b'\x00\xcd' + h.push(destination) + b'\x87'
                commitment = program(contract)
                funding = node.rpc('sendtoaddress', t.bech32m('tnq', 1, commitment), 1)
                node.rpc('generatetoaddress', 1, miner)
                funded = node.rpc('getrawtransaction', funding, True)
                index = next(o['n'] for o in funded['vout'] if o['scriptPubKey']['hex'] == (b'\x51\x20' + commitment).hex())
                utxo = funding, index
                if temporal:
                    node.rpc('setmocktime', target + int(absolute))
                    maturity = node.rpc('generatetoaddress', 6, miner)
                    check(label + '/maturity', node.rpc('getblockchaininfo')['mediantime'] == target + int(absolute), target)
                else:
                    maturity = node.rpc('generatetoaddress', 2, miner)
                    check(label + '/maturity', node.rpc('getblockcount') + 1 == height + 3, height + 3)
                mature_tip = node.rpc('getbestblockhash')
                parent = t.transaction(utxo, contract, destination, locktime, sequence)
                parent_id = node.rpc('sendrawtransaction', parent[1].hex())
                # Serialize a child paying 0.98 XNA, with a 0.01 XNA fee.
                inputs = b'\x01' + h.outpoint(parent_id, 0) + b'\x00' + b'\xff' * 4
                outputs = b'\x01' + t.b.output(98_000_000, legacy)
                witness = b'\x02\x01\x00\x01\x51'
                version, lock = struct.pack('<I', 2), bytes(4)
                child = (version + inputs + outputs + lock,
                         version + b'\x00\x01' + inputs + outputs + witness + lock)
                child_id = node.rpc('sendrawtransaction', child[1].hex())
                ids = {parent_id, child_id}
                check(label + '/pending_pair', set(node.rpc('getrawmempool')) == ids, sorted(ids))

                def rollback(stage):
                    node.rpc('invalidateblock', maturity[0])
                    info = node.rpc('getblockchaininfo')
                    check(label + '/' + stage + '/funding_tip', info['blocks'] == height, info['blocks'])
                    check(label + '/' + stage + '/immature',
                          info['mediantime'] < target if temporal else info['blocks'] + 1 <= target, info['mediantime'])
                    check(label + '/' + stage + '/evicted_with_child', node.rpc('getrawmempool') == [], node.rpc('getrawmempool'))
                    check(label + '/' + stage + '/utxos', node.rpc('gettxout', *utxo) is not None and
                          node.rpc('gettxout', parent_id, 0) is None and node.rpc('gettxout', child_id, 0) is None, parent_id)
                    try:
                        node.rpc('sendrawtransaction', parent[1].hex())
                        check(label + '/' + stage + '/readmission', False, 'accepted')
                    except h.RPCError as error:
                        expected = 'non-final' if absolute else 'non-BIP68-final'
                        check(label + '/' + stage + '/readmission', error.code == -26 and expected in str(error), str(error))
                    template = node.rpc('getblocktemplate', {'rules': ['segwit']})
                    check(label + '/' + stage + '/template', template['height'] == height + 1 and
                          not template['transactions'], len(template['transactions']))

                rollback('pending_rollback')
                node.rpc('reconsiderblock', maturity[0])
                check(label + '/restored_mature_tip', node.rpc('getbestblockhash') == mature_tip, mature_tip)
                check(label + '/parent_readmitted', node.rpc('sendrawtransaction', parent[1].hex()) == parent_id, parent_id)
                check(label + '/child_readmitted', node.rpc('sendrawtransaction', child[1].hex()) == child_id, child_id)
                confirmed_tip = node.rpc('generatetoaddress', 1, miner)[0]
                check(label + '/confirmed_pair', all(node.rpc('getrawtransaction', txid, True).get('confirmations') == 1 for txid in ids), sorted(ids))
                rollback('confirmed_rollback')
                node.rpc('reconsiderblock', maturity[0])
                check(label + '/confirmed_chain_restored', node.rpc('getbestblockhash') == confirmed_tip and
                      all(node.rpc('getrawtransaction', txid, True).get('confirmations') == 1 for txid in ids), confirmed_tip)
                final = node.rpc('gettxout', child_id, 0)
                check(label + '/final_state', node.rpc('getrawmempool') == [] and node.rpc('gettxout', *utxo) is None and
                      node.rpc('gettxout', parent_id, 0) is None and final is not None and
                      final['value'] == 0.98 and final['scriptPubKey']['hex'] == legacy.hex(), final)
                report['boundaries'].append({'par': par, 'kind': kind, 'funding_height': height,
                    'coin_mtp': coin_mtp, 'operand': operand, 'maturity_blocks': len(maturity)})
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
