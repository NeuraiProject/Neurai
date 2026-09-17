#!/usr/bin/env python3
"""Signature opcode activation at height 120, candidate flags and reorg accounting.
Uses isolated nodes only. Testnet/mainnet schedules are never modified.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import tempfile

_spec = importlib.util.spec_from_file_location('ed_review', Path(__file__).with_name('review-ed25519-regtest.py'))
e = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(e)
h, c = e.h, e.c
_blockspec = importlib.util.spec_from_file_location("block_review", Path(__file__).with_name("review-csfs-block-limit-regtest.py"))
b = importlib.util.module_from_spec(_blockspec)
_blockspec.loader.exec_module(b)
from generate_authscript_vectors import bech32m, sha256


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='signature-height-'))
    report = {'results': [], 'binary_sha256': h.digest_file(args.bindir / 'neuraid'),
              'script_sha256': h.digest_file(Path(__file__))}
    nodes = []
    def check(case, passed, observed):
        report['results'].append({'case': case, 'passed': bool(passed), 'observed': observed})
        print(('PASS ' if passed else 'FAIL ') + case, flush=True)
        if not passed:
            raise RuntimeError(f'{case}: {observed}')
    try:
        source = h.Node(args.bindir, directory / 'source', ['-signatureopcodesheight=120', '-bypassdownload=1'])
        nodes.append(source)
        source.ready()
        miner = source.rpc('getnewaddress')
        source.rpc('generatetoaddress', 116, miner)
        # Branches remain valid before and after activation, but their cost changes.
        scripts = [b'\x00\x63' + bytes([op]) + b'\x68\x51' for op in (0xb4, 0xde, 0xdd)]
        scripts.append(h.push(e.PK) + b'\xdd')
        programs, payments = [], {}
        for script in scripts:
            tag = sha256(b'NeuraiAuthScript')
            program = sha256(tag + tag + b'\x01\x00' + sha256(script))
            programs.append(b'\x51\x20' + program)
            payments[bech32m('tnq', 1, program)] = 1
        funding = source.rpc('sendmany', '', payments)
        source.rpc('generatetoaddress', 1, miner)
        funded = source.rpc('getrawtransaction', funding, True)
        indices = {o['scriptPubKey']['hex']: o['n'] for o in funded['vout']}
        target = b'\x53\x20' + bytes(range(32))
        raws = [h.transaction((funding, indices[p.hex()]), script, target)
                for p, script in zip(programs[:3], scripts[:3])]
        ed_raw = c.transaction((funding, indices[programs[3].hex()]), scripts[3], e.SIG, b'', target)
        def reject_ed(label):
            result = source.rpc('testmempoolaccept', [ed_raw])[0]
            check(label, result.get('allowed') != 1 and 'Opcode missing or not understood' in str(result), result)
        reject_ed('height117/ed25519_disabled')
        txids = [source.rpc('sendrawtransaction', raw) for raw in raws]
        def template_costs(expected, label):
            txs = source.rpc('getblocktemplate', {'rules': ['segwit']})['transactions']
            costs = {t['txid']: t['sigops'] for t in txs}
            check(label, all(costs.get(txid) == expected for txid in txids), costs)
        template_costs(0, 'height117/old_costs')
        history = [source.rpc('getblock', source.rpc('getblockhash', i), False) for i in range(1, 118)]
        producer = h.Node(args.bindir, directory / 'producer', ['-signatureopcodesheight=120', '-bypassdownload=1'])
        nodes.append(producer)
        producer.ready()
        for raw in history:
            if producer.rpc('submitblock', raw) is not None:
                raise RuntimeError('producer rejected history')
        empty = producer.rpc('generatetoaddress', 2, miner)
        raw118, raw119 = [producer.rpc('getblock', block_hash, False) for block_hash in empty]
        check('connect118', source.rpc('submitblock', raw118) is None, empty[0])
        template_costs(0, 'height118/old_costs_preserved')
        reject_ed('height118/ed25519_disabled')
        check('connect119', source.rpc('submitblock', raw119) is None, empty[1])
        check('height119/stale_costs_evicted', not set(txids) & set(source.rpc('getrawmempool')), source.rpc('getrawmempool'))
        for raw in raws:
            source.rpc('sendrawtransaction', raw)
        template_costs(1, 'height119/new_costs')
        ed_txid = source.rpc('sendrawtransaction', ed_raw)
        check('height119/ed25519_admitted', ed_txid in source.rpc('getrawmempool'), ed_txid)
        # A wrong-height candidate contains valid witness/PoW but a disabled opcode.
        # Build a block at 119 on a validator still at 118, then the valid 120 block.
        before_template = source.rpc('getblocktemplate', {'rules': ['segwit']})
        before_template.update(height=119, previousblockhash=empty[0])
        # Do not claim fees from the other pending transactions.
        before_template['coinbasevalue'] = producer.rpc('getblocktemplate', {'rules': ['segwit']})['coinbasevalue']
        wire = bytes.fromhex(ed_raw)
        witness_start = 4 + 2 + 1 + 41 + 1 + 8 + 1 + len(target)
        stripped = wire[:4] + wire[6:witness_start] + bytes(4)
        bad119, _, _ = b.block(before_template, (stripped, wire))
        block120_hash = source.rpc('generatetoaddress', 1, miner)[0]
        raw120 = source.rpc('getblock', block120_hash, False)
        check('height120/ed25519_confirmed', source.rpc('getrawtransaction', ed_txid, True)['confirmations'] == 1, ed_txid)
        for par in (1, 2):
            validator = h.Node(args.bindir, directory / f'validator{par}',
                               ['-signatureopcodesheight=120', '-disablewallet=1', f'-par={par}'])
            nodes.append(validator)
            validator.ready()
            for raw in history + [raw118]:
                if validator.rpc('submitblock', raw) is not None:
                    raise RuntimeError('validator rejected pre-activation history')
            result = validator.rpc('submitblock', bad119.hex())
            expected = 'non-mandatory-script-verify-flag (Opcode missing or not understood)' if par == 1 else 'block-validation-failed'
            check(f'par{par}/reject119', result == expected, result)
            log = (validator.directory / 'regtest' / 'debug.log').read_text()
            check(f'par{par}/script_failure', ('Opcode missing or not understood' if par == 1 else 'CheckQueue failed') in log, expected)
            check(f'par{par}/reject_tip_unchanged', validator.rpc('getbestblockhash') == empty[0], validator.rpc('getbestblockhash'))
            for raw in [raw119, raw120]:
                result = validator.rpc('submitblock', raw)
                if result is not None:
                    raise RuntimeError(f'par{par} rejected block: {result}')
            check(f'par{par}/tip', validator.rpc('getbestblockhash') == block120_hash, block120_hash)
        source.rpc('invalidateblock', empty[1])
        check('reorg/height118', source.rpc('getblockcount') == 118, source.rpc('getblockcount'))
        check('reorg/ed25519_removed', ed_txid not in source.rpc('getrawmempool'), source.rpc('getrawmempool'))
        reject_ed('reorg/ed25519_disabled')
        # Re-broadcast the branch-only spends; any survivors must already have cost zero.
        for raw in raws:
            source.rpc('sendrawtransaction', raw)
        template_costs(0, 'reorg/old_costs_restored')
        source.rpc('reconsiderblock', empty[1])
        check('reconsider/tip120', source.rpc('getbestblockhash') == block120_hash, source.rpc('getbestblockhash'))
        check('reconsider/confirmed', source.rpc('getrawtransaction', ed_txid, True)['confirmations'] == 1, ed_txid)
        import subprocess
        command = source.proc.args
        source.close()
        source.log = (source.directory / 'process.log').open('a')
        source.proc = subprocess.Popen(command, stdout=source.log, stderr=subprocess.STDOUT)
        source.ready()
        check('restart/tip', source.rpc('getbestblockhash') == block120_hash, source.rpc('getbestblockhash'))
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
