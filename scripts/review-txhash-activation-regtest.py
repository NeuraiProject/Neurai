#!/usr/bin/env python3
"""NIP-042 candidate-height activation, block validation and ordinary reference reorgs."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import tempfile

spec = importlib.util.spec_from_file_location('txhash', Path(__file__).with_name('review-txhash-regtest.py'))
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
h = t.h
bspec = importlib.util.spec_from_file_location('blocks', Path(__file__).with_name('review-csfs-block-limit-regtest.py'))
b = importlib.util.module_from_spec(bspec)
bspec.loader.exec_module(b)


def address(script):
    tag = t._ctv.sha(b'NeuraiAuthScript')
    commitment = t._ctv.sha(tag + tag + b'\x01\x00' + t._ctv.sha(script))
    return t._ctv.bech32m('tnc', 1, commitment), b'\x51\x20' + commitment


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='txhash-activation-'))
    report = dict(results=[], binary_sha256=h.digest_file(args.bindir / 'neuraid'),
                  source_sha256={p.name: h.digest_file(p) for p in (Path(__file__),
                      Path(__file__).with_name('review-txhash-regtest.py'),
                      Path(__file__).with_name('review-introspection-regtest.py'),
                      Path(__file__).with_name('review-csfs-block-limit-regtest.py'))})
    nodes = []
    def check(label, ok, observed=None):
        report['results'].append(dict(case=label, passed=bool(ok), observed=observed))
        print(('PASS ' if ok else 'FAIL ') + label, flush=True)
        if not ok:
            raise RuntimeError(f'{label}: {observed}')
    def node(name, height, *extra):
        n = h.Node(args.bindir, directory / name, [f'-txhashheight={height}', '-bypassdownload=1', *extra])
        nodes.append(n)
        n.ready()
        return n
    def replay(n, blocks):
        for block in blocks:
            result = n.rpc('submitblock', block)
            if result is not None:
                raise RuntimeError(f'replay: {result}')
    try:
        source = node('source', 120)
        miner = source.rpc('getnewaddress', '', 'legacy')
        output = bytes.fromhex(source.rpc('validateaddress', miner)['scriptPubKey'])
        digest = bytes.fromhex('308542cb639a0e6ac414070f3be7c7e13827c7dde337c4d1202853376519fab1')
        contract = h.push(b'\x00\x01') + b'\xb5' + h.push(digest) + b'\x87'
        source.rpc('generatetoaddress', 116, miner)
        def fund(script, n=source):
            addr, spk = address(script)
            txid = n.rpc('sendtoaddress', addr, 1)
            n.rpc('generatetoaddress', 1, miner)
            decoded = n.rpc('getrawtransaction', txid, True)
            return txid, next(o['n'] for o in decoded['vout'] if o['scriptPubKey']['hex'] == spk.hex())
        utxo = fund(contract)  # height 117
        raw = h.transaction(utxo, contract, output)
        for label in ('before_activation',):
            result = source.rpc('testmempoolaccept', [raw])[0]
            check(label, not result.get('allowed') and 'NOPx' in str(result), result)
        history = [source.rpc('getblock', source.rpc('getblockhash', i), False) for i in range(1, 118)]
        producer = node('producer', 120)
        replay(producer, history)
        empty = producer.rpc('generatetoaddress', 2, miner)
        raw118, raw119 = [producer.rpc('getblock', block, False) for block in empty]
        replay(source, [raw118, raw119])
        txid = source.rpc('sendrawtransaction', raw)
        check('candidate120/admitted_at_tip119', txid in source.rpc('getrawmempool'), txid)
        template = source.rpc('getblocktemplate', {'rules': ['segwit']})
        check('candidate120/in_template', any(tx['txid'] == txid for tx in template['transactions']))
        # Honest proof of work and witness commitment, but one block too early.
        template.update(height=119, previousblockhash=empty[0])
        wire = bytes.fromhex(raw)
        witness_start = 4 + 2 + 1 + 41 + 1 + 8 + len(h.compact(len(output))) + len(output)
        stripped = wire[:4] + wire[6:witness_start] + bytes(4)
        bad119, _, _ = b.block(template, (stripped, wire))
        block120 = source.rpc('generatetoaddress', 1, miner)[0]
        raw120 = source.rpc('getblock', block120, False)
        check('active/confirmed', source.rpc('getrawtransaction', txid, True)['confirmations'] == 1)
        for par in (1, 2):
            validator = node(f'validator{par}', 120, '-disablewallet=1', f'-par={par}')
            replay(validator, history + [raw118])
            rejected = validator.rpc('submitblock', bad119.hex())
            check(f'par{par}/NOP_cannot_satisfy_hash', rejected is not None and
                  ('false' in rejected.lower() if par == 1 else rejected == 'block-validation-failed'), rejected)
            check(f'par{par}/tip_unchanged', validator.rpc('getbestblockhash') == empty[0])
            replay(validator, [raw119, raw120])
            check(f'par{par}/active_tip', validator.rpc('getbestblockhash') == block120)
        source.rpc('invalidateblock', empty[1])
        check('cross_down/tip118', source.rpc('getblockcount') == 118)
        check('cross_down/evicted', txid not in source.rpc('getrawmempool'))
        result = source.rpc('testmempoolaccept', [raw])[0]
        check('cross_down/readmission_rejected', not result.get('allowed'), result)
        source.rpc('reconsiderblock', empty[1])
        check('cross_up/confirmed_again', source.rpc('getrawtransaction', txid, True)['confirmations'] == 1)
        # Consensus-valid NOP spend admitted with the regtest-only relaxed
        # policy flag. This exercises the opposite direction: true before,
        # false after activation, including eviction of a cached success.
        forward = node('forward', 120, '-promiscuousmempoolflags=2049')
        replay(forward, history)
        forward.rpc('importprivkey', source.rpc('dumpprivkey', miner), '', True)
        nop_contract = h.push(b'\x00\x01') + b'\xb5' + h.push(b'\x00\x01') + b'\x87'
        nop_utxo = fund(nop_contract, forward)
        nop_raw = h.transaction(nop_utxo, nop_contract, output)
        nop_txid = forward.rpc('sendrawtransaction', nop_raw)
        check('cross_up/NOP_pending', nop_txid in forward.rpc('getrawmempool'))
        peer = node('forward_producer', 120)
        block118 = forward.rpc('getblock', forward.rpc('getblockhash', 118), False)
        replay(peer, history + [block118])
        next_hash = peer.rpc('generatetoaddress', 1, miner)[0]
        replay(forward, [peer.rpc('getblock', next_hash, False)])
        check('cross_up/NOP_success_evicted', nop_txid not in forward.rpc('getrawmempool'))
        result = forward.rpc('testmempoolaccept', [nop_raw])[0]
        check('cross_up/NOP_now_false', not result.get('allowed') and 'false' in str(result).lower(), result)
        forward.rpc('generatetoaddress', 1, miner)
        check('cross_up/mining_not_blocked', forward.rpc('getblockcount') == 120)
        # Reference absent after an ordinary reorg, then available again.
        # The contract gets its expected digest from the witness; this checks
        # reference availability independently of the fixed-digest covenant above.
        refcontract = h.push(b'\x00\x01') + b'\xb5\x87'
        refutxo = fund(refcontract)
        reference_tx = source.rpc('sendtoaddress', miner, 1)
        refblock = source.rpc('generatetoaddress', 1, miner)[0]
        reference_index = next(o['n'] for o in source.rpc('getrawtransaction', reference_tx, True)['vout'] if o['value'] == 1)
        refs = [(reference_tx, reference_index)]
        expected = t.field_hash(0x100, 3, 0, [h.outpoint(*refutxo)], [0xffffffff], [(99000000, output)], 0, [h.outpoint(*refs[0])])
        rawref = bytes.fromhex(h.transaction(refutxo, refcontract, output, refs))
        # Replace [NoAuth, script] by [NoAuth, expected digest, script].
        old = b'\x02\x01\x00' + h.compact(len(refcontract)) + refcontract + bytes(4)
        assert rawref.endswith(old)
        rawref = (rawref[:-len(old)] + b'\x03\x01\x00\x20' + expected + h.compact(len(refcontract)) + refcontract + bytes(4)).hex()
        refspend = source.rpc('sendrawtransaction', rawref)
        source.rpc('invalidateblock', refblock)
        check('refs/disappeared_evicted', refspend not in source.rpc('getrawmempool'))
        result = source.rpc('testmempoolaccept', [rawref])[0]
        check('refs/unconfirmed_reference_rejected', not result.get('allowed'), result)
        source.rpc('reconsiderblock', refblock)
        source.rpc('sendrawtransaction', rawref)
        check('refs/reappeared_admitted', refspend in source.rpc('getrawmempool'))
        source.rpc('generatetoaddress', 1, miner)
        check('refs/mined', source.rpc('getrawtransaction', refspend, True)['confirmations'] == 1)
        # Height one schedule: crossing tip 1 -> 0 still targets active block 1.
        one = node('height_one', 1)
        check('height1/genesis_candidate', one.rpc('getblocktemplate', {'rules': ['segwit']})['height'] == 1)
        first = one.rpc('generatetoaddress', 1, one.rpc('getnewaddress'))[0]
        one.rpc('invalidateblock', first)
        check('height1/rewind_to_genesis', one.rpc('getblockcount') == 0)
        check('height1/rewind_candidate', one.rpc('getblocktemplate', {'rules': ['segwit']})['height'] == 1)
        one.rpc('reconsiderblock', first)
        check('height1/reconnect', one.rpc('getblockcount') == 1)
        command = source.proc.args
        source.close()
        source.log = (source.directory / 'process.log').open('a')
        source.proc = subprocess.Popen(command, stdout=source.log, stderr=subprocess.STDOUT)
        source.ready()
        restart_utxo = fund(contract)
        restart_raw = h.transaction(restart_utxo, contract, output)
        result = source.rpc('testmempoolaccept', [restart_raw])[0]
        check('restart/active_rules_restored', result.get('allowed') == 1, result)
        invalid_dir = directory / 'invalid_option'
        invalid_dir.mkdir()
        for value in ('-1', '2147483648', '1.5', 'invalid'):
            proc = subprocess.run([str(args.bindir / 'neuraid'), '-regtest', f'-txhashheight={value}',
                                   f'-datadir={invalid_dir}'], text=True, capture_output=True, timeout=30)
            check('option/reject_' + value, proc.returncode != 0 and 'Invalid -txhashheight' in proc.stderr, proc.stderr.strip())
        proc = subprocess.run([str(args.bindir / 'neuraid'), '-txhashheight=1', f'-datadir={invalid_dir}'],
                              text=True, capture_output=True, timeout=30)
        check('option/mainnet_override_rejected', proc.returncode != 0 and 'only be overridden on regtest' in proc.stderr, proc.stderr.strip())

    except Exception as error:
        report['error'] = str(error)
        print('ERROR:', error, flush=True)
    finally:
        for n in reversed(nodes):
            n.close()
        report['passed'] = sum(r['passed'] for r in report['results'])
        report['failed'] = sum(not r['passed'] for r in report['results']) + int('error' in report)
        (directory / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print('Report:', directory / 'report.json', flush=True)
    return int(report['failed'] != 0)


if __name__ == '__main__':
    raise SystemExit(main())
