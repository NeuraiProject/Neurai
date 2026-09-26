#!/usr/bin/env python3
"""Mixed-resource screening on disposable regtests; real executed internal signatures.
No mainnet thresholds. Repeated verifychain samples are not cold first receptions.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import statistics
import struct
import subprocess
import tempfile
import time
import traceback


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


d = module('mixed_density', 'review-nip046-poseidon-density-regtest.py')
w = module('mixed_work', 'review-poseidon-work-regtest.py')
r, h = d.r, d.r.h


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    parser.add_argument('--signer', type=Path, default=Path('/tmp/authscript-review-signer'))
    parser.add_argument('--profile', choices=['mixed', 'mixed-ecdsa', 'mixed-pq', 'saturation-ecdsa', 'saturation-pq', 'checksigadd-ecdsa', 'checksigadd-pq', 'ed25519'], required=True)
    parser.add_argument('--par', type=int, choices=[1, 2], default=1)
    parser.add_argument('--cache-mib', type=int, choices=[0, 32], default=0)
    parser.add_argument('--samples', type=int, default=5)
    args = parser.parse_args()
    if args.samples < 1:
        parser.error('samples must be positive')
    directory = Path(tempfile.mkdtemp(prefix='mixed-resources-'))
    nodes = []
    report = dict(profile=args.profile, par=args.par, cache_mib=args.cache_mib,
                  binary_sha256=h.digest_file(args.bindir/'neuraid'),
                  driver_sha256=h.digest_file(Path(__file__)),
                  signer_sha256=h.digest_file(args.signer), results=[], measurements=[], samples=[],
                  scope='Functional and resource screening, one warmup; no approved performance threshold')

    def check(name, ok, observed=None):
        report['results'].append(dict(case=name, passed=bool(ok), observed=observed))
        print(('PASS ' if ok else 'FAIL ')+name, flush=True)
        if not ok:
            raise RuntimeError(f'{name}: {observed}')

    def node(name):
        n = w.WorkTestNode(args.bindir, directory/name,
                          ['-bypassdownload=1', '-acceptnonstdtxn=0', '-minrelaytxfee=0.00001',
                           '-poseidonworkheight=0', '-authscriptbudgetheight=0', f'-par={args.par}',
                           f'-maxsigcachesize={args.cache_mib}'])
        nodes.append(n)
        n.ready()
        return n

    def measured(n, label, method, *params):
        cpu, _ = d.l.counters(n.proc.pid)
        start = time.perf_counter()
        result = n.rpc(method, *params)
        elapsed = time.perf_counter()-start
        after, rss = d.l.counters(n.proc.pid)
        report['measurements'].append(dict(case=label, wall_s=elapsed, daemon_cpu_s=after-cpu, daemon_hwm_kib=rss))
        return result

    try:
        checksigadd = args.profile.startswith('checksigadd-')
        ed25519 = args.profile == 'ed25519'
        family = 'pq' if args.profile.endswith('-pq') else 'ecdsa' if args.profile.endswith('-ecdsa') else None
        pub, secret = b'', ''
        if family:
            public, secret = subprocess.check_output([str(args.signer), 'keygen', family], text=True).splitlines()
            pub = bytes.fromhex(public)
        if ed25519:
            ed = module('mixed_ed', 'review-ed25519-regtest.py')
            pub = ed.PK
        saturation = args.profile.startswith('saturation-') or checksigadd or ed25519
        if saturation:
            # Keep sig/msg/pub on the stack: 3DUP executes a real CSFS on each
            # iteration. CheckSigFromStack has no signature-cache shortcut.
            script = b'\xc9'*200+b'\x75'+b'\x6f\xb4\x69'*100+b'\x6d\x75\x69\x51'
            main_work, signatures, classic, ops = 200, 100, 9600, 504
            count, fillers = 760, 96  # 200000 work; 79424 tx sigops, leaves miner reserve.
        else:
            # Copy 3072 B fifty times. Reuse it for twenty SHA256 calls; the
            # final shorter buffer leaves room for CSFS's 96 classic units.
            script = b'\x76\x75'*50 + b'\x76\xa8\x75'*20 + b'\x75\xa8\x75'
            script += b'\xc9'*300+b'\x75'
            if family:
                script += h.push(pub)+b'\xb4\x69'
            script += b'\x69\x51'  # late guard, after all work and signatures
            main_work, signatures, classic, ops = 300, int(bool(family)), 65536, 465+2*bool(family)
            count, fillers = 666, 0
        if checksigadd:
            script = b'\xc9'*50+b'\x75'+b'\x6f\xde\x51\x9d'*40+b'\x6d\x75\x69\x51'
            main_work, signatures, classic, ops = 50, 40, 0, 494
            count, fillers = 1700, 230
        if ed25519:
            script = script.replace(b'\xb4', b'\xdd')
            classic = 0
        filler_script = b'\xc9'*500+b'\x75\x69\x51'
        address, spk = r.address(script)
        _, filler_spk = r.address(filler_script)
        expected_work = count*main_work+fillers*500
        expected_sigops = count*(signatures+4)+fillers*4
        report['workload'] = dict(main_transactions=count, filler_transactions=fillers,
            poseidon_work=expected_work, tx_sigops=expected_sigops,
            executed_signatures=count*signatures, unique_signatures=count if family else 1 if ed25519 else 0,
            main_classic_units=classic, main_opcodes=ops, main_script_bytes=len(script),
            reused_signature_per_input=saturation, witness_family='native v1 NoAuth')
        check('model/budgets', expected_work <= 200000 and expected_sigops+400 < 80000 and ops <= 512)
        n = node('source')
        miner = n.rpc('getnewaddress', '', 'legacy')
        pay = bytes.fromhex(n.rpc('validateaddress', miner)['scriptPubKey'])
        n.rpc('generatetoaddress', 610, miner)
        funding_raw = struct.pack('<I', 2)+b'\x00'+h.compact(count+fillers)
        funding_raw += r.b.output(200000000, spk)*count+r.b.output(200000000, filler_spk)*fillers+bytes(4)
        funded = n.rpc('fundrawtransaction', funding_raw.hex(), {'feeRate': 0.001})
        signed = n.rpc('signrawtransaction', funded['hex'])
        check('funding/signed', signed['complete'])
        funding_id = n.rpc('sendrawtransaction', signed['hex'])
        n.rpc('generatetoaddress', 1, miner)
        outs = n.rpc('getrawtransaction', funding_id, True)['vout']
        main_coins = [(funding_id, o['n']) for o in outs if o['scriptPubKey']['hex'] == spk.hex()]
        filler_coins = [(funding_id, o['n']) for o in outs if o['scriptPubKey']['hex'] == filler_spk.hex()]
        check('funding/count', len(main_coins) == count and len(filler_coins) == fillers)
        entries = []
        for coin in main_coins:
            msg = r.sha(b'Neurai/mixed-resource-test/'+h.outpoint(*coin))
            sig = bytes.fromhex(subprocess.check_output([str(args.signer), 'sign', family],
                  input=secret+'\n'+r.sha(msg).hex()+'\n', text=True).strip()) if family else b''
            if checksigadd:
                prevout = h.outpoint(*coin)
                sequence = b'\xff'*4
                preimage = (struct.pack('<I', 3)+r.b.hash256(prevout)+r.b.hash256(sequence)+prevout+
                    h.compact(len(script))+script+struct.pack('<Q', 200000000)+sequence+
                    r.b.hash256(r.b.output(190000000, pay))+r.b.hash256(b'')+bytes(4)+b'\x00'+struct.pack('<I', 1))
                sig = bytes.fromhex(subprocess.check_output([str(args.signer), 'sign', family],
                    input=secret+'\n'+r.b.hash256(preimage).hex()+'\n', text=True).strip())
                msg = b''  # CHECKSIGADD starts its counter at zero.
            if ed25519:
                sig, msg = ed.SIG, b''
            arguments = [b'\x01']
            if family or ed25519:
                arguments += [sig, msg]
            if saturation:
                arguments += [pub, b'']
            else:
                arguments += [b'', b'\x42'*(2656 if family else 2752), b'\x42'*3072]
            entries.append((coin, script, arguments, main_work))
        # Last serialized transaction has both expensive work and a late guard.
        last = entries.pop()
        entries += [(coin, filler_script, [b'\x01', b''], 500) for coin in filler_coins]
        entries.append(last)

        def wire(entry, bad_guard=False, bad_message=False):
            coin, leaf, arguments, _ = entry
            arguments = list(arguments)
            if bad_guard:
                arguments[0] = b''
            if bad_message:
                arguments[2] = bytes([arguments[2][0] ^ 1])+arguments[2][1:] if arguments[2] else b'\x01'
            return bytes.fromhex(r.a.raw_transaction([coin], [(190000000, pay)], [], [[b'\x00', *arguments, leaf]]))

        wires = [wire(e) for e in entries]
        bad = wire(last, bad_guard=True)
        check('negative/same_txid_different_witness', r.strip_witness(bad) == r.strip_witness(wires[-1]) and bad != wires[-1])
        result = measured(n, 'late_guard_mempool', 'testmempoolaccept', [bad.hex()])[0]
        check('negative/late_guard_mempool', not result.get('allowed') and 'Script failed an OP_VERIFY operation' in result.get('reject-reason', ''), result)
        if family or ed25519:
            result = measured(n, 'bad_message_mempool', 'testmempoolaccept', [wire(last, bad_message=True).hex()])[0]
            check('negative/counter_is_checked' if checksigadd else 'negative/message_is_authenticated',
                  not result.get('allowed') and ('NUMEQUALVERIFY' if checksigadd else 'Script failed an OP_VERIFY operation' if ed25519 else 'signature') in
                  (result.get('reject-reason', '') if checksigadd or ed25519 else result.get('reject-reason', '').lower()), result)
            if checksigadd:
                tampered = wires[-1].replace(struct.pack('<Q', 190000000), struct.pack('<Q', 189000000), 1)
                result = measured(n, 'bad_output_mempool', 'testmempoolaccept', [tampered.hex()])[0]
                check('negative/output_is_authenticated', not result.get('allowed') and 'signature' in result.get('reject-reason', '').lower(), result)
        history = [n.rpc('getblock', n.rpc('getblockhash', height), False) for height in range(1, n.rpc('getblockcount')+1)]
        template = n.rpc('getblocktemplate', {'rules': ['segwit']})
        template['coinbasevalue'] = 0
        good, good_hash, weight = d.build(template, [(r.strip_witness(x), x) for x in wires])
        invalid_wires = wires[:-1]+[bad]
        invalid, _, _ = d.build(template, [(r.strip_witness(x), x) for x in invalid_wires])
        report['workload']['block_weight'] = weight
        check('model/weight', weight < 7900000, weight)
        ids = [n.rpc('sendrawtransaction', x.hex()) for x in wires]
        costs = [n.rpc('getmempoolentry', txid)['poseidonwork'] for txid in ids]
        check('mempool/work_matches_model', costs == [e[3] for e in entries], sum(costs))
        template = measured(n, 'warm_template', 'getblocktemplate', {'rules': ['segwit']})
        chosen = {x['txid'] for x in template['transactions']}
        check('miner/all_transactions', set(ids) == chosen, len(chosen))
        check('miner/sigops_match_model', sum(x['sigops'] for x in template['transactions']) == expected_sigops)
        v = node('validator')
        for previous in history:
            result = v.rpc('submitblock', previous)
            if result is not None:
                raise RuntimeError('history replay: '+str(result))
        original_tip = v.rpc('getbestblockhash')
        check('validator/empty_mempool', not v.rpc('getrawmempool'))

        def rejects(label, raw):
            log = v.directory/'regtest'/'debug.log'
            offset = log.stat().st_size
            result = measured(v, label, 'submitblock', raw.hex())
            diagnostics = log.read_bytes()[offset:]
            expected = ('mandatory-script-verify-flag-failed (Script failed an OP_VERIFY operation)',
                        'non-mandatory-script-verify-flag (Script failed an OP_VERIFY operation)',
                        'block-validation-failed')
            # The worker queue exposes only block-validation-failed, whereas
            # synchronous CheckInputs logs the exact script error. The same
            # witness mutation was checked independently through admission.
            check(label, result in expected and (args.par == 2 or b'Script failed an OP_VERIFY operation' in diagnostics) and
                  v.rpc('getbestblockhash') == original_tip, result)

        rejects('negative/cold_block_late_guard', invalid)
        result = measured(v, 'first_valid_block', 'submitblock', good.hex())
        check('block/valid_after_invalid_same_txid', result is None and v.rpc('getbestblockhash') == good_hash, result)
        for i in range(1+args.samples):
            ok = measured(v, f'verifychain/{i}', 'verifychain', 4, 1)
            check(f'verifychain/{i}', ok)
            if i:
                report['samples'].append(report['measurements'][-1])
        measured(v, 'reorg_readmission', 'invalidateblock', good_hash)
        check('reorg/readmitted_costs', set(ids) == set(v.rpc('getrawmempool')) and
              sum(v.rpc('getmempoolentry', txid)['poseidonwork'] for txid in ids) == expected_work)
        warm_template = v.rpc('getblocktemplate', {'rules': ['segwit']})
        warm_template['coinbasevalue'] = 0
        warm_template['curtime'] += 1
        warm_invalid, _, _ = d.build(warm_template, [(r.strip_witness(x), x) for x in invalid_wires])
        rejects('negative/warm_block_late_guard', warm_invalid)
        v.rpc('reconsiderblock', good_hash)
        check('reorg/valid_restored', v.rpc('getbestblockhash') == good_hash)
        result = measured(n, 'source_warm_valid_block', 'submitblock', good.hex())
        check('source/warm_block_valid', result is None and n.rpc('getbestblockhash') == good_hash, result)
        for field in ('wall_s', 'daemon_cpu_s', 'daemon_hwm_kib'):
            values = [s[field] for s in report['samples']]
            report.setdefault('summary', {})[field] = dict(median=statistics.median(values), maximum=max(values))
        report['success'] = True
    except Exception as error:
        report['error'] = str(error)
        report['traceback'] = traceback.format_exc()
        print('ERROR '+report['traceback'], flush=True)
    finally:
        for n in reversed(nodes):
            n.close()
        (directory/'report.json').write_text(json.dumps(report, indent=2)+'\n')
        print('REPORT '+str(directory/'report.json'), flush=True)
    return int(not report.get('success'))


if __name__ == '__main__':
    raise SystemExit(main())
