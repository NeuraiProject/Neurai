#!/usr/bin/env python3
"""Poseidon work: exact block/policy limits, envelopes, reorg, caches and mining.
Disposable disconnected regtests only; no external networks or existing wallets.
"""
import argparse
import base64
import urllib.request
import urllib.error
import importlib.util
import json
from pathlib import Path
import struct
import socket
from review_tree_compact import Peer
import subprocess
import tempfile
import time

spec = importlib.util.spec_from_file_location('density', Path(__file__).with_name('review-nip046-poseidon-density-regtest.py'))
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)
r = d.r
BLOCK_LIMIT = 200000
TX_LIMIT = 20000


class WorkTestNode(r.h.Node):
    # Reorg readmission performs several full validation passes. Record its
    # duration; a 30s transport deadline is not a resource acceptance limit.
    def rpc(self, method, *params):
        payload = json.dumps({'jsonrpc': '1.0', 'id': 'work', 'method': method, 'params': params}).encode()
        auth = base64.b64encode(b'review:disposable-regtest').decode()
        request = urllib.request.Request(f'http://127.0.0.1:{self.port}', payload,
                                         {'Authorization': 'Basic ' + auth})
        try:
            response = urllib.request.urlopen(request, timeout=180)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            reply = json.load(response)
        if reply.get('error'):
            raise r.h.RPCError(reply['error'])
        return reply['result']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    parser.add_argument('--compact', action='store_true')
    parser.add_argument('--promiscuous', action='store_true', help='Exercise admission with witness omitted from the first policy check')
    parser.add_argument('--envelope', choices=('native', 'p2sh', 'mast'), default='native')
    args = parser.parse_args()
    directory = Path(tempfile.mkdtemp(prefix='poseidon-work-'))
    nodes = []
    report = {'envelope': args.envelope, 'promiscuous': args.promiscuous, 'results': [], 'measurements': [],
              'binary_sha256': r.h.digest_file(args.bindir / 'neuraid'),
              'driver_sha256': r.h.digest_file(Path(__file__))}

    def check(name, ok, observed=None):
        report['results'].append(dict(case=name, passed=bool(ok), observed=observed))
        print(('PASS ' if ok else 'FAIL ') + name, flush=True)
        if not ok:
            raise RuntimeError(f'{name}: {observed}')

    def node(name, par):
        extra = ['-promiscuousmempoolflags=0'] if args.promiscuous else []
        port = None
        if args.compact and name.startswith('validator'):
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            extra += ['-listen=1', f'-port={port}', f'-bind=127.0.0.1:{port}', '-debug=net']
        n = WorkTestNode(args.bindir, directory / name,
                     ['-bypassdownload=1', '-poseidonworkheight=630', '-acceptnonstdtxn=0',
                      '-minrelaytxfee=0.00001', f'-par={par}', *extra])
        n.p2p_port = port
        nodes.append(n)
        n.ready()
        return n

    def candidate(n, transactions, time_delta=0):
        template = n.rpc('getblocktemplate', {'rules': ['segwit']})
        # Custom blocks may omit the mempool: never claim its unearned fees.
        template['coinbasevalue'] = 0
        template['curtime'] += time_delta
        wires = [bytes.fromhex(tx) for tx in transactions]
        return d.build(template, [(r.strip_witness(wire) if wire[4:6] == b'\x00\x01' else wire, wire)
                                  for wire in wires])

    def submit(n, block, label):
        start = time.perf_counter()
        result = d.submit_slow(n, block)
        report['measurements'].append(dict(case=label, seconds=time.perf_counter()-start, result=result))
        return result

    try:
        n = node('source', 1)
        miner = n.rpc('getnewaddress', '', 'legacy')
        pay = bytes.fromhex(n.rpc('validateaddress', miner)['scriptPubKey'])
        n.rpc('generatetoaddress', 610, miner)

        def contract(calls, override=None):
            script = override if override is not None else b'\xc9' * calls + b'\x75\x51'
            addr, spk = r.address(script)
            witness = [b'\x00', b'', script]
            redeem = None
            if args.envelope == 'mast':
                tag = r.sha(b'NeuraiAuthLeaf')
                leaf = r.sha(tag + tag + b'\x01' + r.h.compact(len(script)) + script)
                tag = r.sha(b'NeuraiAuthScript')
                commitment = r.sha(tag + tag + b'\x04\x00' + leaf)
                spk = b'\x51\x20' + commitment
                witness = [b'\x10', b'', script, b'\x01']
            elif args.envelope == 'p2sh':
                redeem = spk
                addr = n.rpc('decodescript', redeem.hex())['p2sh']
                spk = bytes.fromhex(n.rpc('validateaddress', addr)['scriptPubKey'])
            return spk, witness, redeem

        large = contract(500)
        small = contract(1)
        context = contract(0, b'\x51\xd7'+r.h.push((630).to_bytes(2,'little'))+b'\xa0\x63\xc9\x68\xc9\x75\x51')
        # 400 large inputs reach exactly 200000 units, plus a one-unit input.
        raw = struct.pack('<I', 2) + b'\x00' + r.h.compact(402)
        raw += r.b.output(200000000, large[0]) * 400 + r.b.output(200000000, small[0]) + r.b.output(200000000, context[0]) + bytes(4)
        funded = n.rpc('fundrawtransaction', raw.hex(), {'feeRate': 0.001})
        signed = n.rpc('signrawtransaction', funded['hex'])
        check('funding/signed', signed['complete'])
        funding = n.rpc('sendrawtransaction', signed['hex'])
        n.rpc('generatetoaddress', 1, miner)
        outs = n.rpc('getrawtransaction', funding, True)['vout']
        large_coins = [(funding, x['n']) for x in outs if x['scriptPubKey']['hex'] == large[0].hex()]
        small_coins = [(funding, x['n']) for x in outs if x['scriptPubKey']['hex'] == small[0].hex()]
        context_coins = [(funding, x['n']) for x in outs if x['scriptPubKey']['hex'] == context[0].hex()]
        check('funding/count', len(large_coins) == 400 and len(small_coins) == 1 and len(context_coins) == 1)

        def spend(coins, c, contracts=None):
            contracts = contracts or [c]*len(coins)
            inputs = []
            witnesses = []
            for coin, (_, witness, redeem) in zip(coins, contracts):
                script_sig = r.h.push(redeem) if redeem else b''
                inputs.append(r.h.outpoint(*coin) + r.h.compact(len(script_sig)) + script_sig + b'\xff'*4)
                witnesses.append(r.h.compact(len(witness)) + b''.join(r.h.compact(len(x))+x for x in witness))
            result = struct.pack('<I', 2) + b'\x00\x01' + r.h.compact(len(coins)) + b''.join(inputs)
            result += b'\x01' + r.b.output(len(coins)*200000000-1000000, pay)
            return (result + b''.join(witnesses) + bytes(4)).hex()

        exact = [spend(large_coins[i:i+40], large) for i in range(0, 400, 40)]
        extra = spend(small_coins, small)
        heavy = spend(large_coins[:41], large)
        policy_over = spend(large_coins[:40]+small_coins, large, [large]*40+[small])
        n.rpc('generatetoaddress', 628-n.rpc('getblockcount'), miner)
        validators = [node('validator1', 1), node('validator2', 2)]
        for height in range(1, 629):
            block = n.rpc('getblock', n.rpc('getblockhash', height), False)
            for v in validators:
                result = v.rpc('submitblock', block)
                if result is not None:
                    raise RuntimeError(f'base replay {height}: {result}')
        check('before/policy_20500_allowed', n.rpc('testmempoolaccept', [heavy])[0].get('allowed'))
        heavy_id = n.rpc('sendrawtransaction', heavy)
        check('before/cost_recorded', n.rpc('getmempoolentry', heavy_id)['poseidonwork'] == 20500)
        child = n.rpc('signrawtransaction', r.a.raw_transaction([(heavy_id, 0)],
                    [(41*200000000-2000000, pay)], [], [[]]))['hex']
        child_id = n.rpc('sendrawtransaction', child)
        old, old_hash, _ = candidate(n, exact + [extra])
        for v in validators:
            result = submit(v, old, v.directory.name + '/before/200001')
            check(v.directory.name + '/before/200001_accepted', result is None, result)
            started = time.perf_counter()
            v.rpc('invalidateblock', old_hash)
            report['measurements'].append(dict(case=v.directory.name+'/reorg_readmission', seconds=time.perf_counter()-started))
        empty, boundary, _ = candidate(n, [])
        check('activation/empty629', n.rpc('submitblock', empty.hex()) is None)
        check('activation/heavy_and_descendant_evicted', heavy_id not in n.rpc('getrawmempool') and child_id not in n.rpc('getrawmempool'))
        result = n.rpc('testmempoolaccept', [heavy])[0]
        check('activation/policy_20500_rejected', not result.get('allowed') and 'poseidon-work' in str(result), result)
        result = n.rpc('testmempoolaccept', [policy_over])[0]
        check('activation/policy_20001_rejected', not result.get('allowed') and 'poseidon-work' in str(result), result)
        n.rpc('invalidateblock', boundary)
        check('reorg/down_policy_restored', n.rpc('testmempoolaccept', [heavy])[0].get('allowed'))
        n.rpc('sendrawtransaction', heavy)
        n.rpc('sendrawtransaction', child)
        n.rpc('reconsiderblock', boundary)
        check('reorg/up_evicts_again', heavy_id not in n.rpc('getrawmempool') and child_id not in n.rpc('getrawmempool'))
        for v in validators:
            check(v.directory.name + '/activation/empty629', v.rpc('submitblock', empty.hex()) is None)
        context_wire = spend(context_coins, context)
        context_id = n.rpc('sendrawtransaction', context_wire)
        check('context/cost_before_height_change', n.rpc('getmempoolentry', context_id)['poseidonwork'] == 1)
        context_child = n.rpc('signrawtransaction', r.a.raw_transaction([(context_id, 0)], [(198000000, pay)], [], [[]]))['hex']
        context_child_id = n.rpc('sendrawtransaction', context_child)
        main_ids = []
        for wire in exact:
            result = n.rpc('testmempoolaccept', [wire])[0]
            check('policy/exact20000', result.get('allowed'), result)
            txid = n.rpc('sendrawtransaction', wire)
            main_ids.append(txid)
            check('mempool/exact_cost', n.rpc('getmempoolentry', txid)['poseidonwork'] == TX_LIMIT)
        main_ids.append(n.rpc('sendrawtransaction', extra))
        template = n.rpc('getblocktemplate', {'rules': ['segwit']})
        costs = [n.rpc('getmempoolentry', tx['txid'])['poseidonwork'] for tx in template['transactions']]
        check('miner/cap_and_omission', sum(costs) <= BLOCK_LIMIT and len(set(main_ids) & {tx['txid'] for tx in template['transactions']}) < 11, costs)
        over, _, _ = candidate(n, exact+[extra])
        good, good_hash, _ = candidate(n, exact)
        policy_only, policy_only_hash, _ = candidate(n, [heavy])
        for v in validators:
            result = submit(v, over, v.directory.name + '/active/200001')
            check(v.directory.name + '/active/200001_rejected', result == 'bad-blk-poseidon-work', result)
            if args.compact:
                compact_bad, _, _ = candidate(n, exact+[extra], 1)
                wires = [bytes.fromhex(tx) for tx in exact+[extra]]
                assert compact_bad[80] == len(wires)+1 < 253
                coinbase = compact_bad[81:-sum(map(len, wires))]
                payload = compact_bad[:80] + struct.pack('<Q', 47) + b'\x00' + r.h.compact(len(wires)+1)
                payload += b'\x00' + coinbase + b''.join(b'\x00'+wire for wire in wires)
                peer = Peer(v.p2p_port)
                try:
                    peer.sock.settimeout(90)
                    peer.send('cmpctblock', payload)
                    rejection = peer.until('reject')
                    reason = b'bad-blk-poseidon-work'
                    expected_rejection = b'\x05block\x10' + r.h.compact(len(reason)) + reason + d.D(compact_bad[:80])
                    check(v.directory.name+'/compact/200001_rejected',
                          rejection == expected_rejection and v.rpc('getblockcount') == 629, rejection.hex())
                finally:
                    peer.sock.close()
            check(v.directory.name + '/consensus/tx20500_accepted',
                  submit(v, policy_only, v.directory.name + '/consensus/tx20500') is None)
            v.rpc('invalidateblock', policy_only_hash)
            check(v.directory.name + '/policy/tx20500_not_readmitted',
                  heavy_id not in v.rpc('getrawmempool'))
            result = submit(v, good, v.directory.name + '/active/200000')
            check(v.directory.name + '/active/200000_accepted', result is None and v.rpc('getbestblockhash') == good_hash, result)
        check('source/warm200000_accepted', submit(n, good, 'source/warm200000') is None)
        check('context/changed_cost_and_descendant_evicted', context_id not in n.rpc('getrawmempool') and context_child_id not in n.rpc('getrawmempool'))
        context_id = n.rpc('sendrawtransaction', context_wire)
        check('context/readmission_new_cost', n.rpc('getmempoolentry', context_id)['poseidonwork'] == 2)
        n.rpc('invalidateblock', good_hash)
        check('context/reorg_changed_cost_evicted', context_id not in n.rpc('getrawmempool'))
        template = n.rpc('getblocktemplate', {'rules': ['segwit']})
        work = sum(n.rpc('getmempoolentry', tx['txid'])['poseidonwork'] for tx in template['transactions'])
        check('reorg/readmission_template_cap', work <= BLOCK_LIMIT, work)
        n.close()
        n.log = (n.directory/'restart.log').open('w')
        n.proc = subprocess.Popen(n.proc.args, stdout=n.log, stderr=subprocess.STDOUT)
        n.ready()
        template = n.rpc('getblocktemplate', {'rules': ['segwit']})
        work = sum(n.rpc('getmempoolentry', tx['txid'])['poseidonwork'] for tx in template['transactions'])
        check('restart/mempool_costs_and_template', work <= BLOCK_LIMIT and n.rpc('getblockcount') == 629, work)
        mined = n.rpc('generatetoaddress', 1, miner)[0]
        check('miner/valid_block', n.rpc('getbestblockhash') == mined)
        # A height-aware contract can spend an unconfirmed parent. Tip sweeps
        # must use the mempool view, and must not assert when a disconnect
        # temporarily removes a confirmed parent before readmission.
        coin = next(u for u in n.rpc('listunspent', 1) if u['amount'] > 3)
        amount = round(coin['amount'] * r.h.COIN)
        parent_raw = r.a.raw_transaction([(coin['txid'], coin['vout'])],
                     [(200000000, context[0]), (amount-201000000, pay)], [], [[]])
        signed_parent = n.rpc('signrawtransaction', parent_raw)
        check('unconfirmed/parent_signed', signed_parent['complete'])
        parent_wire = signed_parent['hex']
        parent_id = n.rpc('sendrawtransaction', parent_wire)
        pending_wire = spend([(parent_id, 0)], context)
        pending_id = n.rpc('sendrawtransaction', pending_wire)
        check('unconfirmed/context_cost', n.rpc('getmempoolentry', pending_id)['poseidonwork'] == 2)
        grandchild = n.rpc('signrawtransaction', r.a.raw_transaction([(pending_id, 0)], [(198000000, pay)], [], [[]]))['hex']
        grandchild_id = n.rpc('sendrawtransaction', grandchild)
        empty_next, _, _ = candidate(n, [])
        check('unconfirmed/empty_block', n.rpc('submitblock', empty_next.hex()) is None)
        check('unconfirmed/context_and_descendant_retained', {parent_id, pending_id, grandchild_id}.issubset(set(n.rpc('getrawmempool'))))
        parent_block, parent_block_hash, _ = candidate(n, [parent_wire])
        check('unconfirmed/parent_confirmed', n.rpc('submitblock', parent_block.hex()) is None)
        n.rpc('invalidateblock', parent_block_hash)
        pool = set(n.rpc('getrawmempool'))
        check('unconfirmed/disconnect_parent_readmitted_children_evicted', parent_id in pool and pending_id not in pool and grandchild_id not in pool)
        pending_id = n.rpc('sendrawtransaction', pending_wire)
        check('unconfirmed/child_can_be_resubmitted', n.rpc('getmempoolentry', pending_id)['poseidonwork'] == 2)
        report['success'] = True
    except Exception as error:
        report['error'] = str(error)
        print('ERROR ' + str(error), flush=True)
    finally:
        for n in reversed(nodes):
            n.close()
        (directory/'report.json').write_text(json.dumps(report, indent=2)+'\n')
        print('REPORT ' + str(directory/'report.json'), flush=True)
    return int(not report.get('success'))


if __name__ == '__main__':
    raise SystemExit(main())
