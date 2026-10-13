#!/usr/bin/env python3
"""Privacy-pool transport: unregistered threads, witnesses, cursors and reorgs.

Synthetic AuthScript contracts exercise transport, not privacy cryptography.
Real C6 chain coverage is provided by the separate fixture replay review.
"""
import copy
import hashlib
import json
from pathlib import Path
import struct
import time

from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error

COIN = 100_000_000


def compact(n):
    if n < 253:
        return bytes([n])
    if n <= 65535:
        return b'\xfd' + struct.pack('<H', n)
    return b'\xfe' + struct.pack('<I', n)


def output(value, script):
    return struct.pack('<q', value) + compact(len(script)) + script


def program(leaf):
    tag = hashlib.sha256(b'NeuraiAuthScript').digest()
    return b'\x51\x20' + hashlib.sha256(tag + tag + b'\x01\x00' + hashlib.sha256(leaf).digest()).digest()


class PrivacyPoolTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [['-txindex=1', '-spentindex=1', '-bypassdownload=1'],
                           ['-txindex=1', '-bypassdownload=1']]

    def add_options(self, parser):
        parser.add_option('--report', help='Save assertions and measurements as JSON')

    def run_test(self):
        node = self.nodes[0]
        checks = []
        report = {'success': False, 'scope': __doc__, 'checks': checks, 'measurements': {}}

        def check(label, condition):
            assert condition, label
            checks.append(label)
            self.log.info('PASS %s', label)

        miner = node.getnewaddress('', 'legacy')
        pay = bytes.fromhex(node.validateaddress(miner)['scriptPubKey'])
        node.generatetoaddress(110, miner)
        leaf = b'\x75' * 10 + b'\x51'
        script = program(leaf)

        def fund(vout=0):
            outputs = [(COIN, pay)] * vout + [(500 * COIN, script)]
            raw = struct.pack('<I', 2) + b'\x00' + compact(len(outputs))
            raw += b''.join(output(*item) for item in outputs) + bytes(4)
            funded = node.fundrawtransaction(raw.hex(), {'changePosition': len(outputs)})
            signed = node.signrawtransaction(funded['hex'])
            assert signed['complete']
            return {'txid': node.sendrawtransaction(signed['hex'], True), 'vout': vout}

        def transition(point, value, number, *, ambiguous=False, terminal=False, nonzero_input=False):
            # Public, deliberately non-private bytes. The transport must preserve
            # every witness byte even when it cannot interpret the publication.
            payloads = [hashlib.sha256(('TEST %d/%d' % (number, i)).encode()).digest() * 64 for i in range(10)]
            points = [point]
            if nonzero_input:
                coin = next(c for c in node.listunspent() if c['amount'] > 2)
                points.insert(0, {'txid': coin['txid'], 'vout': coin['vout']})
                value += int(coin['amount'] * COIN)
            vout = 1 if number % 2 else 0
            outputs = [(value - 2 * COIN, pay if terminal else script), (COIN, pay)]
            if vout:
                outputs.reverse()
            if ambiguous:
                outputs[1 - vout] = (COIN, script)
            inputs = compact(len(points)) + b''.join(bytes.fromhex(p['txid'])[::-1] + struct.pack('<I', p['vout']) + b'\x00' + b'\xff' * 4 for p in points)
            stack = [b'\x00', *payloads, leaf]
            witness = (b'\x00' if nonzero_input else b'') + compact(len(stack)) + b''.join(compact(len(item)) + item for item in stack)
            raw = struct.pack('<I', 3) + b'\x00\x01' + inputs + compact(2) + b''.join(output(*item) for item in outputs) + b'\x00' + witness + bytes(4)
            if nonzero_input:
                raw = bytes.fromhex(node.signrawtransaction(raw.hex())['hex'])
            txid = node.sendrawtransaction(raw.hex(), True)
            return {'txid': txid, 'vout': vout}, value - 2 * COIN, raw.hex(), [item.hex() for item in stack]

        try:
            pool = fund(1)
            other = fund()
            assert_raises_rpc_error(-5, 'Confirmed', node.getprivacypoolinfo, pool)
            node.generatetoaddress(1, miner)
            empty = node.getprivacypoolinfo(pool)
            check('unregistered birth at nonzero output is accepted', empty['birth']['vout'] == 1 and empty['history_complete'])
            check('empty history and exact integer amount', empty['current_state']['value_satoshis'] == str(500 * COIN) and empty['transitions_followed'] == 0)
            check('profile identifies transport without guessing privacy circuits', empty['profile'] == 'authscript-v1-state-thread' and empty['privacy_profile'] is None)
            self.sync_all()
            assert_raises_rpc_error(-1, '-spentindex', self.nodes[1].getprivacypoolinfo, pool)
            check('missing indexes are reported explicitly', True)
            assert_raises_rpc_error(-8, 'unknown', node.getprivacypoolinfo, {**pool, 'view_key': 'TEST'})
            assert_raises_rpc_error(-8, 'vout', node.getprivacypoolinfo, {'txid': pool['txid']})
            assert_raises_rpc_error(-8, 'out of range', node.getprivacypoolupdates, pool, None, 0)
            assert_raises_rpc_error(-8, 'out of range', node.getprivacypoolupdates, pool, None, 1001)
            assert_raises_rpc_error(-8, 'does not exist', node.getprivacypoolinfo, {**pool, 'vout': 999})
            assert_raises_rpc_error(-8, 'AuthScript', node.getprivacypoolinfo, {**pool, 'vout': 0})
            check('invalid birth, limits and secret-bearing descriptors are rejected', True)

            point, value = pool, 500 * COIN
            rows = []
            for number in range(70):
                point, value, raw, stack = transition(point, value, number, nonzero_input=number == 0)
                rows.append({'point': point, 'raw': raw, 'stack': stack})
                if number != 0:  # The first two transitions share one block.
                    node.generatetoaddress(1, miner)
            captured = node.getbestblockhash()
            first = node.getprivacypoolupdates(pool, None, 2)
            check('page count and sequence are bounded', len(first['updates']) == 2 and first['has_more'] and first['next_cursor']['sequence'] == 2)
            check('cursor and completion flags use JSON booleans', type(first['next_cursor']['complete']) is bool and type(first['has_more']) is bool)
            check('same-block state order and arbitrary spending input', first['updates'][0]['height'] == first['updates'][1]['height'] and first['updates'][0]['input_index'] == 1)
            check('witnesses and raw bytes are exact', all(r['raw'] == rows[i]['raw'] and r['witness'][-1] == rows[i]['stack'] for i, r in enumerate(first['updates'])))
            limited_info = node.getprivacypoolinfo(pool, 3)
            check('bounded info never labels a partial state as current', limited_info['has_more'] and limited_info['current_state'] is None and limited_info['transitions_followed'] == 3)

            assert_raises_rpc_error(-8, 'different pool', node.getprivacypoolupdates, other, first['next_cursor'])
            forged = copy.deepcopy(first['next_cursor'])
            forged['position'] = other
            forged['sequence'] = 0
            forged['anchor'] = {'height': empty['birth']['height'], 'hash': empty['birth']['blockhash']}
            assert_raises_rpc_error(-8, 'descendant', node.getprivacypoolupdates, pool, forged)
            bad_sequence = copy.deepcopy(first['next_cursor'])
            bad_sequence['sequence'] += 1
            assert_raises_rpc_error(-8, 'sequence', node.getprivacypoolupdates, pool, bad_sequence)
            bad_anchor = copy.deepcopy(first['next_cursor'])
            bad_anchor['anchor']['hash'] = '11' * 32
            assert_raises_rpc_error(-8, 'anchor', node.getprivacypoolupdates, pool, bad_anchor)
            check('foreign, unrelated same-commitment and tampered cursors fail', True)

            extra, extra_value, extra_raw, extra_stack = transition(point, value, 70)
            before_confirm = node.getprivacypoolinfo(pool)
            check('mempool spend does not change confirmed state', before_confirm['current_state']['txid'] == point['txid'])
            node.generatetoaddress(1, miner)
            cursor = first['next_cursor']
            all_rows = list(first['updates'])
            pages = 1
            while True:
                page = node.getprivacypoolupdates(pool, cursor, 7)
                assert_equal(page['snapshot']['hash'], captured)
                all_rows.extend(page['updates'])
                cursor = page['next_cursor']
                pages += 1
                if not page['has_more']:
                    break
            check('pagination stays pinned despite new blocks', [r['raw'] for r in all_rows] == [r['raw'] for r in rows])
            check('page boundary resumes without duplicate or missing transition', [r['sequence'] for r in all_rows] == list(range(1, 71)))
            refreshed = node.getprivacypoolupdates(pool, cursor)
            check('completed cursor downloads only the new suffix', [r['raw'] for r in refreshed['updates']] == [extra_raw] and not refreshed['has_more'])
            no_change = node.getprivacypoolupdates(pool, refreshed['next_cursor'])
            check('unchanged pool needs no transaction redownload', no_change['updates'] == [])

            large = node.getprivacypoolupdates(pool, None, 1000)
            raw_bytes = sum(len(r['raw']) // 2 for r in large['updates'])
            check('byte budget also limits large witness pages', large['has_more'] and 0 < raw_bytes <= 1024 * 1024 and len(large['updates']) < 70)
            check('CLI and named JSON parameters work', node.cli.getprivacypoolinfo(json.dumps(pool))['pool_id'] == empty['pool_id'])
            named = node.cli.getprivacypoolupdates(pool=json.dumps(pool), cursor='null', limit=2)
            assert_equal(len(named['updates']), 2)

            resume_cursor = refreshed['next_cursor']
            self.stop_node(0)
            self.start_node(0)
            node = self.nodes[0]
            restored = node.getprivacypoolupdates(pool, resume_cursor)
            check('cursor remains valid after node restart and cache loss', restored['updates'] == [] and restored['current_state']['txid'] == extra['txid'])
            node.invalidateblock(captured)
            assert_raises_rpc_error(-8, 'reorganized', node.getprivacypoolupdates, pool, first['next_cursor'])
            check('reorganization rejects old snapshots', True)
            fresh = node.getprivacypoolupdates(pool, None, 1000)
            check('fresh scan excludes disconnected transactions', all(r['txid'] not in (rows[-1]['point']['txid'], extra['txid']) for r in fresh['updates']))
            assert_equal(node.getprivacypoolinfo(pool)['current_state']['txid'], rows[-2]['point']['txid'])
            node.reconsiderblock(captured)
            restored = node.getprivacypoolupdates(pool, resume_cursor)
            check('reconsideration restores canonical cursor and indexes', restored['updates'] == [])

            ambiguous_pool = fund()
            terminal_pool = fund()
            node.generatetoaddress(1, miner)
            transition(ambiguous_pool, 500 * COIN, 1, ambiguous=True)
            terminal, _, _, _ = transition(terminal_pool, 500 * COIN, 1, terminal=True)
            node.generatetoaddress(1, miner)
            assert_raises_rpc_error(-8, 'Ambiguous', node.getprivacypoolupdates, ambiguous_pool)
            end = node.getprivacypoolupdates(terminal_pool)
            check('ambiguous successors fail instead of picking a branch', True)
            check('no matching successor is explicit without claiming closure', end['continuation'] == 'not_found' and end['current_state'] is None and len(end['updates']) == 1)
            terminal_resume = node.getprivacypoolupdates(terminal_pool, end['next_cursor'])
            check('terminal transport cursor resumes without repeating the spend', terminal_resume['updates'] == [])

            # Timing on one node, with an explicit optional RTT model. Both
            # strategies check the same canonical transition raws and ancestry.
            def walk_individual(delay=0):
                current = pool
                raws = []
                calls = 0
                while True:
                    if delay: time.sleep(delay)
                    calls += 1
                    txout = node.gettxout(current['txid'], current['vout'], False)
                    if txout is not None:
                        break
                    if delay: time.sleep(delay)
                    calls += 1
                    spent = node.getspentinfo({'txid': current['txid'], 'index': current['vout']})
                    if delay: time.sleep(delay)
                    calls += 1
                    tx = node.getrawtransaction(spent['txid'], True)
                    if delay: time.sleep(delay)
                    calls += 1
                    blockhash = node.getblockhash(spent['height'])
                    assert_equal(blockhash, tx['blockhash'])
                    raws.append(tx['hex'])
                    state_index = next(o['n'] for o in tx['vout'] if o['scriptPubKey']['hex'] == script.hex())
                    current = {'txid': tx['txid'], 'vout': state_index}
                return raws, calls

            def walk_pages(delay=0):
                current = None
                raws = []
                calls = 0
                while True:
                    if delay: time.sleep(delay)
                    calls += 1
                    page = node.getprivacypoolupdates(pool, current)
                    raws.extend(r['raw'] for r in page['updates'])
                    current = page['next_cursor']
                    if not page['has_more']:
                        return raws, calls

            for delay in (0, 0.02):
                measured = {}
                results = []
                for name, method in [('individual', walk_individual), ('pages', walk_pages)]:
                    start = time.monotonic()
                    recovered, calls = method(delay)
                    measured[name] = {'calls': calls, 'seconds': time.monotonic() - start}
                    results.append(recovered)
                assert_equal(*results)
                report['measurements']['localhost' if not delay else 'model_20ms_per_call'] = measured
            check('batched and individual retrieval recover identical canonical raws', True)
            report['success'] = True
        finally:
            if self.options.report:
                Path(self.options.report).write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    PrivacyPoolTest().main()
