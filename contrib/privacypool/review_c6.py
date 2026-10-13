#!/usr/bin/env python3
"""Verify native privacy-pool RPCs against copies of previously validated C6 chains.

Only disposable regtest clones are opened. The supplied nodes are read-only
fixtures; there is no network access, wallet access, proving or publication.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request


class Node:
    def __init__(self, binary, source, directory):
        blocks = directory / 'regtest' / 'blocks'
        blocks.mkdir(parents=True)
        files = list((source / 'regtest' / 'blocks').glob('blk*.dat'))
        if not files:
            raise ValueError('Public regtest block files are required')
        for path in files:
            shutil.copyfile(path, blocks / path.name)
        self.directory = directory
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            self.port = sock.getsockname()[1]
        self.log = (directory.parent / (directory.name + '-process.log')).open('w')
        self.process = subprocess.Popen([
            str(binary), '-regtest', '-server=1', '-listen=0', '-connect=0',
            '-dnsseed=0', '-discover=0', '-disablewallet=1', '-bypassdownload=1',
            '-spentindex=1', '-txindex=1', '-reindex=1', '-assumevalid=0',
            '-par=2', '-rpcuser=review', '-rpcpassword=disposable-regtest',
            '-rpcport=' + str(self.port), '-datadir=' + str(directory),
        ], stdout=self.log, stderr=subprocess.STDOUT)

    def rpc(self, method, *params):
        request = urllib.request.Request('http://127.0.0.1:' + str(self.port),
            json.dumps({'id': 'review', 'method': method, 'params': params}).encode(),
            {'Authorization': 'Basic ' + base64.b64encode(b'review:disposable-regtest').decode()})
        try:
            response = urllib.request.urlopen(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            result = json.load(response)
        if result['error']:
            raise RuntimeError(result['error'])
        return result['result']

    def ready(self, height):
        for _ in range(1200):
            if self.process.poll() is not None:
                raise RuntimeError('Fixture clone exited; see process log')
            try:
                if self.rpc('getblockcount') >= height:
                    return
            except (OSError, ValueError, RuntimeError):
                pass
            time.sleep(0.1)
        raise RuntimeError('Fixture replay timed out')

    def close(self):
        if self.process.poll() is None:
            try:
                self.rpc('stop')
            except (OSError, RuntimeError):
                self.process.terminate()
            try:
                self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--xna-node', type=Path, required=True)
    parser.add_argument('--asset-node', type=Path, required=True)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    report = {'success': False, 'checks': [], 'pools': [],
              'binary_sha256': hashlib.sha256(args.binary.read_bytes()).hexdigest()}

    def save():
        (args.out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')

    def check(label, passed):
        report['checks'].append({'case': label, 'passed': bool(passed)})
        save()
        print(('PASS ' if passed else 'FAIL ') + label, flush=True)
        if not passed:
            raise AssertionError(label)

    try:
        for kind, source, filename in [('xna', args.xna_node, 'c6-operations-chain.json'),
                                       ('asset', args.asset_node, 'c6-assets-chain.json')]:
            fixture = json.loads((args.fixtures / filename).read_text())
            deployment = fixture['deployment']
            height = fixture['replies']['getblockcount\0[]']
            txid, vout = deployment['anchor']['outpoint'].split(':')
            pool = {'txid': txid, 'vout': int(vout)}
            node = Node(args.binary, source, args.out / (kind + '-node'))
            try:
                node.ready(height)
                check(kind + ' fixture genesis and canonical birth',
                      node.rpc('getblockhash', 0) == deployment['genesis'] and
                      node.rpc('getblockhash', deployment['anchor']['height']) == deployment['anchor']['hash'])
                info = node.rpc('getprivacypoolinfo', pool)
                check(kind + ' arbitrary C6 commitment and thread identity',
                      info['commitment'] == deployment['commitment'] and info['thread_asset'] is not None)
                check(kind + ' info is complete at the validated tip',
                      info['history_complete'] and info['indexed_height'] == node.rpc('getblockcount'))
                start = time.monotonic()
                cursor = None
                updates = []
                calls = 0
                snapshots = set()
                while True:
                    page = node.rpc('getprivacypoolupdates', pool, cursor, 3)
                    calls += 1
                    snapshots.add(page['snapshot']['hash'])
                    updates.extend(page['updates'])
                    cursor = page['next_cursor']
                    if not page['has_more']:
                        break
                elapsed = time.monotonic() - start
                # Some captures enumerate only the new operations on top of a
                # pre-existing pool. Independently follow the captured blocks
                # from birth to include that prefix as well.
                expected_point = deployment['anchor']['outpoint']
                ids = []
                captured_blocks = sorted((value for key, value in fixture['replies'].items()
                                          if key.startswith('getblock\0')), key=lambda block: block['height'])
                for block in captured_blocks:
                    for tx in block['tx']:
                        if any(str(vin.get('txid', '')) + ':' + str(vin.get('vout', '')) == expected_point
                               for vin in tx.get('vin', [])):
                            ids.append(tx['txid'])
                            expected_point = tx['txid'] + ':0'
                check(kind + ' captured history includes every reported operation',
                      all(operation['txid'] in ids for operation in fixture['operations']))
                check(kind + ' exact confirmed operation order across pages', [row['txid'] for row in updates] == ids)
                check(kind + ' one immutable snapshot and complete sequence',
                      len(snapshots) == 1 and [row['sequence'] for row in updates] == list(range(1, len(ids) + 1)))
                for row in updates:
                    tx = node.rpc('getrawtransaction', row['txid'], True)
                    check(kind + ' exact raw/witness/block ' + str(row['sequence']),
                          row['raw'] == tx['hex'] and row['wtxid'] == tx['hash'] and
                          row['blockhash'] == tx['blockhash'] and
                          row['witness'] == [vin.get('txinwitness', []) for vin in tx['vin']] and
                          node.rpc('getblockhash', row['height']) == row['blockhash'])
                check(kind + ' current state matches the full history',
                      info['current_state']['txid'] == updates[-1]['txid'] and
                      node.rpc('gettxout', info['current_state']['txid'], info['current_state']['vout'], False)['scriptPubKey']['hex'] == info['current_state']['script'])
                unchanged = node.rpc('getprivacypoolupdates', pool, cursor)
                check(kind + ' incremental refresh needs zero historical transactions', unchanged['updates'] == [])
                invalidated = updates[-1]['blockhash']
                node.rpc('invalidateblock', invalidated)
                try:
                    node.rpc('getprivacypoolupdates', pool, cursor)
                except RuntimeError as error:
                    rejected = 'reorganized' in str(error)
                else:
                    rejected = False
                check(kind + ' real C6 reorg invalidates the old cursor', rejected)
                node.rpc('reconsiderblock', invalidated)
                check(kind + ' C6 reconsideration restores transport history',
                      node.rpc('getprivacypoolupdates', pool, cursor)['updates'] == [])
                (args.out / (kind + '-updates.json')).write_text(json.dumps({'pool': pool, 'info': info, 'updates': updates, 'cursor': cursor}, indent=2) + '\n')
                report['pools'].append({'kind': kind, 'pool': pool, 'transitions': len(updates),
                                        'pages': calls, 'seconds': elapsed, 'bytes_raw': sum(len(row['raw']) // 2 for row in updates)})
                save()
            finally:
                node.close()
        report['success'] = True
    except BaseException as error:
        report['error'] = repr(error)
        raise
    finally:
        save()


if __name__ == '__main__':
    main()
