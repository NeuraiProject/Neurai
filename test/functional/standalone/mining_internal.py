#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see COPYING.
"""Exercise the real internal miner on an isolated mainnet/testnet chain.

Uses a loaded wallet, HTTP RPC, no external peers and no third-party modules.
The low initial network difficulty makes this practical without GPUs.
"""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import http.client
import json
from pathlib import Path
import subprocess
import time


def wait_for(predicate, timeout=90):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError('Timed out waiting for mining test condition')


class Node:
    def __init__(self, args, extra=()):
        self.args = args
        self.log = (args.tmpdir / 'console.log').open('a')
        command = [str(args.neuraid), '-datadir=' + str(args.tmpdir / 'data'), '-server',
                   '-connect=0', '-dnsseed=0', '-discover=0', '-listen=0',
                   '-rpcport=29703', '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1',
                   '-rpcuser=mining-test', '-rpcpassword=isolated-test', '-bypassdownload',
                   '-disablesafemode', '-par=1', '-dbcache=32', '-keypool=16']
        if args.network == 'test': command.append('-testnet')
        if args.network == 'regtest': command.append('-regtest')
        self.process = subprocess.Popen(command + list(extra), stdout=self.log, stderr=subprocess.STDOUT)
        def started():
            assert self.process.poll() is None, 'Node exited during startup'
            try:
                self.rpc('getblockcount')
                return True
            except (OSError, RuntimeError):
                return False
        try: wait_for(started)
        except Exception:
            self.close()
            raise

    def rpc(self, method, *params):
        connection = http.client.HTTPConnection('127.0.0.1', 29703, timeout=60)
        auth = base64.b64encode(b'mining-test:isolated-test').decode()
        try:
            connection.request('POST', '/', json.dumps(dict(id=1, method=method, params=params)),
                               {'Authorization': 'Basic ' + auth})
            result = json.loads(connection.getresponse().read())
        finally: connection.close()
        if result.get('error'): raise RuntimeError(result['error'])
        return result['result']

    def workers(self):
        # Linux test host: unlike a delayed block-count sample, this detects
        # workers that survived a stop/replacement RPC.
        names = []
        for task in Path('/proc', str(self.process.pid), 'task').glob('*/comm'):
            try: names.append(task.read_text().strip())
            except FileNotFoundError: pass
        return names.count('neurai-miner')

    def close(self):
        try:
            if self.process.poll() is None:
                try: self.rpc('stop')
                except (OSError, RuntimeError): self.process.terminate()
            try: code = self.process.wait(timeout=90)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
                raise
            assert code == 0, ('node exit', code)
        finally: self.log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--neuraid', type=Path, required=True)
    parser.add_argument('--network', choices=['main', 'test', 'regtest'], required=True)
    parser.add_argument('--tmpdir', type=Path, required=True)
    args = parser.parse_args()
    args.neuraid = args.neuraid.resolve(); args.tmpdir = args.tmpdir.resolve()
    (args.tmpdir / 'data').mkdir(parents=True)
    results = []
    node = Node(args)
    try:
        if args.network == 'regtest':
            address = node.rpc('getnewaddress')
            blocks = node.rpc('generatetoaddress', 5, address)
            assert len(blocks) == 5
            assert node.rpc('verifychain', 4, 0)
            node.rpc('invalidateblock', blocks[-1])
            node.rpc('reconsiderblock', blocks[-1])
            assert node.rpc('getbestblockhash') == blocks[-1]
            results.append(dict(regtest_blocks=len(blocks), end=5))
        else:
            exercise_miner(node, results)
    finally: node.close()
    node = Node(args, ['-reindex'])
    try:
        # RPC becomes available before background reindexing has finished.
        wait_for(lambda: node.rpc('getblockcount') >= results[-1]['end'])
        assert node.rpc('verifychain', 4, 0)
        assert node.workers() == 0
        results.append(dict(reindexed_height=node.rpc('getblockcount')))
    finally: node.close()
    (args.tmpdir / 'results.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


def exercise_miner(node, results):
    assert not node.rpc('getgenerate')
    for threads in (1, 2, 1):
        height = node.rpc('getblockcount')
        node.rpc('setgenerate', True, threads)
        assert node.rpc('getgenerate')
        wait_for(lambda: node.rpc('getblockcount') >= height + 3)
        node.rpc('setgenerate', False)
        assert not node.rpc('getgenerate'), 'stop must update getgenerate'
        assert node.workers() == 0, 'stop returned before workers exited'
        end = node.rpc('getblockcount')
        results.append(dict(threads=threads, start=height, end=end))
    # Parallel clients replacing/stopping workers must serialize safely.
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(node.rpc, 'setgenerate', value, 1) for value in (True, False, True, False)]
        for future in futures: future.result(timeout=90)
    node.rpc('setgenerate', True, 0)
    assert not node.rpc('getgenerate')
    assert node.workers() == 0
    tip = node.rpc('getbestblockhash')
    before = node.rpc('getblockheader', tip)
    assert node.rpc('verifychain', 4, 0)
    node.rpc('invalidateblock', tip)
    node.rpc('reconsiderblock', tip)
    # Two mining threads can leave equal-work sibling tips. Reconsidering
    # a block makes it eligible again, but need not win that tie.
    best = node.rpc('getblockheader', node.rpc('getbestblockhash'))
    assert int(best['chainwork'], 16) >= int(before['chainwork'], 16)
    # Reconsidering may also activate an already received descendant, so
    # the original block need not remain a leaf in getchaintips.
    valid = False
    for entry in node.rpc('getchaintips'):
        if entry['status'] not in ('active', 'valid-fork'): continue
        header = node.rpc('getblockheader', entry['hash'])
        while header['height'] > before['height']:
            header = node.rpc('getblockheader', header['previousblockhash'])
        valid |= header['hash'] == tip
    assert valid, 'reconsidered block has no fully validated descendant tip'
    # Shutdown while mining must join workers before destroying the wallet.
    node.rpc('setgenerate', True, 1)


if __name__ == '__main__': main()
