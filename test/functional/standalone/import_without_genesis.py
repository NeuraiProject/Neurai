#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see COPYING.
"""Import files that omit genesis into fresh datadirs, with index checks enabled.

Run on main, test and regtest of either maintained branch. Reuses the isolated
node/RPC helpers from block_work_admission; no external peers are contacted.
"""
import argparse
import json
from pathlib import Path
import struct

from block_work_admission import Node, address, wait_for


SCENARIOS = ('loadblock', 'bootstrap', 'empty-reindex', 'empty-chainstate',
             'split-files', 'bootstrap-and-loadblock', 'existing-prefix',
             'with-genesis', 'empty-file')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--neuraid', type=Path, required=True)
    parser.add_argument('--network', choices=['main', 'test', 'regtest'], required=True)
    parser.add_argument('--tmpdir', type=Path, required=True)
    parser.add_argument('--scenario', choices=SCENARIOS)
    args = parser.parse_args()
    args.neuraid = args.neuraid.resolve()
    args.tmpdir = args.tmpdir.resolve()
    args.tmpdir.mkdir(parents=True)
    magic = b'NEUR' if args.network == 'main' else b'RUEN'
    results = []

    miner_dir = args.tmpdir / 'miner'
    node = Node(args, miner_dir)
    try:
        genesis_stats = node.stats()
        genesis = bytes.fromhex(node.rpc('getblock', node.rpc('getblockhash', 0), 0))
        hashes = node.rpc('generatetoaddress', 3, address(args.network != 'main'))
        blocks = [bytes.fromhex(node.rpc('getblock', h, 0)) for h in hashes]
        expected = node.stats()
        network_dir = next(miner_dir.rglob('blk00000.dat')).parent.parent.relative_to(miner_dir)
    finally:
        node.close()

    def write_blocks(path, records):
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('wb') as stream:
            for block in records:
                stream.write(magic + struct.pack('<I', len(block)) + block)

    complete = args.tmpdir / 'without-genesis.dat'
    first = args.tmpdir / 'first.dat'
    suffix = args.tmpdir / 'suffix.dat'
    including_genesis = args.tmpdir / 'with-genesis.dat'
    empty = args.tmpdir / 'empty.dat'
    write_blocks(complete, blocks)
    write_blocks(first, blocks[:1])
    write_blocks(suffix, blocks[1:])
    write_blocks(including_genesis, [genesis] + blocks)
    write_blocks(empty, [])

    for scenario in ([args.scenario] if args.scenario else SCENARIOS):
        directory = args.tmpdir / scenario
        bootstrap = directory / network_dir / 'bootstrap.dat'
        extra = []
        target = expected
        if scenario in ('loadblock', 'empty-reindex', 'empty-chainstate'):
            extra = ['-loadblock=' + str(complete)]
            if scenario == 'empty-reindex': extra.append('-reindex')
            if scenario == 'empty-chainstate': extra.append('-reindex-chainstate')
        elif scenario == 'bootstrap':
            write_blocks(bootstrap, blocks)
        elif scenario == 'bootstrap-and-loadblock':
            write_blocks(bootstrap, blocks[:1])
            extra = ['-loadblock=' + str(suffix)]
        elif scenario == 'split-files':
            extra = ['-loadblock=' + str(first), '-loadblock=' + str(suffix)]
        elif scenario == 'existing-prefix':
            node = Node(args, directory)
            try:
                assert node.rpc('submitblock', blocks[0].hex()) is None
                assert node.rpc('getblockcount') == 1
            finally:
                node.close()
            extra = ['-loadblock=' + str(suffix)]
        elif scenario == 'with-genesis':
            extra = ['-loadblock=' + str(including_genesis)]
        elif scenario == 'empty-file':
            extra = ['-loadblock=' + str(empty)]
            target = genesis_stats

        node = Node(args, directory, extra)
        try:
            wait_for(lambda: node.rpc('getblockcount') == target['height'])
            assert node.stats() == target, (scenario, node.stats(), target)
            assert node.rpc('verifychain', 4, 0), scenario
            if scenario.startswith('bootstrap'):
                wait_for(lambda: bootstrap.with_name('bootstrap.dat.old').exists())
                assert not bootstrap.exists()
        finally:
            node.close()

        # Persisted index/UTXO state must agree after a normal restart too.
        node = Node(args, directory)
        try:
            assert node.stats() == target, (scenario, 'restart')
            assert node.rpc('verifychain', 4, 0), (scenario, 'restart')
        finally:
            node.close()
        results.append(dict(scenario=scenario, restarted=True, verifychain=True, **target))
        (args.tmpdir / 'results.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
