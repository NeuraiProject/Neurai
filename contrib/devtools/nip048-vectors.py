#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Writes src/test/data/nip048_vectors.json from the independent Python
reference of NIP-048 plans (test/functional/test_framework/nip048.py).

The C++ unit tests check every vector, so the node, this reference and any
SDK that passes the file agree on the formats. Run from the repository root:

    contrib/devtools/nip048-vectors.py > src/test/data/nip048_vectors.json
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'test', 'functional'))

from test_framework.nip048 import (allocate, announcement_hash, batch_id, leaf_hash, merkle_path,  # noqa: E402
                                   merkle_root, plan_hash, report_hash, snapshot_hash, snapshot_hash_v2)


def p2pkh(fill):
    return bytes([0x76, 0xa9, 0x14]) + bytes([fill]) * 20 + bytes([0x88, 0xac])


def main():
    scripts = [p2pkh(i) for i in range(1, 10)]
    block_hash = bytes([0x11]) * 32

    leaves = [{"script": scripts[i].hex(), "amount": a, "hash": leaf_hash(scripts[i], a).hex()}
              for i, a in enumerate([4, 3, 3, 1, 2 ** 62])]

    merkle = []
    for n in (0, 1, 2, 3, 5, 9):
        items = [(scripts[i], i + 1) for i in range(n)]
        merkle.append({"leaves": [[s.hex(), a] for s, a in items],
                       "root": merkle_root([leaf_hash(s, a) for s, a in items]).hex()})

    proofs = []
    for n in (1, 2, 3, 5, 9):
        hashes = [leaf_hash(scripts[i], i + 1) for i in range(n)]
        for index in range(n):
            proofs.append({"leaves": [[scripts[i].hex(), i + 1] for i in range(n)], "index": index,
                           "path": [h.hex() for h in merkle_path(hashes, index)],
                           "root": merkle_root(hashes).hex()})

    holdings = [(scripts[0], 1), (scripts[1], 1), (scripts[2], 1)]
    snapshots_v1 = [{"asset": "TOKEN", "height": 100, "block_hash": block_hash.hex(),
                     "holdings": [[s.hex(), h] for s, h in holdings],
                     "hash": snapshot_hash("TOKEN", 100, block_hash, holdings).hex()}]

    stateful = [(scripts[0], 1, 0, ["#A"]), (scripts[1], 1, 1, []), (scripts[2], 1, 2, ["#A", "#B"])]
    snapshots_v2 = []
    for frozen in (False, True):
        snapshots_v2.append({"asset": "TOKEN", "height": 100, "block_hash": block_hash.hex(), "global_frozen": frozen,
                             "holdings": [[s.hex(), h, f, t] for s, h, f, t in stateful],
                             "hash": snapshot_hash_v2("TOKEN", 100, block_hash, frozen, stateful).hex()})

    reports = []
    for weights in ({"AAA": 3, "BBB": 1}, {"tAddress": 1}, {"z": 7, "a": 2, "M": 5}):
        reports.append({"weights": weights, "hash": report_hash(weights).hex()})

    announcements = [{"network": net, "asset": asset, "height": height,
                      "hash": announcement_hash(net, asset, height).hex()}
                     for net, asset, height in (("main", "TOKEN", 100), ("regtest", "&GRID", 2500), ("test", "ROOT/SUB", 1))]

    allocations = []
    for weights, amount, unit, policy in (([100, 200, 300], 600, 1, 0), ([1, 1, 1], 10, 1, 0), ([1, 1, 1], 10, 1, 1),
                                          ([5, 3, 2], 7, 1, 1), ([1, 1, 1], 10 * 10 ** 8, 10 ** 8, 0),
                                          ([1, 1000000], 10, 1, 0), ([2 ** 62, 1], 2 ** 62, 1, 1)):
        items = [(scripts[i], w) for i, w in enumerate(weights)]
        amounts, remainder = allocate(items, amount, unit, policy)
        allocations.append({"holdings": [[s.hex(), w] for s, w in items], "amount": amount, "unit": unit,
                            "policy": policy, "amounts": amounts, "remainder": remainder})

    root = merkle_root([leaf_hash(scripts[i], a) for i, a in enumerate([4, 3, 3])])
    snap = snapshot_hash("TOKEN", 100, block_hash, holdings)
    base = {"network": "main", "asset": "TOKEN", "height": 100, "block_hash": block_hash.hex(), "snapshot_hash": snap.hex(),
            "distribution_asset": "XNA", "amount": 10, "policy": 1, "exclusions": ["EXCLUDED"], "distributed": 10,
            "remainder": 0, "leaf_count": 3, "root": root.hex()}
    plans = []
    weighted = report_hash({"AAA": 3, "BBB": 1})
    for version, announcement, qualifier, report, allocation, min_held in (
            (1, None, None, None, 0, 0), (2, bytes([0x33]) * 32, None, None, 0, 0),
            (3, None, "#A", weighted, 0, 0), (3, bytes([0x33]) * 32, "#A", None, 0, 0),
            (4, None, None, None, 1, 0), (4, None, None, None, 0, 100 * 10 ** 8),
            (4, bytes([0x33]) * 32, "#A", None, 1, 100 * 10 ** 8), (4, None, None, weighted, 0, 1)):
        plan = dict(base, version=version, announcement=announcement.hex() if announcement else None,
                    qualifier=qualifier, report=report.hex() if report else None, allocation=allocation,
                    min_held=min_held)
        plan["hash"] = plan_hash(version, "main", "TOKEN", 100, block_hash, snap, "XNA", 10, 1, ["EXCLUDED"], 10, 0, 3,
                                 root, announcement, qualifier, report, allocation, min_held).hex()
        plans.append(plan)

    batches = [{"plan_hash": plans[0]["hash"], "max_outputs": m, "index": i,
                "hash": batch_id(bytes.fromhex(plans[0]["hash"]), m, i).hex()} for m, i in ((500, 0), (500, 1), (3, 0))]

    vectors = {
        "comment": "NIP-048 reward plan vectors, generated by contrib/devtools/nip048-vectors.py from the Python "
                   "reference test/functional/test_framework/nip048.py. Hashes are hex in hash output order; "
                   "block hashes and txids in internal byte order.",
        "leaf": leaves, "merkle": merkle, "proof": proofs, "snapshot_v1": snapshots_v1, "snapshot_v2": snapshots_v2,
        "report": reports, "announcement": announcements, "allocation": allocations, "plan": plans, "batch_id": batches,
    }
    json.dump(vectors, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == '__main__':
    main()
