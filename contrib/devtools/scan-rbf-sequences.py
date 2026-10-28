#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Read-only scan of a node's active chain for the no-RBF sequence rule.

Classifies every non-coinbase input from a start height to the tip (final,
0xfffffffe, BIP 68 relative lock, or replaceability signal) and lists the
inputs the rule rejects. Run it before deploying the rule on a network that
is already running, and again after the miners have upgraded:

    contrib/devtools/scan-rbf-sequences.py http://127.0.0.1:19101 user pass 10

Exits with status 1 when it finds a violation.
"""
import base64
import collections
import json
import sys
import urllib.request

SEQUENCE_FINAL = 0xffffffff
DISABLE_FLAG = 0x80000000


def allowed(version, sequence):
    """Mirror of CTxIn::IsNoRbfSequenceAllowed."""
    if sequence >= SEQUENCE_FINAL - 1:
        return True
    return (version & 0xffffffff) >= 2 and not sequence & DISABLE_FLAG


def category(version, sequence):
    if sequence == SEQUENCE_FINAL:
        return "final"
    if sequence == SEQUENCE_FINAL - 1:
        return "0xfffffffe"
    return "relative-lock" if allowed(version, sequence) else "signal"


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    url, user, password = sys.argv[1:4]
    start = int(sys.argv[4]) if len(sys.argv) > 4 else 0
    auth = base64.b64encode(("%s:%s" % (user, password)).encode()).decode()

    def batch(calls):
        body = json.dumps([{"jsonrpc": "1.0", "id": i, "method": m, "params": p}
                           for i, (m, p) in enumerate(calls)]).encode()
        request = urllib.request.Request(url, body, {"Authorization": "Basic " + auth,
                                                     "Content-Type": "application/json"})
        replies = sorted(json.loads(urllib.request.urlopen(request, timeout=600).read()), key=lambda r: r["id"])
        for reply in replies:
            if reply.get("error"):
                raise RuntimeError(reply["error"])
        return [reply["result"] for reply in replies]

    tip = batch([("getblockcount", [])])[0]
    inputs = collections.Counter()
    versions = collections.Counter()
    violations = []
    transactions = 0
    for low in range(start, tip + 1, 200):
        heights = list(range(low, min(low + 200, tip + 1)))
        hashes = batch([("getblockhash", [h]) for h in heights])
        for height, block in zip(heights, batch([("getblock", [h, 2]) for h in hashes])):
            for tx in block["tx"]:
                if "coinbase" in tx["vin"][0]:
                    continue
                transactions += 1
                versions[tx["version"]] += 1
                for index, vin in enumerate(tx["vin"]):
                    inputs[category(tx["version"], vin["sequence"])] += 1
                    if not allowed(tx["version"], vin["sequence"]):
                        violations.append((height, tx["txid"], index, vin["sequence"], tx["version"]))

    print("blocks %d..%d: %d non-coinbase transactions" % (start, tip, transactions))
    print("versions:", dict(versions))
    print("inputs:", dict(inputs))
    print("violations:", len(violations))
    for height, txid, index, sequence, version in violations:
        print("  height %d tx %s input %d sequence 0x%08x version %d" % (height, txid, index, sequence, version))
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
