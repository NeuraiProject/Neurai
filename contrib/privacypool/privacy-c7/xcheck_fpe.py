#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Compare the reference diversifiers with the Zcash fpe crate.

    xcheck_fpe.py input > ff1-input.txt
    <rust binary> < ff1-input.txt > ff1-output.txt
    xcheck_fpe.py compare ff1-input.txt ff1-output.txt
"""
import json
import sys
from pathlib import Path

import c7_ref as c
import gen_c7_vectors as g

HERE = Path(__file__).resolve().parent


def cases():
    v = json.loads(g.OUT.read_text())
    dks = {a["name"]: a["dk"] for a in v["accounts"]}
    out = [(dks[a["account"]], a["j"]) for a in v["addresses"]]
    for k in range(200):
        dk = c.sha256(b"fpe dk %d" % k).hex()
        j = int.from_bytes(c.sha256(b"fpe j %d" % k)[:11], "little") >> (k % 88)
        out.append((dk, j))
    out += [(dks["A"], j) for j in (0, 1, 2 ** 31, 2 ** 32, 2 ** 33 - 1, 2 ** 88 - 1)]
    return out


def main():
    if sys.argv[1] == "input":
        for dk, j in cases():
            print(dk, j)
        return 0
    lines = Path(sys.argv[2]).read_text().split("\n")
    got = Path(sys.argv[3]).read_text().split()
    pairs = [x.split() for x in lines if x]
    assert len(pairs) == len(got), (len(pairs), len(got))
    for (dk, j), d in zip(pairs, got):
        mine = c.diversifier_from_index(bytes.fromhex(dk), int(j))
        assert mine.hex() == d, (dk, j, mine.hex(), d)
        assert c.index_from_diversifier(bytes.fromhex(dk), mine) == int(j)
    print(f"OK: {len(got)} diversifiers equal to the Zcash fpe crate (FF1-AES256, radix 2, 88 bits)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
