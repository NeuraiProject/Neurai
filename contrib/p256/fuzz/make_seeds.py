#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Write the P-256 test vectors as seed inputs for p256_diff_fuzz.

Usage: make_seeds.py src/test/data/p256_vectors.json <seed directory>

A raw-mode input is [0x01, public key length selector, signature length
selector, public key, signature, message]. Vectors whose lengths the selectors
cannot express (a few invalid-size cases) are skipped.
"""
import json
import os
import sys


def pub_selector(length):
    if length == 33:
        return 0
    for b in range(224, 256):
        if b % 40 == length:
            return b
    return None


def sig_selector(length):
    if length == 64:
        return 0
    if length == 0:
        return 200
    for b in range(216, 256):
        if b % 72 == length:
            return b
    return None


def main():
    vectors = json.load(open(sys.argv[1]))['vectors']
    out = sys.argv[2]
    os.makedirs(out, exist_ok=True)
    written = skipped = 0
    for v in vectors:
        pub, sig, msg = (bytes.fromhex(v[k]) for k in ('pub', 'sig', 'msg'))
        a, b = pub_selector(len(pub)), sig_selector(len(sig))
        if a is None or b is None:
            skipped += 1
            continue
        with open(os.path.join(out, '%s-%s' % (v['source'], v['id'])), 'wb') as f:
            f.write(bytes([0x01, a, b]) + pub + sig + msg)
        written += 1
    print('seeds', written, 'skipped', skipped)


if __name__ == '__main__':
    main()
