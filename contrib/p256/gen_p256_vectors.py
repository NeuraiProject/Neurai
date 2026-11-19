#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Generate src/test/data/p256_vectors.json for the NIP-060 strict profile.

Sources, mapped to the strict profile (33-byte compressed keys, 64-byte
r || s signatures with low S) and checked against the pure-Python reference
in test/functional/test_framework/key_p256.py:

  - nip: the NIP-060 §11 vectors and the boundary cases it lists;
  - wycheproof: C2SP/wycheproof testvectors_v1/ecdsa_secp256r1_sha256_p1363_test.json
    (commit 65ca494727a52944c204441c860b039e6786b99b). Signatures that
    Wycheproof accepts with a high S are SIG_ENCODING in the strict profile;
    their low-S twin (r, n - s) is added as a valid vector;
  - nist: NIST CAVP 186-4 SigVer.rsp, section [P-256,SHA-256].

Each entry: {"source", "id", "pub", "msg", "sig", "expect"} with expect one
of "valid", "invalid", "PUBKEY_SIZE", "PUBKEY_ENCODING", "SIG_SIZE",
"SIG_ENCODING".

Usage:
  gen_p256_vectors.py --wycheproof p1363.json --nist SigVer.rsp > src/test/data/p256_vectors.json
"""

import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'test', 'functional'))
from test_framework import key_p256 as k  # noqa: E402

N, P, HALF_N = k.N, k.P, k.HALF_N


def b32(v):
    return v.to_bytes(32, 'big')


def strict_expect(pub, msg, sig):
    """Expected strict-profile outcome, in the NIP-060 §4.5 order."""
    if len(pub) != 33:
        return 'PUBKEY_SIZE'
    if pub[0] not in (2, 3) or k.decompress(pub) is None:
        return 'PUBKEY_ENCODING'
    if len(sig) not in (0, 64):
        return 'SIG_SIZE'
    if len(sig) == 0:
        return 'invalid'
    r = int.from_bytes(sig[:32], 'big')
    s = int.from_bytes(sig[32:], 'big')
    if not (1 <= r < N) or not (1 <= s < N) or s > HALF_N:
        return 'SIG_ENCODING'
    return 'valid' if k.verify(pub, msg, sig) else 'invalid'


def nip_vectors():
    # The seed keeps the provisional label NIP-XX: the published vectors
    # (NIP-060 section 11) were derived from it.
    d = int.from_bytes(hashlib.sha256(b'NIP-XX OP_CHECKSIG_P256 vector key 1').digest(), 'big') % N
    pub = k.pubkey_from_privkey(d)
    assert pub.hex() == '0301cfb7f8207152900493007ff3a86d1f83be039b6f17418ac3ad52c2debc35a9'
    msg = b'NeuraiP256/v1/test' + bytes([0, 1, 2, 3])
    r = bytes.fromhex('03284da89332dae4ca1f4853777269f1c6659893c0830fdb2eaea3ecca4aee35')
    s = bytes.fromhex('5ccf79bc073f56306cd3069d7ffe5b1447e7e6d6e4b52ca89d10c192d01bc1e3')
    sig = r + s
    point = k.decompress(pub)
    uncompressed = b'\x04' + b32(point[0]) + b32(point[1])
    x1 = b'\x02' + b32(1)
    cases = [
        (1, 'valid signature', pub, msg, sig, 'valid'),
        (2, 'empty signature', pub, msg, b'', 'invalid'),
        (3, 'high s', pub, msg, r + b32(N - int.from_bytes(s, 'big')), 'SIG_ENCODING'),
        (4, 'altered message', pub, msg[:-1] + b'\x02', sig, 'invalid'),
        (5, 'r = 0', pub, msg, b32(0) + s, 'SIG_ENCODING'),
        (6, 'r = n', pub, msg, b32(N) + s, 'SIG_ENCODING'),
        (7, '65-byte signature', pub, msg, sig + b'\x01', 'SIG_SIZE'),
        (8, 'uncompressed key', uncompressed, msg, sig, 'PUBKEY_SIZE'),
        (9, 'prefix 04 with 33 bytes', b'\x04' + pub[1:], msg, sig, 'PUBKEY_ENCODING'),
        (10, 'X = p', b'\x02' + b32(P), msg, sig, 'PUBKEY_ENCODING'),
        (11, 'X = 1 not on the curve', x1, msg, sig, 'PUBKEY_ENCODING'),
        (12, 'invalid key and empty signature', x1, msg, b'', 'PUBKEY_ENCODING'),
        (15, 's = 0', pub, msg, r + b32(0), 'SIG_ENCODING'),
        (16, 'parity flipped', b'\x02' + pub[1:], msg, sig, 'invalid'),
        (17, 'key and signature both wrong size', uncompressed, msg, sig + b'\x01', 'PUBKEY_SIZE'),
        (18, 's = floor(n/2) is in range', pub, msg, r + b32(HALF_N), 'invalid'),
        (19, 's = floor(n/2) + 1 is high', pub, msg, r + b32(HALF_N + 1), 'SIG_ENCODING'),
        (20, 's = n', pub, msg, r + b32(N), 'SIG_ENCODING'),
        (21, 'r = n - 1 is in range', pub, msg, b32(N - 1) + s, 'invalid'),
        (22, 'empty message, valid signature', pub, b'', k.sign(d, b''), 'valid'),
        (23, 'X = p - 1', b'\x02' + b32(P - 1), msg, sig, None),
        (24, 'X = 0', b'\x02' + b32(0), msg, sig, None),
        (25, '32-byte signature', pub, msg, sig[:32], 'SIG_SIZE'),
        (26, '0-byte key', b'', msg, sig, 'PUBKEY_SIZE'),
        (27, 'prefix 05', b'\x05' + pub[1:], msg, sig, 'PUBKEY_ENCODING'),
        (28, 'prefix 06 (hybrid)', b'\x06' + pub[1:], msg, sig, 'PUBKEY_ENCODING'),
    ]
    # A message whose 520-byte body exercises the hash path above one block.
    long_msg = bytes(range(256)) * 2 + b'NeuraiP2'
    cases.append((29, '520-byte message', pub, long_msg, k.sign(d, long_msg), 'valid'))
    out = []
    for cid, comment, p, m, sg, expect in cases:
        computed = strict_expect(p, m, sg)
        if expect is not None:
            assert computed == expect, (cid, comment, computed, expect)
        out.append({'source': 'nip', 'id': cid, 'comment': comment, 'pub': p.hex(), 'msg': m.hex(),
                    'sig': sg.hex(), 'expect': computed})
    return out


def wycheproof_vectors(path):
    data = json.load(open(path))
    assert data['algorithm'] == 'ECDSA' and data['schema'] == 'ecdsa_p1363_verify_schema_v1.json'
    out = []
    stats = {'high_s_twins': 0, 'e_ge_n': 0, 'xr_ge_n': 0}
    for group in data['testGroups']:
        key = group['publicKey']
        assert key['curve'] == 'secp256r1' and group['sha'] == 'SHA-256'
        x = int(key['wx'], 16)
        y = int(key['wy'], 16)
        pub = bytes([2 + (y & 1)]) + b32(x)
        assert k.decompress(pub) == (x, y)
        for t in group['tests']:
            msg = bytes.fromhex(t['msg'])
            sig = bytes.fromhex(t['sig'])
            expect = strict_expect(pub, msg, sig)
            if int.from_bytes(hashlib.sha256(msg).digest(), 'big') >= N:
                stats['e_ge_n'] += 1
            # Consistency with Wycheproof's own verdict.
            if t['result'] == 'valid':
                assert expect in ('valid', 'SIG_ENCODING'), (t['tcId'], expect)
                if expect == 'SIG_ENCODING':
                    s = int.from_bytes(sig[32:], 'big')
                    assert s > HALF_N
                    twin = sig[:32] + b32(N - s)
                    assert strict_expect(pub, msg, twin) == 'valid'
                    out.append({'source': 'wycheproof', 'id': '%d-low-s' % t['tcId'],
                                'comment': 'low-S twin of a high-S valid signature',
                                'pub': pub.hex(), 'msg': msg.hex(), 'sig': twin.hex(), 'expect': 'valid'})
                    stats['high_s_twins'] += 1
                else:
                    r = int.from_bytes(sig[:32], 'big')
                    if r < P - N:
                        stats['xr_ge_n'] += 1
            elif t['result'] == 'invalid':
                assert expect != 'valid', (t['tcId'],)
            else:
                raise SystemExit('unexpected result %s' % t['result'])
            out.append({'source': 'wycheproof', 'id': t['tcId'], 'comment': t.get('comment', ''),
                        'pub': pub.hex(), 'msg': msg.hex(), 'sig': sig.hex(), 'expect': expect})
    print('wycheproof: %d vectors, %s' % (len(out), stats), file=sys.stderr)
    return out


def nist_vectors(path):
    section = []
    inside = False
    for line in open(path):
        line = line.strip()
        if line.startswith('['):
            inside = line == '[P-256,SHA-256]'
            continue
        if inside and line:
            section.append(line)
    entries = []
    cur = {}
    for line in section:
        key, _, value = line.partition(' = ')
        cur[key] = value
        if key == 'Result':
            entries.append(cur)
            cur = {}
    out = []
    for i, e in enumerate(entries):
        msg = bytes.fromhex(e['Msg'])
        x, y = int(e['Qx'], 16), int(e['Qy'], 16)
        on_curve = (y * y - (x ** 3 + k.A * x + k.B)) % P == 0
        pub = bytes([2 + (y & 1)]) + b32(x)
        if not on_curve:
            # Not representable as a compressed key of the same point.
            pub = bytes([2 + (y & 1)]) + b32(x)
        sig = b32(int(e['R'], 16)) + b32(int(e['S'], 16))
        expect = strict_expect(pub, msg, sig)
        passed = e['Result'].startswith('P')
        if passed:
            assert on_curve and expect in ('valid', 'SIG_ENCODING')
            if expect == 'SIG_ENCODING':
                s = int(e['S'], 16)
                twin = sig[:32] + b32(N - s)
                assert strict_expect(pub, msg, twin) == 'valid'
                out.append({'source': 'nist', 'id': '%d-low-s' % i, 'comment': 'low-S twin',
                            'pub': pub.hex(), 'msg': msg.hex(), 'sig': twin.hex(), 'expect': 'valid'})
        else:
            assert expect != 'valid', (i, e['Result'])
        out.append({'source': 'nist', 'id': i, 'comment': e['Result'], 'pub': pub.hex(),
                    'msg': msg.hex(), 'sig': sig.hex(), 'expect': expect})
    print('nist: %d vectors' % len(out), file=sys.stderr)
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--wycheproof', required=True)
    parser.add_argument('--nist', required=True)
    args = parser.parse_args()
    vectors = nip_vectors() + wycheproof_vectors(args.wycheproof) + nist_vectors(args.nist)
    doc = {
        '_comment': [
            'NIP-060 OP_CHECKSIG_P256 strict-profile vectors, generated by',
            'contrib/p256/gen_p256_vectors.py from the NIP-060 section 11 cases,',
            'C2SP/wycheproof ecdsa_secp256r1_sha256_p1363_test.json',
            '(65ca494727a52944c204441c860b039e6786b99b) and NIST CAVP 186-4',
            'SigVer [P-256,SHA-256]. expect: valid, invalid, PUBKEY_SIZE,',
            'PUBKEY_ENCODING, SIG_SIZE or SIG_ENCODING.',
        ],
        'vectors': vectors,
    }
    json.dump(doc, sys.stdout, indent=1)
    sys.stdout.write('\n')
    from collections import Counter
    print(Counter(v['expect'] for v in vectors), file=sys.stderr)


if __name__ == '__main__':
    main()
