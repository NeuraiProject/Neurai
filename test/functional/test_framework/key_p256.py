#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Pure-Python NIST P-256 (secp256r1) ECDSA, for tests only.

Implements the NIP-060 OP_CHECKSIG_P256 profile:
  - public keys: 33-byte SEC 1 compressed (02/03 || X);
  - signatures: 64-byte r || s with low S (s <= n/2);
  - digest: e = SHA-256(msg), reduced mod n.

Signing is deterministic (RFC 6979 with HMAC-SHA256). Not constant time and
not meant for real keys.
"""

import hashlib
import hmac

P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
A = P - 3
B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
HALF_N = N // 2


def _add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    if p1[0] == p2[0]:
        if (p1[1] + p2[1]) % P == 0:
            return None
        lam = (3 * p1[0] * p1[0] + A) * pow(2 * p1[1], -1, P) % P
    else:
        lam = (p2[1] - p1[1]) * pow(p2[0] - p1[0], -1, P) % P
    x = (lam * lam - p1[0] - p2[0]) % P
    return (x, (lam * (p1[0] - x) - p1[1]) % P)


def point_mul(k, point=G):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def compress(point):
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, 'big')


def decompress(pub):
    """Return the point for a 33-byte compressed key, or None if invalid."""
    if len(pub) != 33 or pub[0] not in (2, 3):
        return None
    x = int.from_bytes(pub[1:], 'big')
    if x >= P:
        return None
    rhs = (x * x * x + A * x + B) % P
    y = pow(rhs, (P + 1) // 4, P)
    if y * y % P != rhs:
        return None
    if (y & 1) != (pub[0] & 1):
        y = P - y
    return (x, y)


def pubkey_from_privkey(priv):
    return compress(point_mul(priv))


def digest_int(msg):
    return int.from_bytes(hashlib.sha256(msg).digest(), 'big') % N


def _rfc6979_nonce(priv, h1):
    """RFC 6979 §3.2 with HMAC-SHA256; h1 is the 32-byte digest."""
    x = priv.to_bytes(32, 'big')
    h = (int.from_bytes(h1, 'big') % N).to_bytes(32, 'big')
    v = b'\x01' * 32
    k = b'\x00' * 32
    k = hmac.new(k, v + b'\x00' + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b'\x01' + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        cand = int.from_bytes(v, 'big')
        if 1 <= cand < N:
            return cand
        k = hmac.new(k, v + b'\x00', hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign_digest(priv, digest32, low_s=True):
    """Sign a 32-byte SHA-256 digest; returns 64-byte r || s."""
    e = int.from_bytes(digest32, 'big') % N
    k = _rfc6979_nonce(priv, digest32)
    r = point_mul(k)[0] % N
    s = pow(k, -1, N) * (e + r * priv) % N
    assert r != 0 and s != 0
    if low_s and s > HALF_N:
        s = N - s
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


def sign(priv, msg, low_s=True):
    """Sign SHA-256(msg), the digest OP_CHECKSIG_P256 checks."""
    return sign_digest(priv, hashlib.sha256(msg).digest(), low_s)


def verify(pub, msg, sig):
    """Strict-profile verification: True, False, or None if malformed."""
    point = decompress(pub)
    if point is None or len(sig) not in (0, 64):
        return None
    if len(sig) == 0:
        return False
    r = int.from_bytes(sig[:32], 'big')
    s = int.from_bytes(sig[32:], 'big')
    if not (1 <= r < N) or not (1 <= s <= HALF_N):
        return None
    e = digest_int(msg)
    w = pow(s, -1, N)
    R = _add(point_mul(e * w % N), point_mul(r * w % N, point))
    return R is not None and R[0] % N == r


def recover_candidates(digest32, sig):
    """Public keys (compressed) that verify sig over digest32 (SEC 1 §4.1.6).

    Up to four: x(R) can be r or r + n, each with two parities.
    """
    r = int.from_bytes(sig[:32], 'big')
    s = int.from_bytes(sig[32:], 'big')
    e = int.from_bytes(digest32, 'big') % N
    out = []
    for j in (0, 1):
        x = r + j * N
        if x >= P:
            continue
        for prefix in (2, 3):
            R = decompress(bytes([prefix]) + x.to_bytes(32, 'big'))
            if R is None:
                continue
            rinv = pow(r, -1, N)
            # Q = r^-1 (s R - e G)
            sR = point_mul(s, R)
            eG = point_mul((-e) % N)
            Q = point_mul(rinv, _add(sR, eG))
            if Q is not None:
                out.append(compress(Q))
    return out
