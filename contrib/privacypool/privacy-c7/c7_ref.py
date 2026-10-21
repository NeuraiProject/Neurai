#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Independent pure-Python reference of the C7 privacy pool notes (NeuraiZK/v3).

Specification: README.md in this directory. Testnet experiment, not
production code: big-integer arithmetic and no constant time. Every primitive
is written here from its RFC/NIST specification; test_c7_ref.py checks them
against published vectors, xcheck_libsodium.py against libsodium and
xcheck_fpe.py against the FF1 crate used by Zcash.
"""
import hashlib
import hmac
import os
import struct
from pathlib import Path


class C7Error(Exception):
    """Failure with a stable reason, used by the negative vectors."""

    def __init__(self, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


# ---------------------------------------------------------------- hashes

def sha256(data):
    return hashlib.sha256(data).digest()


def sha512(data):
    return hashlib.sha512(data).digest()


def hmac_sha256(key, data):
    return hmac.new(key, data, hashlib.sha256).digest()


def blake2b(data, personal, size):
    """RFC 7693 BLAKE2b without key or salt; personalization zero-padded to 16 bytes."""
    person = personal.encode("ascii") if isinstance(personal, str) else personal
    if len(person) > 16:
        raise ValueError("BLAKE2b personalization longer than 16 bytes")
    return hashlib.blake2b(data, digest_size=size, person=person.ljust(16, b"\0")).digest()


def expand_message_xmd(msg, dst, length, h=hashlib.sha512, block=128):
    """RFC 9380 section 5.3.1."""
    b_len = h().digest_size
    ell = (length + b_len - 1) // b_len
    if ell > 255 or length > 65535 or len(dst) > 255:
        raise ValueError("expand_message_xmd parameters out of range")
    dst_prime = dst + bytes([len(dst)])
    msg_prime = bytes(block) + msg + length.to_bytes(2, "big") + b"\0" + dst_prime
    b0 = h(msg_prime).digest()
    out = b_prev = h(b0 + b"\1" + dst_prime).digest()
    for i in range(2, ell + 1):
        b_prev = h(bytes(x ^ y for x, y in zip(b0, b_prev)) + bytes([i]) + dst_prime).digest()
        out += b_prev
    return out[:length]


# ------------------------------------------------- ChaCha20-Poly1305 (RFC 8439)

def _rotl32(v, c):
    return ((v << c) & 0xFFFFFFFF) | (v >> (32 - c))


def _quarter(w, a, b, c, d):
    w[a] = (w[a] + w[b]) & 0xFFFFFFFF; w[d] = _rotl32(w[d] ^ w[a], 16)
    w[c] = (w[c] + w[d]) & 0xFFFFFFFF; w[b] = _rotl32(w[b] ^ w[c], 12)
    w[a] = (w[a] + w[b]) & 0xFFFFFFFF; w[d] = _rotl32(w[d] ^ w[a], 8)
    w[c] = (w[c] + w[d]) & 0xFFFFFFFF; w[b] = _rotl32(w[b] ^ w[c], 7)


def chacha20_block(key, counter, nonce):
    state = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574, *struct.unpack("<8I", key), counter,
             *struct.unpack("<3I", nonce)]
    w = state[:]
    for _ in range(10):
        _quarter(w, 0, 4, 8, 12); _quarter(w, 1, 5, 9, 13); _quarter(w, 2, 6, 10, 14); _quarter(w, 3, 7, 11, 15)
        _quarter(w, 0, 5, 10, 15); _quarter(w, 1, 6, 11, 12); _quarter(w, 2, 7, 8, 13); _quarter(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(w[i] + state[i]) & 0xFFFFFFFF for i in range(16)])


def chacha20_xor(key, counter, nonce, data):
    out = bytearray()
    for block in range(0, len(data), 64):
        stream = chacha20_block(key, counter + block // 64, nonce)
        out += bytes(x ^ y for x, y in zip(data[block:block + 64], stream))
    return bytes(out)


def poly1305(key, msg):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        acc = (acc + int.from_bytes(msg[i:i + 16] + b"\1", "little")) * r % p
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")


def _pad16(data):
    return bytes(-len(data) % 16)


def _poly_input(aad, ct):
    return aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<QQ", len(aad), len(ct))


def aead_encrypt(key, nonce, plaintext, aad):
    otk = chacha20_block(key, 0, nonce)[:32]
    ct = chacha20_xor(key, 1, nonce, plaintext)
    return ct + poly1305(otk, _poly_input(aad, ct))


def aead_decrypt(key, nonce, data, aad):
    if len(data) < 16:
        raise C7Error("aead-failed", "ciphertext shorter than the tag")
    ct, tag = data[:-16], data[-16:]
    otk = chacha20_block(key, 0, nonce)[:32]
    if not hmac.compare_digest(poly1305(otk, _poly_input(aad, ct)), tag):
        raise C7Error("aead-failed")
    return chacha20_xor(key, 1, nonce, ct)


# ------------------------------------------------------------ AES (FIPS 197)

def _make_sbox():
    sbox = [0] * 256
    p = q = 1
    while True:
        p = (p ^ (p << 1) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        rot = lambda x, s: ((x << s) | (x >> (8 - s))) & 0xFF  # noqa: E731
        sbox[p] = q ^ rot(q, 1) ^ rot(q, 2) ^ rot(q, 3) ^ rot(q, 4) ^ 0x63
        if p == 1:
            break
    sbox[0] = 0x63
    return sbox


_SBOX = _make_sbox()


def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def _expand_key(key):
    nk = len(key) // 4
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24 or 32 bytes")
    nr = nk + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        t = words[i - 1][:]
        if i % nk == 0:
            t = [_SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        elif nk > 6 and i % nk == 4:
            t = [_SBOX[b] for b in t]
        words.append([a ^ b for a, b in zip(words[i - nk], t)])
    return nr, [sum(words[4 * r:4 * r + 4], []) for r in range(nr + 1)]


def aes_encrypt(key, block):
    nr, keys = _expand_key(key)
    s = [a ^ b for a, b in zip(block, keys[0])]
    for rnd in range(1, nr + 1):
        s = [_SBOX[b] for b in s]
        s = [s[(4 * ((c + r) % 4)) + r] for c in range(4) for r in range(4)]  # ShiftRows
        if rnd != nr:
            mixed = []
            for c in range(4):
                a = s[4 * c:4 * c + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                mixed += [a[i] ^ t ^ _xtime(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
            s = mixed
        s = [a ^ b for a, b in zip(s, keys[rnd])]
    return bytes(s)


# ------------------------------------------------------ FF1 (NIST SP 800-38G)

def _num(digits, radix):
    value = 0
    for digit in digits:
        value = value * radix + digit
    return value


def _str(value, radix, length):
    out = [0] * length
    for i in range(length - 1, -1, -1):
        out[i] = value % radix
        value //= radix
    return out


def _cbc_mac(key, data):
    y = bytes(16)
    for i in range(0, len(data), 16):
        y = aes_encrypt(key, bytes(a ^ b for a, b in zip(y, data[i:i + 16])))
    return y


def ff1(key, tweak, digits, radix, decrypt=False):
    """FF1 encryption (Algorithm 7) or decryption (Algorithm 8) of a numeral string."""
    n, t = len(digits), len(tweak)
    if n < 2 or any(not 0 <= x < radix for x in digits):
        raise ValueError("invalid FF1 numeral string")
    u, v = n // 2, n - n // 2
    a, b = list(digits[:u]), list(digits[u:])
    blen = ((radix ** v - 1).bit_length() + 7) // 8
    d = 4 * ((blen + 3) // 4) + 4
    p = bytes([1, 2, 1]) + radix.to_bytes(3, "big") + bytes([10, u % 256]) + n.to_bytes(4, "big") + t.to_bytes(4, "big")
    for i in (range(9, -1, -1) if decrypt else range(10)):
        source = a if decrypt else b
        q = tweak + bytes((-t - blen - 1) % 16) + bytes([i]) + _num(source, radix).to_bytes(blen, "big")
        r = _cbc_mac(key, p + q)
        s, j = r, 1
        while len(s) < d:
            s += aes_encrypt(key, bytes(x ^ y for x, y in zip(r, j.to_bytes(16, "big"))))
            j += 1
        y = int.from_bytes(s[:d], "big")
        m = u if i % 2 == 0 else v
        if decrypt:
            c = _str((_num(b, radix) - y) % radix ** m, radix, m)
            a, b = c, a
        else:
            c = _str((_num(a, radix) + y) % radix ** m, radix, m)
            a, b = b, c
    return a + b


# ---------------------------------------------------- ristretto255 (RFC 9496)

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, -1, P) % P


def _is_negative(x):
    return (x % P) & 1


def _abs(x):
    x %= P
    return P - x if _is_negative(x) else x


def _sqrt_ratio_m1(u, v):
    r = (u * pow(v, 3, P)) * pow(u * pow(v, 7, P), (P - 5) // 8, P) % P
    check = v * r * r % P
    correct = check == u % P
    flipped = check == -u % P
    flipped_i = check == (-u * SQRT_M1) % P
    if flipped or flipped_i:
        r = r * SQRT_M1 % P
    return correct or flipped, _abs(r)


# RFC 9496 section 4.1. SQRT_AD_MINUS_ONE is the odd ("negative") root, so the
# constants are taken literally and only checked here.
SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752
SQRT_AD_MINUS_ONE = 25063068953384623474111414158702152701244531502492656460079210482610430750235
INVSQRT_A_MINUS_D = 54469307008909316920995813868745141605393597292927456921205312896311721017578
ONE_MINUS_D_SQ = 1159843021668779879193775521855586647937357759715417654439879720876111806838
D_MINUS_ONE_SQ = 40440834346308536858101042469323190826248399146238708352240133220865137265952
assert SQRT_M1 * SQRT_M1 % P == P - 1
assert SQRT_AD_MINUS_ONE * SQRT_AD_MINUS_ONE % P == (-D - 1) % P
assert INVSQRT_A_MINUS_D * INVSQRT_A_MINUS_D * (-1 - D) % P == 1
assert ONE_MINUS_D_SQ == (1 - D * D) % P and D_MINUS_ONE_SQ == (D - 1) * (D - 1) % P

IDENTITY = (0, 1, 1, 0)
_BASE_Y = 4 * pow(5, -1, P) % P
_BASE_X = 15112221349535400772501151409588531511454012693041857206046113283949847762202
BASE = (_BASE_X, _BASE_Y, 1, _BASE_X * _BASE_Y % P)
assert (_BASE_Y ** 2 - _BASE_X ** 2 - 1 - D * _BASE_X ** 2 * _BASE_Y ** 2) % P == 0


def point_add(p1, p2):
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = t1 * 2 * D * t2 % P
    d = z1 * 2 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def point_mul(scalar, point):
    result, addend = IDENTITY, point
    scalar %= L
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def point_eq(p1, p2):
    x1, y1, _, _ = p1
    x2, y2, _, _ = p2
    return (x1 * y2 - y1 * x2) % P == 0 or (y1 * y2 - x1 * x2) % P == 0


def is_identity(point):
    return point_eq(point, IDENTITY)


def ristretto_decode(data):
    """RFC 9496 section 4.3.1; rejects non-canonical encodings."""
    if len(data) != 32:
        raise C7Error("point-invalid", "length")
    s = int.from_bytes(data, "little")
    if s >= P or _is_negative(s):
        raise C7Error("point-invalid", "non-canonical")
    ss = s * s % P
    u1, u2 = (1 - ss) % P, (1 + ss) % P
    u2_sqr = u2 * u2 % P
    v = (-(D * u1 * u1) - u2_sqr) % P
    was_square, invsqrt = _sqrt_ratio_m1(1, v * u2_sqr % P)
    den_x = invsqrt * u2 % P
    den_y = invsqrt * den_x * v % P
    x = _abs(2 * s * den_x)
    y = u1 * den_y % P
    t = x * y % P
    if not was_square or _is_negative(t) or y == 0:
        raise C7Error("point-invalid", "not a ristretto255 encoding")
    return (x, y, 1, t)


def ristretto_encode(point):
    """RFC 9496 section 4.3.2."""
    x0, y0, z0, t0 = point
    u1 = (z0 + y0) * (z0 - y0) % P
    u2 = x0 * y0 % P
    _, invsqrt = _sqrt_ratio_m1(1, u1 * u2 * u2 % P)
    den1, den2 = invsqrt * u1 % P, invsqrt * u2 % P
    z_inv = den1 * den2 * t0 % P
    ix0, iy0 = x0 * SQRT_M1 % P, y0 * SQRT_M1 % P
    enchanted = den1 * INVSQRT_A_MINUS_D % P
    rotate = _is_negative(t0 * z_inv)
    x, y = (iy0, ix0) if rotate else (x0, y0)
    den_inv = enchanted if rotate else den2
    if _is_negative(x * z_inv):
        y = -y % P
    return _abs(den_inv * (z0 - y)).to_bytes(32, "little")


def _elligator(t):
    r = SQRT_M1 * t * t % P
    u = (r + 1) * ONE_MINUS_D_SQ % P
    v = (-1 - r * D) * (r + D) % P
    was_square, s = _sqrt_ratio_m1(u, v)
    if not was_square:
        s = -_abs(s * t) % P
    c = P - 1 if was_square else r
    n = (c * (r - 1) * D_MINUS_ONE_SQ - v) % P
    w0, w1 = 2 * s * v % P, n * SQRT_AD_MINUS_ONE % P
    w2, w3 = (1 - s * s) % P, (1 + s * s) % P
    return (w0 * w3 % P, w2 * w1 % P, w1 * w3 % P, w0 * w2 % P)


def ristretto_from_uniform(data):
    """RFC 9496 one-way map of 64 uniform bytes (libsodium: crypto_core_ristretto255_from_hash)."""
    if len(data) != 64:
        raise ValueError("one-way map needs 64 bytes")
    mask = (1 << 255) - 1
    r0 = (int.from_bytes(data[:32], "little") & mask) % P
    r1 = (int.from_bytes(data[32:], "little") & mask) % P
    return point_add(_elligator(r0), _elligator(r1))


def hash_to_ristretto255(msg, dst):
    """RFC 9380 appendix B (ristretto255_XMD:SHA-512_R255MAP_RO_), in its two explicit steps."""
    uniform = expand_message_xmd(msg, dst, 64)
    return uniform, ristretto_from_uniform(uniform)


def to_scalar(data64):
    return int.from_bytes(data64, "little") % L


# ------------------------------------------------------ Poseidon CP1 (NIP-036)

R_BN254 = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def _poseidon_header():
    here = Path(__file__).resolve().parent
    candidates = [os.environ.get("C7_POSEIDON_HEADER"), here / "data/poseidon_bn254_constants.h"]
    candidates += [parent / "src/crypto/poseidon_bn254_constants.h" for parent in here.parents]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate).read_text()
    raise FileNotFoundError("poseidon_bn254_constants.h not found (set C7_POSEIDON_HEADER)")


def _poseidon_constants():
    import re
    header = _poseidon_header()

    def table(name):
        body = header.split(name, 1)[1].split("};", 1)[0]
        limbs = [int(v, 16) for v in re.findall(r"0x([0-9a-fA-F]+)ULL", body)]
        return [sum(limbs[i + j] << (64 * j) for j in range(4)) for i in range(0, len(limbs), 4)]

    return table("POSEIDON_BN254_RC[195][4]"), table("POSEIDON_BN254_MDS[3][3][4]")


_RC, _MDS = _poseidon_constants()


def _poseidon_permute(state):
    for rnd in range(65):
        state = [(x + _RC[rnd * 3 + i]) % R_BN254 for i, x in enumerate(state)]
        state = [pow(x, 5, R_BN254) if i == 0 or rnd < 4 or rnd >= 61 else x for i, x in enumerate(state)]
        state = [sum(_MDS[i * 3 + j] * state[j] for j in range(3)) % R_BN254 for i in range(3)]
    return state


def poseidon_bytes(data):
    """CP1 byte sponge: 0x01 padding, 31-byte big-endian chunks, rate two."""
    padded = data + b"\1"
    padded += bytes(-len(padded) % 31)
    elements = [int.from_bytes(padded[i:i + 31], "big") for i in range(0, len(padded), 31)]
    state = [0, 0, 0]
    for i in range(0, len(elements), 2):
        for j, x in enumerate(elements[i:i + 2]):
            state[j] = (state[j] + x) % R_BN254
        state = _poseidon_permute(state)
    return state[0].to_bytes(32, "big")


assert _poseidon_permute([0, 1, 2])[0] == int("115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a", 16)


# ------------------------------------------------------------- Bech32m

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32M = 0x2BC830A3


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frombits, tobits, pad):
    acc = bits = 0
    out = []
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & ((1 << tobits) - 1))
    if pad and bits:
        out.append((acc << (tobits - bits)) & ((1 << tobits) - 1))
    elif not pad and (bits >= frombits or (acc << (tobits - bits)) & ((1 << tobits) - 1)):
        raise C7Error("address-encoding", "padding")
    return out


def bech32m_encode(hrp, payload):
    data = _convertbits(payload, 8, 5, True)
    checksum = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ _BECH32M
    return hrp + "1" + "".join(_CHARSET[d] for d in data + [(checksum >> 5 * (5 - i)) & 31 for i in range(6)])


def bech32m_decode(text):
    if text.lower() != text and text.upper() != text:
        raise C7Error("address-encoding", "mixed case")
    text = text.lower()
    pos = text.rfind("1")
    if pos < 1 or pos + 7 > len(text) or len(text) > 200:
        raise C7Error("address-encoding", "separator or length")
    hrp, rest = text[:pos], text[pos + 1:]
    if any(c not in _CHARSET for c in rest):
        raise C7Error("address-encoding", "charset")
    data = [_CHARSET.index(c) for c in rest]
    if _polymod(_hrp_expand(hrp) + data) != _BECH32M:
        raise C7Error("address-encoding", "checksum")
    return hrp, bytes(_convertbits(data[:-6], 5, 8, False))


# ------------------------------------------------------- C7 / NeuraiZK v3

FAMILIES = {"legacy": 0, "ecdsa": 1, "pq": 2}
HRPS = {"main": "nzk", "test": "tnzk", "regtest": "rnzk"}
MAX_ACCOUNT = MAX_INDEX = 2 ** 31 - 1
MAX_AMOUNT = 2_100_000_000_000_000_000
ADDRESS_VERSION = 3
RECORD_VERSION = 2
RECORD_BYTES = 230
NOTE_BYTES = 169
DIVERSIFIER_BYTES = 11
DST_GD = b"NeuraiZKv3-gd"
AAD_LABEL = b"NIP043/note/CP2"
NONCE = bytes(12)


def u32le(value, maximum=2 ** 32 - 1):
    if not isinstance(value, int) or not 0 <= value <= maximum:
        raise ValueError("u32 value out of range")
    return value.to_bytes(4, "little")


def instance_tag(domain, asset_id):
    return sha256(b"NeuraiZK/v3/instance" + domain + asset_id)[:4]


def xna_asset_id():
    return sha256(b"NeuraiPool/asset/XNA")


def pool_domain(genesis, emission_txid, vout, identity):
    """Domain of one pool instance. Hashes are given in display (RPC) order."""
    name = identity.encode("ascii")
    if not 1 <= len(name) <= 64 or not all(0x21 <= c <= 0x7e for c in name):
        raise ValueError("invalid pool identity")
    return sha256(b"NeuraiPoolC7/domain" + b"\1" + bytes.fromhex(genesis)[::-1] + bytes.fromhex(emission_txid)[::-1] +
                  u32le(vout) + bytes([len(name)]) + name)


def pool_context(domain, asset_id):
    """Public input 0 of every C7 proof; same construction as C6."""
    return poseidon_bytes(b"NeuraiPoolCtx\1" + domain + asset_id + (1).to_bytes(8, "little") + bytes(32))


def diversifier_from_index(dk, j):
    """d = LEBS2OSP_88(FF1-AES256(dk, "", I2LEBSP_88(j))), radix 2, empty tweak."""
    if not 0 <= j < 2 ** 88:
        raise ValueError("diversifier index out of range")
    bits = ff1(dk, b"", [(j >> k) & 1 for k in range(88)], 2)
    return bytes(sum(bits[8 * i + k] << k for k in range(8)) for i in range(11))


def index_from_diversifier(dk, d):
    bits = ff1(dk, b"", [(d[k // 8] >> (k % 8)) & 1 for k in range(88)], 2, decrypt=True)
    return sum(bit << k for k, bit in enumerate(bits))


def diversify_hash(d, domain, asset_id):
    uniform, point = hash_to_ristretto255(d + domain + asset_id, DST_GD)
    if is_identity(point):
        raise C7Error("diversifier-identity")
    return uniform, point


def derive_esk(rho, domain, asset_id):
    return to_scalar(blake2b(rho + domain + asset_id, "NeuraiZKv3_esk", 64))


def note_kdf(shared, epk):
    return blake2b(shared + epk, "NeuraiZKv3_KDF", 32)


def view_tag(shared, epk):
    return blake2b(shared + epk, "NeuraiZKv3_vtag", 32)[0]


def note_aad(domain, cm):
    return AAD_LABEL + domain + cm


def canonical_field(data):
    return len(data) == 32 and int.from_bytes(data, "big") < R_BN254


def encode_note(domain, asset_id, owner, pk_d, amount, rho):
    if not canonical_field(owner) or int.from_bytes(owner, "big") == 0:
        raise C7Error("note-malformed", "owner")
    ristretto_decode(pk_d)
    if not isinstance(amount, int) or not 1 <= amount <= MAX_AMOUNT:
        raise C7Error("note-malformed", "amount")
    if len(rho) != 32:
        raise C7Error("note-malformed", "rho")
    return b"\1" + domain + asset_id + owner + pk_d + amount.to_bytes(8, "little") + rho


def decode_note(note, domain, asset_id):
    if len(note) != NOTE_BYTES or note[0] != 1:
        raise C7Error("note-malformed", "version or length")
    if note[1:33] != domain or note[33:65] != asset_id:
        raise C7Error("note-instance")
    owner, pk_d = note[65:97], note[97:129]
    amount = int.from_bytes(note[129:137], "little")
    if not canonical_field(owner) or int.from_bytes(owner, "big") == 0 or not 1 <= amount <= MAX_AMOUNT:
        raise C7Error("note-malformed", "owner or amount")
    return {"owner": owner, "pk_d": pk_d, "amount": amount, "rho": note[137:169]}


def note_commitment(note):
    cm = poseidon_bytes(b"NIP043/cm/CP1" + note)
    if int.from_bytes(cm, "big") == 0:
        raise C7Error("note-malformed", "zero commitment")
    return cm


def nullifier(domain, nk, rho, cm):
    return poseidon_bytes(b"NIP043/nf/CP1" + domain + nk + rho + cm)


class Instance:
    def __init__(self, network, domain, asset_id):
        if network not in HRPS or len(domain) != 32 or len(asset_id) != 32:
            raise ValueError("invalid instance")
        self.network, self.domain, self.asset_id = network, domain, asset_id


class ViewKey:
    """Receive-only key (ivk, dk): finds incoming notes, cannot check ownership or nullifiers."""

    def __init__(self, instance, ivk, dk):
        self.instance, self.ivk, self.dk = instance, ivk, dk


class Account:
    """Keys of one (family, account) for one pool instance, from the v2 private root R."""

    def __init__(self, instance, root, family="ecdsa", account=0):
        if len(root) != 64:
            raise ValueError("private root R must be 64 bytes (NeuraiZK/v2, section 4.2)")
        if family not in FAMILIES or not 0 <= account <= MAX_ACCOUNT:
            raise ValueError("invalid family or account")
        self.instance, self.family, self.account = instance, FAMILIES[family], account
        self.prk = hmac_sha256(b"NeuraiZK/v2/account", root)
        self.q = bytes([self.family]) + u32le(account) + instance.domain + instance.asset_id
        self.ivk_seed = self.expand32(b"NeuraiZK/v3/ivk" + self.q)
        self.ivk = to_scalar(blake2b(self.ivk_seed, "NeuraiZKv3_ivk", 64))
        if self.ivk == 0:
            raise C7Error("ivk-zero", "fail explicitly, do not retry")
        self.dk = self.expand32(b"NeuraiZK/v3/dk" + self.q)

    def expand32(self, info):
        return hmac_sha256(self.prk, info + b"\1")

    def view_key(self):
        return ViewKey(self.instance, self.ivk, self.dk)

    def p(self, branch, index):
        if branch not in (0, 1) or not 0 <= index <= MAX_INDEX:
            raise C7Error("index-out-of-range")
        return (bytes([self.family]) + u32le(self.account) + u32le(branch) + u32le(index) +
                self.instance.domain + self.instance.asset_id)

    def spend_keys(self, branch, index):
        spend = self.expand32(b"NeuraiZK/v3/spend" + self.p(branch, index))
        if spend == bytes(32):
            raise C7Error("spend-secret-zero", "fail explicitly, do not retry")
        domain = self.instance.domain
        owner = poseidon_bytes(b"NIP043/owner/CP1" + domain + spend)
        nk = poseidon_bytes(b"NIP043/nk/CP1" + domain + spend)
        if int.from_bytes(owner, "big") == 0:
            raise C7Error("owner-zero")
        return spend, owner, nk

    def address(self, branch, index):
        p = self.p(branch, index)
        spend, owner, nk = self.spend_keys(branch, index)
        j = branch * 2 ** 32 + index
        d = diversifier_from_index(self.dk, j)
        uniform, g_d = diversify_hash(d, self.instance.domain, self.instance.asset_id)
        pk_point = point_mul(self.ivk, g_d)
        if is_identity(pk_point):
            raise C7Error("pk_d-identity")
        pk_d = ristretto_encode(pk_point)
        payload = bytes([ADDRESS_VERSION]) + owner + d + pk_d + instance_tag(self.instance.domain, self.instance.asset_id)
        return {"branch": branch, "index": index, "p": p, "spend_secret": spend, "owner": owner, "nk": nk, "j": j,
                "d": d, "gd_uniform": uniform, "g_d": ristretto_encode(g_d), "pk_d": pk_d, "payload": payload,
                "text": bech32m_encode(HRPS[self.instance.network], payload)}


def parse_address(text, instance):
    hrp, payload = bech32m_decode(text)
    if hrp != HRPS[instance.network]:
        raise C7Error("address-hrp")
    if len(payload) != 80:
        raise C7Error("address-length")
    if payload[0] != ADDRESS_VERSION:
        raise C7Error("address-version")
    if payload[76:80] != instance_tag(instance.domain, instance.asset_id):
        raise C7Error("address-instance")
    owner, d, pk_d = payload[1:33], payload[33:44], payload[44:76]
    if not canonical_field(owner) or int.from_bytes(owner, "big") == 0:
        raise C7Error("owner-invalid")
    try:
        point = ristretto_decode(pk_d)
    except C7Error:
        raise C7Error("pk_d-invalid", "not canonical")
    if is_identity(point):
        raise C7Error("pk_d-invalid", "identity")
    return {"owner": owner, "d": d, "pk_d": pk_d}


def seal_note(recipient, amount, rho, instance, *, esk=None, note_owner=None, note_pk_d=None, aad_cm=None,
              vtag_xor=0, raw_note=None):
    """Sender side (plan section 4.4). The keyword arguments only exist to build
    malicious records for the negative vectors; a conforming sender never sets them."""
    domain, asset_id = instance.domain, instance.asset_id
    if raw_note is None:
        note = encode_note(domain, asset_id, note_owner or recipient["owner"], note_pk_d or recipient["pk_d"], amount,
                           rho)
    else:
        note, rho = raw_note, raw_note[137:169]
    cm = poseidon_bytes(b"NIP043/cm/CP1" + note)
    if esk is None:
        esk = derive_esk(rho, domain, asset_id)
    if esk % L == 0:
        raise C7Error("esk-zero", "choose another rho")
    _, g_d = diversify_hash(recipient["d"], domain, asset_id)
    epk = ristretto_encode(point_mul(esk, g_d))
    shared = ristretto_encode(point_mul(esk, ristretto_decode(recipient["pk_d"])))
    tag = view_tag(shared, epk) ^ vtag_xor
    key = note_kdf(shared, epk)
    plaintext = note + recipient["d"]
    ct = aead_encrypt(key, NONCE, plaintext, note_aad(domain, aad_cm or cm))
    record = bytes([RECORD_VERSION, tag]) + epk + ct
    assert len(record) == RECORD_BYTES
    return {"note": note, "cm": cm, "esk": esk.to_bytes(32, "little"), "epk": epk, "shared": shared, "vtag": tag,
            "key": key, "plaintext": plaintext, "ct": ct, "record": record}


def scan_receive(record, cm, view, check_vtag=True):
    """Receive-only scanner (plan section 4.5, steps 1 to 8). check_vtag=False is
    the brute-force mode of the tests: it must find exactly the same notes."""
    inst = view.instance
    if len(record) != RECORD_BYTES:
        raise C7Error("record-length")
    if record[0] != RECORD_VERSION:
        raise C7Error("record-version")
    tag, epk, ct = record[1], record[2:34], record[34:]
    try:
        epk_point = ristretto_decode(epk)
    except C7Error:
        raise C7Error("epk-invalid")
    if is_identity(epk_point):
        raise C7Error("epk-identity")
    shared = ristretto_encode(point_mul(view.ivk, epk_point))
    if check_vtag and view_tag(shared, epk) != tag:
        raise C7Error("vtag-mismatch")
    plaintext = aead_decrypt(note_kdf(shared, epk), NONCE, ct, note_aad(inst.domain, cm))
    note, d = plaintext[:NOTE_BYTES], plaintext[NOTE_BYTES:]
    fields = decode_note(note, inst.domain, inst.asset_id)
    j = index_from_diversifier(view.dk, d)
    branch, index = j >> 32, j & 0xFFFFFFFF
    if branch > 1 or index > MAX_INDEX:
        raise C7Error("index-out-of-range")
    _, g_d = diversify_hash(d, inst.domain, inst.asset_id)
    if ristretto_encode(point_mul(view.ivk, g_d)) != fields["pk_d"]:
        raise C7Error("pk_d-mismatch")
    esk = derive_esk(fields["rho"], inst.domain, inst.asset_id)
    if esk == 0 or ristretto_encode(point_mul(esk, g_d)) != epk:
        raise C7Error("epk-mismatch")
    if note_commitment(note) != cm:
        raise C7Error("cm-mismatch")
    return {"status": "received", "ownership": "unverified", "branch": branch, "index": index,
            "amount": fields["amount"], "note": note, "d": d}


def scan_full(record, cm, account):
    """Full scanner (plan section 4.5, steps 1 to 10): ownership and nullifier."""
    found = scan_receive(record, cm, account.view_key())
    _, owner, nk = account.spend_keys(found["branch"], found["index"])
    fields = decode_note(found["note"], account.instance.domain, account.instance.asset_id)
    if owner != fields["owner"]:
        raise C7Error("owner-mismatch")
    found.update(status="owned", ownership="verified",
                 nf=nullifier(account.instance.domain, nk, fields["rho"], cm))
    return found
