#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Recompute the C7 vectors with libsodium (ctypes) and AES with OpenSSL (cryptography).

Independent of c7_ref.py for: ristretto255 (encoding, decoding, one-way map,
scalar multiplication), ToScalar (scalar_reduce), BLAKE2b with personalization,
ChaCha20-Poly1305 IETF and AES. expand_message_xmd is recomputed with hashlib
here only; noble checks it independently (bench/xcheck-noble.mjs).
"""
import ctypes
import ctypes.util
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gen_c7_vectors as g  # noqa: E402
import rfc_vectors as t  # noqa: E402

h = bytes.fromhex
lib = ctypes.CDLL(ctypes.util.find_library("sodium") or "libsodium.so.23")
assert lib.sodium_init() >= 0
lib.sodium_version_string.restype = ctypes.c_char_p
checks = {"ok": 0}


def check(cond, what):
    if not cond:
        raise AssertionError(what)
    checks["ok"] += 1


def buf(n):
    return ctypes.create_string_buffer(n)


def base_mul(scalar32):
    out = buf(32)
    rc = lib.crypto_scalarmult_ristretto255_base(out, scalar32)
    return None if rc != 0 else out.raw


def mul(scalar32, point):
    out = buf(32)
    rc = lib.crypto_scalarmult_ristretto255(out, scalar32, point)
    return None if rc != 0 else out.raw


def valid(point):
    return lib.crypto_core_ristretto255_is_valid_point(point) == 1


def from_hash(uniform):
    out = buf(32)
    lib.crypto_core_ristretto255_from_hash(out, uniform)
    return out.raw


def reduce64(wide):
    out = buf(32)
    lib.crypto_core_ristretto255_scalar_reduce(out, wide)
    return out.raw


def blake2b(data, personal, size):
    out = buf(size)
    person = personal.encode().ljust(16, b"\0")
    rc = lib.crypto_generichash_blake2b_salt_personal(out, ctypes.c_size_t(size), data, ctypes.c_ulonglong(len(data)),
                                                      None, ctypes.c_size_t(0), None, person)
    assert rc == 0
    return out.raw


def aead(key, plaintext, aad):
    out = buf(len(plaintext) + 16)
    out_len = ctypes.c_ulonglong()
    rc = lib.crypto_aead_chacha20poly1305_ietf_encrypt(out, ctypes.byref(out_len), plaintext,
                                                       ctypes.c_ulonglong(len(plaintext)), aad,
                                                       ctypes.c_ulonglong(len(aad)), None, bytes(12), key)
    assert rc == 0
    return out.raw[:out_len.value]


def aead_open(key, data, aad):
    out = buf(len(data))
    out_len = ctypes.c_ulonglong()
    rc = lib.crypto_aead_chacha20poly1305_ietf_decrypt(out, ctypes.byref(out_len), None, data,
                                                       ctypes.c_ulonglong(len(data)), aad,
                                                       ctypes.c_ulonglong(len(aad)), bytes(12), key)
    return None if rc != 0 else out.raw[:out_len.value]


def xmd(msg, dst, length=64):
    """RFC 9380 section 5.3.1, written again here without c7_ref."""
    dst_prime = dst + bytes([len(dst)])
    b0 = hashlib.sha512(bytes(128) + msg + length.to_bytes(2, "big") + b"\0" + dst_prime).digest()
    blocks = [hashlib.sha512(b0 + b"\1" + dst_prime).digest()]
    while len(blocks) * 64 < length:
        prev = bytes(x ^ y for x, y in zip(b0, blocks[-1]))
        blocks.append(hashlib.sha512(prev + bytes([len(blocks) + 1]) + dst_prime).digest())
    return b"".join(blocks)[:length]


def from_string_ro(msg, dst):
    """libsodium >= 1.0.19 hash_to_ristretto255 (XMD SHA-512), when present."""
    fn = getattr(lib, "crypto_core_ristretto255_from_string_ro", None)
    if fn is None:
        return None
    out = buf(32)
    rc = fn(out, dst + b"\0", msg, ctypes.c_size_t(len(msg)), 2)
    return out.raw if rc == 0 else None


def rfc_lists():
    for k, expected in enumerate(t.RISTRETTO_MULTIPLES):
        if k == 0:
            check(base_mul(bytes(32)) is None, "libsodium refuses the identity result")
            continue
        check(base_mul(k.to_bytes(32, "little")) == h(expected), f"[{k}]B")
        check(valid(h(expected)), f"valid [{k}]B")
    for bad in t.RISTRETTO_BAD:
        check(not valid(h(bad)), f"bad encoding accepted by libsodium: {bad}")
    for uniform, expected in t.RISTRETTO_MAP:
        check(from_hash(h(uniform)) == h(expected), f"map {uniform}")


def scheme(v):
    dst = v["constants"]["dst_gd"].encode()
    domain, asset = h(v["instance"]["domain"]), h(v["instance"]["asset_id"])
    for name, digest in v["constants"]["personalizations"].items():
        check(blake2b(b"", name, len(h(digest))) == h(digest), f"personalization {name}")
    accounts = {}
    for a in v["accounts"]:
        check(blake2b(h(a["ivk_seed"]), "NeuraiZKv3_ivk", 64) == h(a["ivk_wide"]), "ivk_wide")
        check(reduce64(h(a["ivk_wide"])) == h(a["ivk"]), "ivk = ToScalar")
        accounts[a["name"]] = h(a["ivk"])
    ro_available = from_string_ro(b"probe", dst) is not None
    for a in v["addresses"]:
        d = h(a["d"])
        msg = d + domain + asset
        check(xmd(msg, dst) == h(a["gd_uniform"]), "expand_message_xmd")
        check(from_hash(h(a["gd_uniform"])) == h(a["g_d"]), "G_d = map(uniform)")
        if ro_available:
            check(from_string_ro(msg, dst) == h(a["g_d"]), "G_d = crypto_core_ristretto255_from_string_ro")
        check(mul(accounts[a["account"]], h(a["g_d"])) == h(a["pk_d"]), "pk_d = [ivk]G_d")
        payload = h(a["payload"])
        check(payload == b"\3" + h(a["owner"]) + d + h(a["pk_d"]) + h(v["instance"]["instance_tag"]), "payload")
    for n in v["notes"]:
        ivk = accounts[n["to"]["account"]]
        addr = next(a for a in v["addresses"] if a["text"] == n["to"]["address"])
        check(blake2b(h(n["rho"]) + domain + asset, "NeuraiZKv3_esk", 64) == h(n["esk_wide"]), "esk_wide")
        check(reduce64(h(n["esk_wide"])) == h(n["esk"]), "esk = ToScalar")
        check(mul(h(n["esk"]), h(addr["g_d"])) == h(n["epk"]), "epk = [esk]G_d")
        check(mul(h(n["esk"]), h(addr["pk_d"])) == h(n["shared"]), "S = [esk]pk_d")
        check(mul(ivk, h(n["epk"])) == h(n["shared"]), "S = [ivk]epk")
        seed = h(n["shared"]) + h(n["epk"])
        check(blake2b(seed, "NeuraiZKv3_vtag", 32)[0] == n["vtag"], "vtag")
        check(blake2b(seed, "NeuraiZKv3_KDF", 32) == h(n["key"]), "K")
        check(h(n["aad"]) == b"NIP043/note/CP2" + domain + h(n["cm"]), "aad")
        check(h(n["plaintext"]) == h(n["note"]) + h(addr["d"]), "plaintext")
        check(aead(h(n["key"]), h(n["plaintext"]), h(n["aad"])) == h(n["ct"]), "ChaCha20-Poly1305")
        check(h(n["record"]) == bytes([2, n["vtag"]]) + h(n["epk"]) + h(n["ct"]), "record v2")
    reasons = {"vtag-mismatch", "aead-failed", "epk-invalid", "epk-identity"}
    for neg in v["negatives"]:
        if neg["receive"] not in reasons:
            continue
        record, cm, ivk = h(neg["record"]), h(neg["cm"]), accounts[neg["account"]]
        epk = record[2:34]
        if neg["receive"] == "epk-invalid":
            check(not valid(epk), neg["name"])
            continue
        if neg["receive"] == "epk-identity":
            # The identity is a valid encoding for libsodium; it refuses it as a product.
            check(valid(epk) and epk == bytes(32) and mul(ivk, epk) is None, neg["name"])
            continue
        shared = mul(ivk, epk)
        seed = shared + epk
        tag_ok = blake2b(seed, "NeuraiZKv3_vtag", 32)[0] == record[1]
        opened = aead_open(blake2b(seed, "NeuraiZKv3_KDF", 32), record[34:], b"NIP043/note/CP2" + domain + cm)
        got = "vtag-mismatch" if not tag_ok else ("aead-failed" if opened is None else "opened")
        check(got == neg["receive"], f"{neg['name']}: libsodium says {got}")
    return ro_available


def aes_openssl(v):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    import c7_ref as c
    for size in (16, 24, 32):
        key = hashlib.sha256(bytes([size])).digest()[:size]
        for i in range(64):
            block = hashlib.sha256(bytes([size, i])).digest()[:16]
            enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
            check(c.aes_encrypt(key, block) == enc.update(block) + enc.finalize(), "AES vs OpenSSL")
    check(v["instance"]["asset_id"] == hashlib.sha256(b"NeuraiPool/asset/XNA").hexdigest(), "asset id")


def main():
    vectors = json.loads(g.OUT.read_text())
    print("libsodium", lib.sodium_version_string().decode())
    rfc_lists()
    ro = scheme(vectors)
    aes_openssl(vectors)
    print(f"crypto_core_ristretto255_from_string_ro: {'checked' if ro else 'not in this libsodium'}")
    print(f"OK: {checks['ok']} checks")


if __name__ == "__main__":
    main()
