#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests of the C7 reference: published primitive vectors, the v2 base, the
instance derivation, frozen vectors, negatives with their reason and the two scanners."""
import hashlib
import json
import unittest
from pathlib import Path
from unittest import mock

import c7_ref as c
import gen_c7_vectors as g
from rfc_vectors import (DIGITS, FF1_KEYS, FF1_SAMPLES, RISTRETTO_BAD, RISTRETTO_MAP, RISTRETTO_MULTIPLES,
                         XMD_DST, XMD_SHA512)

HERE = Path(__file__).resolve().parent
h = bytes.fromhex

def load_vectors():
    return json.loads(g.OUT.read_text())


def reason(fn):
    try:
        result = fn()
    except c.C7Error as e:
        return e.reason
    return result["status"]


class Primitives(unittest.TestCase):
    def test_blake2b(self):
        self.assertEqual(c.blake2b(b"abc", b"", 64).hex(),
                         "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                         "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
        padded = hashlib.blake2b(b"x", digest_size=32, person=b"NeuraiZKv3_vtag\0").digest()
        self.assertEqual(c.blake2b(b"x", "NeuraiZKv3_vtag", 32), padded)
        self.assertNotEqual(c.blake2b(b"x", "NeuraiZKv3_KDF", 32), c.blake2b(b"x", "NeuraiZKv3_KDF\0\1", 32))
        with self.assertRaises(ValueError):
            c.blake2b(b"", "NeuraiZKv3_personal", 32)

    def test_expand_message_xmd_rfc9380(self):
        for msg, expected in XMD_SHA512:
            self.assertEqual(c.expand_message_xmd(msg.encode(), XMD_DST.encode(), 0x20).hex(), expected)

    def test_chacha20_poly1305_rfc8439(self):
        block = c.chacha20_block(bytes(range(32)), 1, h("000000090000004a00000000"))
        self.assertEqual(block.hex(), "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
                                      "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")
        tag = c.poly1305(h("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
                         b"Cryptographic Forum Research Group")
        self.assertEqual(tag.hex(), "a8061dc1305136c6c22b8baf0c0127a9")
        key = bytes(range(0x80, 0xA0))
        nonce, aad = h("070000004041424344454647"), h("50515253c0c1c2c3c4c5c6c7")
        pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
              b"sunscreen would be it.")
        sealed = c.aead_encrypt(key, nonce, pt, aad)
        self.assertEqual(sealed[:-16].hex(),
                         "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da"
                         "92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585"
                         "808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116")
        self.assertEqual(sealed[-16:].hex(), "1ae10b594f09e26a7e902ecbd0600691")
        self.assertEqual(c.aead_decrypt(key, nonce, sealed, aad), pt)
        for bad in (sealed[:-1] + bytes([sealed[-1] ^ 1]), bytes([sealed[0] ^ 1]) + sealed[1:]):
            with self.assertRaises(c.C7Error):
                c.aead_decrypt(key, nonce, bad, aad)
        with self.assertRaises(c.C7Error):
            c.aead_decrypt(key, nonce, sealed, aad + b"\0")

    def test_aes_fips197(self):
        pt = h("00112233445566778899aabbccddeeff")
        self.assertEqual(c.aes_encrypt(bytes(range(16)), pt).hex(), "69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(c.aes_encrypt(bytes(range(24)), pt).hex(), "dda97ca4864cdfe06eaf70a0ec0d7191")
        self.assertEqual(c.aes_encrypt(bytes(range(32)), pt).hex(), "8ea2b7ca516745bfeafc49904b496089")

    def test_ff1_nist_samples(self):
        for bits, tweak, radix, pt, ct in FF1_SAMPLES:
            key = h(FF1_KEYS[bits])
            digits = [DIGITS.index(x) for x in pt]
            out = c.ff1(key, h(tweak), digits, radix)
            self.assertEqual("".join(DIGITS[x] for x in out), ct, (bits, tweak, radix))
            self.assertEqual(c.ff1(key, h(tweak), out, radix, decrypt=True), digits)

    def test_ff1_radix2_88_roundtrip(self):
        dk = c.sha256(b"dk")
        seen = set()
        for j in (0, 1, 2, 2 ** 31 - 1, 2 ** 32, 2 ** 33 - 1, 2 ** 87, 2 ** 88 - 1):
            d = c.diversifier_from_index(dk, j)
            self.assertEqual(len(d), 11)
            self.assertEqual(c.index_from_diversifier(dk, d), j)
            seen.add(d)
        self.assertEqual(len(seen), 8)
        with self.assertRaises(ValueError):
            c.diversifier_from_index(dk, 2 ** 88)

    def test_ristretto_rfc9496(self):
        point = c.IDENTITY
        for k, expected in enumerate(RISTRETTO_MULTIPLES):
            self.assertEqual(c.ristretto_encode(point).hex(), expected, k)
            self.assertEqual(c.ristretto_encode(c.point_mul(k, c.BASE)).hex(), expected, k)
            self.assertEqual(c.ristretto_encode(c.ristretto_decode(h(expected))).hex(), expected, k)
            point = c.point_add(point, c.BASE)
        for bad in RISTRETTO_BAD:
            with self.assertRaises(c.C7Error, msg=bad) as ctx:
                c.ristretto_decode(h(bad))
            self.assertEqual(ctx.exception.reason, "point-invalid")
        for uniform, expected in RISTRETTO_MAP:
            point = c.ristretto_from_uniform(h(uniform))
            self.assertEqual(c.ristretto_encode(point).hex(), expected, uniform)
        self.assertTrue(c.is_identity(c.point_mul(c.L, c.BASE)))

    def test_hash_to_group_is_xmd_then_map(self):
        msg = b"\7" * 75
        uniform, point = c.hash_to_ristretto255(msg, c.DST_GD)
        self.assertEqual(uniform, c.expand_message_xmd(msg, c.DST_GD, 64))
        self.assertNotEqual(c.ristretto_encode(point), c.ristretto_encode(c.ristretto_from_uniform(c.sha512(msg))))

    def test_to_scalar_little_endian(self):
        self.assertEqual(c.to_scalar(bytes([1]) + bytes(63)), 1)
        self.assertEqual(c.to_scalar(bytes(63) + bytes([1])), 2 ** 504 % c.L)
        self.assertEqual(c.to_scalar(c.L.to_bytes(64, "little")), 0)

    def test_poseidon_and_bech32m(self):
        self.assertEqual(c.poseidon_bytes(b"").hex(),
                         "067761295e881eec953a764e4d72bbccedf07472b57b9a3f754dcb5012441956")
        self.assertEqual(c.bech32m_encode("a", b""), "a1lqfn3a")
        self.assertEqual(c.bech32m_decode("A1LQFN3A"), ("a", b""))
        for bad in ("a1lqfn3q", "A1lqfn3a", "1lqfn3a"):
            with self.assertRaises(c.C7Error):
                c.bech32m_decode(bad)


# Expected values from neurai-privacy test/fixtures/nzk-vectors.json (NeuraiZK/v2).
V2_FIXTURE_DOMAIN = bytes(range(32))
V2_FIXTURE_ASSET = bytes(range(32, 64))
V2_FIXTURE = [
    ("zk-empty", "legacy", 0, 0, 0, {
        "prk": "92921b11d26f811319cfe62e766ef2ed34e7a0b2d094ba367145ca16c58cd7a2",
        "spend_secret": "ab0a2bf02b0e0016f40c911c7618fd8990a47de7c7175a05bf3cb904ca254f7d",
        "owner": "0add5d7cdfc4e242f0e0c7f88ead690a807f59c26f65091e58a2bd30a8260a86",
        "nk": "2069ff977a0a45a3b89132b17c1ac9047d974f8b777e1043e47d6d5c15d7d92f"}),
    ("zk-contrasena", "legacy", 0, 0, 0, {
        "prk": "2a5f0bae0fdd4f877defa19cb86f09b235ed1a2b7e3995443e22f0c69968f32b",
        "spend_secret": "b2188f96ea5b15526e44584913b6bf660f306c38194bcdcd9c4233afd2e5dd26",
        "owner": "06b364e28d7d4a21ea8351eb184c0885e0ccc644da053571f5aeda04fef91071",
        "nk": "14e5feee30db0f7a547a7c3400e9e23dd54fbf3491c43f991d6821bfc97f7ce0"}),
    ("zk-empty", "pq", 2 ** 31 - 1, 1, 2 ** 31 - 1, {
        "prk": "92921b11d26f811319cfe62e766ef2ed34e7a0b2d094ba367145ca16c58cd7a2",
        "p": "02ffffff7f01000000ffffff7f" + V2_FIXTURE_DOMAIN.hex() + V2_FIXTURE_ASSET.hex(),
        "spend_secret": "3611db7a5b3157df11c491f21c1a2bb15273b7b0c33524e0fa317d0c9d7ba142",
        "owner": "0cd23e8e058a3a7772a47274d3e57089af57ab45a0f04fd9721f2cd98b2c534b",
        "nk": "2c668ad1a01dc11bbbc8e107075bc188389d347610e606f227ce6e5b2e150db3"}),
]


class V2Base(unittest.TestCase):
    """The C7 keys sit on the v2 PRK/Q/P: recompute NeuraiZK/v2 vectors of neurai-privacy."""

    def test_v2_fixture_chain(self):
        inst = c.Instance("test", V2_FIXTURE_DOMAIN, V2_FIXTURE_ASSET)
        for root, family, account, branch, index, want in V2_FIXTURE:
            acc = c.Account(inst, g.ROOTS[root], family, account)
            self.assertEqual(acc.prk.hex(), want["prk"])
            p = acc.p(branch, index)
            if "p" in want:
                self.assertEqual(p.hex(), want["p"])
            spend = acc.expand32(b"NeuraiZK/v2/spend" + p)
            self.assertEqual(spend.hex(), want["spend_secret"])
            self.assertEqual(c.poseidon_bytes(b"NIP043/owner/CP1" + inst.domain + spend).hex(), want["owner"])
            self.assertEqual(c.poseidon_bytes(b"NIP043/nk/CP1" + inst.domain + spend).hex(), want["nk"])


class Scheme(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = load_vectors()
        cls.accounts = g.accounts()
        cls.inst = g.INSTANCE

    def test_vectors_are_frozen(self):
        self.assertEqual(g.hexed(g.build()), self.vectors)

    def test_instance_derivation(self):
        inst = self.vectors["instance"]
        domain = c.pool_domain(inst["genesis"], inst["emission_txid"], inst["emission_vout"], inst["identity"])
        self.assertEqual(domain.hex(), inst["domain"])
        self.assertEqual(c.xna_asset_id().hex(), inst["asset_id"])
        self.assertEqual(c.pool_context(domain, c.xna_asset_id()).hex(), inst["ctx"])
        other = c.pool_domain(inst["genesis"], inst["emission_txid"], inst["emission_vout"], "C7TESTVECTOR#POOX")
        self.assertNotEqual(other, domain)
        for bad in ("", "A" * 65, "C7 TEST#POOL", "C7TEST\u00d1#POOL"):
            with self.assertRaises((ValueError, UnicodeEncodeError)):
                c.pool_domain(inst["genesis"], inst["emission_txid"], 0, bad)

    def test_vector_values_recomputed(self):
        for av in self.vectors["accounts"]:
            acc = self.accounts[av["name"]]
            self.assertEqual(acc.ivk.to_bytes(32, "little").hex(), av["ivk"])
            self.assertEqual(c.to_scalar(h(av["ivk_wide"])), acc.ivk)
            self.assertEqual(acc.dk.hex(), av["dk"])
        for v in self.vectors["addresses"]:
            acc = self.accounts[v["account"]]
            self.assertEqual(c.diversifier_from_index(acc.dk, v["j"]).hex(), v["d"])
            self.assertEqual(v["j"], v["branch"] * 2 ** 32 + v["index"])
            parsed = c.parse_address(v["text"], self.inst)
            self.assertEqual((parsed["owner"].hex(), parsed["d"].hex(), parsed["pk_d"].hex()),
                             (v["owner"], v["d"], v["pk_d"]))
            self.assertEqual(len(h(v["payload"])), 80)
            g_d = c.ristretto_from_uniform(h(v["gd_uniform"]))
            self.assertEqual(c.ristretto_encode(g_d).hex(), v["g_d"])
            self.assertEqual(c.ristretto_encode(c.point_mul(acc.ivk, g_d)).hex(), v["pk_d"])
        for n in self.vectors["notes"]:
            acc = self.accounts[n["to"]["account"]]
            record, cm = h(n["record"]), h(n["cm"])
            self.assertEqual(len(record), c.RECORD_BYTES)
            self.assertEqual(record, bytes([2, n["vtag"]]) + h(n["epk"]) + h(n["ct"]))
            self.assertEqual(c.to_scalar(h(n["esk_wide"])).to_bytes(32, "little").hex(), n["esk"])
            self.assertEqual(c.ristretto_encode(c.point_mul(acc.ivk, c.ristretto_decode(h(n["epk"])))).hex(),
                             n["shared"])
            self.assertEqual(c.aead_decrypt(h(n["key"]), bytes(12), h(n["ct"]), h(n["aad"])).hex(), n["plaintext"])
            view = c.scan_receive(record, cm, acc.view_key())
            self.assertEqual((view["status"], view["ownership"], view["branch"], view["index"], str(view["amount"])),
                             ("received", "unverified", n["to"]["branch"], n["to"]["index"], n["amount"]))
            full = c.scan_full(record, cm, acc)
            self.assertEqual((full["status"], full["nf"].hex()), ("owned", n["full_scan"]["nf"]))

    def test_negatives_fail_for_the_expected_reason(self):
        self.assertGreaterEqual(len(self.vectors["negatives"]), 20)
        for v in self.vectors["negatives"]:
            acc = self.accounts[v["account"]]
            record, cm = h(v["record"]), h(v["cm"])
            self.assertEqual(reason(lambda: c.scan_receive(record, cm, acc.view_key())), v["receive"], v["name"])
            self.assertEqual(reason(lambda: c.scan_full(record, cm, acc)), v["full"], v["name"])

    def test_invalid_addresses(self):
        for v in self.vectors["addresses_invalid"]:
            with self.assertRaises(c.C7Error, msg=v["name"]) as ctx:
                c.parse_address(v["text"], self.inst)
            self.assertEqual(ctx.exception.reason, v["reason"], v["name"])
        other = c.Instance("test", g.DOMAIN, bytes(32))
        with self.assertRaises(c.C7Error) as ctx:
            c.parse_address(self.vectors["addresses"][0]["text"], other)
        self.assertEqual(ctx.exception.reason, "address-instance")

    def test_scanner_separation(self):
        a, b = self.accounts["A"], self.accounts["B"]
        view = a.view_key()
        self.assertFalse(any(hasattr(view, k) for k in ("prk", "spend_keys", "expand32", "address")))
        a00 = a.address(0, 0)
        honest = c.seal_note(a00, 10, g.rho("sep-honest"), self.inst)
        stolen = c.seal_note(a00, 10, g.rho("sep-stolen"), self.inst, note_owner=b.address(0, 0)["owner"])
        for sealed in (honest, stolen):
            found = c.scan_receive(sealed["record"], sealed["cm"], view)
            self.assertEqual((found["status"], found["ownership"]), ("received", "unverified"))
            self.assertNotIn("nf", found)
        self.assertEqual(c.scan_full(honest["record"], honest["cm"], a)["ownership"], "verified")
        self.assertEqual(reason(lambda: c.scan_full(stolen["record"], stolen["cm"], a)), "owner-mismatch")

    def test_brute_force_equivalence_and_accounts(self):
        records, truth = [], set()
        plan = [("A", 0, i) for i in (0, 3, 17, 250)] + [("A", 1, 0), ("A", 1, 1_000_000)] + \
               [("B", 0, i) for i in range(4)] + [("C", 1, c.MAX_INDEX), ("D", 0, 0), ("D", 0, 5)]
        for n, (key, branch, index) in enumerate(plan):
            sealed = c.seal_note(self.accounts[key].address(branch, index), 100 + n, g.rho(f"mix/{n}"), self.inst)
            records.append((sealed["record"], sealed["cm"]))
            if key == "A":
                truth.add((branch, index, 100 + n))
        for key in "AB":
            view = self.accounts[key].view_key()
            for check in (True, False):
                found = set()
                for record, cm in records:
                    try:
                        r = c.scan_receive(record, cm, view, check_vtag=check)
                    except c.C7Error as e:
                        self.assertIn(e.reason, ("vtag-mismatch", "aead-failed"))
                        continue
                    found.add((r["branch"], r["index"], r["amount"]))
                if key == "A":
                    self.assertEqual(found, truth)
                else:
                    self.assertEqual({x[:2] for x in found}, {(0, i) for i in range(4)})

    def test_view_tag_rate(self):
        a, b = self.accounts["A"], self.accounts["B"]
        target = b.address(0, 0)
        _, g_d = c.diversify_hash(target["d"], g.DOMAIN, g.ASSET_ID)
        pk_d = c.ristretto_decode(target["pk_d"])
        trials, hits = 2048, 0
        for t in range(trials):
            esk = c.derive_esk(g.rho(f"rate/{t}"), g.DOMAIN, g.ASSET_ID)
            epk_point = c.point_mul(esk, g_d)
            epk = c.ristretto_encode(epk_point)
            theirs = c.view_tag(c.ristretto_encode(c.point_mul(esk, pk_d)), epk)
            hits += theirs == c.view_tag(c.ristretto_encode(c.point_mul(a.ivk, epk_point)), epk)
        print(f"\nview tag: {hits} foreign matches in {trials} records (expected {trials / 256:.1f})")
        self.assertTrue(1 <= hits <= 20, hits)

    def test_unlinkability_basic(self):
        a = self.accounts["A"]
        addrs = [a.address(0, i) for i in range(48)] + [a.address(1, i) for i in range(16)]
        for field in ("owner", "d", "pk_d", "g_d", "nk"):
            self.assertEqual(len({x[field] for x in addrs}), len(addrs), field)
        self.assertEqual({x["payload"][76:] for x in addrs}, {c.instance_tag(g.DOMAIN, g.ASSET_ID)})

    def test_index_limits_and_zero_scalars(self):
        a = self.accounts["A"]
        for branch, index in ((2, 0), (0, 2 ** 31), (-1, 0), (0, -1)):
            with self.assertRaises(c.C7Error):
                a.address(branch, index)
        with self.assertRaises(ValueError):
            c.Account(self.inst, bytes(64), "ecdsa", 2 ** 31)
        with mock.patch.object(c, "to_scalar", return_value=0):
            with self.assertRaises(c.C7Error) as ctx:
                c.Account(self.inst, bytes(64), "ecdsa", 0)
        self.assertEqual(ctx.exception.reason, "ivk-zero")
        with mock.patch.object(c.Account, "expand32", lambda self, info: bytes(32)):
            with self.assertRaises(c.C7Error) as ctx:
                a.spend_keys(0, 0)
        self.assertEqual(ctx.exception.reason, "spend-secret-zero")
        with self.assertRaises(c.C7Error) as ctx:
            c.seal_note(a.address(0, 0), 1, g.rho("zero-esk"), self.inst, esk=c.L)
        self.assertEqual(ctx.exception.reason, "esk-zero")

    def test_j2_output(self):
        notes = {n["name"]: n for n in self.vectors["notes"]}
        j2 = notes["j2-out"]
        self.assertEqual((j2["to"]["branch"], j2["to"]["index"]), (notes["n1"]["to"]["branch"],
                                                                   notes["n1"]["to"]["index"]))
        self.assertEqual(int(j2["amount"]), int(notes["n1"]["amount"]) + int(notes["n2"]["amount"]))
        nfs = [x["nf"] for x in j2["j2_inputs"]] + [j2["full_scan"]["nf"]]
        self.assertEqual(len(set(nfs)), 3)
        self.assertEqual(j2["j2_inputs"][1]["nf"], notes["n2"]["full_scan"]["nf"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
