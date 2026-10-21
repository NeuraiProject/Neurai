#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Deterministic C7 vectors with every intermediate value.

    gen_c7_vectors.py            compare with src/test/data/privacy_c7_vectors.json (exit 1 on change)
    gen_c7_vectors.py --write    rewrite that file

The private roots R are those of the NeuraiZK/v2 vectors of neurai-privacy
(test/fixtures/nzk-vectors.json), so the chain from the wallet words to C7 is
covered by existing vectors.
"""
import json
import sys
from pathlib import Path

import c7_ref as c
import rfc_vectors as rfc

HERE = Path(__file__).resolve().parent
OUT = HERE.parents[2] / "src/test/data/privacy_c7_vectors.json"

# NeuraiZK/v2 roots: words "abandon ... about", BIP39 passphrase "TREZOR", ZK passphrase "" or "contraseña zk".
ROOTS = {
    "zk-empty": bytes.fromhex("0d0aea2f3729e24ccf9de814a9a27f5ac5c1f614feb99e5f48266f254f644a19"
                              "20b6bf8501d9ead946e0b5faf5d1b160f31896d806392a14fe140cfaea6344dd"),
    "zk-contrasena": bytes.fromhex("3983c498b1fddbb8a655704eb57e433fb4b81537e85bf40b6edfc21236664690"
                                   "04a4cf9c1fd130eb4ef64d8017c539f103610f942573833e4a9b7753bb5b682c"),
}

# A testnet instance born from a fictitious emission outpoint.
GENESIS_TEST = "0000008b384aeffecdab182575dc4e86c9f07f90318c65088532660ed9a8a021"
EMISSION_TXID = c.sha256(b"C7 test vector emission").hex()
EMISSION_VOUT = 3
IDENTITY = "C7TESTVECTOR#POOL"
DOMAIN = c.pool_domain(GENESIS_TEST, EMISSION_TXID, EMISSION_VOUT, IDENTITY)
ASSET_ID = c.xna_asset_id()
INSTANCE = c.Instance("test", DOMAIN, ASSET_ID)


def rho(label):
    return c.sha256(b"C7 test rho/" + label.encode())


def hexed(value):
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    if isinstance(value, dict):
        return {k: hexed(v) for k, v in value.items()}
    if isinstance(value, list):
        return [hexed(v) for v in value]
    return value


ACCOUNTS = {
    "A": ("zk-empty", "ecdsa", 0),
    "B": ("zk-empty", "ecdsa", 1),
    "C": ("zk-empty", "pq", c.MAX_ACCOUNT),
    "D": ("zk-contrasena", "legacy", 0),
}
ADDRESSES = [("A", 0, 0), ("A", 0, 1), ("A", 1, 0), ("A", 0, 1_000_000), ("A", 1, 1_000_000),
             ("A", 0, c.MAX_INDEX), ("A", 1, c.MAX_INDEX), ("B", 0, 0), ("C", 1, c.MAX_INDEX), ("D", 0, 0)]
NOTES = [("n1", "A", 0, 0, 1), ("n2", "A", 0, 1, 123_456_789), ("n3", "A", 1, 0, c.MAX_AMOUNT),
         ("n4", "A", 0, 1_000_000, 500_000_000), ("n5", "A", 1, c.MAX_INDEX, 42), ("n6", "B", 0, 0, 777),
         ("n7", "C", 1, c.MAX_INDEX, 9), ("n8", "D", 0, 0, 31_337)]


def accounts():
    return {k: c.Account(INSTANCE, ROOTS[r], family, number) for k, (r, family, number) in ACCOUNTS.items()}


def account_vector(key, acc):
    return {"name": key, "root": ACCOUNTS[key][0], "family": ACCOUNTS[key][1], "account": acc.account,
            "R": ROOTS[ACCOUNTS[key][0]], "prk": acc.prk, "Q": acc.q, "ivk_seed": acc.ivk_seed,
            "ivk_wide": c.blake2b(acc.ivk_seed, "NeuraiZKv3_ivk", 64), "ivk": acc.ivk.to_bytes(32, "little"),
            "dk": acc.dk}


def address_vector(key, acc, branch, index):
    a = acc.address(branch, index)
    return {"account": key, **{k: a[k] for k in ("branch", "index", "p", "spend_secret", "owner", "nk", "j", "d",
                                                 "gd_uniform", "g_d", "pk_d", "payload", "text")}}


def sealed_vector(name, key, acc, branch, index, amount):
    addr = acc.address(branch, index)
    r = rho(name)
    sealed = c.seal_note(addr, amount, r, INSTANCE)
    view = c.scan_receive(sealed["record"], sealed["cm"], acc.view_key())
    full = c.scan_full(sealed["record"], sealed["cm"], acc)
    return {"name": name, "to": {"account": key, "branch": branch, "index": index, "address": addr["text"]},
            "amount": str(amount), "rho": r, "note": sealed["note"], "cm": sealed["cm"],
            "esk_wide": c.blake2b(r + DOMAIN + ASSET_ID, "NeuraiZKv3_esk", 64), "esk": sealed["esk"],
            "epk": sealed["epk"], "shared": sealed["shared"], "vtag": sealed["vtag"], "key": sealed["key"],
            "aad": c.note_aad(DOMAIN, sealed["cm"]), "plaintext": sealed["plaintext"], "ct": sealed["ct"],
            "record": sealed["record"],
            "receive_scan": {"status": view["status"], "ownership": view["ownership"], "branch": view["branch"],
                             "index": view["index"], "amount": str(view["amount"])},
            "full_scan": {"status": full["status"], "ownership": full["ownership"], "nf": full["nf"]}}


def negative(name, record, cm, account_key, receive, full, why):
    """receive/full: expected failure reason, or "received"/"owned" when that scanner accepts."""
    return {"name": name, "account": account_key, "record": record, "cm": cm, "receive": receive, "full": full,
            "why": why}


def negatives(a, b):
    a00, a01 = a.address(0, 0), a.address(0, 1)
    base = c.seal_note(a00, 1000, rho("neg-base"), INSTANCE)
    rec, cm = base["record"], base["cm"]
    neg = [negative("record-length", rec[:-1], cm, "A", "record-length", "record-length", "229 bytes"),
           negative("record-version", b"\1" + rec[1:], cm, "A", "record-version", "record-version",
                    "version byte 0x01 (C6 HPKE record)")]
    for bad in ("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
                "0100000000000000000000000000000000000000000000000000000000000000",
                "26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371"):
        neg.append(negative("epk-invalid " + bad[:8], rec[:2] + bytes.fromhex(bad) + rec[34:], cm, "A",
                            "epk-invalid", "epk-invalid", "epk is not a canonical ristretto255 encoding"))
    neg.append(negative("epk-identity", rec[:2] + bytes(32) + rec[34:], cm, "A", "epk-identity", "epk-identity",
                        "epk encodes the identity"))
    other_epk = c.ristretto_encode(c.point_mul(5, c.BASE))
    neg.append(negative("epk-altered", rec[:2] + other_epk + rec[34:], cm, "A", "vtag-mismatch", "vtag-mismatch",
                        "valid but different epk: the tag check fails first (deterministic for this vector)"))
    neg.append(negative("vtag-altered", rec[:1] + bytes([rec[1] ^ 1]) + rec[2:], cm, "A", "vtag-mismatch",
                        "vtag-mismatch", "view tag flipped"))
    flipped = bytearray(rec)
    flipped[100] ^= 0x40
    neg.append(negative("ct-altered", bytes(flipped), cm, "A", "aead-failed", "aead-failed", "ciphertext bit flip"))
    other_cm = bytes(31) + b"\1"
    neg.append(negative("cm-other-in-publication", rec, other_cm, "A", "aead-failed", "aead-failed",
                        "cm is in the AAD: a different published cm fails authentication"))
    forged_cm = c.seal_note(a00, 1000, rho("neg-cm"), INSTANCE, aad_cm=other_cm)
    neg.append(negative("cm-mismatch", forged_cm["record"], other_cm, "A", "cm-mismatch", "cm-mismatch",
                        "sender authenticated with the published cm, but the note commits to another cm"))
    zip212 = c.seal_note(a00, 1000, rho("neg-esk"), INSTANCE, esk=c.to_scalar(c.sha512(b"C7 random esk")))
    neg.append(negative("epk-not-from-rho", zip212["record"], zip212["cm"], "A", "epk-mismatch", "epk-mismatch",
                        "ZIP 212 analogue: epk != [esk(rho)]G_d although S matches"))
    wrong_pkd = c.seal_note(a00, 1000, rho("neg-pkd"), INSTANCE, note_pk_d=a01["pk_d"])
    neg.append(negative("pk_d-not-of-d", wrong_pkd["record"], wrong_pkd["cm"], "A", "pk_d-mismatch",
                        "pk_d-mismatch", "note carries pk_d of address (0,1) but d of address (0,0)"))
    for label, j in (("branch-2", 2 * 2 ** 32 + 5), ("index-2^31", 2 ** 31), ("index-2^32-1", 2 ** 32 - 1),
                     ("branch-1-index-2^31", 2 ** 32 + 2 ** 31)):
        d = c.diversifier_from_index(a.dk, j)
        _, g_d = c.diversify_hash(d, DOMAIN, ASSET_ID)
        crafted = {"owner": a00["owner"], "d": d, "pk_d": c.ristretto_encode(c.point_mul(a.ivk, g_d))}
        sealed = c.seal_note(crafted, 1000, rho("neg-" + label), INSTANCE)
        neg.append(negative("index-out-of-range " + label, sealed["record"], sealed["cm"], "A",
                            "index-out-of-range", "index-out-of-range",
                            f"d inverts to j={j}: branch > 1 or index >= 2^31"))
    stolen = c.seal_note(a00, 1000, rho("neg-owner"), INSTANCE, note_owner=b.address(0, 0)["owner"])
    neg.append(negative("owner-foreign", stolen["record"], stolen["cm"], "A", "received", "owner-mismatch",
                        "malicious sender: pk_d of A, owner of B; the receive-only scanner shows it unverified"))
    good_note = c.encode_note(DOMAIN, ASSET_ID, a00["owner"], a00["pk_d"], 5, rho("neg-raw"))
    sealed = c.seal_note(a00, 0, None, INSTANCE, raw_note=good_note[:129] + bytes(8) + good_note[137:])
    neg.append(negative("note-amount-zero", sealed["record"], sealed["cm"], "A", "note-malformed", "note-malformed",
                        "authenticated note with amount 0"))
    sealed = c.seal_note(a00, 0, None, INSTANCE, raw_note=good_note[:33] + bytes(32) + good_note[65:])
    neg.append(negative("note-other-instance", sealed["record"], sealed["cm"], "A", "note-instance", "note-instance",
                        "authenticated note for another assetId"))
    to_b = c.seal_note(b.address(0, 0), 1000, rho("neg-to-b"), INSTANCE)
    neg.append(negative("other-account", to_b["record"], to_b["cm"], "A", "vtag-mismatch", "vtag-mismatch",
                        "note of account B scanned by account A"))
    collision = vtag_collision(a, b)
    neg.append(negative("vtag-collision", collision["record"], collision["cm"], "A", "aead-failed", "aead-failed",
                        f"note of account B whose tag matches under A's ivk (rho search: {collision['tries']} tries)"))
    return neg


def vtag_collision(mine, other):
    target = other.address(0, 0)
    _, g_d = c.diversify_hash(target["d"], DOMAIN, ASSET_ID)
    for tries in range(1, 10_000):
        r = rho(f"collision/{tries}")
        esk = c.derive_esk(r, DOMAIN, ASSET_ID)
        epk_point = c.point_mul(esk, g_d)
        epk = c.ristretto_encode(epk_point)
        theirs = c.view_tag(c.ristretto_encode(c.point_mul(esk, c.ristretto_decode(target["pk_d"]))), epk)
        if theirs == c.view_tag(c.ristretto_encode(c.point_mul(mine.ivk, epk_point)), epk):
            return {**c.seal_note(target, 1000, r, INSTANCE), "tries": tries}
    raise RuntimeError("no view tag collision found")


def invalid_addresses(addr):
    payload, text, hrp = addr["payload"], addr["text"], c.HRPS["test"]
    noncanonical = bytes.fromhex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
    return [{"name": name, "text": value, "reason": reason} for name, value, reason in (
        ("hrp-main", c.bech32m_encode(c.HRPS["main"], payload), "address-hrp"),
        ("length-79", c.bech32m_encode(hrp, payload[:-1]), "address-length"),
        ("version-1", c.bech32m_encode(hrp, b"\1" + payload[1:]), "address-version"),
        ("instance-tag", c.bech32m_encode(hrp, payload[:76] + bytes(4)), "address-instance"),
        ("owner-noncanonical", c.bech32m_encode(hrp, payload[:1] + c.R_BN254.to_bytes(32, "big") + payload[33:]),
         "owner-invalid"),
        ("owner-zero", c.bech32m_encode(hrp, payload[:1] + bytes(32) + payload[33:]), "owner-invalid"),
        ("pk_d-noncanonical", c.bech32m_encode(hrp, payload[:44] + noncanonical + payload[76:]), "pk_d-invalid"),
        ("pk_d-identity", c.bech32m_encode(hrp, payload[:44] + bytes(32) + payload[76:]), "pk_d-invalid"),
        ("checksum", text[:-1] + ("q" if text[-1] != "q" else "p"), "address-encoding"),
        ("mixed-case", text[:5] + text[5:].upper(), "address-encoding"))]


def rfc_block():
    return {"ristretto_multiples": rfc.RISTRETTO_MULTIPLES, "ristretto_bad": rfc.RISTRETTO_BAD,
            "ristretto_map": [{"uniform": u, "point": p} for u, p in rfc.RISTRETTO_MAP],
            "xmd_sha512": {"dst": rfc.XMD_DST, "cases": [{"msg": m.encode().hex(), "out": o} for m, o in rfc.XMD_SHA512]},
            "ff1": [{"key": rfc.FF1_KEYS[bits], "tweak": tweak, "radix": radix,
                     "plaintext": [rfc.DIGITS.index(x) for x in pt], "ciphertext": [rfc.DIGITS.index(x) for x in ct]}
                    for bits, tweak, radix, pt, ct in rfc.FF1_SAMPLES],
            "aead_rfc8439": rfc.AEAD_8439}


def build():
    accs = accounts()
    a, b = accs["A"], accs["B"]
    out = {
        "spec": "NeuraiZK/v3 C7 privacy pool notes, contrib/privacypool/privacy-c7/README.md",
        "status": "TEST ONLY, testnet experiment, unaudited",
        "instance": {"network": "test", "hrp": c.HRPS["test"], "genesis": GENESIS_TEST,
                     "emission_txid": EMISSION_TXID, "emission_vout": EMISSION_VOUT, "identity": IDENTITY,
                     "domain": DOMAIN, "asset_id": ASSET_ID, "ctx": c.pool_context(DOMAIN, ASSET_ID),
                     "instance_tag": c.instance_tag(DOMAIN, ASSET_ID)},
        "constants": {"l": str(c.L), "dst_gd": c.DST_GD.decode(), "aad_label": c.AAD_LABEL.decode(),
                      "personalizations": {k: c.blake2b(b"", k, 32 if k in ("NeuraiZKv3_vtag", "NeuraiZKv3_KDF")
                                                         else 64)
                                           for k in ("NeuraiZKv3_ivk", "NeuraiZKv3_esk", "NeuraiZKv3_vtag",
                                                     "NeuraiZKv3_KDF")},
                      "personalizations_note": "BLAKE2b of the empty string with each zero-padded personalization"},
        "accounts": [account_vector(k, accs[k]) for k in ACCOUNTS],
        "addresses": [address_vector(k, accs[k], br, ix) for k, br, ix in ADDRESSES],
    }
    notes = [sealed_vector(n, k, accs[k], br, ix, amt) for n, k, br, ix, amt in NOTES]
    # J2: two notes of account A from different addresses are spent; the new note goes to input 0's address.
    j2 = sealed_vector("j2-out", "A", a, 0, 0, 1 + 123_456_789)
    j2["j2_inputs"] = [{"note": "n1", "nf": notes[0]["full_scan"]["nf"]},
                       {"note": "n2", "nf": notes[1]["full_scan"]["nf"]}]
    out["notes"] = notes + [j2]
    out["negatives"] = negatives(a, b)
    out["addresses_invalid"] = invalid_addresses(a.address(0, 0))
    out["rfc"] = rfc_block()
    return out


def render():
    return json.dumps(hexed(build()), indent=1, ensure_ascii=False) + "\n"


def main():
    data = render()
    if "--write" in sys.argv:
        OUT.write_text(data)
        print(f"wrote {OUT} ({len(data)} bytes)")
        return 0
    if not OUT.exists() or OUT.read_text() != data:
        print(f"vectors differ from {OUT}")
        return 1
    print(f"vectors match {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
