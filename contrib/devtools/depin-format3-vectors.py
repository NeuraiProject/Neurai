#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Reference implementation of the DePIN envelope, format 3.

It follows doc/depin-messaging-protocol.md step by step and shares no code
with the node. It produces src/test/data/depin_format3.json and checks the
vectors against itself: the valid message opens for every recipient, and each
altered message stops at the step the protocol names. The unit tests check
the node against the same file.

Needs the secp256k1 helpers of the functional tests and the `cryptography`
package (AES-GCM). Slow, not constant time: for vectors only. Run from the
root of the repository:

    python3 contrib/devtools/depin-format3-vectors.py            # check and write
    python3 contrib/devtools/depin-format3-vectors.py --check    # check only
"""

import hashlib
import hmac
import json
import os
import random
import struct
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
sys.path.insert(0, os.path.join(ROOT, "test", "functional"))

from cryptography.exceptions import InvalidTag  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from test_framework.key import ECKey, ECPubKey, SECP256K1, SECP256K1_G, SECP256K1_ORDER  # noqa: E402

TAG_MESSAGE = "Neurai/DePIN/message/v3"
TAG_REPLY = "Neurai/DePIN/reply/v3"
TAG_SUBMIT = "Neurai/DePIN/submit/v3"
TAG_WRAP = "Neurai/DePIN/wrap/v3"
TAG_COMMIT = "Neurai/DePIN/commit/v3"

# The stages of the receiver, in order. A message stops at the first that fails.
FORMAT, EXPECTED, SIGNER, SIGNATURE, RECIPIENT, UNWRAP, COMMITMENT, DECRYPT, OK = (
    "format", "expected", "signer", "signature", "recipient", "unwrap", "commitment", "decrypt", "ok")


# ---------------------------------------------------------------- encodings
def sha256(data):
    return hashlib.sha256(data).digest()


def compact(size):
    if size < 253:
        return bytes([size])
    if size <= 0xffff:
        return b"\xfd" + struct.pack("<H", size)
    if size <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", size)
    return b"\xff" + struct.pack("<Q", size)


def var(data):
    """Bytes with their length in front."""
    return compact(len(data)) + data


def text(value):
    return var(value.encode("ascii"))


class Reader:
    def __init__(self, data):
        self.data, self.at = data, 0

    def take(self, count):
        if self.at + count > len(self.data):
            raise ValueError("truncated")
        piece = self.data[self.at:self.at + count]
        self.at += count
        return piece

    def compact(self):
        first = self.take(1)[0]
        if first < 253:
            return first
        width, least = {253: (2, 253), 254: (4, 0x10000), 255: (8, 0x100000000)}[first]
        value = int.from_bytes(self.take(width), "little")
        if value < least:
            raise ValueError("non-canonical size")
        return value

    def var(self, least=0, most=None):
        size = self.compact()
        if size < least or (most is not None and size > most):
            raise ValueError("size out of range")
        return self.take(size)

    def done(self):
        return self.at == len(self.data)


# ------------------------------------------------------------------ contexts
def message_context(network, token, sender, timestamp, kind):
    return sha256(text(TAG_MESSAGE) + network + text(token) + text(sender) +
                  struct.pack("<q", timestamp) + bytes([kind]))


def transport_context(tag, network):
    return sha256(text(tag) + network)


def message_hash(context, envelope):
    return sha256(sha256(context + var(envelope)))


# ---------------------------------------------------------------------- keys
def compressed(point):
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, "big")


def public_key(secret):
    return compressed(SECP256K1.affine(SECP256K1.mul([(SECP256K1_G, secret)])))


def shared_secret(secret, their_public):
    """Z: SHA-256 of the compressed shared point, as the node computes it today."""
    public = ECPubKey()
    public.set(their_public)
    if not public.is_valid:
        raise ValueError("invalid public key")
    return sha256(compressed(SECP256K1.affine(SECP256K1.mul([(public.p, secret)]))))


def wrap_key(context, shared, ephemeral_public, recipient_id):
    """HKDF-SHA256 (RFC 5869), 32 bytes: salt = context, IKM = Z, info = tag || E || recipient."""
    prk = hmac.new(context, shared, hashlib.sha256).digest()
    info = text(TAG_WRAP) + var(ephemeral_public) + var(recipient_id)
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def commitment(context, content_key):
    return sha256(text(TAG_COMMIT) + context + content_key)


def seal(key, nonce, plaintext, aad=b""):
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad or None)


def unseal(key, sealed, aad=b""):
    return AESGCM(key).decrypt(sealed[:12], sealed[12:], aad or None)


def hash160(data):
    return hashlib.new("ripemd160", sha256(data)).digest()


def legacy_address(public, version=127):
    raw = bytes([version]) + hash160(public)
    raw += sha256(sha256(raw))[:4]
    number, encoded = int.from_bytes(raw, "big"), ""
    while number:
        number, digit = divmod(number, 58)
        encoded = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"[digit] + encoded
    return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + encoded


def legacy_id(public):
    return b"\x00" + hash160(public)


# ------------------------------------------------------------------ envelope
def encode_envelope(ephemeral_public, commit, payload, entries):
    return (b"\x00\x03" + var(ephemeral_public) + commit + var(payload) + compact(len(entries)) +
            b"".join(recipient + var(wrapped) for recipient, wrapped in sorted(entries.items())))


def decode_envelope(data, max_recipients=50):
    reader = Reader(data)
    if reader.take(2) != b"\x00\x03":
        raise ValueError("not format 3")
    ephemeral_public = reader.var(33, 33)
    if ephemeral_public[0] not in (2, 3):
        raise ValueError("ephemeral key is not compressed")
    commit = reader.take(32)
    payload = reader.var(12 + 16 + 1)
    count = reader.compact()
    if not 1 <= count <= max_recipients:
        raise ValueError("number of recipients out of range")
    entries, previous = {}, None
    for _ in range(count):
        kind = reader.take(1)
        if kind not in (b"\x00", b"\x03"):
            raise ValueError("unknown recipient type")
        recipient = kind + reader.take(20 if kind == b"\x00" else 32)
        if previous is not None and not previous < recipient:
            raise ValueError("recipients repeated or out of order")
        entries[recipient] = reader.var(60, 60)
        previous = recipient
    if not reader.done():
        raise ValueError("trailing bytes")
    return ephemeral_public, commit, payload, entries


def build_envelope(context, ephemeral_secret, content_key, payload_nonce, plaintext, recipients, *,
                   committed_key=None, payload_context=None, wrap_context=None, keys=None):
    """`recipients`: {id: (public key, nonce of its wrap)}. The keyword arguments make the altered vectors."""
    ephemeral_public = public_key(ephemeral_secret)
    payload = seal(content_key, payload_nonce, plaintext, context if payload_context is None else payload_context)
    entries = {}
    for recipient, (public, nonce) in recipients.items():
        key = wrap_key(context if wrap_context is None else wrap_context,
                       shared_secret(ephemeral_secret, public), ephemeral_public, recipient)
        entries[recipient] = seal(key, nonce, (keys or {}).get(recipient, content_key))
    commit = commitment(context, content_key if committed_key is None else committed_key)
    return encode_envelope(ephemeral_public, commit, payload, entries)


# ------------------------------------------------------------------ messages
def sign(secret, digest):
    key = ECKey()
    key.set(secret.to_bytes(32, "big"), True)
    return key.sign_ecdsa(digest)


def make_message(network, token, sender, timestamp, kind, envelope, signer_secret):
    context = message_context(network, token, sender, timestamp, kind)
    return {"token": token, "sender": sender, "timestamp": timestamp, "type": kind, "envelope": envelope,
            "signature": sign(signer_secret, message_hash(context, envelope)),
            "sender_pubkey": public_key(signer_secret)}


def receive(message, network, section, recipient_secret, recipient_id):
    """What a recipient does with a message, in the order of the specification.

    Returns (stage, plaintext): the stage it stopped at, or OK and the text."""
    try:
        ephemeral_public, commit, payload, entries = decode_envelope(message["envelope"])
    except ValueError:
        return FORMAT, None
    if message["token"] != section and not message["token"].startswith(section + "/"):
        return EXPECTED, None
    context = message_context(network, message["token"], message["sender"], message["timestamp"], message["type"])
    if legacy_address(message["sender_pubkey"]) != message["sender"]:
        return SIGNER, None
    signer = ECPubKey()
    signer.set(message["sender_pubkey"])
    if not signer.verify_ecdsa(message["signature"], message_hash(context, message["envelope"])):
        return SIGNATURE, None
    if recipient_id not in entries:
        return RECIPIENT, None
    try:
        key = wrap_key(context, shared_secret(recipient_secret, ephemeral_public), ephemeral_public, recipient_id)
        content_key = unseal(key, entries[recipient_id])
    except InvalidTag:
        return UNWRAP, None
    if not hmac.compare_digest(commitment(context, content_key), commit):
        return COMMITMENT, None
    try:
        return OK, unseal(content_key, payload, context)
    except InvalidTag:
        return DECRYPT, None


def open_transport(envelope, context, recipient_secret, recipient_id):
    """A reply or a submission shell: the same envelope under the context of its use."""
    try:
        ephemeral_public, commit, payload, entries = decode_envelope(envelope)
    except ValueError:
        return FORMAT, None
    if recipient_id not in entries:
        return RECIPIENT, None
    try:
        key = wrap_key(context, shared_secret(recipient_secret, ephemeral_public), ephemeral_public, recipient_id)
        content_key = unseal(key, entries[recipient_id])
    except InvalidTag:
        return UNWRAP, None
    if not hmac.compare_digest(commitment(context, content_key), commit):
        return COMMITMENT, None
    try:
        return OK, unseal(content_key, payload, context)
    except InvalidTag:
        return DECRYPT, None


# ------------------------------------------------------------------- vectors
def seed(label, size=32):
    return sha256(("Neurai/DePIN/vector/" + label).encode())[:size]


def secret(label):
    return int.from_bytes(seed(label), "big") % (SECP256K1_ORDER - 1) + 1


def build_vectors():
    random.seed(20261115)  # the signatures of the test helper use `random`
    network = bytes.fromhex("000000c710413a4265a996d30c86043aedef6a563900f1bc43fea61d5b2dc77d")  # testnet
    other_network = bytes.fromhex("00000044d33c0c0ba019be5c0249730424a69cb4c222153322f68c6104484806")
    token, timestamp, kind = "&TEST/A", 1794736920, 2
    plaintext = "Reunión a las 10".encode("utf-8")

    people = {}
    for name in ("ana", "luis", "marta"):
        people[name] = {"secret": secret(name), "public": public_key(secret(name))}
        people[name]["address"] = legacy_address(people[name]["public"])
        people[name]["id"] = legacy_id(people[name]["public"])
    # Marta reads at a strict address: its 32-byte commitment is the recipient
    # id. The value is arbitrary here; only its bytes enter the derivation.
    people["marta"]["id"] = b"\x03" + seed("marta/strict-commitment")
    ana, luis, marta = people["ana"], people["luis"], people["marta"]

    ephemeral, content_key = secret("ephemeral"), seed("content-key")
    recipients = {person["id"]: (person["public"], seed("wrap-nonce/" + name, 12)) for name, person in people.items()}
    context = message_context(network, token, ana["address"], timestamp, kind)
    envelope = build_envelope(context, ephemeral, content_key, seed("payload-nonce", 12), plaintext, recipients)
    valid = make_message(network, token, ana["address"], timestamp, kind, envelope, ana["secret"])

    ephemeral_public = public_key(ephemeral)
    # The derivation written out above is HKDF: the library gives the same key
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    for person in people.values():
        shared = shared_secret(ephemeral, person["public"])
        info = text(TAG_WRAP) + var(ephemeral_public) + var(person["id"])
        assert HKDF(hashes.SHA256(), 32, context, info).derive(shared) == \
            wrap_key(context, shared, ephemeral_public, person["id"])
    steps = {
        "context": context,
        "ephemeral_public": ephemeral_public,
        "content_key": content_key,
        "commitment": commitment(context, content_key),
        "payload": decode_envelope(envelope)[2],
        "message_hash": message_hash(context, envelope),
        "message_hash_displayed": message_hash(context, envelope)[::-1],
        "recipients": {name: {
            "shared_secret": shared_secret(ephemeral, person["public"]),
            "wrap_key": wrap_key(context, shared_secret(ephemeral, person["public"]), ephemeral_public, person["id"]),
            "wrapped_key": decode_envelope(envelope)[3][person["id"]],
        } for name, person in people.items()},
    }

    def resigned(by=ana, **header):
        """The same envelope under another header, with a new valid signature of `by`."""
        fields = {"token": token, "sender": by["address"], "timestamp": timestamp, "kind": kind}
        fields.update(header)
        return make_message(network, fields["token"], fields["sender"], fields["timestamp"], fields["kind"],
                            envelope, by["secret"])

    def with_envelope(changed, signer=ana):
        return make_message(network, token, ana["address"], timestamp, kind, changed, signer["secret"])

    other_key = seed("content-key/other")
    two_keys = {luis["id"]: other_key}  # Luis gets another key than Ana and Marta
    swapped = dict(decode_envelope(envelope)[3])
    swapped[ana["id"]], swapped[luis["id"]] = swapped[luis["id"]], swapped[ana["id"]]
    parts = decode_envelope(envelope)
    bad_signature = dict(valid)
    bad_signature["signature"] = valid["signature"][:-1] + bytes([valid["signature"][-1] ^ 1])
    wrong_signer = dict(valid)
    wrong_signer["sender_pubkey"] = luis["public"]

    cases = [
        # (name, what was done, message, {reader: stage})
        ("valid", "the message as its author published it", valid,
         {"ana": OK, "luis": OK, "marta": OK}),
        ("republished_by_another_member", "Luis publishes the envelope under his name and signs it", resigned(by=luis),
         {"ana": UNWRAP, "marta": UNWRAP}),
        ("moved_to_another_section", "the author signs the same envelope for another section",
         resigned(token="&TEST/B"), {"luis": EXPECTED}),
        ("moved_to_a_subsection", "the author signs the same envelope for a section inside the one being read",
         resigned(token="&TEST/A/X"), {"luis": UNWRAP, "marta": UNWRAP}),
        ("dated_again", "the author signs the same envelope with another date", resigned(timestamp=timestamp + 60),
         {"luis": UNWRAP}),
        ("type_changed", "the author signs the same envelope as a private message", resigned(kind=1),
         {"luis": UNWRAP}),
        ("made_for_another_network", "an envelope made on another network, signed for this one",
         with_envelope(build_envelope(message_context(other_network, token, ana["address"], timestamp, kind),
                                      ephemeral, content_key, seed("payload-nonce", 12), plaintext, recipients)),
         {"luis": UNWRAP}),
        ("signature_altered", "one bit of the signature is changed", bad_signature, {"luis": SIGNATURE}),
        ("public_key_of_someone_else", "the message arrives with the public key of another member", wrong_signer,
         {"luis": SIGNER}),
        ("commitment_altered", "one bit of the commitment is changed; the author signs again",
         with_envelope(encode_envelope(parts[0], bytes([parts[1][0] ^ 1]) + parts[1][1:], parts[2], parts[3])),
         {"luis": COMMITMENT, "marta": COMMITMENT}),
        ("two_keys_commitment_to_the_first",
         "Luis is given another key; the commitment and the text are of the key of Ana and Marta",
         with_envelope(build_envelope(context, ephemeral, content_key, seed("payload-nonce", 12), plaintext,
                                      recipients, keys=two_keys)),
         {"ana": OK, "marta": OK, "luis": COMMITMENT}),
        ("two_keys_commitment_to_the_second",
         "Luis is given another key; the commitment is of his key, the text of the other",
         with_envelope(build_envelope(context, ephemeral, content_key, seed("payload-nonce", 12), plaintext,
                                      recipients, keys=two_keys, committed_key=other_key)),
         {"ana": COMMITMENT, "marta": COMMITMENT, "luis": DECRYPT}),
        ("two_keys_commitment_to_neither", "Luis is given another key; the commitment is of a third key",
         with_envelope(build_envelope(context, ephemeral, content_key, seed("payload-nonce", 12), plaintext,
                                      recipients, keys=two_keys, committed_key=seed("content-key/third"))),
         {"ana": COMMITMENT, "marta": COMMITMENT, "luis": COMMITMENT}),
        ("wrapped_keys_swapped", "the wrapped keys of Ana and Luis change places; the author signs again",
         with_envelope(encode_envelope(parts[0], parts[1], parts[2], swapped)),
         {"ana": UNWRAP, "luis": UNWRAP, "marta": OK}),
        ("text_sealed_under_another_header", "the keys are derived with the header, the text sealed with another",
         with_envelope(build_envelope(context, ephemeral, content_key, seed("payload-nonce", 12), plaintext,
                                      recipients, payload_context=message_context(network, "&TEST/B", ana["address"],
                                                                                  timestamp, kind))),
         {"luis": DECRYPT}),
        ("not_a_recipient", "a valid message read by someone it is not encrypted for",
         with_envelope(build_envelope(context, ephemeral, content_key, seed("payload-nonce", 12), plaintext,
                                      {ana["id"]: recipients[ana["id"]]})),
         {"ana": OK, "luis": RECIPIENT}),
        ("format_2_prefix", "the envelope says it is format 2; the author signs again",
         with_envelope(b"\x00\x02" + envelope[2:]), {"luis": FORMAT}),
        ("trailing_byte", "one byte after the last recipient; the author signs again",
         with_envelope(envelope + b"\x00"), {"luis": FORMAT}),
    ]
    for name, _, message, expected in cases:
        for reader, stage in expected.items():
            found, opened = receive(message, network, token, people[reader]["secret"], people[reader]["id"])
            assert found == stage, "%s read by %s: stopped at %s, expected %s" % (name, reader, found, stage)
            assert (opened == plaintext) == (stage == OK), name

    # The two transport uses: the same envelope under the context of the use
    reply_context = transport_context(TAG_REPLY, network)
    submit_context = transport_context(TAG_SUBMIT, network)
    reply_text = b'{"result":"ok"}'
    reply = build_envelope(reply_context, secret("ephemeral/reply"), seed("content-key/reply"),
                           seed("payload-nonce/reply", 12), reply_text,
                           {luis["id"]: (luis["public"], seed("wrap-nonce/reply", 12))})
    assert open_transport(reply, reply_context, luis["secret"], luis["id"]) == (OK, reply_text)
    assert open_transport(reply, submit_context, luis["secret"], luis["id"])[0] == UNWRAP
    as_message = make_message(network, token, ana["address"], timestamp, kind, reply, ana["secret"])
    assert receive(as_message, network, token, luis["secret"], luis["id"])[0] == UNWRAP
    assert open_transport(envelope, reply_context, luis["secret"], luis["id"])[0] == UNWRAP

    def shown(value):
        if isinstance(value, bytes):
            return value.hex()
        if isinstance(value, dict):
            return {key.hex() if isinstance(key, bytes) else key: shown(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [shown(item) for item in value]
        return value

    return shown({
        "format": 3,
        "about": "DePIN envelope format 3, see contrib/devtools/depin-format3-vectors.py. Hex unless a field says otherwise. "
                 "`secret` values are test keys; `message_hash_displayed` is the hash as the node prints it.",
        "tags": {"message": TAG_MESSAGE, "reply": TAG_REPLY, "submit": TAG_SUBMIT, "wrap": TAG_WRAP,
                 "commit": TAG_COMMIT},
        "network": network,
        "section_being_read": token,
        "people": {name: {"secret": person["secret"].to_bytes(32, "big"), "public": person["public"],
                          "address": person["address"], "recipient_id": person["id"]}
                   for name, person in people.items()},
        "inputs": {"token": token, "sender": ana["address"], "timestamp": timestamp, "type": kind,
                   "plaintext_utf8": plaintext.decode("utf-8"), "plaintext": plaintext,
                   "ephemeral_secret": ephemeral.to_bytes(32, "big"), "content_key": content_key,
                   "payload_nonce": seed("payload-nonce", 12),
                   "wrap_nonces": {name: seed("wrap-nonce/" + name, 12) for name in people}},
        "steps": steps,
        "cases": [{"name": name, "what": what,
                   "message": {key: message[key] for key in ("token", "sender", "timestamp", "type", "envelope",
                                                             "signature", "sender_pubkey")},
                   "stops_at": expected} for name, what, message, expected in cases],
        "transport": {"reply_context": reply_context, "submit_context": submit_context,
                      "reply": {"recipient": "luis", "plaintext": reply_text, "envelope": reply,
                                "opens_with": "reply_context",
                                "stops_at": {"submit_context": UNWRAP, "as_a_message": UNWRAP}}},
    })


if __name__ == "__main__":
    vectors = build_vectors()
    print("%d cases checked against the reference" % len(vectors["cases"]))
    if "--check" not in sys.argv:
        with open(os.path.join(ROOT, "src", "test", "data", "depin_format3.json"), "w") as out:
            json.dump(vectors, out, indent=1, ensure_ascii=False)
            out.write("\n")
        print("src/test/data/depin_format3.json written")
