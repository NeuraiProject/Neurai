// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "privacy/notes.h"

#include <algorithm>

namespace privacy {
namespace {

const std::string OWNER_TAG = "NIP043/owner/CP1";
const std::string NK_TAG = "NIP043/nk/CP1";
const std::string CM_TAG = "NIP043/cm/CP1";
const std::string NF_TAG = "NIP043/nf/CP1";

const std::string HPKE_PREFIX = "HPKE-v1";
const Bytes KEM_ID = {'K', 'E', 'M', 0, 0x20};
const Bytes SUITE_ID = {'H', 'P', 'K', 'E', 0, 0x20, 0, 1, 0, 3};
const std::string NOTE_INFO = "NIP043/HPKE/CP1";
const std::string NOTE_AAD = "NIP043/note/CP1";
const uint8_t RECORD_HEADER[3] = {1, 217, 0};

bool Equal(const uint8_t* a, const uint8_t* b, size_t size)
{
    uint8_t different = 0;
    for (size_t i = 0; i < size; ++i) different |= a[i] ^ b[i];
    return different == 0;
}

bool Equal(const Bytes32& a, const Bytes32& b) { return Equal(a.data(), b.data(), 32); }

Bytes32 Slice32(const Bytes& data, size_t offset)
{
    Bytes32 out;
    std::copy(data.begin() + offset, data.begin() + offset + 32, out.begin());
    return out;
}

Bytes32 LabeledExtract(const Bytes& suite, const Bytes& salt, const std::string& label, const Bytes& input)
{
    Bytes message;
    Append(message, HPKE_PREFIX);
    Append(message, suite);
    Append(message, label);
    Append(message, input);
    return HmacSha256(salt, message);
}

Bytes LabeledExpand(const Bytes& suite, const Bytes32& prk, const std::string& label, const Bytes& context, size_t length)
{
    Bytes info = {static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length & 255)};
    Append(info, HPKE_PREFIX);
    Append(info, suite);
    Append(info, label);
    Append(info, context);
    return HkdfExpand(prk, info, length);
}

Bytes NoteContext(const Bytes32& domain, const Bytes32& assetId)
{
    Bytes info;
    Append(info, NOTE_INFO);
    Append(info, domain);
    Append(info, assetId);
    return info;
}

Bytes NoteAad(const Bytes32& domain, const Bytes32& cm)
{
    Bytes aad;
    Append(aad, NOTE_AAD);
    Append(aad, domain);
    Append(aad, cm);
    return aad;
}

Bytes32 TaggedHash(const std::string& tag, const Bytes32& a, const Bytes32& b)
{
    Bytes data;
    Append(data, tag);
    Append(data, a);
    Append(data, b);
    Bytes32 out = PoseidonBytes(data);
    Wipe(data);
    return out;
}

bool ValidOwner(const Bytes32& owner) { return IsCanonicalField(owner) && !IsZero(owner); }

} // namespace

namespace hpke {

void DeriveKeyPair(const Bytes32& ikm, Bytes32& secret, Bytes32& publicKey)
{
    Bytes input(ikm.begin(), ikm.end());
    Bytes32 prk = LabeledExtract(KEM_ID, {}, "dkp_prk", input);
    Bytes sk = LabeledExpand(KEM_ID, prk, "sk", {}, 32);
    std::copy(sk.begin(), sk.end(), secret.begin());
    X25519Public(secret, publicKey);
    Wipe(prk);
    Wipe(sk);
    Wipe(input);
}

bool Shared(const Bytes32& secret, const Bytes32& peer, const Bytes32& enc, const Bytes32& recipient, Bytes32& out)
{
    if (!IsValidViewPublic(peer)) return false;
    Bytes32 dh;
    if (!X25519Shared(secret, peer, dh)) return false;
    Bytes dhBytes(dh.begin(), dh.end());
    Bytes32 prk = LabeledExtract(KEM_ID, {}, "eae_prk", dhBytes);
    Bytes context;
    Append(context, enc);
    Append(context, recipient);
    Bytes shared = LabeledExpand(KEM_ID, prk, "shared_secret", context, 32);
    std::copy(shared.begin(), shared.end(), out.begin());
    Wipe(dh);
    Wipe(dhBytes);
    Wipe(prk);
    Wipe(shared);
    return true;
}

void Schedule(const Bytes32& shared, const Bytes& info, Bytes32& key, std::array<uint8_t, 12>& nonce)
{
    Bytes context = {0};
    Append(context, LabeledExtract(SUITE_ID, {}, "psk_id_hash", {}));
    Append(context, LabeledExtract(SUITE_ID, {}, "info_hash", info));
    Bytes32 secret = LabeledExtract(SUITE_ID, Bytes(shared.begin(), shared.end()), "secret", {});
    Bytes k = LabeledExpand(SUITE_ID, secret, "key", context, 32);
    Bytes n = LabeledExpand(SUITE_ID, secret, "base_nonce", context, 12);
    std::copy(k.begin(), k.end(), key.begin());
    std::copy(n.begin(), n.end(), nonce.begin());
    Wipe(secret);
    Wipe(k);
}

} // namespace hpke

bool IsValidViewPublic(const Bytes32& viewPub)
{
    // Little-endian u-coordinate: non-zero and below p = 2^255 - 19.
    if (IsZero(viewPub)) return false;
    if (viewPub[31] < 0x7f) return true;
    if (viewPub[31] > 0x7f) return false;
    for (int i = 30; i >= 1; --i) {
        if (viewPub[i] != 0xff) return true;
    }
    return viewPub[0] < 0xed;
}

bool EncodeNote(const Note& note, Bytes& out, std::string& error)
{
    if (!ValidOwner(note.owner)) {
        error = "note owner must be a non-zero field element";
        return false;
    }
    if (!IsValidViewPublic(note.viewPub)) {
        error = "noncanonical X25519 view public key";
        return false;
    }
    if (note.amount < 1 || note.amount > MAX_NOTE_AMOUNT) {
        error = "note amount out of range";
        return false;
    }
    out.clear();
    out.reserve(NOTE_SIZE);
    out.push_back(1);
    Append(out, note.domain);
    Append(out, note.assetId);
    Append(out, note.owner);
    Append(out, note.viewPub);
    Append(out, U64LE(note.amount));
    Append(out, note.rho);
    return true;
}

bool DecodeNote(const Bytes& encoded, Note& note, std::string& error)
{
    if (encoded.size() != NOTE_SIZE || encoded[0] != 1) {
        error = "invalid CP1 note encoding";
        return false;
    }
    note.domain = Slice32(encoded, 1);
    note.assetId = Slice32(encoded, 33);
    note.owner = Slice32(encoded, 65);
    note.viewPub = Slice32(encoded, 97);
    note.amount = 0;
    for (int i = 7; i >= 0; --i) note.amount = note.amount << 8 | encoded[129 + i];
    note.rho = Slice32(encoded, 137);
    if (!IsValidViewPublic(note.viewPub)) {
        error = "noncanonical X25519 view public key";
        return false;
    }
    if (!ValidOwner(note.owner)) {
        error = "note owner must be a non-zero field element";
        return false;
    }
    if (note.amount < 1 || note.amount > MAX_NOTE_AMOUNT) {
        error = "note amount out of range";
        return false;
    }
    return true;
}

Bytes32 DeriveOwner(const Bytes32& domain, const Bytes32& spendSecret)
{
    return TaggedHash(OWNER_TAG, domain, spendSecret);
}

Bytes32 DeriveNullifierKey(const Bytes32& domain, const Bytes32& spendSecret)
{
    return TaggedHash(NK_TAG, domain, spendSecret);
}

bool NoteCommitment(const Bytes& encoded, Bytes32& cm, std::string& error)
{
    Note note;
    if (!DecodeNote(encoded, note, error)) return false;
    Bytes data;
    Append(data, CM_TAG);
    Append(data, encoded);
    cm = PoseidonBytes(data);
    if (IsZero(cm)) {
        error = "note commitment must be nonzero";
        return false;
    }
    return true;
}

bool NoteNullifier(const Bytes& encoded, const Bytes32& spendSecret, Bytes32& nf, std::string& error)
{
    Note note;
    Bytes32 cm;
    if (!DecodeNote(encoded, note, error) || !NoteCommitment(encoded, cm, error)) return false;
    if (!Equal(note.owner, DeriveOwner(note.domain, spendSecret))) {
        error = "spend secret does not own this note";
        return false;
    }
    Bytes32 nk = DeriveNullifierKey(note.domain, spendSecret);
    Bytes data;
    Append(data, NF_TAG);
    Append(data, note.domain);
    Append(data, nk);
    Append(data, note.rho);
    Append(data, cm);
    nf = PoseidonBytes(data);
    Wipe(nk);
    Wipe(data);
    return true;
}

Bytes32 DeriveViewPublic(const Bytes32& viewSeed)
{
    Bytes32 secret, publicKey;
    hpke::DeriveKeyPair(viewSeed, secret, publicKey);
    Wipe(secret);
    return publicKey;
}

Recipient RecipientFor(const Bytes32& domain, const Bytes32& assetId, const Bytes32& spendSecret, const Bytes32& viewSeed)
{
    Recipient recipient;
    recipient.domain = domain;
    recipient.assetId = assetId;
    recipient.owner = DeriveOwner(domain, spendSecret);
    recipient.viewPub = DeriveViewPublic(viewSeed);
    return recipient;
}

bool SealNote(const Recipient& recipient, uint64_t amount, SealedNote& out, std::string& error,
              const Bytes32* ikm, const Bytes32* rho)
{
    if (!ValidOwner(recipient.owner)) {
        error = "recipient owner must be nonzero";
        return false;
    }
    if (!IsValidViewPublic(recipient.viewPub)) {
        error = "noncanonical X25519 view public key";
        return false;
    }
    Bytes32 seed = ikm ? *ikm : RandomBytes32();
    Note note;
    note.domain = recipient.domain;
    note.assetId = recipient.assetId;
    note.owner = recipient.owner;
    note.viewPub = recipient.viewPub;
    note.amount = amount;
    note.rho = rho ? *rho : RandomBytes32();

    Bytes32 ephSecret, ephPublic;
    hpke::DeriveKeyPair(seed, ephSecret, ephPublic);
    Wipe(seed);
    bool ok = EncodeNote(note, out.note, error) && NoteCommitment(out.note, out.cm, error);
    Bytes32 shared{}, key{};
    std::array<uint8_t, 12> nonce{};
    if (ok && !hpke::Shared(ephSecret, recipient.viewPub, ephPublic, recipient.viewPub, shared)) {
        error = "invalid recipient view key";
        ok = false;
    }
    Wipe(ephSecret);
    if (ok) {
        hpke::Schedule(shared, NoteContext(recipient.domain, recipient.assetId), key, nonce);
        Bytes ciphertext = AeadSeal(key, nonce, NoteAad(recipient.domain, out.cm), out.note);
        out.record.assign(RECORD_SIZE, 0);
        std::copy(RECORD_HEADER, RECORD_HEADER + 3, out.record.begin());
        std::copy(ephPublic.begin(), ephPublic.end(), out.record.begin() + 3);
        std::copy(ciphertext.begin(), ciphertext.end(), out.record.begin() + 35);
        ok = ciphertext.size() == RECORD_USED - 35;
        if (!ok) error = "unexpected CP1 ciphertext length";
    }
    Wipe(shared);
    Wipe(key);
    return ok;
}

bool OpenNoteRecord(const Bytes& record, const Bytes32& cm, const Bytes32& domain, const Bytes32& assetId,
                    const Bytes32& viewSeed, const Bytes32& spendSecret, OpenedNote& out, std::string& error)
{
    if (record.size() != RECORD_SIZE || !Equal(record.data(), RECORD_HEADER, 3) ||
        std::any_of(record.begin() + RECORD_USED, record.end(), [](uint8_t b) { return b != 0; })) {
        error = "invalid CP1 note record";
        return false;
    }
    if (!IsCanonicalField(cm) || IsZero(cm)) {
        error = "commitment must be a nonzero field element";
        return false;
    }
    const Bytes32 enc = Slice32(record, 3);
    Bytes32 secret, publicKey, shared, key;
    std::array<uint8_t, 12> nonce;
    hpke::DeriveKeyPair(viewSeed, secret, publicKey);
    const bool agreed = hpke::Shared(secret, enc, enc, publicKey, shared);
    Wipe(secret);
    if (!agreed) {
        error = "invalid record encapsulation";
        return false;
    }
    hpke::Schedule(shared, NoteContext(domain, assetId), key, nonce);
    Wipe(shared);
    Bytes plain;
    const bool opened = AeadOpen(key, nonce, NoteAad(domain, cm), record.data() + 35, RECORD_USED - 35, plain);
    Wipe(key);
    if (!opened) {
        error = "record is not addressed to this viewing key";
        return false;
    }
    Note note;
    Bytes32 computed;
    if (!DecodeNote(plain, note, error) || !NoteCommitment(plain, computed, error)) return false;
    if (!Equal(note.domain, domain) || !Equal(note.assetId, assetId) || !Equal(note.viewPub, publicKey) ||
        !Equal(computed, cm)) {
        error = "CP1 note does not match pool or commitment";
        return false;
    }
    if (!Equal(note.owner, DeriveOwner(domain, spendSecret))) {
        error = "spend secret does not own this note";
        return false;
    }
    if (!NoteNullifier(plain, spendSecret, out.nf, error)) return false;
    out.note = std::move(plain);
    out.cm = cm;
    out.amount = note.amount;
    return true;
}

} // namespace privacy
