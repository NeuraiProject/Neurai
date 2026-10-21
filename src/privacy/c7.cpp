// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "privacy/c7.h"

#include "crypto/aes.h"
#include "crypto/sha512.h"
#include "monocypher/monocypher.h"

#include <algorithm>
#include <cstring>

extern "C" {
#include "crypto/ed25519/ref10_types.h"
}

namespace privacy {
namespace c7 {
namespace {

const std::string DST_GD = "NeuraiZKv3-gd";
const std::string AAD_LABEL = "NIP043/note/CP2";
const std::array<uint8_t, 12> ZERO_NONCE{};

bool AllZero(const uint8_t* data, size_t size)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < size; ++i) acc |= data[i];
    return acc == 0;
}

uint64_t LoadLE64(const uint8_t* p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}

Bytes Concat(std::initializer_list<Bytes> parts)
{
    Bytes out;
    for (const auto& part : parts) Append(out, part);
    return out;
}

Bytes Ascii(const std::string& text) { return Bytes(text.begin(), text.end()); }

template <typename T>
Bytes ToBytes(const T& data) { return Bytes(data.begin(), data.end()); }

Point DiversifyHash(const Diversifier& d, const Instance& instance, std::array<uint8_t, 64>* uniformOut = nullptr)
{
    std::array<uint8_t, 64> uniform;
    ExpandMessageXmd(Concat({ToBytes(d), ToBytes(instance.domain), ToBytes(instance.assetId)}), DST_GD,
                     uniform.data(), uniform.size());
    if (uniformOut) *uniformOut = uniform;
    return FromUniform(uniform.data());
}

Scalar DeriveEsk(const Bytes32& rho, const Instance& instance)
{
    std::array<uint8_t, 64> wide;
    const Bytes input = Concat({ToBytes(rho), ToBytes(instance.domain), ToBytes(instance.assetId)});
    Blake2b("NeuraiZKv3_esk", input.data(), input.size(), wide.data(), wide.size());
    Scalar esk = ToScalar(wide.data());
    Wipe(wide);
    return esk;
}

void TagAndKey(const Point& shared, const Point& epk, uint8_t& vtag, Bytes32& key)
{
    std::array<uint8_t, 64> input;
    std::copy(shared.begin(), shared.end(), input.begin());
    std::copy(epk.begin(), epk.end(), input.begin() + 32);
    Bytes32 tag;
    Blake2b("NeuraiZKv3_vtag", input.data(), input.size(), tag.data(), tag.size());
    Blake2b("NeuraiZKv3_KDF", input.data(), input.size(), key.data(), key.size());
    vtag = tag[0];
    Wipe(input);
}

Bytes NoteAad(const Instance& instance, const Bytes32& cm)
{
    return Concat({Ascii(AAD_LABEL), ToBytes(instance.domain), ToBytes(cm)});
}

Bytes32 NoteCommitment(const Bytes& note)
{
    return PoseidonBytes(Concat({Ascii("NIP043/cm/CP1"), note}));
}

bool ValidOwner(const Bytes32& owner) { return IsCanonicalField(owner) && !IsZero(owner); }

/** Parses a decrypted CP1 note of this instance. */
bool DecodeNote(const Bytes& note, const Instance& instance, ReceivedNote& out, Point& pkd, std::string& reason)
{
    if (note.size() != NOTE_SIZE || note[0] != 1) {
        reason = "note-malformed";
        return false;
    }
    if (!std::equal(instance.domain.begin(), instance.domain.end(), note.begin() + 1) ||
        !std::equal(instance.assetId.begin(), instance.assetId.end(), note.begin() + 33)) {
        reason = "note-instance";
        return false;
    }
    std::copy(note.begin() + 65, note.begin() + 97, out.owner.begin());
    std::copy(note.begin() + 97, note.begin() + 129, pkd.begin());
    out.amount = LoadLE64(note.data() + 129);
    std::copy(note.begin() + 137, note.begin() + 169, out.rho.begin());
    if (!ValidOwner(out.owner) || out.amount < 1 || out.amount > MAX_AMOUNT) {
        reason = "note-malformed";
        return false;
    }
    return true;
}

/** Numeral string value; the caller guarantees it stays below 2^56. */
uint64_t Num(const std::vector<uint32_t>& x, size_t from, size_t count, uint32_t radix)
{
    uint64_t value = 0;
    for (size_t i = 0; i < count; ++i) value = value * radix + x[from + i];
    return value;
}

void Str(uint64_t value, uint32_t radix, size_t count, std::vector<uint32_t>& out)
{
    out.assign(count, 0);
    for (size_t i = count; i-- > 0;) {
        out[i] = value % radix;
        value /= radix;
    }
}

} // namespace

// --- primitives -------------------------------------------------------------

bool IsValidPoint(const Point& point)
{
    ge25519_p3 p;
    return ristretto255_frombytes(&p, point.data()) == 0;
}

bool IsIdentity(const Point& point) { return AllZero(point.data(), point.size()); }

bool ScalarMult(const Scalar& scalar, const Point& point, Point& out)
{
    // crypto_scalarmult_ristretto255 of libsodium, on its vendored ref10 code.
    ge25519_p3 p, q;
    if (ristretto255_frombytes(&p, point.data()) != 0) return false;
    Scalar t = scalar;
    t[31] &= 127;
    ge25519_scalarmult(&q, t.data(), &p);
    Wipe(t);
    ristretto255_p3_tobytes(out.data(), &q);
    return !IsIdentity(out);
}

Point FromUniform(const uint8_t uniform[64])
{
    Point out;
    ristretto255_from_hash(out.data(), uniform);
    return out;
}

Scalar ToScalar(const uint8_t wide[64])
{
    std::array<uint8_t, 64> t;
    std::copy(wide, wide + 64, t.begin());
    sc25519_reduce(t.data());
    Scalar out;
    std::copy(t.begin(), t.begin() + 32, out.begin());
    Wipe(t);
    return out;
}

void Blake2b(const std::string& personal, const uint8_t* data, size_t size, uint8_t* out, size_t outSize)
{
    // The personalization occupies words 6 and 7 of the parameter block, which
    // BLAKE2b XORs into the initial hash (RFC 7693 section 2.5).
    uint8_t person[16] = {0};
    std::copy(personal.begin(), personal.begin() + std::min<size_t>(personal.size(), 16), person);
    crypto_blake2b_ctx ctx;
    crypto_blake2b_init(&ctx, outSize);
    ctx.hash[6] ^= LoadLE64(person);
    ctx.hash[7] ^= LoadLE64(person + 8);
    crypto_blake2b_update(&ctx, data, size);
    crypto_blake2b_final(&ctx, out);
}

bool ExpandMessageXmd(const Bytes& msg, const std::string& dst, uint8_t* out, size_t outSize)
{
    const size_t ell = (outSize + 63) / 64;
    if (ell == 0 || ell > 255 || outSize > 65535 || dst.size() > 255) return false;
    Bytes dstPrime = Ascii(dst);
    dstPrime.push_back(static_cast<uint8_t>(dst.size()));
    uint8_t b0[64], bi[64];
    const uint8_t zpad[128] = {0};
    const uint8_t lib[3] = {static_cast<uint8_t>(outSize >> 8), static_cast<uint8_t>(outSize), 0};
    CSHA512().Write(zpad, sizeof(zpad)).Write(msg.data(), msg.size()).Write(lib, 3)
        .Write(dstPrime.data(), dstPrime.size()).Finalize(b0);
    const uint8_t one = 1;
    CSHA512().Write(b0, 64).Write(&one, 1).Write(dstPrime.data(), dstPrime.size()).Finalize(bi);
    for (size_t i = 1;; ++i) {
        const size_t at = (i - 1) * 64;
        std::copy(bi, bi + std::min<size_t>(64, outSize - at), out + at);
        if (i == ell) break;
        uint8_t mixed[64];
        for (int k = 0; k < 64; ++k) mixed[k] = b0[k] ^ bi[k];
        const uint8_t counter = static_cast<uint8_t>(i + 1);
        CSHA512().Write(mixed, 64).Write(&counter, 1).Write(dstPrime.data(), dstPrime.size()).Finalize(bi);
    }
    return true;
}

bool Ff1(const Bytes32& key, const Bytes& tweak, uint32_t radix, std::vector<uint32_t>& x, bool decrypt)
{
    const size_t n = x.size();
    if (radix < 2 || radix > (1u << 16) || n < 2 || tweak.size() > 0xffffffff) return false;
    for (uint32_t digit : x) {
        if (digit >= radix) return false;
    }
    const size_t u = n / 2, v = n - u;
    // radix^u and radix^v must stay below 2^56 so that every value fits a uint64_t.
    uint64_t powU = 1, powV = 1;
    for (size_t i = 0; i < v; ++i) {
        if (powV > (uint64_t{1} << 56) / radix) return false;
        powV *= radix;
        if (i < u) powU *= radix;
    }
    size_t bits = 0;
    for (uint64_t m = powV - 1; m; m >>= 1) ++bits;
    const size_t b = (bits + 7) / 8;
    const size_t d = 4 * ((b + 3) / 4) + 4;
    const AES256Encrypt aes(key.data());

    uint8_t p[16] = {1, 2, 1, static_cast<uint8_t>(radix >> 16), static_cast<uint8_t>(radix >> 8),
                     static_cast<uint8_t>(radix), 10, static_cast<uint8_t>(u % 256)};
    for (int i = 0; i < 4; ++i) {
        p[8 + i] = static_cast<uint8_t>(n >> (24 - 8 * i));
        p[12 + i] = static_cast<uint8_t>(tweak.size() >> (24 - 8 * i));
    }
    std::vector<uint32_t> a(x.begin(), x.begin() + u), bv(x.begin() + u, x.end()), c;
    for (int step = 0; step < 10; ++step) {
        const int round = decrypt ? 9 - step : step;
        Bytes q(tweak);
        q.insert(q.end(), (16 * 4 - (tweak.size() + b + 1) % 16) % 16, 0);
        q.push_back(static_cast<uint8_t>(round));
        const std::vector<uint32_t>& source = decrypt ? a : bv;
        const uint64_t num = Num(source, 0, source.size(), radix);
        for (size_t i = 0; i < b; ++i) q.push_back(static_cast<uint8_t>(num >> (8 * (b - 1 - i))));
        // R = PRF(P || Q): CBC-MAC with a zero IV.
        uint8_t r[16];
        aes.Encrypt(r, p);
        for (size_t at = 0; at < q.size(); at += 16) {
            uint8_t block[16];
            for (int k = 0; k < 16; ++k) block[k] = r[k] ^ q[at + k];
            aes.Encrypt(r, block);
        }
        Bytes s(r, r + 16);
        for (uint32_t j = 1; s.size() < d; ++j) {
            uint8_t block[16], enc[16];
            std::copy(r, r + 16, block);
            for (int k = 0; k < 4; ++k) block[12 + k] ^= static_cast<uint8_t>(j >> (24 - 8 * k));
            aes.Encrypt(enc, block);
            s.insert(s.end(), enc, enc + 16);
        }
        const size_t m = round % 2 == 0 ? u : v;
        const uint64_t mod = m == u ? powU : powV;
        uint64_t y = 0;
        for (size_t i = 0; i < d; ++i) y = ((y << 8) | s[i]) % mod;
        if (decrypt) {
            const uint64_t value = (Num(bv, 0, bv.size(), radix) + mod - y) % mod;
            Str(value, radix, m, c);
            bv = a;
            a = c;
        } else {
            const uint64_t value = (Num(a, 0, a.size(), radix) + y) % mod;
            Str(value, radix, m, c);
            a = bv;
            bv = c;
        }
    }
    x = a;
    x.insert(x.end(), bv.begin(), bv.end());
    return true;
}

Diversifier DiversifierFromIndex(const Bytes32& dk, uint64_t j)
{
    std::vector<uint32_t> bits(88);
    for (size_t k = 0; k < 64; ++k) bits[k] = (j >> k) & 1;
    Ff1(dk, {}, 2, bits, false);
    Diversifier d{};
    for (size_t k = 0; k < 88; ++k) d[k / 8] |= static_cast<uint8_t>(bits[k] << (k % 8));
    return d;
}

void IndexFromDiversifier(const Bytes32& dk, const Diversifier& d, uint64_t& high, uint32_t& low)
{
    std::vector<uint32_t> bits(88);
    for (size_t k = 0; k < 88; ++k) bits[k] = (d[k / 8] >> (k % 8)) & 1;
    Ff1(dk, {}, 2, bits, true);
    low = 0;
    high = 0;
    for (size_t k = 0; k < 32; ++k) low |= static_cast<uint32_t>(bits[k]) << k;
    for (size_t k = 32; k < 88; ++k) high |= static_cast<uint64_t>(bits[k]) << (k - 32);
}

// --- pool instance ----------------------------------------------------------

bool PoolDomain(const Bytes32& genesis, const Bytes32& emissionTxid, uint32_t emissionVout,
                const std::string& identity, Bytes32& domain)
{
    if (identity.empty() || identity.size() > 64) return false;
    for (char c : identity) {
        if (c < 0x21 || c > 0x7e) return false;
    }
    Bytes data = Ascii("NeuraiPoolC7/domain");
    data.push_back(1);
    Append(data, genesis);
    Append(data, emissionTxid);
    Append(data, U32LE(emissionVout));
    data.push_back(static_cast<uint8_t>(identity.size()));
    Append(data, identity);
    domain = Sha256(data);
    return true;
}

Bytes32 XnaAssetId() { return Sha256(Ascii("NeuraiPool/asset/XNA")); }

Bytes32 PoolContext(const Bytes32& domain, const Bytes32& assetId)
{
    Bytes data = Ascii("NeuraiPoolCtx");
    data.push_back(1);
    Append(data, domain);
    Append(data, assetId);
    Append(data, U64LE(1));
    data.insert(data.end(), 32, 0);
    return PoseidonBytes(data);
}

std::array<uint8_t, 4> InstanceTag(const Bytes32& domain, const Bytes32& assetId)
{
    const Bytes32 hash = Sha256(Concat({Ascii("NeuraiZK/v3/instance"), ToBytes(domain), ToBytes(assetId)}));
    return {hash[0], hash[1], hash[2], hash[3]};
}

// --- keys and addresses -----------------------------------------------------

Account::Account(NzkFamily family, uint32_t account, const Instance& instance)
    : m_family(family), m_account(account), m_instance(instance) {}

Account::~Account()
{
    Wipe(m_prk);
    Wipe(m_ivk);
    Wipe(m_dk);
}

std::unique_ptr<Account> Account::Create(const uint8_t root[64], NzkFamily family, uint32_t account,
                                         const Instance& instance, std::string& reason)
{
    if (account > MAX_ACCOUNT || static_cast<uint8_t>(family) > 2) {
        reason = "invalid-account";
        return nullptr;
    }
    std::unique_ptr<Account> acc(new Account(family, account, instance));
    const std::string label = "NeuraiZK/v2/account";
    acc->m_prk = HmacSha256(reinterpret_cast<const uint8_t*>(label.data()), label.size(), Bytes(root, root + 64));
    acc->m_q = Concat({Bytes{static_cast<uint8_t>(family)}, U32LE(account), ToBytes(instance.domain),
                       ToBytes(instance.assetId)});
    Bytes32 seed = acc->Expand32(Concat({Ascii("NeuraiZK/v3/ivk"), acc->m_q}));
    std::array<uint8_t, 64> wide;
    Blake2b("NeuraiZKv3_ivk", seed.data(), seed.size(), wide.data(), wide.size());
    acc->m_ivk = ToScalar(wide.data());
    Wipe(seed);
    Wipe(wide);
    if (IsZero(acc->m_ivk)) {
        reason = "ivk-zero";
        return nullptr;
    }
    acc->m_dk = acc->Expand32(Concat({Ascii("NeuraiZK/v3/dk"), acc->m_q}));
    return acc;
}

Bytes32 Account::Expand32(const Bytes& info) const
{
    Bytes data(info);
    data.push_back(1);
    const Bytes32 out = HmacSha256(m_prk.data(), m_prk.size(), data);
    Wipe(data);
    return out;
}

bool Account::AddressScope(uint32_t branch, uint32_t index, Bytes& scope, std::string& reason) const
{
    if (branch > 1 || index > MAX_INDEX) {
        reason = "index-out-of-range";
        return false;
    }
    scope = Concat({Bytes{static_cast<uint8_t>(m_family)}, U32LE(m_account), U32LE(branch), U32LE(index),
                    ToBytes(m_instance.domain), ToBytes(m_instance.assetId)});
    return true;
}

bool Account::SpendKeysAt(uint32_t branch, uint32_t index, SpendKeys& keys, std::string& reason) const
{
    Bytes scope;
    if (!AddressScope(branch, index, scope, reason)) return false;
    keys.spendSecret = Expand32(Concat({Ascii("NeuraiZK/v3/spend"), scope}));
    if (IsZero(keys.spendSecret)) {
        reason = "spend-secret-zero";
        return false;
    }
    const Bytes domain = ToBytes(m_instance.domain);
    Bytes input = Concat({Ascii("NIP043/owner/CP1"), domain, ToBytes(keys.spendSecret)});
    keys.owner = PoseidonBytes(input);
    Wipe(input);
    input = Concat({Ascii("NIP043/nk/CP1"), domain, ToBytes(keys.spendSecret)});
    keys.nk = PoseidonBytes(input);
    Wipe(input);
    if (IsZero(keys.owner)) {
        reason = "owner-zero";
        return false;
    }
    return true;
}

bool Account::AddressAt(uint32_t branch, uint32_t index, Address& address, std::string& reason) const
{
    SpendKeys keys;
    if (!SpendKeysAt(branch, index, keys, reason)) return false;
    address.branch = branch;
    address.index = index;
    address.owner = keys.owner;
    address.d = DiversifierFromIndex(m_dk, (uint64_t{branch} << 32) | index);
    address.gd = DiversifyHash(address.d, m_instance, &address.uniform);
    if (IsIdentity(address.gd)) {
        reason = "diversifier-identity";
        return false;
    }
    if (!ScalarMult(m_ivk, address.gd, address.pkd)) {
        reason = "pk_d-identity";
        return false;
    }
    address.payload = AddressPayload(address, m_instance);
    address.text = bech32m::Encode(m_instance.hrp, address.payload);
    return true;
}

Bytes AddressPayload(const Recipient& recipient, const Instance& instance)
{
    Bytes payload{ADDRESS_VERSION};
    Append(payload, recipient.owner);
    Append(payload, recipient.d);
    Append(payload, recipient.pkd);
    Append(payload, InstanceTag(instance.domain, instance.assetId));
    return payload;
}

std::string EncodeAddress(const Recipient& recipient, const Instance& instance)
{
    return bech32m::Encode(instance.hrp, AddressPayload(recipient, instance));
}

bool ParseAddress(const std::string& text, const Instance& instance, Recipient& recipient, std::string& reason)
{
    std::string hrp;
    Bytes payload;
    if (!bech32m::Decode(text, hrp, payload)) {
        reason = "address-encoding";
        return false;
    }
    if (hrp != instance.hrp) {
        reason = "address-hrp";
        return false;
    }
    if (payload.size() != ADDRESS_PAYLOAD_SIZE) {
        reason = "address-length";
        return false;
    }
    if (payload[0] != ADDRESS_VERSION) {
        reason = "address-version";
        return false;
    }
    const auto tag = InstanceTag(instance.domain, instance.assetId);
    if (!std::equal(tag.begin(), tag.end(), payload.begin() + 76)) {
        reason = "address-instance";
        return false;
    }
    std::copy(payload.begin() + 1, payload.begin() + 33, recipient.owner.begin());
    std::copy(payload.begin() + 33, payload.begin() + 44, recipient.d.begin());
    std::copy(payload.begin() + 44, payload.begin() + 76, recipient.pkd.begin());
    if (!ValidOwner(recipient.owner)) {
        reason = "owner-invalid";
        return false;
    }
    if (!IsValidPoint(recipient.pkd) || IsIdentity(recipient.pkd)) {
        reason = "pk_d-invalid";
        return false;
    }
    return true;
}

// --- notes and records ------------------------------------------------------

bool SealNote(const Recipient& recipient, uint64_t amount, const Bytes32& rho, const Instance& instance,
              SealedNote& out, std::string& reason)
{
    if (!ValidOwner(recipient.owner) || !IsValidPoint(recipient.pkd) || IsIdentity(recipient.pkd) || amount < 1 ||
        amount > MAX_AMOUNT) {
        reason = "note-malformed";
        return false;
    }
    out.note = Concat({Bytes{1}, ToBytes(instance.domain), ToBytes(instance.assetId), ToBytes(recipient.owner),
                       ToBytes(recipient.pkd), U64LE(amount), ToBytes(rho)});
    out.cm = NoteCommitment(out.note);
    if (IsZero(out.cm)) {
        reason = "note-malformed";
        return false;
    }
    out.esk = DeriveEsk(rho, instance);
    if (IsZero(out.esk)) {
        reason = "esk-zero";
        return false;
    }
    const Point gd = DiversifyHash(recipient.d, instance);
    if (!ScalarMult(out.esk, gd, out.epk) || !ScalarMult(out.esk, recipient.pkd, out.shared)) {
        reason = "point-invalid";
        return false;
    }
    TagAndKey(out.shared, out.epk, out.vtag, out.key);
    Bytes plain = Concat({out.note, ToBytes(recipient.d)});
    const Bytes ct = AeadSeal(out.key, ZERO_NONCE, NoteAad(instance, out.cm), plain);
    Wipe(plain);
    out.record = Concat({Bytes{RECORD_VERSION, out.vtag}, ToBytes(out.epk), ct});
    return true;
}

bool ScanReceive(const Bytes& record, const Bytes32& cm, const ViewKey& view, ReceivedNote& out, std::string& reason,
                 bool checkTag)
{
    const Instance& instance = view.GetInstance();
    if (record.size() != RECORD_SIZE) {
        reason = "record-length";
        return false;
    }
    if (record[0] != RECORD_VERSION) {
        reason = "record-version";
        return false;
    }
    Point epk;
    std::copy(record.begin() + 2, record.begin() + 34, epk.begin());
    if (!IsValidPoint(epk)) {
        reason = "epk-invalid";
        return false;
    }
    if (IsIdentity(epk)) {
        reason = "epk-identity";
        return false;
    }
    Point shared;
    if (!ScalarMult(view.Ivk(), epk, shared)) {
        reason = "epk-invalid";
        return false;
    }
    uint8_t vtag;
    Bytes32 key;
    TagAndKey(shared, epk, vtag, key);
    Wipe(shared);
    if (checkTag && vtag != record[1]) {
        Wipe(key);
        reason = "vtag-mismatch";
        return false;
    }
    Bytes plain;
    const bool opened = AeadOpen(key, ZERO_NONCE, NoteAad(instance, cm), record.data() + 34, record.size() - 34, plain);
    Wipe(key);
    if (!opened || plain.size() != NOTE_SIZE + DIVERSIFIER_SIZE) {
        reason = "aead-failed";
        return false;
    }
    out.note.assign(plain.begin(), plain.begin() + NOTE_SIZE);
    std::copy(plain.begin() + NOTE_SIZE, plain.end(), out.d.begin());
    Wipe(plain);
    Point pkd;
    if (!DecodeNote(out.note, instance, out, pkd, reason)) return false;
    uint64_t high;
    uint32_t low;
    IndexFromDiversifier(view.Dk(), out.d, high, low);
    if (high > 1 || low > MAX_INDEX) {
        reason = "index-out-of-range";
        return false;
    }
    out.branch = static_cast<uint32_t>(high);
    out.index = low;
    const Point gd = DiversifyHash(out.d, instance);
    Point expected;
    if (!ScalarMult(view.Ivk(), gd, expected) || expected != pkd) {
        reason = "pk_d-mismatch";
        return false;
    }
    Scalar esk = DeriveEsk(out.rho, instance);
    const bool epkMatches = !IsZero(esk) && ScalarMult(esk, gd, expected) && expected == epk;
    Wipe(esk);
    if (!epkMatches) {
        reason = "epk-mismatch";
        return false;
    }
    if (NoteCommitment(out.note) != cm) {
        reason = "cm-mismatch";
        return false;
    }
    return true;
}

bool ScanFull(const Bytes& record, const Bytes32& cm, const Account& account, OwnedNote& out, std::string& reason)
{
    if (!ScanReceive(record, cm, account.View(), out, reason)) return false;
    SpendKeys keys;
    if (!account.SpendKeysAt(out.branch, out.index, keys, reason)) return false;
    if (keys.owner != out.owner) {
        reason = "owner-mismatch";
        return false;
    }
    Bytes input = Concat({Ascii("NIP043/nf/CP1"), ToBytes(account.GetInstance().domain), ToBytes(keys.nk),
                          ToBytes(out.rho), ToBytes(cm)});
    out.nf = PoseidonBytes(input);
    Wipe(input);
    return true;
}

} // namespace c7
} // namespace privacy
