// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "privacy/nzk.h"

#include <algorithm>

namespace privacy {
namespace {

const std::string LABEL = "NeuraiZK/v2/";
constexpr size_t PAYLOAD_SIZE = 69;

Bytes Label(const std::string& name)
{
    Bytes out;
    Append(out, LABEL + name);
    return out;
}

bool IsSpace(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'; }

/** Little-endian u-coordinates of Curve25519 and twist points of order dividing 8 below p. */
bool SmallOrder(const Bytes32& u)
{
    static const char* const POINTS[] = {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
        "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    };
    for (const char* hex : POINTS) {
        Bytes32 point;
        ParseHex32(hex, point);
        if (point == u) return true;
    }
    return false;
}

const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
constexpr uint32_t BECH32M_CONST = 0x2bc830a3;

uint32_t Polymod(const Bytes& values)
{
    static const uint32_t GEN[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    uint32_t chk = 1;
    for (uint8_t v : values) {
        const uint32_t top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (int i = 0; i < 5; ++i) {
            if ((top >> i) & 1) chk ^= GEN[i];
        }
    }
    return chk;
}

Bytes ExpandHrp(const std::string& hrp)
{
    Bytes out;
    for (char c : hrp) out.push_back(static_cast<uint8_t>(c) >> 5);
    out.push_back(0);
    for (char c : hrp) out.push_back(static_cast<uint8_t>(c) & 31);
    return out;
}

bool ConvertBits(const Bytes& data, int from, int to, bool pad, Bytes& out)
{
    uint32_t acc = 0;
    int bits = 0;
    const uint32_t max = (1u << to) - 1;
    out.clear();
    for (uint8_t value : data) {
        acc = ((acc << from) | value) & 0xffffff;
        bits += from;
        while (bits >= to) {
            bits -= to;
            out.push_back(static_cast<uint8_t>((acc >> bits) & max));
        }
    }
    if (pad) {
        if (bits) out.push_back(static_cast<uint8_t>((acc << (to - bits)) & max));
    } else if (bits >= from || ((acc << (to - bits)) & max)) {
        return false;
    }
    return true;
}

} // namespace

namespace bech32m {

std::string Encode(const std::string& hrp, const Bytes& data)
{
    Bytes values;
    ConvertBits(data, 8, 5, true, values);
    Bytes check = ExpandHrp(hrp);
    Append(check, values);
    check.insert(check.end(), 6, 0);
    const uint32_t mod = Polymod(check) ^ BECH32M_CONST;
    std::string out = hrp + '1';
    for (uint8_t v : values) out.push_back(CHARSET[v]);
    for (int i = 0; i < 6; ++i) out.push_back(CHARSET[(mod >> (5 * (5 - i))) & 31]);
    return out;
}

bool Decode(const std::string& text, std::string& hrp, Bytes& data)
{
    if (text.size() > 1023) return false;
    bool lower = false, upper = false;
    std::string s = text;
    for (char& c : s) {
        if (c >= 'a' && c <= 'z') lower = true;
        if (c >= 'A' && c <= 'Z') {
            upper = true;
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    if (lower && upper) return false;
    const size_t sep = s.rfind('1');
    if (sep == std::string::npos || sep < 1 || s.size() - sep - 1 < 6) return false;
    hrp = s.substr(0, sep);
    Bytes values;
    for (size_t i = sep + 1; i < s.size(); ++i) {
        const char* at = std::find(CHARSET, CHARSET + 32, s[i]);
        if (at == CHARSET + 32) return false;
        values.push_back(static_cast<uint8_t>(at - CHARSET));
    }
    Bytes check = ExpandHrp(hrp);
    Append(check, values);
    if (Polymod(check) != BECH32M_CONST) return false;
    values.resize(values.size() - 6);
    return ConvertBits(values, 5, 8, false, data);
}

} // namespace bech32m

void NzkWalletSeed(const std::string& mnemonic, const std::string& passphrase, uint8_t seed[64])
{
    Bytes words;
    bool space = false;
    for (char c : mnemonic) {
        if (IsSpace(c)) {
            space = !words.empty();
            continue;
        }
        if (space) words.push_back(' ');
        space = false;
        words.push_back(static_cast<uint8_t>(c));
    }
    Bytes salt;
    Append(salt, std::string("mnemonic") + passphrase);
    Pbkdf2Sha512(words, salt, 2048, seed);
    Wipe(words);
    Wipe(salt);
}

bool NzkRoot(const uint8_t seed[64], const std::string& zkPassphrase, uint8_t root[64])
{
    Bytes password(seed, seed + 64);
    Append(password, U32LE(static_cast<uint32_t>(zkPassphrase.size())));
    Append(password, zkPassphrase);
    const bool ok = Argon2id(password, Label("root"), NZK_ARGON2_PASSES, NZK_ARGON2_MEMORY_KIB, root, 64);
    Wipe(password);
    return ok;
}

std::string NzkHrp(const std::string& chain)
{
    if (chain == "main") return "nzk";
    if (chain == "test") return "tnzk";
    if (chain == "regtest") return "rnzk";
    return "";
}

std::array<uint8_t, 4> NzkInstanceTag(const Bytes32& domain, const Bytes32& assetId)
{
    Bytes data;
    Append(data, std::string("NeuraiZK/v1/instance"));
    Append(data, domain);
    Append(data, assetId);
    const Bytes32 hash = Sha256(data);
    return {hash[0], hash[1], hash[2], hash[3]};
}

std::string EncodeNzkAddress(const Recipient& recipient, const std::string& hrp)
{
    Bytes payload = {1};
    Append(payload, recipient.owner);
    Append(payload, recipient.viewPub);
    Append(payload, NzkInstanceTag(recipient.domain, recipient.assetId));
    return bech32m::Encode(hrp, payload);
}

bool DecodeNzkAddress(const std::string& address, const std::string& hrp, const Bytes32& domain,
                      const Bytes32& assetId, Recipient& recipient, std::string& error)
{
    std::string decodedHrp;
    Bytes payload;
    if (!bech32m::Decode(address, decodedHrp, payload)) {
        error = "invalid private address";
        return false;
    }
    if (decodedHrp != hrp) {
        error = "private address belongs to another network";
        return false;
    }
    if (payload.size() != PAYLOAD_SIZE || payload[0] != 1) {
        error = "unsupported private address version";
        return false;
    }
    const auto tag = NzkInstanceTag(domain, assetId);
    if (!std::equal(tag.begin(), tag.end(), payload.begin() + 65)) {
        error = "private address belongs to another pool";
        return false;
    }
    std::copy(payload.begin() + 1, payload.begin() + 33, recipient.owner.begin());
    std::copy(payload.begin() + 33, payload.begin() + 65, recipient.viewPub.begin());
    if (IsZero(recipient.owner) || !IsCanonicalField(recipient.owner)) {
        error = "private address owner is not a canonical non-zero field element";
        return false;
    }
    if (!IsValidViewPublic(recipient.viewPub) || SmallOrder(recipient.viewPub)) {
        error = "private address view key is invalid";
        return false;
    }
    recipient.domain = domain;
    recipient.assetId = assetId;
    return true;
}

NzkAccount::NzkAccount(const uint8_t root[64], NzkFamily family, uint32_t account, const Bytes32& domain,
                       const Bytes32& assetId)
    : m_family(family), m_account(account), m_domain(domain), m_assetId(assetId)
{
    const Bytes key = Label("account");
    m_prk = HmacSha256(key.data(), key.size(), Bytes(root, root + 64));
}

NzkAccount::~NzkAccount()
{
    Wipe(m_prk);
}

Bytes NzkAccount::AccountScope() const
{
    Bytes scope = {static_cast<uint8_t>(m_family)};
    Append(scope, U32LE(m_account));
    Append(scope, m_domain);
    Append(scope, m_assetId);
    return scope;
}

bool NzkAccount::Keys(uint32_t chain, uint32_t index, NzkAddressKeys& keys) const
{
    if (chain > NZK_CHAIN_CHANGE || index >= 0x80000000u || m_account >= 0x80000000u) return false;
    Bytes scope = {static_cast<uint8_t>(m_family)};
    Append(scope, U32LE(m_account));
    Append(scope, U32LE(chain));
    Append(scope, U32LE(index));
    Append(scope, m_domain);
    Append(scope, m_assetId);
    Bytes info = Label("spend");
    Append(info, scope);
    Bytes spend = HkdfExpand(m_prk, info, 32);
    info = Label("view");
    Append(info, scope);
    Bytes view = HkdfExpand(m_prk, info, 32);
    std::copy(spend.begin(), spend.end(), keys.spendSecret.begin());
    std::copy(view.begin(), view.end(), keys.viewSeed.begin());
    Wipe(spend);
    Wipe(view);
    return !IsZero(keys.spendSecret);
}

Recipient NzkAccount::RecipientAt(uint32_t chain, uint32_t index) const
{
    NzkAddressKeys keys;
    Keys(chain, index, keys);
    return RecipientFor(m_domain, m_assetId, keys.spendSecret, keys.viewSeed);
}

std::string NzkAccount::Fingerprint() const
{
    Bytes info = Label("fingerprint");
    Append(info, AccountScope());
    const Bytes32 hash = Sha256(HkdfExpand(m_prk, info, 32));
    return Hex(hash.data(), 4);
}

std::string NzkAccount::StorageId() const
{
    Bytes info = Label("storage");
    Append(info, AccountScope());
    return Hex(Sha256(HkdfExpand(m_prk, info, 32)));
}

Bytes32 NzkAccount::CheckpointKey() const
{
    Bytes info = Label("scan-checkpoint");
    Append(info, AccountScope());
    Bytes key = HkdfExpand(m_prk, info, 32);
    Bytes32 out;
    std::copy(key.begin(), key.end(), out.begin());
    Wipe(key);
    return out;
}

} // namespace privacy
