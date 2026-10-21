// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// C7 privacy pool notes (privacy/c7.h) against the vectors of the independent
// Python reference (contrib/privacypool/privacy-c7): published primitive vectors,
// instance derivation, every intermediate value of keys, addresses and
// records, both scanners, and the negative cases with their reason.

#include "privacy/c7.h"

#include "data/privacy_c7_vectors.json.h"
#include "test/test_neurai.h"
#include "utilstrencodings.h"

#include <boost/test/unit_test.hpp>
#include <univalue.h>

#include <map>
#include <memory>
#include <set>
#include <string>

// privacy:: also has C6 types with the same names (Recipient, SealedNote).
using privacy::AeadSeal;
using privacy::Bytes;
using privacy::Bytes32;
using privacy::IsZero;
using privacy::NzkFamily;
using namespace privacy::c7;

namespace {

UniValue ReadVectors()
{
    UniValue v;
    const std::string s(json_tests::privacy_c7_vectors,
                        json_tests::privacy_c7_vectors + sizeof(json_tests::privacy_c7_vectors));
    BOOST_REQUIRE(v.read(s));
    return v;
}

Bytes FromHex(const UniValue& value) { return ParseHex(value.get_str()); }

template <typename T>
T Fixed(const UniValue& value)
{
    const Bytes bytes = FromHex(value);
    BOOST_REQUIRE_EQUAL(bytes.size(), T().size());
    T out;
    std::copy(bytes.begin(), bytes.end(), out.begin());
    return out;
}

/** Display-order (RPC) hash to internal byte order. */
Bytes32 Internal(const UniValue& value)
{
    Bytes32 out = Fixed<Bytes32>(value);
    std::reverse(out.begin(), out.end());
    return out;
}

template <typename T>
std::string HexOf(const T& data) { return HexStr(data.begin(), data.end()); }

NzkFamily Family(const std::string& name)
{
    if (name == "legacy") return NzkFamily::LEGACY;
    if (name == "ecdsa") return NzkFamily::ECDSA;
    BOOST_REQUIRE_EQUAL(name, "pq");
    return NzkFamily::PQ;
}

Instance VectorInstance(const UniValue& v)
{
    const UniValue& inst = find_value(v, "instance");
    return Instance{inst["hrp"].get_str(), Fixed<Bytes32>(inst["domain"]), Fixed<Bytes32>(inst["asset_id"])};
}

std::map<std::string, std::unique_ptr<Account>> VectorAccounts(const UniValue& v, const Instance& instance)
{
    std::map<std::string, std::unique_ptr<Account>> out;
    for (const UniValue& a : v["accounts"].getValues()) {
        const Bytes root = FromHex(a["R"]);
        BOOST_REQUIRE_EQUAL(root.size(), 64U);
        std::string reason;
        auto acc = Account::Create(root.data(), Family(a["family"].get_str()), a["account"].get_int(), instance, reason);
        BOOST_REQUIRE_MESSAGE(acc, reason);
        out[a["name"].get_str()] = std::move(acc);
    }
    return out;
}

/** "received", "owned" or the failure reason, as in the vectors. */
std::string ReceiveOutcome(const Bytes& record, const Bytes32& cm, const Account& account)
{
    ReceivedNote note;
    std::string reason;
    return ScanReceive(record, cm, account.View(), note, reason) ? "received" : reason;
}

std::string FullOutcome(const Bytes& record, const Bytes32& cm, const Account& account)
{
    OwnedNote note;
    std::string reason;
    return ScanFull(record, cm, account, note, reason) ? "owned" : reason;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(privacy_c7_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(published_primitive_vectors)
{
    const UniValue rfc = find_value(ReadVectors(), "rfc");
    const UniValue& multiples = rfc["ristretto_multiples"];
    const Point base = Fixed<Point>(multiples[1]);
    for (size_t k = 0; k < multiples.size(); ++k) {
        const Point expected = Fixed<Point>(multiples[k]);
        BOOST_CHECK(IsValidPoint(expected));
        Scalar scalar{};
        scalar[0] = static_cast<uint8_t>(k);
        Point out;
        // The identity is a valid encoding but never a valid product.
        BOOST_CHECK_EQUAL(ScalarMult(scalar, base, out), k != 0);
        if (k) BOOST_CHECK_EQUAL(HexOf(out), multiples[k].get_str());
    }
    for (const UniValue& bad : rfc["ristretto_bad"].getValues()) {
        BOOST_CHECK_MESSAGE(!IsValidPoint(Fixed<Point>(bad)), bad.get_str());
    }
    for (const UniValue& map : rfc["ristretto_map"].getValues()) {
        const Bytes uniform = FromHex(map["uniform"]);
        BOOST_CHECK_EQUAL(HexOf(FromUniform(uniform.data())), map["point"].get_str());
    }
    const UniValue& xmd = rfc["xmd_sha512"];
    for (const UniValue& item : xmd["cases"].getValues()) {
        uint8_t out[32];
        BOOST_REQUIRE(ExpandMessageXmd(FromHex(item["msg"]), xmd["dst"].get_str(), out, sizeof(out)));
        BOOST_CHECK_EQUAL(HexStr(out, out + 32), item["out"].get_str());
    }
    size_t ff1Checked = 0;
    for (const UniValue& sample : rfc["ff1"].getValues()) {
        const Bytes key = FromHex(sample["key"]);
        if (key.size() != 32) continue; // C7 only uses AES-256 (NIST samples 7 to 9)
        Bytes32 key32;
        std::copy(key.begin(), key.end(), key32.begin());
        std::vector<uint32_t> digits, expected;
        for (const UniValue& d : sample["plaintext"].getValues()) digits.push_back(d.get_int());
        for (const UniValue& d : sample["ciphertext"].getValues()) expected.push_back(d.get_int());
        const std::vector<uint32_t> plain = digits;
        const uint32_t radix = sample["radix"].get_int();
        BOOST_REQUIRE(Ff1(key32, FromHex(sample["tweak"]), radix, digits, false));
        BOOST_CHECK(digits == expected);
        BOOST_REQUIRE(Ff1(key32, FromHex(sample["tweak"]), radix, digits, true));
        BOOST_CHECK(digits == plain);
        ++ff1Checked;
    }
    BOOST_CHECK_EQUAL(ff1Checked, 3U);
    const UniValue& aead = rfc["aead_rfc8439"];
    Bytes32 key = Fixed<Bytes32>(aead["key"]);
    const auto nonce = Fixed<std::array<uint8_t, 12>>(aead["nonce"]);
    const Bytes sealed = AeadSeal(key, nonce, FromHex(aead["aad"]), FromHex(aead["plaintext"]));
    BOOST_CHECK_EQUAL(HexStr(sealed), aead["sealed"].get_str());
}

BOOST_AUTO_TEST_CASE(blake2b_personalization_and_scalars)
{
    const UniValue v = ReadVectors();
    for (const std::string& name : v["constants"]["personalizations"].getKeys()) {
        const std::string want = v["constants"]["personalizations"][name].get_str();
        std::vector<uint8_t> out(want.size() / 2);
        Blake2b(name, nullptr, 0, out.data(), out.size());
        BOOST_CHECK_EQUAL(HexStr(out), want);
    }
    uint8_t wide[64] = {0};
    wide[0] = 1;
    BOOST_CHECK_EQUAL(HexOf(ToScalar(wide)), "01" + std::string(62, '0'));
    // l itself, little-endian, reduces to zero.
    const Bytes l = ParseHex("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    std::fill(wide, wide + 64, 0);
    std::copy(l.begin(), l.end(), wide);
    BOOST_CHECK(IsZero(ToScalar(wide)));
}

BOOST_AUTO_TEST_CASE(instance_derivation)
{
    const UniValue v = ReadVectors();
    const UniValue& inst = v["instance"];
    Bytes32 domain;
    BOOST_REQUIRE(PoolDomain(Internal(inst["genesis"]), Internal(inst["emission_txid"]), inst["emission_vout"].get_int(),
                             inst["identity"].get_str(), domain));
    BOOST_CHECK_EQUAL(HexOf(domain), inst["domain"].get_str());
    BOOST_CHECK_EQUAL(HexOf(XnaAssetId()), inst["asset_id"].get_str());
    BOOST_CHECK_EQUAL(HexOf(PoolContext(domain, XnaAssetId())), inst["ctx"].get_str());
    BOOST_CHECK_EQUAL(HexOf(InstanceTag(domain, XnaAssetId())), inst["instance_tag"].get_str());
    Bytes32 other;
    BOOST_REQUIRE(PoolDomain(Internal(inst["genesis"]), Internal(inst["emission_txid"]), inst["emission_vout"].get_int() + 1,
                             inst["identity"].get_str(), other));
    BOOST_CHECK(other != domain);
    for (const std::string& bad : {std::string(), std::string(65, 'A'), std::string("C7 TEST#POOL"),
                                   std::string("C7\xc3\x91#POOL")}) {
        BOOST_CHECK(!PoolDomain(domain, domain, 0, bad, other));
    }
}

BOOST_AUTO_TEST_CASE(keys_and_addresses)
{
    const UniValue v = ReadVectors();
    const Instance instance = VectorInstance(v);
    const auto accounts = VectorAccounts(v, instance);
    for (const UniValue& a : v["accounts"].getValues()) {
        const Account& acc = *accounts.at(a["name"].get_str());
        BOOST_CHECK_EQUAL(HexOf(acc.Prk()), a["prk"].get_str());
        BOOST_CHECK_EQUAL(HexStr(acc.Q()), a["Q"].get_str());
        Bytes info(acc.Q());
        const std::string label = "NeuraiZK/v3/ivk";
        info.insert(info.begin(), label.begin(), label.end());
        const Bytes32 seed = acc.Expand32(info);
        BOOST_CHECK_EQUAL(HexOf(seed), a["ivk_seed"].get_str());
        uint8_t wide[64];
        Blake2b("NeuraiZKv3_ivk", seed.data(), seed.size(), wide, sizeof(wide));
        BOOST_CHECK_EQUAL(HexStr(wide, wide + 64), a["ivk_wide"].get_str());
        BOOST_CHECK_EQUAL(HexOf(acc.Ivk()), a["ivk"].get_str());
        BOOST_CHECK_EQUAL(HexOf(acc.Dk()), a["dk"].get_str());
    }
    for (const UniValue& a : v["addresses"].getValues()) {
        const Account& acc = *accounts.at(a["account"].get_str());
        const uint32_t branch = a["branch"].get_int(), index = a["index"].get_int64();
        std::string reason;
        Bytes scope;
        BOOST_REQUIRE(acc.AddressScope(branch, index, scope, reason));
        BOOST_CHECK_EQUAL(HexStr(scope), a["p"].get_str());
        SpendKeys keys;
        BOOST_REQUIRE(acc.SpendKeysAt(branch, index, keys, reason));
        BOOST_CHECK_EQUAL(HexOf(keys.spendSecret), a["spend_secret"].get_str());
        BOOST_CHECK_EQUAL(HexOf(keys.nk), a["nk"].get_str());
        Address address;
        BOOST_REQUIRE_MESSAGE(acc.AddressAt(branch, index, address, reason), reason);
        BOOST_CHECK_EQUAL(HexOf(address.owner), a["owner"].get_str());
        BOOST_CHECK_EQUAL(HexOf(address.d), a["d"].get_str());
        BOOST_CHECK_EQUAL(HexOf(address.uniform), a["gd_uniform"].get_str());
        BOOST_CHECK_EQUAL(HexOf(address.gd), a["g_d"].get_str());
        BOOST_CHECK_EQUAL(HexOf(address.pkd), a["pk_d"].get_str());
        BOOST_CHECK_EQUAL(HexStr(address.payload), a["payload"].get_str());
        BOOST_CHECK_EQUAL(address.text, a["text"].get_str());
        uint64_t high;
        uint32_t low;
        IndexFromDiversifier(acc.Dk(), address.d, high, low);
        BOOST_CHECK_EQUAL((high << 32) | low, (uint64_t)a["j"].get_int64());
        Recipient parsed;
        BOOST_REQUIRE_MESSAGE(ParseAddress(address.text, instance, parsed, reason), reason);
        BOOST_CHECK(parsed.owner == address.owner && parsed.d == address.d && parsed.pkd == address.pkd);
    }
    for (const UniValue& bad : v["addresses_invalid"].getValues()) {
        Recipient parsed;
        std::string reason;
        BOOST_CHECK(!ParseAddress(bad["text"].get_str(), instance, parsed, reason));
        BOOST_CHECK_MESSAGE(reason == bad["reason"].get_str(), bad["name"].get_str() + ": " + reason);
    }
    const Account& a = *accounts.at("A");
    Address address;
    std::string reason;
    for (const auto& bad : std::vector<std::pair<uint32_t, uint32_t>>{{2, 0}, {0, 0x80000000}, {0xffffffff, 0}}) {
        BOOST_CHECK(!a.AddressAt(bad.first, bad.second, address, reason));
        BOOST_CHECK_EQUAL(reason, "index-out-of-range");
    }
    const uint8_t root[64] = {0};
    BOOST_CHECK(!Account::Create(root, NzkFamily::ECDSA, 0x80000000, instance, reason));
}

BOOST_AUTO_TEST_CASE(diversifier_roundtrip)
{
    Bytes32 dk{};
    dk[0] = 7;
    std::set<Diversifier> seen;
    for (uint64_t j : {uint64_t{0}, uint64_t{1}, uint64_t{0x7fffffff}, uint64_t{1} << 32, (uint64_t{1} << 33) - 1,
                       ~uint64_t{0}}) {
        const Diversifier d = DiversifierFromIndex(dk, j);
        uint64_t high;
        uint32_t low;
        IndexFromDiversifier(dk, d, high, low);
        BOOST_CHECK_EQUAL((high << 32) | low, j);
        seen.insert(d);
    }
    BOOST_CHECK_EQUAL(seen.size(), 6U);
}

BOOST_AUTO_TEST_CASE(notes_and_both_scanners)
{
    const UniValue v = ReadVectors();
    const Instance instance = VectorInstance(v);
    const auto accounts = VectorAccounts(v, instance);
    for (const UniValue& n : v["notes"].getValues()) {
        const UniValue& to = n["to"];
        const Account& acc = *accounts.at(to["account"].get_str());
        std::string reason;
        Address address;
        BOOST_REQUIRE(acc.AddressAt(to["branch"].get_int(), to["index"].get_int64(), address, reason));
        BOOST_CHECK_EQUAL(address.text, to["address"].get_str());
        SealedNote sealed;
        const uint64_t amount = std::stoull(n["amount"].get_str());
        BOOST_REQUIRE_MESSAGE(SealNote(address, amount, Fixed<Bytes32>(n["rho"]), instance, sealed, reason), reason);
        BOOST_CHECK_EQUAL(HexStr(sealed.note), n["note"].get_str());
        BOOST_CHECK_EQUAL(HexOf(sealed.cm), n["cm"].get_str());
        BOOST_CHECK_EQUAL(HexOf(sealed.esk), n["esk"].get_str());
        BOOST_CHECK_EQUAL(HexOf(sealed.epk), n["epk"].get_str());
        BOOST_CHECK_EQUAL(HexOf(sealed.shared), n["shared"].get_str());
        BOOST_CHECK_EQUAL(sealed.vtag, n["vtag"].get_int());
        BOOST_CHECK_EQUAL(HexOf(sealed.key), n["key"].get_str());
        BOOST_CHECK_EQUAL(HexStr(sealed.record), n["record"].get_str());

        const Bytes record = FromHex(n["record"]);
        const Bytes32 cm = Fixed<Bytes32>(n["cm"]);
        for (bool checkTag : {true, false}) {
            ReceivedNote received;
            BOOST_REQUIRE_MESSAGE(ScanReceive(record, cm, acc.View(), received, reason, checkTag), reason);
            BOOST_CHECK_EQUAL(received.branch, n["receive_scan"]["branch"].get_int());
            BOOST_CHECK_EQUAL(received.index, (uint32_t)n["receive_scan"]["index"].get_int64());
            BOOST_CHECK_EQUAL(received.amount, amount);
        }
        OwnedNote owned;
        BOOST_REQUIRE_MESSAGE(ScanFull(record, cm, acc, owned, reason), reason);
        BOOST_CHECK_EQUAL(HexOf(owned.nf), n["full_scan"]["nf"].get_str());
        // Another account never sees it.
        for (const auto& other : accounts) {
            if (other.second.get() == &acc) continue;
            const std::string outcome = ReceiveOutcome(record, cm, *other.second);
            BOOST_CHECK(outcome == "vtag-mismatch" || outcome == "aead-failed");
        }
    }
}

BOOST_AUTO_TEST_CASE(negatives_fail_for_the_expected_reason)
{
    const UniValue v = ReadVectors();
    const Instance instance = VectorInstance(v);
    const auto accounts = VectorAccounts(v, instance);
    const UniValue& negatives = v["negatives"];
    BOOST_CHECK_GE(negatives.size(), 22U);
    for (const UniValue& n : negatives.getValues()) {
        const Account& acc = *accounts.at(n["account"].get_str());
        const Bytes record = FromHex(n["record"]);
        const Bytes32 cm = Fixed<Bytes32>(n["cm"]);
        const std::string receive = ReceiveOutcome(record, cm, acc), full = FullOutcome(record, cm, acc);
        BOOST_CHECK_MESSAGE(receive == n["receive"].get_str(), n["name"].get_str() + " (receive-only): " + receive);
        BOOST_CHECK_MESSAGE(full == n["full"].get_str(), n["name"].get_str() + " (full): " + full);
    }
}

BOOST_AUTO_TEST_CASE(receive_only_scanner_never_claims_ownership)
{
    const UniValue v = ReadVectors();
    const Instance instance = VectorInstance(v);
    const auto accounts = VectorAccounts(v, instance);
    const Account& a = *accounts.at("A");
    const Account& b = *accounts.at("B");
    std::string reason;
    Address mine, theirs;
    BOOST_REQUIRE(a.AddressAt(0, 0, mine, reason));
    BOOST_REQUIRE(b.AddressAt(0, 0, theirs, reason));
    // A malicious sender encrypts to A's pk_d a note owned by B.
    Recipient forged = mine;
    forged.owner = theirs.owner;
    Bytes32 rho{};
    rho[0] = 42;
    SealedNote sealed;
    // The note carries B's owner and A's pk_d: the receive-only scanner lists it
    // as received (ownership unverified) and the full scanner rejects it.
    BOOST_REQUIRE(SealNote(forged, 10, rho, instance, sealed, reason));
    BOOST_CHECK_EQUAL(ReceiveOutcome(sealed.record, sealed.cm, a), "received");
    BOOST_CHECK_EQUAL(FullOutcome(sealed.record, sealed.cm, a), "owner-mismatch");
    BOOST_REQUIRE(SealNote(mine, 10, rho, instance, sealed, reason));
    BOOST_CHECK_EQUAL(FullOutcome(sealed.record, sealed.cm, a), "owned");
}

BOOST_AUTO_TEST_SUITE_END()
