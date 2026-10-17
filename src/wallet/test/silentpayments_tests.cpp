// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NIP-047 Silent Payments: native module against the vectors of the isolated
// lab (NIP/NIP_SIN_NUMERO/silent-payments-lab, run1/vectors.json), generated
// there by an independent pure-Python reference and the libsecp256k1 helper.

#include "wallet/silentpayments.h"

#include "bech32.h"
#include "key.h"
#include "random.h"
#include "test/test_neurai.h"
#include "utilstrencodings.h"
#include "wallet/bip39.h"

#include <boost/test/unit_test.hpp>

#include <cctype>

namespace {

const char* const REGTEST_GENESIS = "5241e503402b81548ea32dbfd7b670829b30fb83220a92ad9804ad893ecdce71";
const char* const CONTEXT_N = "025241e503402b81548ea32dbfd7b670829b30fb83220a92ad9804ad893ecdce710003";
const char* const R_WORDS = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const char* const R_PASSPHRASE = "SP-LAB-R disposable";
const char* const R_SCAN = "0387aed1e3a07f33f03dffa404063072d6f06980a78ea3c241ab7863d0d339b5ca";
const char* const R_SPEND = "031d1fcccaa2a28356358ba6c5f4dab529dfc16c55e67c990958904148e7c35526";
const char* const R_CODE = "tnsp1qqgpc0tk3uws87vls8hl6gpqxxpeddurfszncag7zgx4hsc7s6vumtjsrr50uej4z52p4vdvt5mzlfk44980uzmz4ue7fjz2cjpq53e7r25nqzs6e6l";

struct VectorPayment {
    uint32_t k;
    const char* t;
    const char* P;
    const char* spk;
};

struct Vector {
    const char* name;
    std::vector<const char*> privs;
    std::vector<const char*> outpoints;
    const char* A;
    const char* h;
    const char* S;
    std::vector<VectorPayment> payments;
};

const std::vector<Vector> VECTORS = {
    {"single_input",
     {"0c46855f3a9062ce3baba47cbaf0814d1d2b812d40c2f4c2cb79e82ba057faec"},
     {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000"},
     "0242801399239bb00bb2fdae7ac874804ec8385e200e438748e4fc35dc8bc5ec1b", "874fb474a1ecba6df02f765b63f7e6736a9fb6a1f2c09761b4feffc1caac5b5b", "02be440d3feec075011a3f16c7df98ee28947db89120474887ae99acb79e3cfdad",
     {{0, "4e0138b11e832b0d1a671cfbf44f29d1d53fd1478fcc4527c50e50fa5376b3b9", "037832a7404253ada70122ca48fb4d686a2ae8e47c0bb9f416403489eb6fba78d7", "53204e10a9875e7661baac493895bba5152fded967ab92ad06011f7c60356e5ca3f8"}}},
    {"three_inputs_three_payments",
     {"0c46855f3a9062ce3baba47cbaf0814d1d2b812d40c2f4c2cb79e82ba057faec", "77c1f8a5e6981b254d88ac15c31499dcf28f30d00e7a47f4cd7ead94c2731485", "8713e9af79b5158c740d7343923f3c682805eee4771fe72cf431316abb2bcd3d"},
     {"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb01000000", "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc0107000000", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb00000000"},
     "02b246ee6b042f255d0a7f368c6be1e1ca66d1aa1fbc3d4f925564b39a3a6d0df0", "054457a5dbbb025fc61411e76f0b5051711ade3e79218d2bb0b74ec29671a37e", "03f0e85fa6fbd9cb43cd4afb8ee636b389c560fc0e6a37a93e2932ece641e4894e",
     {{0, "4ae1db273ab1e614c8ddc984a3b06d369f3f38abd1836200fb47d3ed2229b5ec", "020465c6798b9a3f9aa16c4a97fb023ffc1cf6ffab8e00b1a46f7af86c29b475ae", "53206b303d07c36cc2ae5db9bdd301a2bdc7246adf441496b6f0105382000d481671"},
      {1, "6e75720905fb5a4080a8540f8de491be5177da5a034a8f3d7fcf9dbf65d5ac68", "0391a7f01319bf5f0bfbd867556fc4665b9b01e02db50734c4be3896cba384ae4e", "5320e19cb8a88a45079d373d333ac7045537d654d9b6189bcad13128e38620d7133d"},
      {2, "289bb5b6bafa9dcbfb2cc977f598ea5f91b86d49838434b40d6a079c124d0500", "02b65f76a106fc7088b422d3ff3f1157c5a39c431d933f5a035a1659d27c5e5c45", "5320b523e21ff2082993cf65532ec2c68ab665af8884550fa56904887b5e762a185b"}}},
    {"same_key_twice",
     {"c9d5a9b0f89061c47ede5d332935cb994ac4ee6c6b5775cec11d96459e8ba918", "c9d5a9b0f89061c47ede5d332935cb994ac4ee6c6b5775cec11d96459e8ba918"},
     {"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd00000000", "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd01000000"},
     "0248f0cf4ebd6a00de5c83ae13c206d93d2721258b912f977856b5e293599b7f86", "94480945966c2f5a371c46a7a50a76bc6be38a2366b7b14359e9115926a9b7de", "03a489c001109897d768838d56dc59c270c8b37f4f2298f20fbbd8c4f01c146a63",
     {{0, "5fb098816d3e99f0123d8519e3d11680348fc99aca02c44c9f024b40e2489338", "02c20b9c4948eda57594774a3567190b02cc09e82cd8ec301d2198557fb978704c", "5320fc75e32c047cc40c0c732cd85d28046b48a14a5a66d9ab7f9314e227bcb3a1a2"},
      {1, "0101d25e269fee6bd2bb789cdf4d253680d76984fbfdfbf139db20cb6380360d", "029f9393ef241b111d1df05c9eeb2a9cc4caa56b9767da480939fe2714fc1c49e2", "5320a831f39751308da49e4605e2b7139a4dedaf99ffd71d3754c185eee43b6324c1"}}},
};

CPubKey PubFromHex(const char* hex)
{
    const std::vector<unsigned char> v = ParseHex(hex);
    return CPubKey(v.begin(), v.end());
}

CKey KeyFromHex(const char* hex)
{
    const std::vector<unsigned char> v = ParseHex(hex);
    CKey key;
    key.Set(v.begin(), v.end(), true);
    return key;
}

COutPoint OutpointFromHex(const char* hex)
{
    const std::vector<unsigned char> v = ParseHex(hex); // txid (wire order) || vout LE
    COutPoint o;
    o.hash = uint256(std::vector<unsigned char>(v.begin(), v.begin() + 32));
    o.n = v[32] | (v[33] << 8) | (v[34] << 16) | ((uint32_t)v[35] << 24);
    return o;
}

std::vector<unsigned char> GetRandBytesVector(size_t n)
{
    std::vector<unsigned char> v(n);
    if (n) GetRandBytes(v.data(), n);
    return v;
}

std::vector<unsigned char> RegtestContext()
{
    return silentpayments::Context(silentpayments::REGTEST, uint256S(REGTEST_GENESIS));
}

silentpayments::AccountKeys LabIdentity()
{
    SecureVector seed;
    CMnemonic::ToSeed(SecureString(R_WORDS), SecureString(R_PASSPHRASE), seed);
    silentpayments::AccountKeys keys;
    BOOST_REQUIRE(silentpayments::DeriveAccountKeys(seed, silentpayments::REGTEST, keys));
    return keys;
}

/** A transaction spending `outpoints` with the strict v3 witness of `keys`
 *  (the signature is a placeholder: the scanner never verifies it). */
CMutableTransaction EligibleTx(const std::vector<CKey>& keys, const std::vector<COutPoint>& outpoints,
                               const std::vector<CTxOut>& outputs, std::vector<CTxOut>& spent)
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    spent.clear();
    for (size_t i = 0; i < keys.size(); ++i) {
        CTxIn in(outpoints[i]);
        const CPubKey pub = keys[i].GetPubKey();
        in.scriptWitness.stack = {{0x02}, std::vector<unsigned char>(71, 0x30), std::vector<unsigned char>(pub.begin(), pub.end()), {OP_TRUE}};
        tx.vin.push_back(in);
        spent.emplace_back(10 * COIN, silentpayments::PaymentScript(pub));
    }
    tx.vout = outputs;
    return tx;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(silentpayments_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(context_and_identity_match_lab)
{
    BOOST_CHECK_EQUAL(HexStr(RegtestContext()), CONTEXT_N);

    const silentpayments::AccountKeys keys = LabIdentity();
    BOOST_CHECK_EQUAL(HexStr(keys.scanPub), R_SCAN);
    BOOST_CHECK_EQUAL(HexStr(keys.spendPub), R_SPEND);

    silentpayments::PaymentCode code{silentpayments::REGTEST, keys.scanPub, keys.spendPub};
    const std::string encoded = silentpayments::EncodeCode(code);
    BOOST_CHECK_EQUAL(encoded, R_CODE);
    BOOST_CHECK_EQUAL(encoded.size(), 120U);

    silentpayments::PaymentCode decoded;
    std::string error;
    BOOST_CHECK(silentpayments::DecodeCode(encoded, silentpayments::REGTEST, decoded, error));
    BOOST_CHECK(decoded.scanKey == keys.scanPub && decoded.spendKey == keys.spendPub);

    // The passphrase and the network component change the identity.
    SecureVector seed;
    CMnemonic::ToSeed(SecureString(R_WORDS), SecureString(""), seed);
    silentpayments::AccountKeys other;
    BOOST_REQUIRE(silentpayments::DeriveAccountKeys(seed, silentpayments::REGTEST, other));
    BOOST_CHECK(other.scanPub != keys.scanPub);
    CMnemonic::ToSeed(SecureString(R_WORDS), SecureString(R_PASSPHRASE), seed);
    BOOST_REQUIRE(silentpayments::DeriveAccountKeys(seed, silentpayments::TESTNET, other));
    BOOST_CHECK(other.scanPub != keys.scanPub && other.spendPub != keys.spendPub);
}

BOOST_AUTO_TEST_CASE(sender_and_receiver_match_lab_vectors)
{
    const std::vector<unsigned char> context = RegtestContext();
    const silentpayments::AccountKeys identity = LabIdentity();
    silentpayments::PaymentCode code{silentpayments::REGTEST, identity.scanPub, identity.spendPub};

    for (const Vector& vec : VECTORS) {
        BOOST_TEST_MESSAGE(vec.name);
        std::vector<CKey> keys;
        std::vector<CPubKey> pubs;
        std::vector<COutPoint> outpoints;
        for (const char* p : vec.privs) {
            keys.push_back(KeyFromHex(p));
            pubs.push_back(keys.back().GetPubKey());
        }
        for (const char* o : vec.outpoints) outpoints.push_back(OutpointFromHex(o));

        CPubKey sum;
        BOOST_REQUIRE(silentpayments::SumPublicKeys(pubs, sum));
        BOOST_CHECK_EQUAL(HexStr(sum), vec.A);

        // Sender: one recipient entry per payment to the same code.
        std::vector<silentpayments::Recipient> recipients(vec.payments.size(), silentpayments::Recipient{code, COIN});
        std::vector<CTxOut> outputs;
        std::string error;
        BOOST_REQUIRE_MESSAGE(silentpayments::CreateOutputs(context, keys, outpoints, recipients, outputs, error), error);
        BOOST_REQUIRE_EQUAL(outputs.size(), vec.payments.size());
        for (size_t i = 0; i < outputs.size(); ++i) {
            BOOST_CHECK_EQUAL(HexStr(outputs[i].scriptPubKey), vec.payments[i].spk);
        }

        // Receiver: same payments from the transaction alone, tweaks included.
        std::vector<CTxOut> spent;
        CMutableTransaction mtx = EligibleTx(keys, outpoints, outputs, spent);
        mtx.vout.insert(mtx.vout.begin(), CTxOut(COIN, CScript() << OP_TRUE)); // unrelated output first
        const CTransaction tx(mtx);
        std::vector<CPubKey> inputPubs;
        std::vector<COutPoint> inputOutpoints;
        BOOST_REQUIRE(silentpayments::GetEligibleInputs(tx, spent, inputPubs, inputOutpoints));
        std::vector<silentpayments::Match> matches =
            silentpayments::ScanTransaction(context, tx, inputPubs, inputOutpoints, identity.scan, identity.spendPub);
        BOOST_REQUIRE_EQUAL(matches.size(), vec.payments.size());
        for (size_t i = 0; i < matches.size(); ++i) {
            BOOST_CHECK_EQUAL(matches[i].k, vec.payments[i].k);
            BOOST_CHECK_EQUAL(matches[i].vout, i + 1);
            BOOST_CHECK_EQUAL(HexStr(matches[i].tweak), vec.payments[i].t);
            BOOST_CHECK_EQUAL(HexStr(matches[i].key), vec.payments[i].P);
            CKey d;
            BOOST_REQUIRE(silentpayments::PaymentPrivateKey(identity.spend, matches[i].tweak, d));
            BOOST_CHECK(d.GetPubKey() == matches[i].key);
        }

        // Input order changes neither the sum nor the smallest outpoint.
        std::vector<CKey> rkeys(keys.rbegin(), keys.rend());
        std::vector<COutPoint> routpoints(outpoints.rbegin(), outpoints.rend());
        std::vector<CTxOut> reordered;
        BOOST_REQUIRE(silentpayments::CreateOutputs(context, rkeys, routpoints, recipients, reordered, error));
        BOOST_CHECK(reordered == outputs);
    }
}

BOOST_AUTO_TEST_CASE(receiver_rejects_other_identities_and_ineligible_inputs)
{
    const std::vector<unsigned char> context = RegtestContext();
    const silentpayments::AccountKeys identity = LabIdentity();
    silentpayments::PaymentCode code{silentpayments::REGTEST, identity.scanPub, identity.spendPub};
    const Vector& vec = VECTORS[1];
    std::vector<CKey> keys;
    std::vector<COutPoint> outpoints;
    for (const char* p : vec.privs) keys.push_back(KeyFromHex(p));
    for (const char* o : vec.outpoints) outpoints.push_back(OutpointFromHex(o));
    std::vector<silentpayments::Recipient> recipients(2, silentpayments::Recipient{code, COIN});
    std::vector<CTxOut> outputs;
    std::string error;
    BOOST_REQUIRE(silentpayments::CreateOutputs(context, keys, outpoints, recipients, outputs, error));

    std::vector<CTxOut> spent;
    CMutableTransaction mtx = EligibleTx(keys, outpoints, outputs, spent);
    std::vector<CPubKey> pubs;
    std::vector<COutPoint> ops;

    // Another scan key finds nothing.
    {
        const CTransaction tx(mtx);
        BOOST_REQUIRE(silentpayments::GetEligibleInputs(tx, spent, pubs, ops));
        CKey otherScan;
        otherScan.MakeNewKey(true);
        BOOST_CHECK(silentpayments::ScanTransaction(context, tx, pubs, ops, otherScan, identity.spendPub).empty());
        // Another network context finds nothing either.
        const std::vector<unsigned char> testnet = silentpayments::Context(silentpayments::TESTNET, uint256S(REGTEST_GENESIS));
        BOOST_CHECK(silentpayments::ScanTransaction(testnet, tx, pubs, ops, identity.scan, identity.spendPub).empty());
    }
    // k = 0 missing: the sequence ends and k = 1 is not reported.
    {
        CMutableTransaction gap = mtx;
        gap.vout.erase(gap.vout.begin());
        const CTransaction tx(gap);
        BOOST_REQUIRE(silentpayments::GetEligibleInputs(tx, spent, pubs, ops));
        BOOST_CHECK(silentpayments::ScanTransaction(context, tx, pubs, ops, identity.scan, identity.spendPub).empty());
    }
    // nVersion other than 2.
    {
        CMutableTransaction v1 = mtx;
        v1.nVersion = 1;
        BOOST_CHECK(!silentpayments::GetEligibleInputs(CTransaction(v1), spent, pubs, ops));
    }
    // One prevout of another family with the same witness shape (v1 AuthScript).
    {
        std::vector<CTxOut> mixed = spent;
        mixed[0].scriptPubKey = CScript() << OP_1 << std::vector<unsigned char>(32, 0x11);
        BOOST_CHECK(!silentpayments::GetEligibleInputs(CTransaction(mtx), mixed, pubs, ops));
    }
    // Witness key that does not open the prevout commitment.
    {
        std::vector<CTxOut> wrong = spent;
        wrong[1].scriptPubKey = wrong[0].scriptPubKey;
        BOOST_CHECK(!silentpayments::GetEligibleInputs(CTransaction(mtx), wrong, pubs, ops));
    }
    // A PQ-shaped witness (different template) is not eligible.
    {
        CMutableTransaction pq = mtx;
        pq.vin[0].scriptWitness.stack[0] = {0x01};
        BOOST_CHECK(!silentpayments::MayBeEligible(CTransaction(pq)));
        BOOST_CHECK(!silentpayments::GetEligibleInputs(CTransaction(pq), spent, pubs, ops));
    }
}

BOOST_AUTO_TEST_CASE(sender_rules)
{
    const std::vector<unsigned char> context = RegtestContext();
    const silentpayments::AccountKeys identity = LabIdentity();
    silentpayments::PaymentCode code{silentpayments::REGTEST, identity.scanPub, identity.spendPub};
    std::vector<CKey> keys{KeyFromHex(VECTORS[0].privs[0])};
    std::vector<COutPoint> outpoints{OutpointFromHex(VECTORS[0].outpoints[0])};
    std::vector<CTxOut> outputs;
    std::string error;

    // At most 16 payments to one code.
    std::vector<silentpayments::Recipient> sixteen(16, silentpayments::Recipient{code, COIN});
    BOOST_CHECK(silentpayments::CreateOutputs(context, keys, outpoints, sixteen, outputs, error));
    BOOST_CHECK_EQUAL(outputs.size(), 16U);
    sixteen.push_back(silentpayments::Recipient{code, COIN});
    BOOST_CHECK(!silentpayments::CreateOutputs(context, keys, outpoints, sixteen, outputs, error));

    // Two codes sharing a scan key with different spend keys are refused.
    CKey otherSpend;
    otherSpend.MakeNewKey(true);
    silentpayments::PaymentCode twin{silentpayments::REGTEST, identity.scanPub, otherSpend.GetPubKey()};
    std::vector<silentpayments::Recipient> mixed{{code, COIN}, {twin, COIN}};
    BOOST_CHECK(!silentpayments::CreateOutputs(context, keys, outpoints, mixed, outputs, error));

    // Inputs whose keys sum to zero are refused; a cancelling prefix is not.
    CKey a = KeyFromHex(VECTORS[0].privs[0]);
    CKey negA;
    {
        // n - a
        std::vector<unsigned char> n = ParseHex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        std::vector<unsigned char> av(a.begin(), a.end()), out(32);
        int borrow = 0;
        for (int i = 31; i >= 0; --i) {
            int d = n[i] - av[i] - borrow;
            borrow = d < 0;
            out[i] = (d + 256) & 0xff;
        }
        negA.Set(out.begin(), out.end(), true);
    }
    BOOST_REQUIRE(negA.IsValid());
    CKey sum;
    BOOST_CHECK(!silentpayments::SumPrivateKeys({a, negA}, sum));
    CKey b = KeyFromHex(VECTORS[2].privs[0]);
    BOOST_CHECK(silentpayments::SumPrivateKeys({a, negA, b}, sum));
    BOOST_CHECK(sum.GetPubKey() == b.GetPubKey());
    CPubKey pubSum;
    BOOST_CHECK(!silentpayments::SumPublicKeys({a.GetPubKey(), negA.GetPubKey()}, pubSum));
    BOOST_CHECK(silentpayments::SumPublicKeys({a.GetPubKey(), negA.GetPubKey(), b.GetPubKey()}, pubSum));
    BOOST_CHECK(pubSum == b.GetPubKey());
    std::vector<silentpayments::Recipient> one{{code, COIN}};
    BOOST_CHECK(!silentpayments::CreateOutputs(context, {a, negA}, {outpoints[0], COutPoint(uint256(), 1)}, one, outputs, error));
}

BOOST_AUTO_TEST_CASE(code_decoder_rejections)
{
    const silentpayments::AccountKeys identity = LabIdentity();
    silentpayments::PaymentCode code{silentpayments::REGTEST, identity.scanPub, identity.spendPub};
    const std::string good = silentpayments::EncodeCode(code);
    silentpayments::PaymentCode out;
    std::string error;

    auto rejects = [&](const std::string& s, uint8_t net, const std::string& reason) {
        error.clear();
        const bool ok = silentpayments::DecodeCode(s, net, out, error);
        BOOST_CHECK_MESSAGE(!ok && error == reason, s << " -> " << (ok ? "accepted" : error) << " (expected " << reason << ")");
    };

    rejects(good, silentpayments::TESTNET, "network");
    rejects(good, silentpayments::MAINNET, "network");
    std::string upper = good;
    for (char& c : upper) c = toupper(c);
    BOOST_CHECK(silentpayments::DecodeCode(upper, silentpayments::REGTEST, out, error));
    std::string mixedCase = good;
    size_t letter = 5;
    while (!isalpha(mixedCase[letter])) ++letter;
    mixedCase[letter] = toupper(mixedCase[letter]);
    rejects(mixedCase, silentpayments::REGTEST, "mixed case");
    std::string flipped = good;
    flipped[20] = flipped[20] == 'q' ? 'p' : 'q';
    rejects(flipped, silentpayments::REGTEST, "checksum");
    rejects(good.substr(0, good.size() - 1), silentpayments::REGTEST, "checksum");
    rejects("tnsp1", silentpayments::REGTEST, "length");
    rejects(std::string(201, 'q'), silentpayments::REGTEST, "length");
    rejects(good + "q", silentpayments::REGTEST, "checksum");

    // Re-encode payloads by hand to reach the later checks.
    auto encode = [](const std::string& hrp, uint8_t version, const std::vector<uint8_t>& payload) {
        std::vector<uint8_t> data{version};
        bech32::ConvertBits<8, 5, true>(payload, data);
        return bech32::Encode(hrp, data, bech32::Encoding::BECH32M);
    };
    std::vector<uint8_t> payload{silentpayments::REGTEST};
    payload.insert(payload.end(), identity.scanPub.begin(), identity.scanPub.end());
    payload.insert(payload.end(), identity.spendPub.begin(), identity.spendPub.end());
    BOOST_CHECK(silentpayments::DecodeCode(encode("tnsp", 0, payload), silentpayments::REGTEST, out, error));
    rejects(encode("xnsp", 0, payload), silentpayments::REGTEST, "hrp");
    rejects(encode("tnsp", 1, payload), silentpayments::REGTEST, "version");
    rejects(encode("nsp", 0, payload), silentpayments::REGTEST, "hrp/network_id");
    std::vector<uint8_t> shortPayload(payload.begin(), payload.end() - 1);
    rejects(encode("tnsp", 0, shortPayload), silentpayments::REGTEST, "payload length");
    std::vector<uint8_t> badNet = payload;
    badNet[0] = 7;
    rejects(encode("tnsp", 0, badNet), silentpayments::REGTEST, "hrp/network_id");
    std::vector<uint8_t> badPoint = payload;
    badPoint[1] = 0x04;
    rejects(encode("tnsp", 0, badPoint), silentpayments::REGTEST, "point");
    std::vector<uint8_t> offCurve = payload;
    std::fill(offCurve.begin() + 2, offCurve.begin() + 34, 0x00); // x = 0 is not on secp256k1
    rejects(encode("tnsp", 0, offCurve), silentpayments::REGTEST, "point");
    std::vector<uint8_t> sameKey = payload;
    std::copy(payload.begin() + 1, payload.begin() + 34, sameKey.begin() + 34);
    rejects(encode("tnsp", 0, sameKey), silentpayments::REGTEST, "scan equals +-spend");
    std::vector<uint8_t> negated = sameKey;
    negated[34] ^= 0x01; // -B_scan as spend key
    rejects(encode("tnsp", 0, negated), silentpayments::REGTEST, "scan equals +-spend");
}

BOOST_AUTO_TEST_CASE(code_decoder_mutation_fuzz)
{
    // V3.5: random edits of a valid code never crash the decoder, every
    // rejection names its reason, and nothing but the original is accepted.
    const silentpayments::AccountKeys identity = LabIdentity();
    const std::string good = silentpayments::EncodeCode(silentpayments::PaymentCode{silentpayments::REGTEST, identity.scanPub, identity.spendPub});
    const std::string charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    FastRandomContext rng(true);
    int accepted = 0, collisions = 0;
    std::map<std::string, int> reasons;
    for (int i = 0; i < 200000; ++i) {
        std::string s = good;
        const int edits = 1 + rng.randrange(4);
        for (int e = 0; e < edits && !s.empty(); ++e) {
            const size_t pos = rng.randrange(s.size());
            switch (rng.randrange(7)) {
            case 0: s[pos] = charset[rng.randrange(charset.size())]; break;
            case 1: s.insert(s.begin() + pos, charset[rng.randrange(charset.size())]); break;
            case 2: s.erase(s.begin() + pos); break;
            case 3: s[pos] = isupper(s[pos]) ? tolower(s[pos]) : toupper(s[pos]); break;
            case 4: s.resize(pos); break;
            case 5: s[pos] = (char)rng.randrange(256); break;
            case 6: std::swap(s[pos], s[rng.randrange(s.size())]); break;
            }
        }
        silentpayments::PaymentCode out;
        std::string error;
        if (silentpayments::DecodeCode(s, silentpayments::REGTEST, out, error)) {
            ++accepted;
            std::string lower = s;
            for (char& c : lower) c = tolower(c);
            if (lower != good) ++collisions;
        } else {
            BOOST_CHECK(!error.empty());
            ++reasons[error];
        }
    }
    BOOST_CHECK_EQUAL(collisions, 0);
    std::string summary;
    for (const auto& r : reasons) summary += strprintf("%s=%d ", r.first, r.second);
    BOOST_TEST_MESSAGE("mutations accepted unchanged: " << accepted << "; rejections: " << summary);
}

BOOST_AUTO_TEST_CASE(scanner_fuzz)
{
    // V3.6: malformed, ineligible or huge transactions never crash the
    // scanner and never report a payment that was not made.
    const std::vector<unsigned char> context = RegtestContext();
    const silentpayments::AccountKeys identity = LabIdentity();
    const silentpayments::PaymentCode code{silentpayments::REGTEST, identity.scanPub, identity.spendPub};
    FastRandomContext rng(true);
    int eligible = 0, genuine = 0;
    for (int i = 0; i < 3000; ++i) {
        CMutableTransaction mtx;
        mtx.nVersion = rng.randrange(5) ? 2 : (int32_t)rng.rand32();
        std::vector<CTxOut> spent;
        std::vector<CKey> keys;
        std::vector<COutPoint> outpoints;
        bool allValid = true;
        const int nIn = 1 + rng.randrange(6);
        for (int j = 0; j < nIn; ++j) {
            CKey key;
            key.MakeNewKey(true);
            const CPubKey pub = key.GetPubKey();
            CTxIn in(COutPoint(GetRandHash(), rng.randrange(4)));
            std::vector<unsigned char> pubBytes(pub.begin(), pub.end());
            CScript script = silentpayments::PaymentScript(pub);
            switch (rng.randrange(8)) {
            case 0: pubBytes = GetRandBytesVector(33); allValid = false; break;          // not a point
            case 1: script = CScript() << OP_3 << ToByteVector(GetRandHash()); allValid = false; break; // other commitment
            case 2: script = CScript() << OP_1 << ToByteVector(GetRandHash()); allValid = false; break; // v1 prevout
            case 3: pubBytes.resize(rng.randrange(80)); allValid = false; break;       // wrong size
            default: break;
            }
            in.scriptWitness.stack = {{0x02}, GetRandBytesVector(rng.randrange(80)), pubBytes, {OP_TRUE}};
            if (rng.randrange(10) == 0) {
                in.scriptWitness.stack.resize(rng.randrange(7));
                allValid = false;
            }
            mtx.vin.push_back(in);
            spent.emplace_back(rng.randrange(100) * COIN, script);
            keys.push_back(key);
            outpoints.push_back(in.prevout);
        }
        const int nOut = i % 100 == 0 ? 3000 : rng.randrange(20);
        for (int j = 0; j < nOut; ++j) {
            CScript out = rng.randrange(3) ? CScript() << OP_3 << ToByteVector(GetRandHash())
                                           : CScript(GetRandBytesVector(rng.randrange(60)));
            mtx.vout.emplace_back(rng.randrange(1000), out);
        }
        // Some transactions carry real payments to the identity.
        size_t made = 0;
        if (allValid && rng.randrange(3) == 0) {
            std::vector<silentpayments::Recipient> recipients(1 + rng.randrange(4), silentpayments::Recipient{code, COIN});
            std::vector<CTxOut> outputs;
            std::string error;
            BOOST_REQUIRE(silentpayments::CreateOutputs(context, keys, outpoints, recipients, outputs, error));
            for (const CTxOut& o : outputs) mtx.vout.insert(mtx.vout.begin() + rng.randrange(mtx.vout.size() + 1), o);
            made = outputs.size();
        }
        if (rng.randrange(20) == 0) spent.pop_back(); // size mismatch

        const CTransaction tx(mtx);
        std::vector<CPubKey> pubs;
        std::vector<COutPoint> ops;
        const bool isEligible = silentpayments::GetEligibleInputs(tx, spent, pubs, ops);
        BOOST_CHECK(!isEligible || silentpayments::MayBeEligible(tx));
        if (!isEligible) continue;
        ++eligible;
        std::vector<silentpayments::Match> matches =
            silentpayments::ScanTransaction(context, tx, pubs, ops, identity.scan, identity.spendPub);
        const size_t expected = tx.nVersion == 2 ? made : 0;
        BOOST_CHECK_EQUAL(matches.size(), expected);
        genuine += matches.size();
    }
    BOOST_TEST_MESSAGE("eligible: " << eligible << ", payments found: " << genuine);
    BOOST_CHECK(eligible > 100 && genuine > 50);
}

BOOST_AUTO_TEST_SUITE_END()
