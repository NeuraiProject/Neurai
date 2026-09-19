// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Fixed test vectors for AuthScript commitments, addresses and sighashes,
// covering generic witness v1 and the strict v2 (PQ) / v3 (ECDSA) families.
//
// Every expected hex value below was independently recomputed outside the
// node with scripts/generate_authscript_vectors.py (hashlib for SHA256 and
// RIPEMD160; independent serialization, tagged hashing and bech32m encoding). The scriptCode is always exactly OP_TRUE, matching the fixed
// witnessScript of the strict families. External implementations (wallets,
// signers) can use these to check their own commitment, address and sighash
// computation without needing this node.
//
// The two fixed public keys below are NOT real keys: they are deterministic
// filler bytes chosen so any accidental byte-order bug (e.g. reversing the
// pubkey or the commitment) changes the result. They only need to be
// well-formed enough for CPubKey::IsValid()/IsCompressed()/IsPQ(), which
// GetAuthScriptCommitment relies on; no ECDSA or ML-DSA validity is required
// to compute a commitment, an address or a sighash.

#include "base58.h"
#include "chainparams.h"
#include "hash.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/standard.h"
#include "test/test_neurai.h"
#include "uint256.h"
#include "utilstrencodings.h"

#include <boost/test/unit_test.hpp>

#include <vector>

namespace {

typedef std::vector<unsigned char> valtype;

// ECDSA compressed pubkey: 0x02 followed by ascending bytes 00..1f (33 bytes
// total). Not a real curve point; GetAuthScriptCommitment never checks that.
CPubKey FixedEcdsaPubKey()
{
    valtype vch;
    vch.reserve(33);
    vch.push_back(0x02);
    for (int i = 0; i < 32; i++) vch.push_back((unsigned char)i);
    return CPubKey(vch);
}

// PQ pubkey: 0x05 header + 1312 bytes counting modulo 256 (1313 bytes total,
// CPubKey's declared ML-DSA-44 pubkey length).
CPubKey FixedPQPubKey()
{
    valtype vch;
    vch.reserve(1 + ML_DSA_44_PUBKEY_SIZE);
    vch.push_back(0x05);
    for (unsigned int i = 0; i < ML_DSA_44_PUBKEY_SIZE; i++) vch.push_back((unsigned char)(i % 256));
    return CPubKey(vch);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(authscript_vectors_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(fixed_pubkeys_are_well_formed)
{
    const CPubKey ecdsa = FixedEcdsaPubKey();
    const CPubKey pq = FixedPQPubKey();
    BOOST_REQUIRE(ecdsa.IsValid());
    BOOST_REQUIRE(ecdsa.IsCompressed());
    BOOST_REQUIRE(!ecdsa.IsPQ());
    BOOST_CHECK_EQUAL(ecdsa.size(), 33U);
    BOOST_CHECK_EQUAL(HexStr(ecdsa), "02000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

    BOOST_REQUIRE(pq.IsValid());
    BOOST_REQUIRE(pq.IsPQ());
    BOOST_CHECK_EQUAL(pq.size(), 1U + ML_DSA_44_PUBKEY_SIZE);
    BOOST_CHECK_EQUAL(HexStr(pq.begin(), pq.begin() + 8), "0500010203040506");
    BOOST_CHECK_EQUAL(HexStr(pq.end() - 8, pq.end()), "18191a1b1c1d1e1f");
}

// Commitment vectors. witnessScript is always OP_TRUE (0x51) in every case.
BOOST_AUTO_TEST_CASE(commitment_vectors)
{
    const CPubKey ecdsa = FixedEcdsaPubKey();
    const CPubKey pq = FixedPQPubKey();
    const CScript tmpl = GetStrictAuthScriptTemplate(); // OP_TRUE
    BOOST_REQUIRE(tmpl == (CScript() << OP_TRUE));

    // Generic witness v1 (commitment version 0x01, the historical default).
    const uint256 c_v1_pq = GetAuthScriptCommitment(0x01, &pq, tmpl);
    const uint256 c_v1_ecdsa = GetAuthScriptCommitment(0x02, &ecdsa, tmpl);
    const uint256 c_v1_noauth = GetAuthScriptCommitment(0x00, nullptr, tmpl);
    BOOST_CHECK_EQUAL(HexStr(c_v1_pq.begin(), c_v1_pq.end()), "893d608e80620f81640872ac2455c5dc31e23a25bd44f035818e56e4f8021e6d");
    BOOST_CHECK_EQUAL(HexStr(c_v1_ecdsa.begin(), c_v1_ecdsa.end()), "5ef909dff9f31e7fbd34ef4615863fa48c6bf567d8be51bcd75fbb9324724e9b");
    BOOST_CHECK_EQUAL(HexStr(c_v1_noauth.begin(), c_v1_noauth.end()), "a6c181fcd8137e65528a30e4e2d457b51778238441b8f5dd8911c2084a17ee7b");

    // Strict PQ (v2) and strict ECDSA (v3): commitment version equals the
    // witness version, so the same key under OP_TRUE gives a different
    // commitment for each family.
    const uint256 c_v2_pq = GetAuthScriptCommitment(0x01, &pq, tmpl, 2);
    const uint256 c_v3_ecdsa = GetAuthScriptCommitment(0x02, &ecdsa, tmpl, 3);
    BOOST_CHECK_EQUAL(HexStr(c_v2_pq.begin(), c_v2_pq.end()), "e72ae3c298d87dba49126bf5016e6cf2faacc11514e7d4520d25c8d977414644");
    BOOST_CHECK_EQUAL(HexStr(c_v3_ecdsa.begin(), c_v3_ecdsa.end()), "4dc35e48b409fbb4aaba11106f741824814d811e16df29b7083d4e46f519da7b");

    // Cross-check: this is exactly what the wallet's strict-destination helper
    // produces for the same keys.
    WitnessStrictAuthScript strictPQ, strictECDSA;
    BOOST_REQUIRE(GetStrictAuthScriptDestinationForPubKey(pq, strictPQ));
    BOOST_REQUIRE(GetStrictAuthScriptDestinationForPubKey(ecdsa, strictECDSA));
    BOOST_CHECK(strictPQ.commitment == c_v2_pq);
    BOOST_CHECK(strictECDSA.commitment == c_v3_ecdsa);
}

// Address vectors: mainnet (nc/nq/pq) and testnet/regtest (tnc/tnq/tpq) HRPs for the
// same five commitments above.
BOOST_AUTO_TEST_CASE(address_vectors)
{
    struct RestoreNetwork {
        const std::string previous = GetParams().NetworkIDString();
        ~RestoreNetwork() { SelectParams(previous); }
    } restore;

    const CPubKey ecdsa = FixedEcdsaPubKey();
    const CPubKey pq = FixedPQPubKey();
    const CScript tmpl = GetStrictAuthScriptTemplate();
    const WitnessV1AuthScript v1pq(GetAuthScriptCommitment(0x01, &pq, tmpl));
    const WitnessV1AuthScript v1ecdsa(GetAuthScriptCommitment(0x02, &ecdsa, tmpl));
    const WitnessV1AuthScript v1noauth(GetAuthScriptCommitment(0x00, nullptr, tmpl));
    const WitnessStrictAuthScript v2pq(2, GetAuthScriptCommitment(0x01, &pq, tmpl, 2));
    const WitnessStrictAuthScript v3ecdsa(3, GetAuthScriptCommitment(0x02, &ecdsa, tmpl, 3));

    struct Vector { const char* label; const CTxDestination dest; const char* mainnet; const char* testnet; };
    const Vector vectors[] = {
        {"v1 generic, PQ key",     v1pq,     "nc1p3y7kpr5qvg8czeqgw2kzg4w9msc7yw39h4z0qdvp3etwf7qzreksj3ypsd",  "tnc1p3y7kpr5qvg8czeqgw2kzg4w9msc7yw39h4z0qdvp3etwf7qzreksngkxpz"},
        {"v1 generic, ECDSA key",  v1ecdsa,  "nc1ptmusnhle7v08l0f5aarptp3l5jxxhat8mzl9r0xht7aexfrjf6dsx9lmna",  "tnc1ptmusnhle7v08l0f5aarptp3l5jxxhat8mzl9r0xht7aexfrjf6ds8uduzj"},
        {"v1 generic, no key",     v1noauth, "nc1p5mqcrlxczdlx2552xrjw94zhk5thsguygxu0thvfz8pqsjshaeas9jqzud",  "tnc1p5mqcrlxczdlx2552xrjw94zhk5thsguygxu0thvfz8pqsjshaeasytj9dz"},
        {"v2 strict PQ",           v2pq,     "pq1zuu4w8s5cmp7m5jgjd06szmnv7ta2esg4znnag5sdyhydja6pgezqsh4e35",  "tpq1zuu4w8s5cmp7m5jgjd06szmnv7ta2esg4znnag5sdyhydja6pgezq3w87qm"},
        {"v3 strict ECDSA",        v3ecdsa,  "nq1rfhp4uj95p8amf246zygx7aqcyjq5mqg7zm0jndcg848ydagemfasrnxzdt",  "tnq1rfhp4uj95p8amf246zygx7aqcyjq5mqg7zm0jndcg848ydagemfasz259uy"},
    };

    // DecodeDestination refuses a strict (v2/v3) address outside the strict
    // AuthScript activation context, by design (see CStrictAuthScriptContext):
    // before activation, those bech32m strings must not resolve to a spendable
    // destination. Decoding here is exercised as if the block being processed
    // had activation active, which is what a wallet building a payment to one
    // of these addresses would do once the families are live.
    CStrictAuthScriptContext activeForDecoding(true);

    // Construct each network once; selecting testnet mines its genesis.
    for (const std::string& network : {CBaseChainParams::MAIN, CBaseChainParams::TESTNET, CBaseChainParams::REGTEST}) {
        SelectParams(network);
        for (const auto& v : vectors) {
            const char* expected = network == CBaseChainParams::MAIN ? v.mainnet : v.testnet;
            BOOST_CHECK_MESSAGE(EncodeDestination(v.dest) == expected, v.label << " (" << network << ")");
            // regtest shares testnet's HRPs, checked by the encoding above.
            if (network != CBaseChainParams::REGTEST) {
                BOOST_CHECK_MESSAGE(DecodeDestination(expected) == v.dest, v.label << " (" << network << " decode)");
            }
        }
    }
}

// Sighash vectors for a fixed transaction, comparing the generic witness v1
// domain (SIGVERSION_AUTHSCRIPT) against the strict v2/v3 domain
// (SIGVERSION_AUTHSCRIPT_STRICT): same authType, different resulting hash,
// because the strict domain additionally commits to the witness version.
BOOST_AUTO_TEST_CASE(sighash_vectors)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.resize(1);
    valtype prevoutHash;
    for (int i = 0; i < 32; i++) prevoutHash.push_back((unsigned char)i); // ascending 00..1f
    mtx.vin[0].prevout = COutPoint(uint256(prevoutHash), 7);
    mtx.vin[0].nSequence = 0xfffffffd;
    mtx.vout.resize(1);
    mtx.vout[0].nValue = 123456789;
    mtx.vout[0].scriptPubKey = CScript() << OP_DUP << OP_HASH160 << valtype(20, 0xab) << OP_EQUALVERIFY << OP_CHECKSIG;
    mtx.nLockTime = 1700000000;
    const CTransaction tx(mtx);

    const CScript scriptCode = GetStrictAuthScriptTemplate(); // OP_TRUE
    const CAmount spentAmount = 987654321;

    const uint256 h_v1_domain_pq = SignatureHash(scriptCode, tx, 0, SIGHASH_ALL, spentAmount, SIGVERSION_AUTHSCRIPT, nullptr, 0x01);
    const uint256 h_v2_domain_pq = SignatureHash(scriptCode, tx, 0, SIGHASH_ALL, spentAmount, SIGVERSION_AUTHSCRIPT_STRICT, nullptr, 0x01);
    const uint256 h_v3_domain_ecdsa = SignatureHash(scriptCode, tx, 0, SIGHASH_ALL, spentAmount, SIGVERSION_AUTHSCRIPT_STRICT, nullptr, 0x02);

    BOOST_CHECK_EQUAL(HexStr(h_v1_domain_pq.begin(), h_v1_domain_pq.end()), "d12c4bb636907de9ab5fefa2c28643303f7809666808f21bdd1d44133d4323f1");
    BOOST_CHECK_EQUAL(HexStr(h_v2_domain_pq.begin(), h_v2_domain_pq.end()), "4c446a6b45054be4cbca7876fa7b0ead1df851ef4452304509f4d3fac6b8297d");
    BOOST_CHECK_EQUAL(HexStr(h_v3_domain_ecdsa.begin(), h_v3_domain_ecdsa.end()), "9a4d77433f1b45dc3b4491b38b818433ca08b091603917bd8d99c4d507bbd62d");

    // The three hashes are pairwise distinct: same tx and amount, different
    // sighash domain / authType produce distinct results for this vector.
    BOOST_CHECK(h_v1_domain_pq != h_v2_domain_pq);
    BOOST_CHECK(h_v2_domain_pq != h_v3_domain_ecdsa);
    BOOST_CHECK(h_v1_domain_pq != h_v3_domain_ecdsa);
}

BOOST_AUTO_TEST_SUITE_END()
