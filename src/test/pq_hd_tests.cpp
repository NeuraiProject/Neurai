// Copyright (c) 2024 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Tests for NIP-022: Native PQ-HD derivation (CExtKeyPQ / CKDer_PQ).

#include "key.h"
#include "pubkey.h"
#include "utilstrencodings.h"
#include "test/test_neurai.h"

#include <vector>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pq_hd_tests, BasicTestingSetup)

// ---- helpers ---------------------------------------------------------------

static std::vector<unsigned char> ZeroSeed32()
{
    return std::vector<unsigned char>(32, 0x00);
}

// A known 64-byte BIP39 seed for "abandon×11 about" + passphrase ""
// Matches BIP39 test vector: PBKDF2-HMAC-SHA512("abandon...about", "mnemonic", 2048, 64)
static std::vector<unsigned char> AbandonSeed64()
{
    return ParseHex(
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
        "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4");
}

// ---- 1. SetSeed determinism ------------------------------------------------

BOOST_AUTO_TEST_CASE(setseed_determinism)
{
    auto seed = AbandonSeed64();
    CExtKeyPQ k1, k2;
    k1.SetSeed(seed.data(), seed.size());
    k2.SetSeed(seed.data(), seed.size());

    BOOST_CHECK(k1.IsValid());
    BOOST_CHECK(k2.IsValid());
    BOOST_CHECK(k1.pq_seed == k2.pq_seed);
    BOOST_CHECK(k1.chaincode == k2.chaincode);
    BOOST_CHECK_EQUAL(k1.nDepth, 0);
    BOOST_CHECK_EQUAL(k1.nChild, 0);
}

// ---- 2. Domain separation from EC master ----------------------------------

BOOST_AUTO_TEST_CASE(domain_separation_from_ec)
{
    // PQ master seed must differ from EC master seed for the same BIP39 seed.
    // EC SetSeed uses "Bitcoin seed"; PQ uses "Neurai PQ seed".
    auto seed = AbandonSeed64();

    CExtKey   ecMaster;
    CExtKeyPQ pqMaster;
    ecMaster.SetSeed(seed.data(), seed.size());
    pqMaster.SetSeed(seed.data(), seed.size());

    // The 32-byte seeds must differ
    std::vector<unsigned char> ecSeed(ecMaster.key.begin(), ecMaster.key.end());
    BOOST_CHECK(ecSeed != std::vector<unsigned char>(pqMaster.pq_seed.begin(), pqMaster.pq_seed.end()));
    BOOST_CHECK(ecMaster.chaincode != pqMaster.chaincode);
}

// ---- 3. Hardened-only enforcement -----------------------------------------

BOOST_AUTO_TEST_CASE(hardened_only)
{
    auto seed = AbandonSeed64();
    CExtKeyPQ master, child;
    master.SetSeed(seed.data(), seed.size());

    // Non-hardened index must fail
    BOOST_CHECK(!master.Derive(child, 0));
    BOOST_CHECK(!master.Derive(child, 0x7FFFFFFF));

    // Hardened index must succeed
    BOOST_CHECK(master.Derive(child, 0x80000000));
    BOOST_CHECK(child.IsValid());
    BOOST_CHECK_EQUAL(child.nDepth, 1);
    BOOST_CHECK_EQUAL(child.nChild, 0x80000000u);
}

// ---- 4. Derivation determinism --------------------------------------------

BOOST_AUTO_TEST_CASE(derivation_determinism)
{
    auto seed = AbandonSeed64();

    // Derive the same path twice and verify identical results
    auto derive_path = [&](CExtKeyPQ& leaf) {
        CExtKeyPQ master, a, b, c, d;
        master.SetSeed(seed.data(), seed.size());
        BOOST_CHECK(master.Derive(a, 100 | 0x80000000));
        BOOST_CHECK(a.Derive(b, 1   | 0x80000000));
        BOOST_CHECK(b.Derive(c, 0   | 0x80000000));
        BOOST_CHECK(c.Derive(d, 0   | 0x80000000));
        BOOST_CHECK(d.Derive(leaf,  0   | 0x80000000));
    };

    CExtKeyPQ leaf1, leaf2;
    derive_path(leaf1);
    derive_path(leaf2);

    BOOST_CHECK(leaf1.IsValid());
    BOOST_CHECK(leaf1.pq_seed   == leaf2.pq_seed);
    BOOST_CHECK(leaf1.chaincode == leaf2.chaincode);

    // And the resulting pubkeys must be identical
    CPubKey pk1 = leaf1.GetPubKey();
    CPubKey pk2 = leaf2.GetPubKey();
    BOOST_CHECK(pk1.IsValid() && pk1.IsPQ());
    BOOST_CHECK(pk1 == pk2);
}

// ---- 5. Child keys differ per index ---------------------------------------

BOOST_AUTO_TEST_CASE(child_keys_unique)
{
    auto seed = AbandonSeed64();
    CExtKeyPQ master, child0, child1;
    master.SetSeed(seed.data(), seed.size());
    BOOST_CHECK(master.Derive(child0, 0x80000000));
    BOOST_CHECK(master.Derive(child1, 0x80000001));
    BOOST_CHECK(child0.pq_seed   != child1.pq_seed);
    BOOST_CHECK(child0.chaincode != child1.chaincode);
}

// ---- 6. Depth and fingerprint tracking ------------------------------------

BOOST_AUTO_TEST_CASE(depth_and_fingerprint)
{
    auto seed = AbandonSeed64();
    CExtKeyPQ master, depth1, depth2;
    master.SetSeed(seed.data(), seed.size());

    BOOST_CHECK_EQUAL(master.nDepth, 0);
    BOOST_CHECK(master.Derive(depth1, 0x80000000));
    BOOST_CHECK_EQUAL(depth1.nDepth, 1);
    BOOST_CHECK(depth1.Derive(depth2, 0x80000001));
    BOOST_CHECK_EQUAL(depth2.nDepth, 2);

    // Fingerprint of depth1 must equal Hash160(master.GetPubKey())[0:4]
    CKeyID masterId = master.GetPubKey().GetID();
    unsigned char expectedFP[4];
    memcpy(expectedFP, &masterId, 4);
    BOOST_CHECK(memcmp(depth1.vchFingerprint, expectedFP, 4) == 0);
}

// ---- 7. Encode / Decode roundtrip -----------------------------------------

BOOST_AUTO_TEST_CASE(encode_decode_roundtrip)
{
    auto seed = AbandonSeed64();
    CExtKeyPQ master, child, recovered;
    master.SetSeed(seed.data(), seed.size());
    BOOST_CHECK(master.Derive(child, 100 | 0x80000000));

    unsigned char buf[BIP32_PQ_EXTKEY_SIZE];
    child.Encode(buf);
    recovered.Decode(buf);

    BOOST_CHECK_EQUAL(recovered.nDepth,  child.nDepth);
    BOOST_CHECK_EQUAL(recovered.nChild,  child.nChild);
    BOOST_CHECK(recovered.chaincode == child.chaincode);
    BOOST_CHECK(recovered.pq_seed   == child.pq_seed);
    BOOST_CHECK(memcmp(recovered.vchFingerprint, child.vchFingerprint, 4) == 0);

    // Re-encode and compare buffers
    unsigned char buf2[BIP32_PQ_EXTKEY_SIZE];
    recovered.Encode(buf2);
    BOOST_CHECK(memcmp(buf, buf2, BIP32_PQ_EXTKEY_SIZE) == 0);
}

// ---- 8. GetKey() / GetPubKey() consistency --------------------------------

BOOST_AUTO_TEST_CASE(getkey_getpubkey_consistency)
{
    std::vector<unsigned char> seed32 = ZeroSeed32();
    CExtKeyPQ node;
    // Use SetSeed with a 32-byte seed (valid; HMAC-SHA512 accepts any length)
    node.SetSeed(seed32.data(), seed32.size());

    CKey key = node.GetKey();
    BOOST_CHECK(key.IsValid());
    BOOST_CHECK(key.IsPQ());

    CPubKey pub1 = key.GetPubKey();
    CPubKey pub2 = node.GetPubKey();
    BOOST_CHECK(pub1.IsValid() && pub1.IsPQ());
    BOOST_CHECK(pub1 == pub2);

    // VerifyPubKey must pass
    BOOST_CHECK(key.VerifyPubKey(pub1));
}

// ---- 9. Derivation path m_pq/100'/1'/0'/0'/0' (NIP-022 canonical path) ----

BOOST_AUTO_TEST_CASE(canonical_path_testnet)
{
    // Path: m_pq / 100' / 1' / 0' / 0' / 0'  (testnet: coin_type=1)
    auto seed = AbandonSeed64();
    CExtKeyPQ master, purpose, cointype, account, chain, leaf;
    master.SetSeed(seed.data(), seed.size());
    BOOST_CHECK(master.Derive(purpose,  100 | 0x80000000));
    BOOST_CHECK(purpose.Derive(cointype,  1 | 0x80000000));
    BOOST_CHECK(cointype.Derive(account,  0 | 0x80000000));
    BOOST_CHECK(account.Derive(chain,     0 | 0x80000000));
    BOOST_CHECK(chain.Derive(leaf,        0 | 0x80000000));

    BOOST_CHECK(leaf.IsValid());
    BOOST_CHECK_EQUAL(leaf.nDepth, 5);

    CPubKey pk = leaf.GetPubKey();
    BOOST_CHECK(pk.IsValid() && pk.IsPQ());
    BOOST_CHECK_EQUAL(pk.size(), 1313u);

    // NIP-022 §9.2 vector: values are PENDIENTE until generated with Rust reference implementation.
    // Uncomment and fill in once vectors are available:
    // BOOST_CHECK_EQUAL(HexStr(pk.begin(), pk.end()).substr(0, 8), "PENDIENTE");
}

// ---- 10. Zero seed produces valid (but weak) key --------------------------

BOOST_AUTO_TEST_CASE(zero_seed_valid)
{
    // NIP-022 §9.1: MakeNewKeyPQ with seed=0x00×32 must be deterministic.
    // This test verifies determinism; pinned pk_hex goes in §9.1 of the NIP.
    std::vector<unsigned char> seed32(32, 0x00);
    CKey k1, k2;
    k1.MakeNewKeyPQ(seed32);
    k2.MakeNewKeyPQ(seed32);
    BOOST_CHECK(k1.IsValid() && k1.IsPQ());
    BOOST_CHECK(k1.GetPubKey() == k2.GetPubKey());
}

BOOST_AUTO_TEST_SUITE_END()
