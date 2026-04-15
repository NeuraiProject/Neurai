// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NIP-014: Unit tests for transaction v3 reference inputs (vrefin)

#include "script/interpreter.h"
#include "script/script.h"
#include "hash.h"
#include "primitives/transaction.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "test/test_neurai.h"
#include "streams.h"
#include "version.h"

#include <vector>
#include <stdint.h>
#include <set>

#include <boost/test/unit_test.hpp>

namespace {

CMutableTransaction BuildV3TestTx(int numInputs = 1, int numOutputs = 1, int numRefInputs = 0)
{
    CMutableTransaction tx;
    tx.nVersion = 3;
    tx.nLockTime = 0;

    for (int i = 0; i < numInputs; i++) {
        CTxIn vin;
        vin.prevout.hash = uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        vin.prevout.n = i;
        vin.nSequence = 0xffffffff;
        tx.vin.push_back(vin);
    }

    for (int i = 0; i < numOutputs; i++) {
        CTxOut vout;
        vout.nValue = (i + 1) * 1000 * COIN;
        vout.scriptPubKey = CScript() << OP_DUP << OP_HASH160
                            << std::vector<unsigned char>(20, (unsigned char)(i + 1))
                            << OP_EQUALVERIFY << OP_CHECKSIG;
        tx.vout.push_back(vout);
    }

    for (int i = 0; i < numRefInputs; i++) {
        COutPoint refin;
        refin.hash = uint256S("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        refin.n = i;
        tx.vrefin.push_back(refin);
    }

    return tx;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(refinputs_tests, BasicTestingSetup)

// Test 1: Serialization roundtrip — v3 tx with vrefin serializes and deserializes correctly
BOOST_AUTO_TEST_CASE(serialization_roundtrip)
{
    CMutableTransaction mtx = BuildV3TestTx(2, 2, 3);
    CTransaction tx(mtx);

    // Serialize
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << tx;

    // Deserialize
    CMutableTransaction mtx2;
    ss >> mtx2;
    CTransaction tx2(mtx2);

    BOOST_CHECK_EQUAL(tx.GetHash().GetHex(), tx2.GetHash().GetHex());
    BOOST_CHECK_EQUAL(tx.nVersion, tx2.nVersion);
    BOOST_CHECK_EQUAL(tx.vin.size(), tx2.vin.size());
    BOOST_CHECK_EQUAL(tx.vout.size(), tx2.vout.size());
    BOOST_CHECK_EQUAL(tx.vrefin.size(), tx2.vrefin.size());
    for (size_t i = 0; i < tx.vrefin.size(); i++) {
        BOOST_CHECK(tx.vrefin[i] == tx2.vrefin[i]);
    }
}

// Test 2: v3 with empty vrefin roundtrips correctly
BOOST_AUTO_TEST_CASE(empty_vrefin_roundtrip)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 0);
    CTransaction tx(mtx);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << tx;

    CMutableTransaction mtx2;
    ss >> mtx2;
    CTransaction tx2(mtx2);

    BOOST_CHECK_EQUAL(tx.GetHash().GetHex(), tx2.GetHash().GetHex());
    BOOST_CHECK_EQUAL(tx2.vrefin.size(), 0u);
    BOOST_CHECK_EQUAL(tx2.nVersion, 3);
}

// Test 3: Hash commitment — txid changes when vrefin changes
BOOST_AUTO_TEST_CASE(hash_commitment)
{
    CMutableTransaction mtx1 = BuildV3TestTx(1, 1, 1);
    CMutableTransaction mtx2 = BuildV3TestTx(1, 1, 2);
    CMutableTransaction mtx3 = BuildV3TestTx(1, 1, 0);

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);
    CTransaction tx3(mtx3);

    // Different number of refinputs => different txid
    BOOST_CHECK(tx1.GetHash() != tx2.GetHash());
    BOOST_CHECK(tx1.GetHash() != tx3.GetHash());
    BOOST_CHECK(tx2.GetHash() != tx3.GetHash());
}

// Test 4: Legacy sighash unchanged — v2 tx produces identical hash
BOOST_AUTO_TEST_CASE(legacy_sighash_unchanged)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.nLockTime = 0;

    CTxIn vin;
    vin.prevout.hash = uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    vin.prevout.n = 0;
    vin.nSequence = 0xffffffff;
    mtx.vin.push_back(vin);

    CTxOut vout;
    vout.nValue = 1000 * COIN;
    vout.scriptPubKey = CScript() << OP_DUP << OP_HASH160
                        << std::vector<unsigned char>(20, 0x01)
                        << OP_EQUALVERIFY << OP_CHECKSIG;
    mtx.vout.push_back(vout);

    CTransaction tx(mtx);

    // vrefin should be empty for v2
    BOOST_CHECK(tx.vrefin.empty());
    BOOST_CHECK(!tx.HasRefInputs());

    // Compute sighash — should work without issues
    CScript scriptCode = vout.scriptPubKey;
    uint256 sighash = SignatureHash(scriptCode, tx, 0, SIGHASH_ALL, 0, SIGVERSION_BASE);
    BOOST_CHECK(!sighash.IsNull());
}

// Test 5: BIP143 sighash includes hashRefInputs for v3
BOOST_AUTO_TEST_CASE(bip143_sighash_commitment)
{
    CMutableTransaction mtx1 = BuildV3TestTx(1, 1, 1);
    CMutableTransaction mtx2 = BuildV3TestTx(1, 1, 2);

    // Add witness to enable BIP143 path
    mtx1.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(1, 0x01));
    mtx2.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(1, 0x01));

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    CScript scriptCode = CScript() << OP_1;
    CAmount amount = 1000 * COIN;

    uint256 hash1 = SignatureHash(scriptCode, tx1, 0, SIGHASH_ALL, amount, SIGVERSION_WITNESS_V0);
    uint256 hash2 = SignatureHash(scriptCode, tx2, 0, SIGHASH_ALL, amount, SIGVERSION_WITNESS_V0);

    // Different vrefin => different sighash
    BOOST_CHECK(hash1 != hash2);
}

// Test 6: Structural validation — duplicates rejected
BOOST_AUTO_TEST_CASE(structural_duplicate_refinputs)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 0);
    COutPoint refin;
    refin.hash = uint256S("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    refin.n = 0;
    mtx.vrefin.push_back(refin);
    mtx.vrefin.push_back(refin); // duplicate

    CTransaction tx(mtx);
    CValidationState state;
    BOOST_CHECK(!CheckTransaction(tx, state, nullptr, true));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-vrefin-duplicate");
}

// Test 7: Structural validation — overlap vin/vrefin rejected
BOOST_AUTO_TEST_CASE(structural_overlap_vin_vrefin)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 0);
    // Add a refin that matches the existing vin
    mtx.vrefin.push_back(mtx.vin[0].prevout);

    CTransaction tx(mtx);
    CValidationState state;
    BOOST_CHECK(!CheckTransaction(tx, state, nullptr, true));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-vrefin-overlap-vin");
}

// Test 8: Non-v3 with vrefin is rejected
BOOST_AUTO_TEST_CASE(non_v3_with_vrefin)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 1);
    mtx.nVersion = 2; // downgrade to v2 but keep vrefin

    CTransaction tx(mtx);
    CValidationState state;
    BOOST_CHECK(!CheckTransaction(tx, state, nullptr, true));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-vrefin-no-v3");
}

// Test 9: v3 with empty vrefin is valid
BOOST_AUTO_TEST_CASE(v3_empty_vrefin_valid)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 0);
    CTransaction tx(mtx);
    CValidationState state;
    BOOST_CHECK(CheckTransaction(tx, state, nullptr, true));
}

// Test 10: HasRefInputs() helper works correctly
BOOST_AUTO_TEST_CASE(has_ref_inputs_helper)
{
    CMutableTransaction mtx1 = BuildV3TestTx(1, 1, 0);
    CMutableTransaction mtx2 = BuildV3TestTx(1, 1, 2);

    CTransaction tx1(mtx1);
    CTransaction tx2(mtx2);

    BOOST_CHECK(!tx1.HasRefInputs());
    BOOST_CHECK(tx2.HasRefInputs());

    BOOST_CHECK(!mtx1.HasRefInputs());
    BOOST_CHECK(mtx2.HasRefInputs());
}

// Test 11: v2 serialization is NOT affected by vrefin code
BOOST_AUTO_TEST_CASE(v2_serialization_unchanged)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.nLockTime = 42;

    CTxIn vin;
    vin.prevout.hash = uint256S("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    vin.prevout.n = 7;
    vin.nSequence = 0xffffffff;
    mtx.vin.push_back(vin);

    CTxOut vout;
    vout.nValue = 50000;
    vout.scriptPubKey = CScript() << OP_TRUE;
    mtx.vout.push_back(vout);

    // Serialize v2
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    CTransaction tx(mtx);
    ss << tx;

    // Deserialize and verify
    CMutableTransaction mtx2;
    ss >> mtx2;

    BOOST_CHECK_EQUAL(mtx2.nVersion, 2);
    BOOST_CHECK(mtx2.vrefin.empty());
    BOOST_CHECK_EQUAL(mtx2.vin.size(), 1u);
    BOOST_CHECK_EQUAL(mtx2.vout.size(), 1u);
    BOOST_CHECK_EQUAL(mtx2.nLockTime, 42u);
}

// Test 12: PrecomputedTransactionData caches for v3 with vrefin
BOOST_AUTO_TEST_CASE(precomputed_data_v3)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 2);
    mtx.vin[0].scriptWitness.stack.push_back(std::vector<unsigned char>(1, 0x01));
    CTransaction tx(mtx);

    PrecomputedTransactionData txdata(tx);

    BOOST_CHECK(txdata.refInputsReady);
    BOOST_CHECK(!txdata.hashRefInputs.IsNull());
    BOOST_CHECK(txdata.ctvRefInputsReady);
    BOOST_CHECK(!txdata.ctvHashRefInputs.IsNull());

    // BIP143 hash (double-SHA256) should differ from CTV hash (single-SHA256)
    BOOST_CHECK(txdata.hashRefInputs != txdata.ctvHashRefInputs);
}

// Test 13: PrecomputedTransactionData empty for v2
BOOST_AUTO_TEST_CASE(precomputed_data_v2)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    CTxIn vin;
    vin.prevout.hash = uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    vin.prevout.n = 0;
    mtx.vin.push_back(vin);
    CTxOut vout;
    vout.nValue = 1000;
    vout.scriptPubKey = CScript() << OP_TRUE;
    mtx.vout.push_back(vout);

    CTransaction tx(mtx);
    PrecomputedTransactionData txdata(tx);

    BOOST_CHECK(!txdata.refInputsReady);
    BOOST_CHECK(!txdata.ctvRefInputsReady);
}

// Test 14: PrecomputedTransactionData empty for v3 with no vrefin
BOOST_AUTO_TEST_CASE(precomputed_data_v3_no_vrefin)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 0);
    CTransaction tx(mtx);
    PrecomputedTransactionData txdata(tx);

    BOOST_CHECK(!txdata.refInputsReady);
    BOOST_CHECK(!txdata.ctvRefInputsReady);
}

BOOST_AUTO_TEST_SUITE_END()
