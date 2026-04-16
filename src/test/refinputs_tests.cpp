// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NIP-014: Unit tests for transaction v3 reference inputs (vrefin)
// NIP-017: Unit tests for OP_REFINPUT* opcode family

#include "assets/assets.h"
#include "base58.h"
#include "chainparams.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "hash.h"
#include "primitives/transaction.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "test/test_neurai.h"
#include "streams.h"
#include "version.h"

#include <cstring>
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

// NIP-017: Flag sets for opcode tests
static constexpr script_verify_flags REFINPUT_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_REFINPUTS;
static constexpr script_verify_flags REFINPUT_FLAGS_64BIT =
    REFINPUT_FLAGS | SCRIPT_VERIFY_64BIT_INTEGERS;
static constexpr script_verify_flags NO_REFINPUT_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
static constexpr script_verify_flags NO_REFINPUT_FLAGS_DISCOURAGE =
    NO_REFINPUT_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;

std::vector<unsigned char> EncodeLE8(int64_t value)
{
    std::vector<unsigned char> out(8);
    memcpy(out.data(), &value, 8);
    return out;
}

bool RunRefInputScript(const CTransaction& tx, const std::vector<CTxOut>& refOutputs,
                       const CScript& script, script_verify_flags flags,
                       std::vector<std::vector<unsigned char>>& resultStack,
                       ScriptError* errOut = nullptr)
{
    PrecomputedTransactionData txdata(tx);
    CScript dummySPK = CScript() << OP_TRUE;
    TransactionSignatureChecker checker(&tx, 0, 0, txdata, dummySPK, nullptr, &refOutputs);
    ScriptError serror = SCRIPT_ERR_OK;
    std::vector<std::vector<unsigned char>> stack;
    bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    if (errOut) *errOut = serror;
    resultStack = stack;
    return ok;
}

std::vector<CTxOut> BuildRefOutputs_Plain(int count, CAmount baseValue = 500000000)
{
    std::vector<CTxOut> refs;
    for (int i = 0; i < count; i++) {
        CTxOut out;
        out.nValue = baseValue * (i + 1);
        out.scriptPubKey = CScript() << OP_DUP << OP_HASH160
                           << std::vector<unsigned char>(20, (unsigned char)(0x50 + i))
                           << OP_EQUALVERIFY << OP_CHECKSIG;
        refs.push_back(out);
    }
    return refs;
}

CTxOut BuildAuthScriptRefOutput(const std::vector<unsigned char>& commitment32)
{
    CTxOut out;
    out.nValue = 1000;
    std::vector<unsigned char> raw;
    raw.push_back(0x51); // OP_1
    raw.push_back(0x20); // push 32 bytes
    raw.insert(raw.end(), commitment32.begin(), commitment32.end());
    out.scriptPubKey = CScript(raw.begin(), raw.end());
    return out;
}

std::vector<CTxOut> BuildAssetRefOutputsForNetwork(const std::string& chain)
{
    SelectParams(chain);
    std::vector<CTxOut> refs;
    const CTxDestination dest = DecodeDestination(GetParams().GlobalBurnAddress());

    // Ref 0: transfer asset
    {
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey = GetScriptForDestination(dest);
        CAssetTransfer transfer("MYASSET", 100 * COIN);
        transfer.ConstructTransaction(out.scriptPubKey);
        refs.push_back(out);
    }

    // Ref 1: new asset with IPFS
    {
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey = GetScriptForDestination(dest);
        CNewAsset asset("TESTASSET", 500 * COIN, 8, 1, 1,
                        DecodeAssetData("QmacSRmrkVmvJfbCpmU6pK72furJ8E8fbKHindrLxmYMQo"));
        asset.ConstructTransaction(out.scriptPubKey);
        refs.push_back(out);
    }

    // Ref 2: new asset without IPFS
    {
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey = GetScriptForDestination(dest);
        CNewAsset asset("NOIPFS", 200 * COIN, 4, 0, 0, "");
        asset.ConstructTransaction(out.scriptPubKey);
        refs.push_back(out);
    }

    return refs;
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
    BOOST_CHECK(!CheckTransaction(tx, state, true, true));
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
    BOOST_CHECK(!CheckTransaction(tx, state, true, true));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-vrefin-overlap-vin");
}

// Test 8: Non-v3 with vrefin is rejected
BOOST_AUTO_TEST_CASE(non_v3_with_vrefin)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 1);
    mtx.nVersion = 2; // downgrade to v2 but keep vrefin

    CTransaction tx(mtx);
    CValidationState state;
    BOOST_CHECK(!CheckTransaction(tx, state, true, true));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-vrefin-no-v3");
}

// Test 9: v3 with empty vrefin is valid
BOOST_AUTO_TEST_CASE(v3_empty_vrefin_valid)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 0);
    CTransaction tx(mtx);
    CValidationState state;
    BOOST_CHECK(CheckTransaction(tx, state, true, true));
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

// =============================================================================
// NIP-017: OP_REFINPUTCOUNT tests
// =============================================================================

BOOST_AUTO_TEST_CASE(op_refinputcount_basic)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 3);
    CTransaction tx(mtx);
    std::vector<CTxOut> refOutputs = BuildRefOutputs_Plain(3);

    CScript script;
    script << OP_REFINPUTCOUNT << CScriptNum(3) << OP_NUMEQUALVERIFY << OP_1;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result));
}

BOOST_AUTO_TEST_CASE(op_refinputcount_zero)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 0);
    CTransaction tx(mtx);
    std::vector<CTxOut> refOutputs;

    CScript script;
    script << OP_REFINPUTCOUNT << CScriptNum(0) << OP_NUMEQUALVERIFY << OP_1;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result));
}

BOOST_AUTO_TEST_CASE(op_refinputcount_disabled_nop)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 3);
    CTransaction tx(mtx);
    std::vector<CTxOut> refOutputs = BuildRefOutputs_Plain(3);

    // Without SCRIPT_VERIFY_REFINPUTS, OP_REFINPUTCOUNT is a NOP.
    // Nothing pushed, nothing consumed. OP_1 provides truthy top.
    CScript script;
    script << OP_REFINPUTCOUNT << OP_1;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(RunRefInputScript(tx, refOutputs, script, NO_REFINPUT_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(result.size(), 1U); // Only OP_1 on stack
}

BOOST_AUTO_TEST_CASE(op_refinputcount_disabled_discourage)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 3);
    CTransaction tx(mtx);
    std::vector<CTxOut> refOutputs = BuildRefOutputs_Plain(3);

    CScript script;
    script << OP_REFINPUTCOUNT << OP_1;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunRefInputScript(tx, refOutputs, script, NO_REFINPUT_FLAGS_DISCOURAGE, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

// =============================================================================
// NIP-017: OP_REFINPUTFIELD tests
// =============================================================================

BOOST_AUTO_TEST_CASE(op_refinputfield_value)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 1);
    CTransaction tx(mtx);

    CAmount expectedValue = 500000000; // 5 XNA
    std::vector<CTxOut> refOutputs;
    CTxOut out;
    out.nValue = expectedValue;
    out.scriptPubKey = CScript() << OP_TRUE;
    refOutputs.push_back(out);

    CScript script;
    script << CScriptNum(0) << std::vector<unsigned char>{0x01} << OP_REFINPUTFIELD
           << EncodeLE8(expectedValue) << OP_EQUALVERIFY << OP_1;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result));
}

BOOST_AUTO_TEST_CASE(op_refinputfield_value_scriptnum_conversion)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 1);
    CTransaction tx(mtx);

    CAmount expectedValue = 500000000;
    std::vector<CTxOut> refOutputs;
    CTxOut out;
    out.nValue = expectedValue;
    out.scriptPubKey = CScript() << OP_TRUE;
    refOutputs.push_back(out);

    // With 64-bit integers, value is returned as CScriptNum
    CScript script;
    script << CScriptNum(0) << std::vector<unsigned char>{0x01} << OP_REFINPUTFIELD
           << CScriptNum(expectedValue) << OP_NUMEQUALVERIFY << OP_1;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS_64BIT, result));
}

BOOST_AUTO_TEST_CASE(op_refinputfield_scriptpubkey)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 1);
    CTransaction tx(mtx);

    CScript expectedSPK = CScript() << OP_DUP << OP_HASH160
                           << std::vector<unsigned char>(20, 0xAA)
                           << OP_EQUALVERIFY << OP_CHECKSIG;
    std::vector<CTxOut> refOutputs;
    CTxOut out;
    out.nValue = 1000;
    out.scriptPubKey = expectedSPK;
    refOutputs.push_back(out);

    std::vector<unsigned char> expectedBytes(expectedSPK.begin(), expectedSPK.end());

    CScript script;
    script << CScriptNum(0) << std::vector<unsigned char>{0x03} << OP_REFINPUTFIELD
           << expectedBytes << OP_EQUALVERIFY << OP_1;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result));
}

BOOST_AUTO_TEST_CASE(op_refinputfield_scriptpubkey_max_size)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 1);
    CTransaction tx(mtx);

    // scriptPubKey of exactly MAX_SCRIPT_ELEMENT_SIZE (520 bytes) — should succeed
    std::vector<unsigned char> bigScript(520, 0x42);
    std::vector<CTxOut> refOutputs;
    CTxOut out;
    out.nValue = 1000;
    out.scriptPubKey = CScript(bigScript.begin(), bigScript.end());
    refOutputs.push_back(out);

    CScript script;
    script << CScriptNum(0) << std::vector<unsigned char>{0x03} << OP_REFINPUTFIELD;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK_EQUAL(result[0].size(), 520U);
}

BOOST_AUTO_TEST_CASE(op_refinputfield_scriptpubkey_oversized)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 1);
    CTransaction tx(mtx);

    // scriptPubKey of 521 bytes — exceeds MAX_SCRIPT_ELEMENT_SIZE, should fail
    std::vector<unsigned char> bigScript(521, 0x42);
    std::vector<CTxOut> refOutputs;
    CTxOut out;
    out.nValue = 1000;
    out.scriptPubKey = CScript(bigScript.begin(), bigScript.end());
    refOutputs.push_back(out);

    CScript script;
    script << CScriptNum(0) << std::vector<unsigned char>{0x03} << OP_REFINPUTFIELD;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_REFINPUTFIELD);
}

BOOST_AUTO_TEST_CASE(op_refinputfield_authscript)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 1);
    CTransaction tx(mtx);

    std::vector<unsigned char> commitment(32);
    for (int i = 0; i < 32; i++) commitment[i] = (unsigned char)(i * 7 + 3);

    std::vector<CTxOut> refOutputs;
    refOutputs.push_back(BuildAuthScriptRefOutput(commitment));

    CScript script;
    script << CScriptNum(0) << std::vector<unsigned char>{0x02} << OP_REFINPUTFIELD
           << commitment << OP_EQUALVERIFY << OP_1;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result));
}

BOOST_AUTO_TEST_CASE(op_refinputfield_authscript_not_authscript_output)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 1);
    CTransaction tx(mtx);

    // Normal P2PKH output — not an AuthScript
    std::vector<CTxOut> refOutputs = BuildRefOutputs_Plain(1);

    CScript script;
    script << CScriptNum(0) << std::vector<unsigned char>{0x02} << OP_REFINPUTFIELD;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_REFINPUTFIELD);
}

BOOST_AUTO_TEST_CASE(op_refinputfield_bad_index)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 1);
    CTransaction tx(mtx);
    std::vector<CTxOut> refOutputs = BuildRefOutputs_Plain(1);

    // Index 5 but only 1 ref output
    CScript script;
    script << CScriptNum(5) << std::vector<unsigned char>{0x01} << OP_REFINPUTFIELD;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_REFINPUTFIELD);
}

BOOST_AUTO_TEST_CASE(op_refinputfield_negative_index)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 1);
    CTransaction tx(mtx);
    std::vector<CTxOut> refOutputs = BuildRefOutputs_Plain(1);

    CScript script;
    script << CScriptNum(-1) << std::vector<unsigned char>{0x01} << OP_REFINPUTFIELD;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_REFINPUTFIELD);
}

BOOST_AUTO_TEST_CASE(op_refinputfield_bad_selector_zero)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 1);
    CTransaction tx(mtx);
    std::vector<CTxOut> refOutputs = BuildRefOutputs_Plain(1);

    CScript script;
    script << CScriptNum(0) << std::vector<unsigned char>{0x00} << OP_REFINPUTFIELD;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_REFINPUTFIELD);
}

BOOST_AUTO_TEST_CASE(op_refinputfield_bad_selector_high)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 1);
    CTransaction tx(mtx);
    std::vector<CTxOut> refOutputs = BuildRefOutputs_Plain(1);

    CScript script;
    script << CScriptNum(0) << std::vector<unsigned char>{0x04} << OP_REFINPUTFIELD;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_REFINPUTFIELD);
}

BOOST_AUTO_TEST_CASE(op_refinputfield_selector_not_one_byte)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 1);
    CTransaction tx(mtx);
    std::vector<CTxOut> refOutputs = BuildRefOutputs_Plain(1);

    // Selector is 2 bytes — must be exactly 1 byte
    CScript script;
    script << CScriptNum(0) << std::vector<unsigned char>{0x01, 0x02} << OP_REFINPUTFIELD;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_REFINPUTFIELD);
}

BOOST_AUTO_TEST_CASE(op_refinputfield_stack_underflow)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 1);
    CTransaction tx(mtx);
    std::vector<CTxOut> refOutputs = BuildRefOutputs_Plain(1);

    // Only 1 item on stack, needs 2
    CScript script;
    script << std::vector<unsigned char>{0x01} << OP_REFINPUTFIELD;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(op_refinputfield_disabled_nop)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 1);
    CTransaction tx(mtx);
    std::vector<CTxOut> refOutputs = BuildRefOutputs_Plain(1);

    // Without SCRIPT_VERIFY_REFINPUTS, OP_REFINPUTFIELD is a NOP.
    // The two arguments (nRef=0, selector=0x01) remain on the stack unconsumed.
    // Stack ends as [0x00, 0x01]; top element is 0x01 (truthy).
    CScript script;
    script << CScriptNum(0) << std::vector<unsigned char>{0x01} << OP_REFINPUTFIELD;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(RunRefInputScript(tx, refOutputs, script, NO_REFINPUT_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(result.size(), 2U); // Both args remain on stack
}

// =============================================================================
// NIP-017: OP_REFINPUTASSETFIELD tests
// =============================================================================

BOOST_AUTO_TEST_CASE(op_refinputassetfield_name)
{
    std::vector<CTxOut> refOutputs = BuildAssetRefOutputsForNetwork(CBaseChainParams::TESTNET);
    CMutableTransaction mtx = BuildV3TestTx(1, 1, refOutputs.size());
    CTransaction tx(mtx);

    std::string expectedName = "MYASSET";
    std::vector<unsigned char> nameBytes(expectedName.begin(), expectedName.end());

    CScript script;
    script << CScriptNum(0) << std::vector<unsigned char>{0x01} << OP_REFINPUTASSETFIELD
           << nameBytes << OP_EQUALVERIFY << OP_1;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result));
}

BOOST_AUTO_TEST_CASE(op_refinputassetfield_amount)
{
    std::vector<CTxOut> refOutputs = BuildAssetRefOutputsForNetwork(CBaseChainParams::TESTNET);
    CMutableTransaction mtx = BuildV3TestTx(1, 1, refOutputs.size());
    CTransaction tx(mtx);

    CScript script;
    script << CScriptNum(0) << std::vector<unsigned char>{0x02} << OP_REFINPUTASSETFIELD
           << EncodeLE8(100 * COIN) << OP_EQUALVERIFY << OP_1;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result));
}

BOOST_AUTO_TEST_CASE(op_refinputassetfield_amount_scriptnum_conversion)
{
    std::vector<CTxOut> refOutputs = BuildAssetRefOutputsForNetwork(CBaseChainParams::TESTNET);
    CMutableTransaction mtx = BuildV3TestTx(1, 1, refOutputs.size());
    CTransaction tx(mtx);

    // With 64-bit integers, amount is returned as CScriptNum
    CScript script;
    script << CScriptNum(0) << std::vector<unsigned char>{0x02} << OP_REFINPUTASSETFIELD
           << CScriptNum(100 * COIN) << OP_NUMEQUALVERIFY << OP_1;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS_64BIT, result));
}

BOOST_AUTO_TEST_CASE(op_refinputassetfield_units)
{
    std::vector<CTxOut> refOutputs = BuildAssetRefOutputsForNetwork(CBaseChainParams::TESTNET);
    CMutableTransaction mtx = BuildV3TestTx(1, 1, refOutputs.size());
    CTransaction tx(mtx);

    // Ref 1 is "TESTASSET" with units=8
    CScript script;
    script << CScriptNum(1) << std::vector<unsigned char>{0x03} << OP_REFINPUTASSETFIELD
           << CScriptNum(8) << OP_NUMEQUALVERIFY << OP_1;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result));
}

BOOST_AUTO_TEST_CASE(op_refinputassetfield_has_ipfs)
{
    std::vector<CTxOut> refOutputs = BuildAssetRefOutputsForNetwork(CBaseChainParams::TESTNET);
    CMutableTransaction mtx = BuildV3TestTx(1, 1, refOutputs.size());
    CTransaction tx(mtx);

    // Ref 1 is "TESTASSET" with nHasIPFS=1
    CScript script;
    script << CScriptNum(1) << std::vector<unsigned char>{0x05} << OP_REFINPUTASSETFIELD
           << CScriptNum(1) << OP_NUMEQUALVERIFY << OP_1;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result));
}

BOOST_AUTO_TEST_CASE(op_refinputassetfield_no_asset)
{
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 1);
    CTransaction tx(mtx);

    // Plain XNA output with no asset data
    std::vector<CTxOut> refOutputs = BuildRefOutputs_Plain(1);

    CScript script;
    script << CScriptNum(0) << std::vector<unsigned char>{0x01} << OP_REFINPUTASSETFIELD;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_REFINPUTASSETFIELD);
}

BOOST_AUTO_TEST_CASE(op_refinputassetfield_bad_selector_zero)
{
    std::vector<CTxOut> refOutputs = BuildAssetRefOutputsForNetwork(CBaseChainParams::TESTNET);
    CMutableTransaction mtx = BuildV3TestTx(1, 1, refOutputs.size());
    CTransaction tx(mtx);

    CScript script;
    script << CScriptNum(0) << std::vector<unsigned char>{0x00} << OP_REFINPUTASSETFIELD;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_REFINPUTASSETFIELD);
}

BOOST_AUTO_TEST_CASE(op_refinputassetfield_bad_selector_high)
{
    std::vector<CTxOut> refOutputs = BuildAssetRefOutputsForNetwork(CBaseChainParams::TESTNET);
    CMutableTransaction mtx = BuildV3TestTx(1, 1, refOutputs.size());
    CTransaction tx(mtx);

    CScript script;
    script << CScriptNum(0) << std::vector<unsigned char>{0x08} << OP_REFINPUTASSETFIELD;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_REFINPUTASSETFIELD);
}

BOOST_AUTO_TEST_CASE(op_refinputassetfield_selector_not_one_byte)
{
    std::vector<CTxOut> refOutputs = BuildAssetRefOutputsForNetwork(CBaseChainParams::TESTNET);
    CMutableTransaction mtx = BuildV3TestTx(1, 1, refOutputs.size());
    CTransaction tx(mtx);

    CScript script;
    script << CScriptNum(0) << std::vector<unsigned char>{0x01, 0x02} << OP_REFINPUTASSETFIELD;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_REFINPUTASSETFIELD);
}

BOOST_AUTO_TEST_CASE(op_refinputassetfield_ipfs_no_ipfs)
{
    std::vector<CTxOut> refOutputs = BuildAssetRefOutputsForNetwork(CBaseChainParams::TESTNET);
    CMutableTransaction mtx = BuildV3TestTx(1, 1, refOutputs.size());
    CTransaction tx(mtx);

    // Ref 2 is "NOIPFS" with nHasIPFS=0 — requesting IPFS hash should fail
    CScript script;
    script << CScriptNum(2) << std::vector<unsigned char>{0x06} << OP_REFINPUTASSETFIELD;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_REFINPUTASSETFIELD);
}

BOOST_AUTO_TEST_CASE(op_refinputassetfield_disabled_nop)
{
    std::vector<CTxOut> refOutputs = BuildAssetRefOutputsForNetwork(CBaseChainParams::TESTNET);
    CMutableTransaction mtx = BuildV3TestTx(1, 1, refOutputs.size());
    CTransaction tx(mtx);

    // Without SCRIPT_VERIFY_REFINPUTS, OP_REFINPUTASSETFIELD is a NOP.
    // The two arguments remain on stack, then OP_1 is pushed.
    CScript script;
    script << CScriptNum(0) << std::vector<unsigned char>{0x01} << OP_REFINPUTASSETFIELD << OP_1;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(RunRefInputScript(tx, refOutputs, script, NO_REFINPUT_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(result.size(), 3U); // [nRef, selector, OP_1]
}

BOOST_AUTO_TEST_CASE(op_refinputassetfield_disabled_discourage)
{
    std::vector<CTxOut> refOutputs = BuildAssetRefOutputsForNetwork(CBaseChainParams::TESTNET);
    CMutableTransaction mtx = BuildV3TestTx(1, 1, refOutputs.size());
    CTransaction tx(mtx);

    CScript script;
    script << CScriptNum(0) << std::vector<unsigned char>{0x01} << OP_REFINPUTASSETFIELD << OP_1;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunRefInputScript(tx, refOutputs, script, NO_REFINPUT_FLAGS_DISCOURAGE, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

// =============================================================================
// NIP-017: Integration / cross-opcode tests
// =============================================================================

BOOST_AUTO_TEST_CASE(refinput_cross_opcode_count_and_field)
{
    // Verify that OP_REFINPUTCOUNT and OP_REFINPUTFIELD work together:
    // read count, verify it is 2, then read value of ref 0 and ref 1
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 2);
    CTransaction tx(mtx);

    CAmount val0 = 500000000;
    CAmount val1 = 1000000000;
    std::vector<CTxOut> refOutputs;
    {
        CTxOut out;
        out.nValue = val0;
        out.scriptPubKey = CScript() << OP_TRUE;
        refOutputs.push_back(out);
    }
    {
        CTxOut out;
        out.nValue = val1;
        out.scriptPubKey = CScript() << OP_TRUE;
        refOutputs.push_back(out);
    }

    CScript script;
    // Verify count is 2
    script << OP_REFINPUTCOUNT << CScriptNum(2) << OP_NUMEQUALVERIFY;
    // Read value of ref 0
    script << CScriptNum(0) << std::vector<unsigned char>{0x01} << OP_REFINPUTFIELD
           << EncodeLE8(val0) << OP_EQUALVERIFY;
    // Read value of ref 1
    script << CScriptNum(1) << std::vector<unsigned char>{0x01} << OP_REFINPUTFIELD
           << EncodeLE8(val1) << OP_EQUALVERIFY;
    script << OP_1;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result));
}

BOOST_AUTO_TEST_CASE(refinput_authscript_covenant_pattern)
{
    // Pattern: verify that a referenced UTXO carries a specific AuthScript commitment.
    // This enables covenant patterns where a script checks that a config UTXO
    // is an AuthScript with a known program hash.
    CMutableTransaction mtx = BuildV3TestTx(1, 1, 1);
    CTransaction tx(mtx);

    std::vector<unsigned char> expectedCommitment(32, 0x55);

    std::vector<CTxOut> refOutputs;
    refOutputs.push_back(BuildAuthScriptRefOutput(expectedCommitment));

    CScript script;
    script << CScriptNum(0) << std::vector<unsigned char>{0x02} << OP_REFINPUTFIELD
           << expectedCommitment << OP_EQUALVERIFY
           << CScriptNum(0) << std::vector<unsigned char>{0x01} << OP_REFINPUTFIELD
           << EncodeLE8(1000) << OP_EQUALVERIFY
           << OP_1;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunRefInputScript(tx, refOutputs, script, REFINPUT_FLAGS, result));
}

BOOST_AUTO_TEST_SUITE_END()
