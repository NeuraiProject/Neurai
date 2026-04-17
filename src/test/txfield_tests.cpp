// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "primitives/transaction.h"
#include "test/test_neurai.h"

#include <vector>
#include <cstring>

#include <boost/test/unit_test.hpp>

// Verification flags
static constexpr script_verify_flags TXFIELD_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TXFIELD;
static constexpr script_verify_flags TXFIELD_FLAGS_DISCOURAGE =
    TXFIELD_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
static constexpr script_verify_flags NO_TXFIELD_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
static constexpr script_verify_flags NO_TXFIELD_DISCOURAGE =
    NO_TXFIELD_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
static constexpr script_verify_flags TXFIELD_SPLIT_FLAGS =
    TXFIELD_FLAGS | SCRIPT_VERIFY_SPLIT;

// Selector constants (must match interpreter.cpp)
static const unsigned char TXFIELD_SPENT_VALUE          = 0x01;
static const unsigned char TXFIELD_SPENT_AUTHCOMMITMENT = 0x02;
static const unsigned char TXFIELD_SPENT_FULLSCRIPT     = 0x03;

namespace {

// Build a minimal transaction for testing
CMutableTransaction BuildTx(CAmount inputAmount = 5000)
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
    vout.nValue = inputAmount - 100;
    vout.scriptPubKey = CScript() << OP_1;
    mtx.vout.push_back(vout);
    return mtx;
}

// Build a 34-byte AuthScript scriptPubKey: OP_1 <0x20> <32-byte commitment>
CScript BuildAuthScriptSPK(const std::vector<unsigned char>& commitment32)
{
    assert(commitment32.size() == 32);
    CScript spk;
    // OP_1 (0x51) + push 32 (0x20) + 32 bytes
    std::vector<unsigned char> raw;
    raw.push_back(0x51);  // OP_1
    raw.push_back(0x20);  // push 32 bytes
    raw.insert(raw.end(), commitment32.begin(), commitment32.end());
    spk = CScript(raw.begin(), raw.end());
    return spk;
}

// Build an AuthScript SPK with an asset suffix appended
CScript BuildAuthScriptSPKWithAssetSuffix(const std::vector<unsigned char>& commitment32,
                                           const std::vector<unsigned char>& suffix)
{
    CScript base = BuildAuthScriptSPK(commitment32);
    std::vector<unsigned char> raw(base.begin(), base.end());
    raw.insert(raw.end(), suffix.begin(), suffix.end());
    return CScript(raw.begin(), raw.end());
}

// Run a script using OP_TXFIELD with the given spentScriptPubKey.
// The script receives <selector> on the stack (pushed by the script itself).
bool RunTxFieldScript(const CScript& scriptPubKey,
                      const CScript& spentSPK,
                      CAmount spentAmount,
                      script_verify_flags flags,
                      std::vector<std::vector<unsigned char>>& resultStack,
                      ScriptError* errOut = nullptr)
{
    CMutableTransaction mtx = BuildTx(spentAmount + 100);
    CTransaction tx(mtx);

    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, spentAmount, txdata, spentSPK);

    ScriptError serror = SCRIPT_ERR_OK;
    std::vector<std::vector<unsigned char>> stack;
    bool ok = EvalScript(stack, scriptPubKey, flags, checker, SIGVERSION_BASE, &serror);

    if (errOut) *errOut = serror;
    resultStack = stack;
    return ok;
}

// Call GetTxField() directly on a checker
bool DirectGetTxField(unsigned char selector,
                      const CScript& spentSPK,
                      CAmount spentAmount,
                      std::vector<unsigned char>& result)
{
    CMutableTransaction mtx = BuildTx(spentAmount + 100);
    CTransaction tx(mtx);
    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, spentAmount, txdata, spentSPK);
    return checker.GetTxField(selector, result);
}

// Call GetTxField() directly on a checker built without PrecomputedTransactionData.
bool DirectGetTxFieldNoTxData(unsigned char selector,
                              const CScript& spentSPK,
                              CAmount spentAmount,
                              std::vector<unsigned char>& result)
{
    CMutableTransaction mtx = BuildTx(spentAmount + 100);
    CTransaction tx(mtx);
    TransactionSignatureChecker checker(&tx, 0, spentAmount, spentSPK);
    return checker.GetTxField(selector, result);
}

// Call GetTxField() with no spentScriptPubKey (only amount)
bool DirectGetTxFieldNoSPK(unsigned char selector,
                            CAmount spentAmount,
                            std::vector<unsigned char>& result)
{
    CMutableTransaction mtx = BuildTx(spentAmount + 100);
    CTransaction tx(mtx);
    TransactionSignatureChecker checker(&tx, 0, spentAmount);
    return checker.GetTxField(selector, result);
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(txfield_tests, BasicTestingSetup)

// ============================================================================
// 1. Opcode disabled / NOP behavior
// ============================================================================

BOOST_AUTO_TEST_CASE(txfield_disabled_treated_as_nop)
{
    // Without SCRIPT_VERIFY_TXFIELD, OP_TXFIELD acts as NOP7 — selector stays on stack.
    // Script: <0x01> OP_TXFIELD OP_DROP OP_1
    // If NOP: stack after TXFIELD = [0x01], DROP removes it, OP_1 → success.
    CScript script;
    script << std::vector<unsigned char>{0x01} << OP_TXFIELD << OP_DROP << OP_1;

    CScript dummySPK = CScript() << OP_1;
    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunTxFieldScript(script, dummySPK, 5000, NO_TXFIELD_FLAGS, result, &err);
    BOOST_CHECK(ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(txfield_disabled_discourage_fails)
{
    CScript script;
    script << std::vector<unsigned char>{0x01} << OP_TXFIELD;

    CScript dummySPK = CScript() << OP_1;
    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunTxFieldScript(script, dummySPK, 5000, NO_TXFIELD_DISCOURAGE, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

// ============================================================================
// 2. Stack underflow
// ============================================================================

BOOST_AUTO_TEST_CASE(txfield_empty_stack_fails)
{
    CScript script;
    script << OP_TXFIELD;

    CScript dummySPK = CScript() << OP_1;
    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunTxFieldScript(script, dummySPK, 5000, TXFIELD_FLAGS, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

// ============================================================================
// 3. Selector size validation
// ============================================================================

BOOST_AUTO_TEST_CASE(txfield_selector_zero_fails)
{
    // Selector 0x00 is invalid
    CScript script;
    script << std::vector<unsigned char>{0x00} << OP_TXFIELD;

    CScript dummySPK = BuildAuthScriptSPK(std::vector<unsigned char>(32, 0xAB));
    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunTxFieldScript(script, dummySPK, 5000, TXFIELD_FLAGS, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TXFIELD);
}

BOOST_AUTO_TEST_CASE(txfield_selector_too_large_fails)
{
    // Selector must be exactly 1 byte; 2 bytes → fail
    CScript script;
    script << std::vector<unsigned char>{0x01, 0x00} << OP_TXFIELD;

    CScript dummySPK = BuildAuthScriptSPK(std::vector<unsigned char>(32, 0xAB));
    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunTxFieldScript(script, dummySPK, 5000, TXFIELD_FLAGS, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TXFIELD);
}

BOOST_AUTO_TEST_CASE(txfield_unknown_selector_fails)
{
    // Selector 0x04 is reserved and unknown → fail
    CScript script;
    script << std::vector<unsigned char>{0x04} << OP_TXFIELD;

    CScript dummySPK = BuildAuthScriptSPK(std::vector<unsigned char>(32, 0xAB));
    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunTxFieldScript(script, dummySPK, 5000, TXFIELD_FLAGS, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_TXFIELD);
}

// ============================================================================
// 4. TXFIELD_SPENT_VALUE (0x01)
// ============================================================================

BOOST_AUTO_TEST_CASE(txfield_spent_value_returns_8_bytes)
{
    CAmount amount = 123456789;
    CScript dummySPK = CScript() << OP_1;
    std::vector<unsigned char> result;
    BOOST_CHECK(DirectGetTxFieldNoSPK(TXFIELD_SPENT_VALUE, amount, result));
    BOOST_CHECK_EQUAL(result.size(), 8U);
}

BOOST_AUTO_TEST_CASE(txfield_spent_value_correct_little_endian)
{
    // 1.0 XNA = 100,000,000 satoshis = 0x05F5E100
    CAmount amount = 100000000;
    CScript dummySPK = CScript() << OP_1;
    std::vector<unsigned char> result;
    BOOST_CHECK(DirectGetTxFieldNoSPK(TXFIELD_SPENT_VALUE, amount, result));
    BOOST_REQUIRE_EQUAL(result.size(), 8U);

    int64_t decoded;
    memcpy(&decoded, result.data(), 8);
    BOOST_CHECK_EQUAL(decoded, (int64_t)amount);
}

BOOST_AUTO_TEST_CASE(txfield_spent_value_available_without_spk)
{
    // Selector 0x01 only needs 'amount', not scriptPubKey → works even without spentSPK
    std::vector<unsigned char> result;
    BOOST_CHECK(DirectGetTxFieldNoSPK(TXFIELD_SPENT_VALUE, 9999, result));
    BOOST_CHECK_EQUAL(result.size(), 8U);
}

BOOST_AUTO_TEST_CASE(txfield_spent_value_via_script)
{
    // Run OP_TXFIELD(0x01) via EvalScript and verify size on stack
    CScript script;
    script << std::vector<unsigned char>{TXFIELD_SPENT_VALUE} << OP_TXFIELD << OP_SIZE;
    // Stack after: [8-byte-value, 8]

    CScript dummySPK = CScript() << OP_1;
    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunTxFieldScript(script, dummySPK, 5000, TXFIELD_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 2U);
    BOOST_CHECK_EQUAL(result[1].size(), 1U);  // OP_SIZE result = CScriptNum(8)
    BOOST_CHECK_EQUAL(result[1][0], 8);       // 8 bytes
}

// ============================================================================
// 5. TXFIELD_SPENT_AUTHCOMMITMENT (0x02)
// ============================================================================

BOOST_AUTO_TEST_CASE(txfield_spent_commitment_returns_32_bytes)
{
    std::vector<unsigned char> commitment(32, 0xCC);
    CScript spk = BuildAuthScriptSPK(commitment);
    std::vector<unsigned char> result;
    BOOST_CHECK(DirectGetTxField(TXFIELD_SPENT_AUTHCOMMITMENT, spk, 1000, result));
    BOOST_CHECK_EQUAL(result.size(), 32U);
}

BOOST_AUTO_TEST_CASE(txfield_spent_commitment_extracts_correct_bytes)
{
    // Commitment is bytes 2..33 of the scriptPubKey
    std::vector<unsigned char> commitment(32);
    for (int i = 0; i < 32; i++) commitment[i] = (unsigned char)(i + 1);

    CScript spk = BuildAuthScriptSPK(commitment);
    std::vector<unsigned char> result;
    BOOST_CHECK(DirectGetTxField(TXFIELD_SPENT_AUTHCOMMITMENT, spk, 1000, result));
    BOOST_CHECK(result == commitment);
}

BOOST_AUTO_TEST_CASE(txfield_spent_commitment_fails_if_no_spk)
{
    // Without spentScriptPubKey, selector 0x02 must fail
    std::vector<unsigned char> result;
    BOOST_CHECK(!DirectGetTxFieldNoSPK(TXFIELD_SPENT_AUTHCOMMITMENT, 1000, result));
}

BOOST_AUTO_TEST_CASE(txfield_spent_commitment_works_without_txdata)
{
    // RPC/signing paths use the constructor without PrecomputedTransactionData.
    std::vector<unsigned char> commitment(32, 0x5A);
    CScript spk = BuildAuthScriptSPK(commitment);
    std::vector<unsigned char> result;
    BOOST_CHECK(DirectGetTxFieldNoTxData(TXFIELD_SPENT_AUTHCOMMITMENT, spk, 1000, result));
    BOOST_CHECK(result == commitment);
}

BOOST_AUTO_TEST_CASE(txfield_spent_commitment_fails_if_not_authscript)
{
    // P2PKH scriptPubKey — does not start with OP_1 0x20 → fail
    CScript p2pkh = CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0xAA) << OP_EQUALVERIFY << OP_CHECKSIG;
    std::vector<unsigned char> result;
    BOOST_CHECK(!DirectGetTxField(TXFIELD_SPENT_AUTHCOMMITMENT, p2pkh, 1000, result));
}

BOOST_AUTO_TEST_CASE(txfield_spent_commitment_wrong_witness_version_fails)
{
    // OP_2 (0x52) instead of OP_1 (0x51) → fails because data[0] != 0x51
    std::vector<unsigned char> raw(34);
    raw[0] = 0x52;  // OP_2 — wrong witness version
    raw[1] = 0x20;  // push 32 bytes
    std::fill(raw.begin() + 2, raw.end(), 0xBB);
    CScript spk(raw.begin(), raw.end());

    std::vector<unsigned char> result;
    BOOST_CHECK(!DirectGetTxField(TXFIELD_SPENT_AUTHCOMMITMENT, spk, 1000, result));
}

BOOST_AUTO_TEST_CASE(txfield_spent_commitment_with_asset_suffix)
{
    // scriptPubKey = OP_1 <0x20> <32-byte-commitment> <asset_suffix>
    // Must still extract the 32-byte commitment correctly
    std::vector<unsigned char> commitment(32, 0xDD);
    std::vector<unsigned char> suffix = {0xC0, 0x04, 'C', 'A', 'T', 'S', 0x01, 0x75}; // OP_XNA_ASSET "CATS" 1 OP_DROP
    CScript spk = BuildAuthScriptSPKWithAssetSuffix(commitment, suffix);

    std::vector<unsigned char> result;
    BOOST_CHECK(DirectGetTxField(TXFIELD_SPENT_AUTHCOMMITMENT, spk, 1000, result));
    BOOST_CHECK(result == commitment);
}

BOOST_AUTO_TEST_CASE(txfield_spent_commitment_too_short_fails)
{
    // scriptPubKey shorter than 34 bytes → fail
    std::vector<unsigned char> raw = {0x51, 0x20, 0xAA}; // only 3 bytes
    CScript spk(raw.begin(), raw.end());

    std::vector<unsigned char> result;
    BOOST_CHECK(!DirectGetTxField(TXFIELD_SPENT_AUTHCOMMITMENT, spk, 1000, result));
}

// ============================================================================
// 6. TXFIELD_SPENT_FULLSCRIPT (0x03)
// ============================================================================

BOOST_AUTO_TEST_CASE(txfield_spent_fullscript_returns_raw_bytes)
{
    std::vector<unsigned char> commitment(32, 0xEE);
    CScript spk = BuildAuthScriptSPK(commitment);

    std::vector<unsigned char> result;
    BOOST_CHECK(DirectGetTxField(TXFIELD_SPENT_FULLSCRIPT, spk, 1000, result));
    BOOST_CHECK_EQUAL(result.size(), 34U);
    // First byte must be OP_1
    BOOST_CHECK_EQUAL(result[0], 0x51);
    // Second byte must be 0x20 (push 32)
    BOOST_CHECK_EQUAL(result[1], 0x20);
    // Bytes [2..33] are the commitment
    BOOST_CHECK(std::vector<unsigned char>(result.begin() + 2, result.end()) == commitment);
}

BOOST_AUTO_TEST_CASE(txfield_spent_fullscript_fails_if_no_spk)
{
    std::vector<unsigned char> result;
    BOOST_CHECK(!DirectGetTxFieldNoSPK(TXFIELD_SPENT_FULLSCRIPT, 1000, result));
}

BOOST_AUTO_TEST_CASE(txfield_spent_fullscript_works_without_txdata)
{
    std::vector<unsigned char> commitment(32, 0x6B);
    CScript spk = BuildAuthScriptSPK(commitment);
    std::vector<unsigned char> result;
    BOOST_CHECK(DirectGetTxFieldNoTxData(TXFIELD_SPENT_FULLSCRIPT, spk, 1000, result));
    BOOST_CHECK(std::vector<unsigned char>(spk.begin(), spk.end()) == result);
}

BOOST_AUTO_TEST_CASE(txfield_spent_fullscript_too_large_returns_bytes)
{
    // NIP-018: the checker no longer enforces MAX_SCRIPT_ELEMENT_SIZE; that
    // belongs to the EvalScript caller (OP_TXFIELD), which raises
    // SCRIPT_ERR_TXFIELD based on EffectiveMaxScriptElementSize(flags).
    // The checker itself is a pure byte-returner and must succeed here.
    std::vector<unsigned char> raw(521, 0x00);
    CScript oversized(raw.begin(), raw.end());

    std::vector<unsigned char> result;
    BOOST_CHECK(DirectGetTxField(TXFIELD_SPENT_FULLSCRIPT, oversized, 1000, result));
    BOOST_CHECK_EQUAL(result.size(), 521u);
}

// ============================================================================
// 7. Integration: OP_TXFIELD via EvalScript — covenant self-reference
// ============================================================================

BOOST_AUTO_TEST_CASE(txfield_covenant_reads_own_commitment)
{
    // Simulate a DEX covenant verifying its own C_S from the spent UTXO.
    // Script: <0x02> OP_TXFIELD <C_S> OP_EQUAL
    // The commitment embedded in the script must match what OP_TXFIELD returns.
    std::vector<unsigned char> commitment(32);
    for (int i = 0; i < 32; i++) commitment[i] = (unsigned char)(i * 7 + 3);

    CScript spk = BuildAuthScriptSPK(commitment);

    CScript script;
    script << std::vector<unsigned char>{TXFIELD_SPENT_AUTHCOMMITMENT}
           << OP_TXFIELD
           << commitment
           << OP_EQUAL;

    std::vector<std::vector<unsigned char>> result;
    bool ok = RunTxFieldScript(script, spk, 5000, TXFIELD_FLAGS, result);
    BOOST_CHECK(ok);
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(!result[0].empty());
    BOOST_CHECK(result[0][0] == 1);  // OP_EQUAL returned true
}

BOOST_AUTO_TEST_CASE(txfield_covenant_wrong_commitment_fails)
{
    // Script has a hardcoded commitment that does NOT match the spent UTXO → OP_EQUAL fails
    std::vector<unsigned char> commitment(32, 0xAA);
    std::vector<unsigned char> wrongCommitment(32, 0xBB);

    CScript spk = BuildAuthScriptSPK(commitment);

    CScript script;
    script << std::vector<unsigned char>{TXFIELD_SPENT_AUTHCOMMITMENT}
           << OP_TXFIELD
           << wrongCommitment
           << OP_EQUALVERIFY  // fails here
           << OP_1;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunTxFieldScript(script, spk, 5000, TXFIELD_FLAGS, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_EQUALVERIFY);
}

BOOST_AUTO_TEST_CASE(txfield_verifyscript_with_rpc_style_checker)
{
    // Full VerifyScript path using the constructor without txdata, matching RPC signing flows.
    std::vector<unsigned char> commitment(32, 0x44);
    CScript spentSPK = BuildAuthScriptSPK(commitment);

    CScript scriptPubKey;
    scriptPubKey << std::vector<unsigned char>{TXFIELD_SPENT_AUTHCOMMITMENT}
                 << OP_TXFIELD
                 << commitment
                 << OP_EQUAL;

    CMutableTransaction mtx = BuildTx(5100);
    CTransaction tx(mtx);
    CScriptWitness witness;
    ScriptError err = SCRIPT_ERR_OK;

    BOOST_CHECK(VerifyScript(CScript(), scriptPubKey, &witness, TXFIELD_FLAGS,
                             TransactionSignatureChecker(&tx, 0, 5000, spentSPK), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

// ============================================================================
// 8. Integration: OP_TXFIELD + OP_SPLIT — extract commitment from full script
// ============================================================================

BOOST_AUTO_TEST_CASE(txfield_split_extract_commitment_from_fullscript)
{
    // Demonstrate that selector 0x02 == selector 0x03 + OP_SPLIT extraction.
    // Script: <0x03> OP_TXFIELD <2> OP_SPLIT OP_NIP <32> OP_SPLIT OP_DROP
    // Should produce same result as: <0x02> OP_TXFIELD
    std::vector<unsigned char> commitment(32);
    for (int i = 0; i < 32; i++) commitment[i] = (unsigned char)(i + 0x10);

    CScript spk = BuildAuthScriptSPK(commitment);

    CScript scriptViaFullScript;
    scriptViaFullScript << std::vector<unsigned char>{TXFIELD_SPENT_FULLSCRIPT}
                        << OP_TXFIELD
                        << CScriptNum(2) << OP_SPLIT << OP_NIP  // discard 2-byte prefix
                        << CScriptNum(32) << OP_SPLIT << OP_DROP; // take 32 bytes, discard rest

    std::vector<std::vector<unsigned char>> result1;
    bool ok1 = RunTxFieldScript(scriptViaFullScript, spk, 1000, TXFIELD_SPLIT_FLAGS, result1);
    BOOST_CHECK(ok1);
    BOOST_REQUIRE_EQUAL(result1.size(), 1U);
    BOOST_CHECK(result1[0] == commitment);

    // Verify it matches direct selector 0x02
    std::vector<unsigned char> directResult;
    BOOST_CHECK(DirectGetTxField(TXFIELD_SPENT_AUTHCOMMITMENT, spk, 1000, directResult));
    BOOST_CHECK(result1[0] == directResult);
}

BOOST_AUTO_TEST_SUITE_END()
