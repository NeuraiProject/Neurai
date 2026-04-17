// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "primitives/transaction.h"
#include "test/test_neurai.h"

#include <vector>

#include <boost/test/unit_test.hpp>

static constexpr script_verify_flags OUTPUTSCRIPT_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_OUTPUTSCRIPT;
static constexpr script_verify_flags OUTPUTSCRIPT_FLAGS_DISCOURAGE =
    OUTPUTSCRIPT_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
static constexpr script_verify_flags NO_OUTPUTSCRIPT_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
static constexpr script_verify_flags NO_OUTPUTSCRIPT_FLAGS_DISCOURAGE =
    NO_OUTPUTSCRIPT_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
// Combined flags for self-reference tests (OP_TXFIELD + OP_OUTPUTSCRIPT)
static constexpr script_verify_flags SELFREF_FLAGS =
    OUTPUTSCRIPT_FLAGS | SCRIPT_VERIFY_TXFIELD;

namespace {

// Build a tx with outputs using different script types:
//   output 0: P2PKH (25 bytes)
//   output 1: P2SH  (23 bytes)
//   output 2: P2WPKH (22 bytes) — OP_0 + 20-byte push
//   output 3: AuthScript / witness v1 (34 bytes) — OP_1 + 32-byte push
//   output 4: empty scriptPubKey
CMutableTransaction BuildTx()
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 0;

    CTxIn vin;
    vin.prevout.hash = uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    vin.prevout.n = 0;
    tx.vin.push_back(vin);

    // Output 0: P2PKH — OP_DUP OP_HASH160 <20b> OP_EQUALVERIFY OP_CHECKSIG
    {
        CTxOut out;
        out.nValue = 1000;
        std::vector<unsigned char> hash20(20, 0x11);
        out.scriptPubKey = CScript() << OP_DUP << OP_HASH160 << hash20 << OP_EQUALVERIFY << OP_CHECKSIG;
        tx.vout.push_back(out);
    }

    // Output 1: P2SH — OP_HASH160 <20b> OP_EQUAL
    {
        CTxOut out;
        out.nValue = 2000;
        std::vector<unsigned char> hash20(20, 0x22);
        out.scriptPubKey = CScript() << OP_HASH160 << hash20 << OP_EQUAL;
        tx.vout.push_back(out);
    }

    // Output 2: P2WPKH — OP_0 <20b>
    {
        CTxOut out;
        out.nValue = 3000;
        std::vector<unsigned char> hash20(20, 0x33);
        out.scriptPubKey = CScript() << OP_0 << hash20;
        tx.vout.push_back(out);
    }

    // Output 3: AuthScript / witness v1 — OP_1 <32b>
    {
        CTxOut out;
        out.nValue = 4000;
        std::vector<unsigned char> commitment(32, 0x44);
        out.scriptPubKey = CScript() << OP_1 << commitment;
        tx.vout.push_back(out);
    }

    // Output 4: empty scriptPubKey
    {
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey = CScript();
        tx.vout.push_back(out);
    }

    return tx;
}

bool RunScript(const CTransaction& tx, const CScript& script, script_verify_flags flags,
               std::vector<std::vector<unsigned char>>& resultStack, ScriptError* errOut = nullptr)
{
    TransactionSignatureChecker checker(&tx, 0, 0);
    ScriptError serror = SCRIPT_ERR_OK;
    std::vector<std::vector<unsigned char>> stack;
    bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    if (errOut) *errOut = serror;
    resultStack = stack;
    return ok;
}

// Run a script with a spentScriptPubKey available (needed for OP_TXFIELD)
bool RunScriptWithSpentSPK(const CTransaction& tx, const CScript& script,
                           const CScript& spentSPK, CAmount spentAmount,
                           script_verify_flags flags,
                           std::vector<std::vector<unsigned char>>& resultStack,
                           ScriptError* errOut = nullptr)
{
    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, spentAmount, txdata, spentSPK);
    ScriptError serror = SCRIPT_ERR_OK;
    std::vector<std::vector<unsigned char>> stack;
    bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    if (errOut) *errOut = serror;
    resultStack = stack;
    return ok;
}

bool DirectGetOutputScript(const CTransaction& tx, unsigned int nOut, std::vector<unsigned char>& result)
{
    TransactionSignatureChecker checker(&tx, 0, 0);
    return checker.GetOutputScript(nOut, result);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(outputscript_tests, BasicTestingSetup)

// --- Disabled behavior ---

BOOST_AUTO_TEST_CASE(outputscript_disabled_treated_as_nop)
{
    CTransaction tx(BuildTx());
    CScript script;
    script << CScriptNum(0) << OP_OUTPUTSCRIPT << OP_DROP << OP_1;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunScript(tx, script, NO_OUTPUTSCRIPT_FLAGS, result, &err);
    BOOST_CHECK(ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(outputscript_disabled_discourage_nops_fails)
{
    CTransaction tx(BuildTx());
    CScript script;
    script << CScriptNum(0) << OP_OUTPUTSCRIPT;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunScript(tx, script, NO_OUTPUTSCRIPT_FLAGS_DISCOURAGE, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

// --- Error cases ---

BOOST_AUTO_TEST_CASE(outputscript_empty_stack_fails)
{
    CTransaction tx(BuildTx());
    CScript script;
    script << OP_OUTPUTSCRIPT;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunScript(tx, script, OUTPUTSCRIPT_FLAGS, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(outputscript_negative_index_fails)
{
    CTransaction tx(BuildTx());
    CScript script;
    script << CScriptNum(-1) << OP_OUTPUTSCRIPT;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunScript(tx, script, OUTPUTSCRIPT_FLAGS, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTSCRIPT);
}

BOOST_AUTO_TEST_CASE(outputscript_out_of_bounds_index_fails)
{
    CTransaction tx(BuildTx());
    CScript script;
    script << CScriptNum(5) << OP_OUTPUTSCRIPT;  // tx has 5 outputs (0..4)

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunScript(tx, script, OUTPUTSCRIPT_FLAGS, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTSCRIPT);
}

// --- Direct checker tests: exact bytes for each output type ---

BOOST_AUTO_TEST_CASE(outputscript_p2pkh_returns_exact_bytes)
{
    CTransaction tx(BuildTx());
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectGetOutputScript(tx, 0, result));

    // P2PKH = OP_DUP OP_HASH160 OP_PUSHBYTES_20 <20b> OP_EQUALVERIFY OP_CHECKSIG = 25 bytes
    std::vector<unsigned char> expected(tx.vout[0].scriptPubKey.begin(),
                                        tx.vout[0].scriptPubKey.end());
    BOOST_CHECK_EQUAL(result.size(), 25U);
    BOOST_CHECK(result == expected);
}

BOOST_AUTO_TEST_CASE(outputscript_p2sh_returns_exact_bytes)
{
    CTransaction tx(BuildTx());
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectGetOutputScript(tx, 1, result));

    // P2SH = OP_HASH160 OP_PUSHBYTES_20 <20b> OP_EQUAL = 23 bytes
    std::vector<unsigned char> expected(tx.vout[1].scriptPubKey.begin(),
                                        tx.vout[1].scriptPubKey.end());
    BOOST_CHECK_EQUAL(result.size(), 23U);
    BOOST_CHECK(result == expected);
}

BOOST_AUTO_TEST_CASE(outputscript_p2wpkh_returns_exact_bytes)
{
    CTransaction tx(BuildTx());
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectGetOutputScript(tx, 2, result));

    // P2WPKH = OP_0 OP_PUSHBYTES_20 <20b> = 22 bytes
    std::vector<unsigned char> expected(tx.vout[2].scriptPubKey.begin(),
                                        tx.vout[2].scriptPubKey.end());
    BOOST_CHECK_EQUAL(result.size(), 22U);
    BOOST_CHECK(result == expected);
}

BOOST_AUTO_TEST_CASE(outputscript_authscript_returns_exact_bytes)
{
    CTransaction tx(BuildTx());
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectGetOutputScript(tx, 3, result));

    // AuthScript = OP_1 OP_PUSHBYTES_32 <32b> = 34 bytes
    std::vector<unsigned char> expected(tx.vout[3].scriptPubKey.begin(),
                                        tx.vout[3].scriptPubKey.end());
    BOOST_CHECK_EQUAL(result.size(), 34U);
    BOOST_CHECK(result == expected);
}

BOOST_AUTO_TEST_CASE(outputscript_empty_script_returns_empty)
{
    CTransaction tx(BuildTx());
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectGetOutputScript(tx, 4, result));
    BOOST_CHECK_EQUAL(result.size(), 0U);
}

// --- Script too large ---

BOOST_AUTO_TEST_CASE(outputscript_too_large_script_returns_bytes)
{
    // NIP-018: the checker no longer enforces MAX_SCRIPT_ELEMENT_SIZE; that
    // belongs to the EvalScript caller (OP_OUTPUTSCRIPT), which raises
    // SCRIPT_ERR_OUTPUTSCRIPT based on EffectiveMaxScriptElementSize(flags).
    // The checker itself is a pure byte-returner and must succeed here.
    CMutableTransaction mtx = BuildTx();
    std::vector<unsigned char> largeData(521, 0xAA);
    mtx.vout[0].scriptPubKey = CScript(largeData.begin(), largeData.end());
    CTransaction tx(mtx);

    std::vector<unsigned char> result;
    BOOST_CHECK(DirectGetOutputScript(tx, 0, result));
    BOOST_CHECK_EQUAL(result.size(), 521u);
}

BOOST_AUTO_TEST_CASE(outputscript_max_size_script_ok)
{
    CMutableTransaction mtx = BuildTx();
    // Exactly 520 bytes should be fine
    std::vector<unsigned char> maxData(520, 0xBB);
    mtx.vout[0].scriptPubKey = CScript(maxData.begin(), maxData.end());
    CTransaction tx(mtx);

    std::vector<unsigned char> result;
    BOOST_CHECK(DirectGetOutputScript(tx, 0, result));
    BOOST_CHECK_EQUAL(result.size(), 520U);
}

// --- EvalScript integration ---

BOOST_AUTO_TEST_CASE(outputscript_evalscript_pushes_script_bytes)
{
    CTransaction tx(BuildTx());
    CScript script;
    script << CScriptNum(0) << OP_OUTPUTSCRIPT;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, OUTPUTSCRIPT_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);

    std::vector<unsigned char> expected(tx.vout[0].scriptPubKey.begin(),
                                        tx.vout[0].scriptPubKey.end());
    BOOST_CHECK(result[0] == expected);
}

BOOST_AUTO_TEST_CASE(outputscript_pops_index_pushes_result)
{
    // Stack has 3 elements before, should have 3 after (pop index, push result)
    CTransaction tx(BuildTx());
    CScript script;
    script << OP_1 << OP_2 << CScriptNum(1) << OP_OUTPUTSCRIPT;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, OUTPUTSCRIPT_FLAGS, result));
    BOOST_CHECK_EQUAL(result.size(), 3U);
}

// --- OP_EQUAL comparison ---

BOOST_AUTO_TEST_CASE(outputscript_result_comparable_with_equal)
{
    CTransaction tx(BuildTx());
    std::vector<unsigned char> expectedScript(tx.vout[0].scriptPubKey.begin(),
                                               tx.vout[0].scriptPubKey.end());

    CScript script;
    script << CScriptNum(0) << OP_OUTPUTSCRIPT << expectedScript << OP_EQUAL;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, OUTPUTSCRIPT_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    // OP_EQUAL should push true (non-empty, non-zero)
    BOOST_CHECK(result[0] == std::vector<unsigned char>{1});
}

BOOST_AUTO_TEST_CASE(outputscript_comparison_wrong_script_returns_false)
{
    CTransaction tx(BuildTx());
    // Use script of output 1 but compare against output 0
    std::vector<unsigned char> wrongScript(tx.vout[1].scriptPubKey.begin(),
                                            tx.vout[1].scriptPubKey.end());

    CScript script;
    script << CScriptNum(0) << OP_OUTPUTSCRIPT << wrongScript << OP_EQUAL;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, OUTPUTSCRIPT_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    // OP_EQUAL should push false (empty)
    BOOST_CHECK(result[0] == std::vector<unsigned char>{});
}

// --- VerifyScript integration ---

BOOST_AUTO_TEST_CASE(outputscript_works_via_verifyscript)
{
    CMutableTransaction mtx = BuildTx();
    CTransaction tx(mtx);

    std::vector<unsigned char> expectedScript(tx.vout[0].scriptPubKey.begin(),
                                               tx.vout[0].scriptPubKey.end());

    CScript scriptSig;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(0) << OP_OUTPUTSCRIPT << expectedScript << OP_EQUAL;

    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(VerifyScript(scriptSig, scriptPubKey, nullptr, OUTPUTSCRIPT_FLAGS,
                             TransactionSignatureChecker(&tx, 0, 0), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

// --- ScriptNum validation ---

BOOST_AUTO_TEST_CASE(outputscript_selector_must_be_scriptnum)
{
    CTransaction tx(BuildTx());
    CScript script;
    // Non-minimal 2-byte encoding for the value 1.  Under MINIMALDATA,
    // CScriptNum(stacktop, fRequireMinimal=true) throws.  Without MINIMALDATA
    // the non-minimal encoding is silently accepted, so this test has to run
    // under MINIMALDATA specifically to exercise the selector validation.
    script << std::vector<unsigned char>{0x01, 0x00} << OP_OUTPUTSCRIPT;

    const script_verify_flags minimalFlags = OUTPUTSCRIPT_FLAGS | SCRIPT_VERIFY_MINIMALDATA;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(!RunScript(tx, script, minimalFlags, result, &err));
    BOOST_CHECK(err != SCRIPT_ERR_OK);
}

// --- Self-reference pattern (covenant auto-referencia) ---
// These tests execute the actual script pattern from the NIP:
//   0x03 OP_TXFIELD   → scriptPubKey of the spent UTXO (input)
//   0 OP_OUTPUTSCRIPT → scriptPubKey of output 0
//   OP_EQUAL          → are they the same?

BOOST_AUTO_TEST_CASE(outputscript_self_reference_same_script)
{
    // The spent UTXO and output 0 share the same scriptPubKey.
    // The covenant script: 0x03 OP_TXFIELD 0 OP_OUTPUTSCRIPT OP_EQUAL
    // should evaluate to true (1).
    std::vector<unsigned char> hash20(20, 0x55);
    CScript covenantScript = CScript() << OP_DUP << OP_HASH160 << hash20 << OP_EQUALVERIFY << OP_CHECKSIG;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    CTxIn vin;
    vin.prevout.hash = uint256S("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    vin.prevout.n = 0;
    mtx.vin.push_back(vin);

    CTxOut out0;
    out0.nValue = 5000;
    out0.scriptPubKey = covenantScript; // same script as spent UTXO
    mtx.vout.push_back(out0);

    CTransaction tx(mtx);

    // The self-reference check script:
    //   push 0x03 → OP_TXFIELD → push 0 → OP_OUTPUTSCRIPT → OP_EQUAL
    CScript testScript;
    testScript << std::vector<unsigned char>{0x03} << OP_TXFIELD
               << CScriptNum(0) << OP_OUTPUTSCRIPT
               << OP_EQUAL;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunScriptWithSpentSPK(tx, testScript, covenantScript, 5000,
                                    SELFREF_FLAGS, result, &err);
    BOOST_CHECK(ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == std::vector<unsigned char>{1}); // OP_EQUAL → true
}

BOOST_AUTO_TEST_CASE(outputscript_self_reference_different_script)
{
    // The spent UTXO has scriptA, but output 0 has scriptB.
    // The covenant self-reference check should evaluate to false (0).
    std::vector<unsigned char> hash20_a(20, 0x66);
    std::vector<unsigned char> hash20_b(20, 0x77);
    CScript scriptA = CScript() << OP_DUP << OP_HASH160 << hash20_a << OP_EQUALVERIFY << OP_CHECKSIG;
    CScript scriptB = CScript() << OP_DUP << OP_HASH160 << hash20_b << OP_EQUALVERIFY << OP_CHECKSIG;

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    CTxIn vin;
    vin.prevout.hash = uint256S("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
    vin.prevout.n = 0;
    mtx.vin.push_back(vin);

    CTxOut out0;
    out0.nValue = 5000;
    out0.scriptPubKey = scriptB; // different from spent UTXO's scriptA
    mtx.vout.push_back(out0);

    CTransaction tx(mtx);

    // Same self-reference check script
    CScript testScript;
    testScript << std::vector<unsigned char>{0x03} << OP_TXFIELD
               << CScriptNum(0) << OP_OUTPUTSCRIPT
               << OP_EQUAL;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunScriptWithSpentSPK(tx, testScript, scriptA, 5000,
                                    SELFREF_FLAGS, result, &err);
    BOOST_CHECK(ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == std::vector<unsigned char>{}); // OP_EQUAL → false
}

BOOST_AUTO_TEST_SUITE_END()
