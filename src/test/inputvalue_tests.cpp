// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for NIP-024: OP_INPUTVALUE.

#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "primitives/transaction.h"
#include "test/test_neurai.h"

#include <cstring>
#include <vector>

#include <boost/test/unit_test.hpp>

static constexpr script_verify_flags IV_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_INPUTVALUE;
static constexpr script_verify_flags IV_FLAGS_DISCOURAGE =
    IV_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
static constexpr script_verify_flags IV_FLAGS_ARITH64 =
    IV_FLAGS | SCRIPT_VERIFY_64BIT_INTEGERS;
static constexpr script_verify_flags NO_IV_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
static constexpr script_verify_flags NO_IV_FLAGS_DISCOURAGE =
    NO_IV_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
// For the fee-check covenant demonstration: OP_INPUTVALUE + OP_OUTPUTVALUE.
static constexpr script_verify_flags FEECHECK_FLAGS =
    IV_FLAGS | SCRIPT_VERIFY_OUTPUTVALUE | SCRIPT_VERIFY_64BIT_INTEGERS;
// For symmetric-with-TXFIELD test.
static constexpr script_verify_flags IV_TXFIELD_FLAGS =
    IV_FLAGS | SCRIPT_VERIFY_TXFIELD;

namespace {

std::vector<unsigned char> EncodeLE8(int64_t value)
{
    std::vector<unsigned char> out(8);
    memcpy(out.data(), &value, 8);
    return out;
}

// Build a 3-input tx with distinct prevout XNA values:
//   prevouts[0].nValue = 1000
//   prevouts[1].nValue = 2500
//   prevouts[2].nValue = 0        (asset-only UTXO)
CMutableTransaction BuildTx()
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 0;

    for (unsigned i = 0; i < 3; ++i) {
        CTxIn vin;
        vin.prevout.hash = uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        vin.prevout.n = i;
        tx.vin.push_back(vin);
    }

    // One dummy output so the tx isn't malformed.
    CTxOut out;
    out.nValue = 100;
    out.scriptPubKey = CScript() << OP_TRUE;
    tx.vout.push_back(out);

    return tx;
}

std::vector<CTxOut> BuildPrevouts()
{
    std::vector<CTxOut> prevouts;
    for (const int64_t v : {int64_t(1000), int64_t(2500), int64_t(0)}) {
        CTxOut out;
        out.nValue = v;
        out.scriptPubKey = CScript() << OP_TRUE;
        prevouts.push_back(out);
    }
    return prevouts;
}

// Run a script with m_allPrevouts populated. nIn selects the currently-spent
// input index (the one running the script).
bool RunScriptWithPrevouts(const CTransaction& tx, const std::vector<CTxOut>& prevouts,
                           unsigned int nIn, const CScript& script,
                           script_verify_flags flags,
                           std::vector<std::vector<unsigned char>>& resultStack,
                           ScriptError* errOut = nullptr)
{
    const CScript spentSPK = nIn < prevouts.size() ? prevouts[nIn].scriptPubKey : CScript();
    const CAmount spentAmt = nIn < prevouts.size() ? prevouts[nIn].nValue : 0;
    TransactionSignatureChecker checker(&tx, nIn, spentAmt, spentSPK, &prevouts);
    ScriptError serror = SCRIPT_ERR_OK;
    std::vector<std::vector<unsigned char>> stack;
    bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    if (errOut) *errOut = serror;
    resultStack = stack;
    return ok;
}

// Run a script with a checker that has no prevouts vector — documents the
// libneuraiconsensus fail-closed path (NIP-024 §3.10 Gap 2).
bool RunScriptWithoutPrevouts(const CTransaction& tx, const CScript& script,
                              script_verify_flags flags,
                              std::vector<std::vector<unsigned char>>& resultStack,
                              ScriptError* errOut = nullptr)
{
    TransactionSignatureChecker checker(&tx, 0, 0);
    ScriptError serror = SCRIPT_ERR_OK;
    std::vector<std::vector<unsigned char>> stack;
    bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    if (errOut) *errOut = serror;
    resultStack = stack;
    return ok;
}

bool DirectGetInputValue(const CTransaction& tx, const std::vector<CTxOut>& prevouts,
                         unsigned int nInput, std::vector<unsigned char>& result)
{
    const CScript spentSPK = prevouts.empty() ? CScript() : prevouts[0].scriptPubKey;
    const CAmount spentAmt = prevouts.empty() ? 0 : prevouts[0].nValue;
    TransactionSignatureChecker checker(&tx, 0, spentAmt, spentSPK, &prevouts);
    return checker.GetInputValue(nInput, result);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(inputvalue_tests, BasicTestingSetup)

// --- Checker: direct value lookup ---

BOOST_AUTO_TEST_CASE(iv_returns_value_of_each_input)
{
    CTransaction tx(BuildTx());
    auto prevouts = BuildPrevouts();

    std::vector<unsigned char> result;
    BOOST_CHECK(DirectGetInputValue(tx, prevouts, 0, result));
    BOOST_CHECK(result == EncodeLE8(1000));

    BOOST_CHECK(DirectGetInputValue(tx, prevouts, 1, result));
    BOOST_CHECK(result == EncodeLE8(2500));

    BOOST_CHECK(DirectGetInputValue(tx, prevouts, 2, result));
    BOOST_CHECK(result == EncodeLE8(0));
}

BOOST_AUTO_TEST_CASE(iv_rejects_out_of_range_index)
{
    CTransaction tx(BuildTx());
    auto prevouts = BuildPrevouts();

    std::vector<unsigned char> result;
    BOOST_CHECK(!DirectGetInputValue(tx, prevouts, 3, result));
    BOOST_CHECK(!DirectGetInputValue(tx, prevouts, 1000, result));
}

BOOST_AUTO_TEST_CASE(iv_fails_without_prevouts)
{
    // Checker with m_allPrevouts == nullptr — documents the fail-closed guard.
    CTransaction tx(BuildTx());
    TransactionSignatureChecker checker(&tx, 0, 0);
    std::vector<unsigned char> result;
    BOOST_CHECK(!checker.GetInputValue(0, result));
}

// --- EvalScript: opcode integration ---

BOOST_AUTO_TEST_CASE(iv_evalscript_pushes_value_current_input)
{
    CTransaction tx(BuildTx());
    auto prevouts = BuildPrevouts();

    CScript script;
    script << CScriptNum(1) << OP_INPUTVALUE;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScriptWithPrevouts(tx, prevouts, /*nIn=*/1, script, IV_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == EncodeLE8(2500));
}

BOOST_AUTO_TEST_CASE(iv_evalscript_pushes_value_of_other_input)
{
    // Script runs inside input[2]; it reads the value of input[0] (1000).
    CTransaction tx(BuildTx());
    auto prevouts = BuildPrevouts();

    CScript script;
    script << CScriptNum(0) << OP_INPUTVALUE;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScriptWithPrevouts(tx, prevouts, /*nIn=*/2, script, IV_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == EncodeLE8(1000));
}

BOOST_AUTO_TEST_CASE(iv_symmetric_with_txfield_spent_value)
{
    // For nIn = currentlySpent, OP_INPUTVALUE must return byte-identical
    // result to OP_TXFIELD(0x01) (= TXFIELD_SPENT_VALUE).
    CTransaction tx(BuildTx());
    auto prevouts = BuildPrevouts();

    CScript scriptIV, scriptTX;
    scriptIV << CScriptNum(1) << OP_INPUTVALUE;
    scriptTX << std::vector<unsigned char>{0x01} << OP_TXFIELD;

    std::vector<std::vector<unsigned char>> r1, r2;
    BOOST_CHECK(RunScriptWithPrevouts(tx, prevouts, /*nIn=*/1, scriptIV, IV_TXFIELD_FLAGS, r1));
    BOOST_CHECK(RunScriptWithPrevouts(tx, prevouts, /*nIn=*/1, scriptTX, IV_TXFIELD_FLAGS, r2));
    BOOST_REQUIRE_EQUAL(r1.size(), 1U);
    BOOST_REQUIRE_EQUAL(r2.size(), 1U);
    BOOST_CHECK(r1[0] == r2[0]);
}

BOOST_AUTO_TEST_CASE(iv_asset_only_utxo_returns_zero)
{
    // prevouts[2] has nValue = 0 (asset-only UTXO).
    CTransaction tx(BuildTx());
    auto prevouts = BuildPrevouts();

    CScript script;
    script << CScriptNum(2) << OP_INPUTVALUE;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScriptWithPrevouts(tx, prevouts, /*nIn=*/0, script, IV_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == EncodeLE8(0));
}

BOOST_AUTO_TEST_CASE(iv_arith64_reencodes_as_scriptnum)
{
    // With SCRIPT_VERIFY_64BIT_INTEGERS, the result is a CScriptNum.
    CTransaction tx(BuildTx());
    auto prevouts = BuildPrevouts();

    CScript script;
    script << CScriptNum(1) << OP_INPUTVALUE;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScriptWithPrevouts(tx, prevouts, /*nIn=*/0, script, IV_FLAGS_ARITH64, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    // CScriptNum(2500).getvch() is a compact encoding, not 8 raw bytes.
    BOOST_CHECK(result[0] == CScriptNum(2500).getvch());
    BOOST_CHECK(result[0].size() < 8U);
}

BOOST_AUTO_TEST_CASE(iv_evalscript_pops_index_pushes_result)
{
    CTransaction tx(BuildTx());
    auto prevouts = BuildPrevouts();

    CScript script;
    // 3 elements on the stack; pop selector + push 8-byte value → 3 elements.
    script << OP_1 << OP_2 << CScriptNum(0) << OP_INPUTVALUE;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScriptWithPrevouts(tx, prevouts, /*nIn=*/0, script, IV_FLAGS, result));
    BOOST_CHECK_EQUAL(result.size(), 3U);
}

// --- Error cases ---

BOOST_AUTO_TEST_CASE(iv_empty_stack_fails)
{
    CTransaction tx(BuildTx());
    auto prevouts = BuildPrevouts();

    CScript script;
    script << OP_INPUTVALUE;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunScriptWithPrevouts(tx, prevouts, 0, script, IV_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(iv_negative_index_fails)
{
    CTransaction tx(BuildTx());
    auto prevouts = BuildPrevouts();

    CScript script;
    script << CScriptNum(-1) << OP_INPUTVALUE;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunScriptWithPrevouts(tx, prevouts, 0, script, IV_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INPUTVALUE);
}

BOOST_AUTO_TEST_CASE(iv_out_of_range_index_fails)
{
    CTransaction tx(BuildTx());
    auto prevouts = BuildPrevouts();

    CScript script;
    script << CScriptNum(3) << OP_INPUTVALUE; // tx has 3 inputs (0..2)

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunScriptWithPrevouts(tx, prevouts, 0, script, IV_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INPUTVALUE);
}

BOOST_AUTO_TEST_CASE(iv_no_prevouts_available_fails)
{
    // Flag is on, stack has a valid index, but checker has no m_allPrevouts
    // → SCRIPT_ERR_INPUTVALUE (fail-closed).
    CTransaction tx(BuildTx());

    CScript script;
    script << CScriptNum(0) << OP_INPUTVALUE;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunScriptWithoutPrevouts(tx, script, IV_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INPUTVALUE);
}

// --- Flag-gate behavior ---

BOOST_AUTO_TEST_CASE(iv_flag_off_is_nop_on_new_node)
{
    // With the flag off and DISCOURAGE_UPGRADABLE_NOPS off, the opcode
    // short-circuits to NOP. Selector is NOT popped.
    CTransaction tx(BuildTx());
    auto prevouts = BuildPrevouts();

    CScript script;
    script << OP_1 << CScriptNum(0) << OP_INPUTVALUE << OP_DROP;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunScriptWithPrevouts(tx, prevouts, 0, script, NO_IV_FLAGS, result, &err);
    BOOST_CHECK(ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(iv_flag_off_with_discourage_nops_fails)
{
    CTransaction tx(BuildTx());
    auto prevouts = BuildPrevouts();

    CScript script;
    script << CScriptNum(0) << OP_INPUTVALUE;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunScriptWithPrevouts(tx, prevouts, 0, script, NO_IV_FLAGS_DISCOURAGE, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

// --- Fee-enforcement covenant demonstration ---
//
// A covenant that enforces "sum(inputs) - sum(outputs) >= floor" with 3 inputs
// and 1 output, under 64-bit arithmetic:
//
//   0 OP_INPUTVALUE  1 OP_INPUTVALUE  OP_ADD  2 OP_INPUTVALUE  OP_ADD
//   ( total_in on stack )
//   0 OP_OUTPUTVALUE
//   ( total_out on stack )
//   OP_SUB  <floor>  OP_GREATERTHANOREQUAL  OP_VERIFY  OP_1

BOOST_AUTO_TEST_CASE(iv_feecheck_covenant_accepts_valid_fee)
{
    // in_total = 1000 + 2500 + 0 = 3500.  out_total = 100 (the dummy output).
    // fee = 3400.  floor = 100 → accepted.
    CTransaction tx(BuildTx());
    auto prevouts = BuildPrevouts();

    CScript script;
    script << CScriptNum(0) << OP_INPUTVALUE
           << CScriptNum(1) << OP_INPUTVALUE << OP_ADD
           << CScriptNum(2) << OP_INPUTVALUE << OP_ADD
           << CScriptNum(0) << OP_OUTPUTVALUE
           << OP_SUB
           << CScriptNum(100) << OP_GREATERTHANOREQUAL
           << OP_VERIFY
           << OP_1;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(RunScriptWithPrevouts(tx, prevouts, 0, script, FEECHECK_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == std::vector<unsigned char>{1});
}

BOOST_AUTO_TEST_CASE(iv_feecheck_covenant_rejects_insufficient_fee)
{
    // Raise floor above the available fee (3400).  OP_VERIFY must fail.
    CTransaction tx(BuildTx());
    auto prevouts = BuildPrevouts();

    CScript script;
    script << CScriptNum(0) << OP_INPUTVALUE
           << CScriptNum(1) << OP_INPUTVALUE << OP_ADD
           << CScriptNum(2) << OP_INPUTVALUE << OP_ADD
           << CScriptNum(0) << OP_OUTPUTVALUE
           << OP_SUB
           << CScriptNum(10000) << OP_GREATERTHANOREQUAL
           << OP_VERIFY
           << OP_1;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunScriptWithPrevouts(tx, prevouts, 0, script, FEECHECK_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_VERIFY);
}

// --- VerifyScript integration ---

BOOST_AUTO_TEST_CASE(iv_works_via_verifyscript)
{
    CTransaction tx(BuildTx());
    auto prevouts = BuildPrevouts();

    CScript scriptSig;
    CScript scriptPubKey;
    // push 1 → OP_INPUTVALUE → push expected 8-byte value → OP_EQUAL
    scriptPubKey << CScriptNum(1) << OP_INPUTVALUE
                 << EncodeLE8(2500) << OP_EQUAL;

    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(VerifyScript(scriptSig, scriptPubKey, nullptr, IV_FLAGS,
                             TransactionSignatureChecker(&tx, 0, prevouts[0].nValue,
                                                         prevouts[0].scriptPubKey,
                                                         &prevouts),
                             &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_SUITE_END()
