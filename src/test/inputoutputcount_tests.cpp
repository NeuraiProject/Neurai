// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "primitives/transaction.h"
#include "test/test_neurai.h"

#include <vector>

#include <boost/test/unit_test.hpp>

static const unsigned int IOCOUNT_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_INPUTOUTPUTCOUNT;
static const unsigned int IOCOUNT_FLAGS_DISCOURAGE =
    IOCOUNT_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
static const unsigned int NO_IOCOUNT_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
static const unsigned int NO_IOCOUNT_FLAGS_DISCOURAGE =
    NO_IOCOUNT_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;

namespace {

CMutableTransaction BuildTx(int nInputs, int nOutputs)
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 0;

    for (int i = 0; i < nInputs; i++) {
        CTxIn vin;
        vin.prevout.hash = uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        vin.prevout.n = i;
        tx.vin.push_back(vin);
    }

    for (int i = 0; i < nOutputs; i++) {
        CTxOut out;
        out.nValue = 1000 * (i + 1);
        std::vector<unsigned char> hash20(20, 0x11 + i);
        out.scriptPubKey = CScript() << OP_DUP << OP_HASH160 << hash20
                                     << OP_EQUALVERIFY << OP_CHECKSIG;
        tx.vout.push_back(out);
    }

    return tx;
}

bool RunScript(const CTransaction& tx, const CScript& script, unsigned int flags,
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

} // namespace

BOOST_FIXTURE_TEST_SUITE(inputoutputcount_tests, BasicTestingSetup)

// =====================================================================
// OP_INPUTCOUNT — basic count
// =====================================================================

BOOST_AUTO_TEST_CASE(inputcount_single_input)
{
    CTransaction tx(BuildTx(1, 1));
    CScript script;
    script << OP_INPUTCOUNT;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, IOCOUNT_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == CScriptNum(1).getvch());
}

BOOST_AUTO_TEST_CASE(inputcount_multiple_inputs)
{
    CTransaction tx(BuildTx(5, 1));
    CScript script;
    script << OP_INPUTCOUNT;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, IOCOUNT_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == CScriptNum(5).getvch());
}

BOOST_AUTO_TEST_CASE(inputcount_two_inputs)
{
    CTransaction tx(BuildTx(2, 3));
    CScript script;
    script << OP_INPUTCOUNT;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, IOCOUNT_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == CScriptNum(2).getvch());
}

// =====================================================================
// OP_OUTPUTCOUNT — basic count
// =====================================================================

BOOST_AUTO_TEST_CASE(outputcount_single_output)
{
    CTransaction tx(BuildTx(1, 1));
    CScript script;
    script << OP_OUTPUTCOUNT;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, IOCOUNT_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == CScriptNum(1).getvch());
}

BOOST_AUTO_TEST_CASE(outputcount_multiple_outputs)
{
    CTransaction tx(BuildTx(1, 4));
    CScript script;
    script << OP_OUTPUTCOUNT;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, IOCOUNT_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == CScriptNum(4).getvch());
}

BOOST_AUTO_TEST_CASE(outputcount_three_outputs)
{
    CTransaction tx(BuildTx(2, 3));
    CScript script;
    script << OP_OUTPUTCOUNT;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, IOCOUNT_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == CScriptNum(3).getvch());
}

// =====================================================================
// OP_NUMEQUALVERIFY integration
// =====================================================================

BOOST_AUTO_TEST_CASE(inputcount_numequalverify_match)
{
    CTransaction tx(BuildTx(2, 1));
    CScript script;
    script << OP_INPUTCOUNT << CScriptNum(2) << OP_NUMEQUALVERIFY << OP_1;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, IOCOUNT_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
}

BOOST_AUTO_TEST_CASE(inputcount_numequalverify_mismatch)
{
    CTransaction tx(BuildTx(3, 1));
    CScript script;
    script << OP_INPUTCOUNT << CScriptNum(2) << OP_NUMEQUALVERIFY << OP_1;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunScript(tx, script, IOCOUNT_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_NUMEQUALVERIFY);
}

BOOST_AUTO_TEST_CASE(outputcount_numequalverify_match)
{
    CTransaction tx(BuildTx(1, 3));
    CScript script;
    script << OP_OUTPUTCOUNT << CScriptNum(3) << OP_NUMEQUALVERIFY << OP_1;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, IOCOUNT_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
}

// =====================================================================
// Numeric comparators
// =====================================================================

BOOST_AUTO_TEST_CASE(outputcount_lessthan)
{
    CTransaction tx(BuildTx(1, 2));
    // 2 < 4 => true
    CScript script;
    script << OP_OUTPUTCOUNT << CScriptNum(4) << OP_LESSTHAN;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, IOCOUNT_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(CScriptNum(result[0], false).getint() != 0);
}

BOOST_AUTO_TEST_CASE(outputcount_greaterthanorequal)
{
    CTransaction tx(BuildTx(1, 3));
    // 3 >= 2 => true
    CScript script;
    script << OP_OUTPUTCOUNT << CScriptNum(2) << OP_GREATERTHANOREQUAL;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, IOCOUNT_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(CScriptNum(result[0], false).getint() != 0);
}

BOOST_AUTO_TEST_CASE(inputcount_within)
{
    CTransaction tx(BuildTx(3, 1));
    // WITHIN: 3 >= 2 && 3 < 5 => true
    CScript script;
    script << OP_INPUTCOUNT << CScriptNum(2) << CScriptNum(5) << OP_WITHIN;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, IOCOUNT_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(CScriptNum(result[0], false).getint() != 0);
}

// =====================================================================
// Disabled behavior (NOP-upgradeable)
// =====================================================================

BOOST_AUTO_TEST_CASE(inputcount_disabled_nop)
{
    // Without the flag, OP_INPUTCOUNT is NOP. Nothing pushed.
    // Stack ends with only OP_1.
    CTransaction tx(BuildTx(1, 1));
    CScript script;
    script << OP_INPUTCOUNT << OP_1;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunScript(tx, script, NO_IOCOUNT_FLAGS, result, &err);
    BOOST_CHECK(ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    // Only OP_1 on stack, OP_INPUTCOUNT was NOP
    BOOST_CHECK_EQUAL(result.size(), 1U);
}

BOOST_AUTO_TEST_CASE(outputcount_disabled_nop)
{
    CTransaction tx(BuildTx(1, 1));
    CScript script;
    script << OP_OUTPUTCOUNT << OP_1;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunScript(tx, script, NO_IOCOUNT_FLAGS, result, &err);
    BOOST_CHECK(ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(result.size(), 1U);
}

BOOST_AUTO_TEST_CASE(inputcount_disabled_discourage_fails)
{
    CTransaction tx(BuildTx(1, 1));
    CScript script;
    script << OP_INPUTCOUNT << OP_1;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunScript(tx, script, NO_IOCOUNT_FLAGS_DISCOURAGE, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

BOOST_AUTO_TEST_CASE(outputcount_disabled_discourage_fails)
{
    CTransaction tx(BuildTx(1, 1));
    CScript script;
    script << OP_OUTPUTCOUNT << OP_1;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunScript(tx, script, NO_IOCOUNT_FLAGS_DISCOURAGE, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

// =====================================================================
// Stack is not modified except for the push
// =====================================================================

BOOST_AUTO_TEST_CASE(inputcount_does_not_consume_stack)
{
    // Stack starts with [OP_1, OP_2], then INPUTCOUNT pushes count.
    // Final stack should have 3 elements.
    CTransaction tx(BuildTx(1, 1));
    CScript script;
    script << OP_1 << OP_2 << OP_INPUTCOUNT;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, IOCOUNT_FLAGS, result));
    BOOST_CHECK_EQUAL(result.size(), 3U);
    BOOST_CHECK(result[2] == CScriptNum(1).getvch());
}

// =====================================================================
// Combined shape constraint
// =====================================================================

BOOST_AUTO_TEST_CASE(combined_shape_constraint)
{
    CTransaction tx(BuildTx(2, 3));
    CScript script;
    script << OP_INPUTCOUNT << CScriptNum(2) << OP_NUMEQUALVERIFY
           << OP_OUTPUTCOUNT << CScriptNum(3) << OP_NUMEQUALVERIFY
           << OP_1;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, IOCOUNT_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
}

BOOST_AUTO_TEST_CASE(combined_shape_constraint_wrong_inputs)
{
    CTransaction tx(BuildTx(3, 3));
    CScript script;
    script << OP_INPUTCOUNT << CScriptNum(2) << OP_NUMEQUALVERIFY
           << OP_OUTPUTCOUNT << CScriptNum(3) << OP_NUMEQUALVERIFY
           << OP_1;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunScript(tx, script, IOCOUNT_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_NUMEQUALVERIFY);
}

BOOST_AUTO_TEST_CASE(combined_shape_constraint_wrong_outputs)
{
    CTransaction tx(BuildTx(2, 4));
    CScript script;
    script << OP_INPUTCOUNT << CScriptNum(2) << OP_NUMEQUALVERIFY
           << OP_OUTPUTCOUNT << CScriptNum(3) << OP_NUMEQUALVERIFY
           << OP_1;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    BOOST_CHECK(!RunScript(tx, script, IOCOUNT_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_NUMEQUALVERIFY);
}

// =====================================================================
// Encoding: always canonical CScriptNum, not affected by 64BIT_INTEGERS
// =====================================================================

BOOST_AUTO_TEST_CASE(inputcount_encoding_not_affected_by_64bit_flag)
{
    CTransaction tx(BuildTx(3, 1));

    // With 64-bit flag active, result must be identical
    unsigned int flags64 = IOCOUNT_FLAGS | SCRIPT_VERIFY_64BIT_INTEGERS;

    CScript script;
    script << OP_INPUTCOUNT;

    std::vector<std::vector<unsigned char>> result_normal;
    BOOST_CHECK(RunScript(tx, script, IOCOUNT_FLAGS, result_normal));

    std::vector<std::vector<unsigned char>> result_64bit;
    BOOST_CHECK(RunScript(tx, script, flags64, result_64bit));

    BOOST_REQUIRE_EQUAL(result_normal.size(), 1U);
    BOOST_REQUIRE_EQUAL(result_64bit.size(), 1U);
    BOOST_CHECK(result_normal[0] == result_64bit[0]);
    BOOST_CHECK(result_normal[0] == CScriptNum(3).getvch());
}

// =====================================================================
// DEPIN network behavior
// =====================================================================

BOOST_AUTO_TEST_CASE(inputoutputcount_depin_network_activation)
{
    SelectParams(CBaseChainParams::TESTNET);
    BOOST_CHECK(GetParams().GetConsensus().nINPUTOUTPUTCOUNTEnabled);

    SelectParams(CBaseChainParams::REGTEST);
    BOOST_CHECK(GetParams().GetConsensus().nINPUTOUTPUTCOUNTEnabled);

    SelectParams(CBaseChainParams::MAIN);
    BOOST_CHECK(!GetParams().GetConsensus().nINPUTOUTPUTCOUNTEnabled);
}

BOOST_AUTO_TEST_SUITE_END()
