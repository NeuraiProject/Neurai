// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "primitives/transaction.h"
#include "test/test_neurai.h"

#include <cstring>
#include <vector>

#include <boost/test/unit_test.hpp>

static constexpr script_verify_flags OUTPUTVALUE_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_OUTPUTVALUE;
static constexpr script_verify_flags OUTPUTVALUE_FLAGS_DISCOURAGE =
    OUTPUTVALUE_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
static constexpr script_verify_flags NO_OUTPUTVALUE_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
static constexpr script_verify_flags NO_OUTPUTVALUE_FLAGS_DISCOURAGE =
    NO_OUTPUTVALUE_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
static constexpr script_verify_flags OUTPUTVALUE_REVERSEBYTES_FLAGS =
    OUTPUTVALUE_FLAGS | SCRIPT_VERIFY_REVERSEBYTES;

namespace {

CMutableTransaction BuildTx()
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 12345;

    CTxIn vin;
    vin.prevout.hash = uint256S("3333333333333333333333333333333333333333333333333333333333333333");
    vin.prevout.n = 0;
    tx.vin.push_back(vin);

    CTxOut vout0;
    vout0.nValue = 1250;
    vout0.scriptPubKey = CScript() << OP_1;
    tx.vout.push_back(vout0);

    CTxOut vout1;
    vout1.nValue = 5000000000LL;
    vout1.scriptPubKey = CScript() << OP_2;
    tx.vout.push_back(vout1);

    CTxOut vout2;
    vout2.nValue = 42;
    vout2.scriptPubKey = CScript() << OP_3;
    tx.vout.push_back(vout2);

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

bool DirectGetOutputValue(const CTransaction& tx, unsigned int nOut, std::vector<unsigned char>& result)
{
    TransactionSignatureChecker checker(&tx, 0, 0);
    return checker.GetOutputValue(nOut, result);
}

std::vector<unsigned char> EncodeAmountLE(int64_t value)
{
    std::vector<unsigned char> result(8);
    memcpy(result.data(), &value, 8);
    return result;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(outputvalue_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(outputvalue_disabled_treated_as_nop)
{
    CTransaction tx(BuildTx());
    CScript script;
    script << CScriptNum(1) << OP_OUTPUTVALUE << OP_DROP << OP_1;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunScript(tx, script, NO_OUTPUTVALUE_FLAGS, result, &err);
    BOOST_CHECK(ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(outputvalue_disabled_discourage_nops_fails)
{
    CTransaction tx(BuildTx());
    CScript script;
    script << CScriptNum(1) << OP_OUTPUTVALUE;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunScript(tx, script, NO_OUTPUTVALUE_FLAGS_DISCOURAGE, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

BOOST_AUTO_TEST_CASE(outputvalue_empty_stack_fails)
{
    CTransaction tx(BuildTx());
    CScript script;
    script << OP_OUTPUTVALUE;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunScript(tx, script, OUTPUTVALUE_FLAGS, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(outputvalue_negative_index_fails)
{
    CTransaction tx(BuildTx());
    CScript script;
    script << CScriptNum(-1) << OP_OUTPUTVALUE;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunScript(tx, script, OUTPUTVALUE_FLAGS, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTVALUE);
}

BOOST_AUTO_TEST_CASE(outputvalue_out_of_bounds_index_fails)
{
    CTransaction tx(BuildTx());
    CScript script;
    script << CScriptNum(3) << OP_OUTPUTVALUE;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunScript(tx, script, OUTPUTVALUE_FLAGS, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OUTPUTVALUE);
}

BOOST_AUTO_TEST_CASE(outputvalue_output_zero)
{
    CTransaction tx(BuildTx());
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectGetOutputValue(tx, 0, result));
    BOOST_CHECK(result == EncodeAmountLE(1250));
}

BOOST_AUTO_TEST_CASE(outputvalue_output_one)
{
    CTransaction tx(BuildTx());
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectGetOutputValue(tx, 1, result));
    BOOST_CHECK(result == EncodeAmountLE(5000000000LL));
}

BOOST_AUTO_TEST_CASE(outputvalue_evalscript_pushes_le_amount)
{
    CTransaction tx(BuildTx());
    CScript script;
    script << CScriptNum(2) << OP_OUTPUTVALUE;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, OUTPUTVALUE_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == EncodeAmountLE(42));
}

BOOST_AUTO_TEST_CASE(outputvalue_returns_8_bytes)
{
    CTransaction tx(BuildTx());
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectGetOutputValue(tx, 1, result));
    BOOST_CHECK_EQUAL(result.size(), 8U);
}

BOOST_AUTO_TEST_CASE(outputvalue_with_reversebytes_produces_big_endian)
{
    CTransaction tx(BuildTx());
    CScript script;
    script << CScriptNum(2) << OP_OUTPUTVALUE << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, OUTPUTVALUE_REVERSEBYTES_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);

    std::vector<unsigned char> little = EncodeAmountLE(42);
    std::vector<unsigned char> big(little.rbegin(), little.rend());
    BOOST_CHECK(result[0] == big);
}

BOOST_AUTO_TEST_CASE(outputvalue_selector_must_be_scriptnum)
{
    CTransaction tx(BuildTx());
    CScript script;
    script << std::vector<unsigned char>{0x01, 0x00} << OP_OUTPUTVALUE;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(!RunScript(tx, script, OUTPUTVALUE_FLAGS, result, &err));
    BOOST_CHECK(err != SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(outputvalue_works_via_verifyscript)
{
    CMutableTransaction mtx = BuildTx();
    CTransaction tx(mtx);

    CScript scriptSig;
    CScript scriptPubKey;
    scriptPubKey << CScriptNum(1) << OP_OUTPUTVALUE << EncodeAmountLE(5000000000LL) << OP_EQUAL;

    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(VerifyScript(scriptSig, scriptPubKey, nullptr, OUTPUTVALUE_FLAGS,
                             TransactionSignatureChecker(&tx, 0, 0), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_SUITE_END()
