// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "assets/assets.h"
#include "base58.h"
#include "chainparams.h"
#include "primitives/transaction.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/standard.h"
#include "test/test_neurai.h"

#include <limits>
#include <vector>

#include <boost/test/unit_test.hpp>

static constexpr script_verify_flags ARITH64_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_64BIT_INTEGERS;
static constexpr script_verify_flags OUTPUTVALUE_ARITH64_FLAGS =
    ARITH64_FLAGS | SCRIPT_VERIFY_OUTPUTVALUE;
static constexpr script_verify_flags OUTPUTASSETFIELD_ARITH64_FLAGS =
    ARITH64_FLAGS | SCRIPT_VERIFY_OUTPUTASSETFIELD;
static constexpr script_verify_flags NO_ARITH64_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;

namespace {

std::vector<unsigned char> EncodeScriptNum(int64_t value)
{
    return CScriptNum(value).getvch();
}

CMutableTransaction BuildValueTx()
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 0;

    CTxIn vin;
    vin.prevout.hash = uint256S("abababababababababababababababababababababababababababababababab");
    vin.prevout.n = 0;
    tx.vin.push_back(vin);

    CTxOut out0;
    out0.nValue = 5000000000LL;
    out0.scriptPubKey = CScript() << OP_1;
    tx.vout.push_back(out0);

    CTxOut out1;
    out1.nValue = 42;
    out1.scriptPubKey = CScript() << OP_2;
    tx.vout.push_back(out1);

    return tx;
}

CMutableTransaction BuildAssetTx()
{
    SelectParams(CBaseChainParams::TESTNET);

    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 0;

    CTxIn vin;
    vin.prevout.hash = uint256S("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
    vin.prevout.n = 0;
    tx.vin.push_back(vin);

    const CTxDestination dest = DecodeDestination(GetParams().GlobalBurnAddress());

    CTxOut out;
    out.nValue = 0;
    out.scriptPubKey = GetScriptForDestination(dest);
    CAssetTransfer transfer("GOLD", 25 * COIN);
    transfer.ConstructTransaction(out.scriptPubKey);
    tx.vout.push_back(out);

    return tx;
}

bool RunScript(const CTransaction& tx, const CScript& script, script_verify_flags flags,
               std::vector<std::vector<unsigned char>>& resultStack, ScriptError* errOut = nullptr)
{
    TransactionSignatureChecker checker(&tx, 0, 0);
    ScriptError serror = SCRIPT_ERR_OK;
    std::vector<std::vector<unsigned char>> stack;
    const bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    if (errOut) *errOut = serror;
    resultStack = stack;
    return ok;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(arithmetic64_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(arithmetic64_disabled_opcodes_fail_even_in_unexecuted_branch)
{
    CTransaction tx(BuildValueTx());
    std::vector<std::vector<unsigned char>> result;
    ScriptError err = SCRIPT_ERR_OK;

    BOOST_CHECK(!RunScript(tx, CScript() << OP_2 << OP_3 << OP_MUL, NO_ARITH64_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISABLED_OPCODE);

    BOOST_CHECK(!RunScript(tx, CScript() << OP_6 << OP_2 << OP_DIV, NO_ARITH64_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISABLED_OPCODE);

    BOOST_CHECK(!RunScript(tx, CScript() << OP_7 << OP_2 << OP_MOD, NO_ARITH64_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISABLED_OPCODE);

    BOOST_CHECK(!RunScript(tx, CScript() << OP_0 << OP_IF << OP_2 << OP_3 << OP_MUL << OP_ENDIF << OP_1, NO_ARITH64_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISABLED_OPCODE);
}

BOOST_AUTO_TEST_CASE(arithmetic64_enabled_opcodes_respect_fexec)
{
    CTransaction tx(BuildValueTx());
    std::vector<std::vector<unsigned char>> result;
    ScriptError err = SCRIPT_ERR_OK;

    BOOST_CHECK(RunScript(tx, CScript() << OP_0 << OP_IF << OP_2 << OP_3 << OP_MUL << OP_ENDIF << OP_1, ARITH64_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == std::vector<unsigned char>{1});
}

BOOST_AUTO_TEST_CASE(arithmetic64_mul_div_mod_basic)
{
    CTransaction tx(BuildValueTx());
    std::vector<std::vector<unsigned char>> result;

    BOOST_CHECK(RunScript(tx, CScript() << OP_2 << OP_3 << OP_MUL << OP_6 << OP_NUMEQUAL, ARITH64_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == std::vector<unsigned char>{1});

    BOOST_CHECK(RunScript(tx, CScript() << OP_7 << OP_2 << OP_DIV << OP_3 << OP_NUMEQUAL, ARITH64_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == std::vector<unsigned char>{1});

    BOOST_CHECK(RunScript(tx, CScript() << OP_7 << OP_2 << OP_MOD << OP_1 << OP_NUMEQUAL, ARITH64_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == std::vector<unsigned char>{1});
}

BOOST_AUTO_TEST_CASE(arithmetic64_overflow_and_divzero)
{
    CTransaction tx(BuildValueTx());
    std::vector<std::vector<unsigned char>> result;
    ScriptError err = SCRIPT_ERR_OK;
    const std::vector<unsigned char> maxv = EncodeScriptNum(std::numeric_limits<int64_t>::max());
    const std::vector<unsigned char> minv = EncodeScriptNum(-std::numeric_limits<int64_t>::max());

    BOOST_CHECK(!RunScript(tx, CScript() << maxv << OP_1 << OP_ADD, ARITH64_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_ADD_OVERFLOW);

    BOOST_CHECK(!RunScript(tx, CScript() << maxv << OP_1ADD, ARITH64_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_ADD_OVERFLOW);

    BOOST_CHECK(!RunScript(tx, CScript() << minv << OP_1SUB, ARITH64_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SUB_OVERFLOW);

    BOOST_CHECK(!RunScript(tx, CScript() << maxv << OP_2 << OP_MUL, ARITH64_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_MUL_OVERFLOW);

    BOOST_CHECK(!RunScript(tx, CScript() << OP_5 << OP_0 << OP_DIV, ARITH64_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DIV_BY_ZERO);

    BOOST_CHECK(!RunScript(tx, CScript() << OP_5 << OP_0 << OP_MOD, ARITH64_FLAGS, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_MOD_BY_ZERO);
}

BOOST_AUTO_TEST_CASE(arithmetic64_outputvalue_integrates_with_numeric_ops)
{
    CTransaction tx(BuildValueTx());
    std::vector<std::vector<unsigned char>> result;

    BOOST_CHECK(RunScript(tx, CScript() << CScriptNum(0) << OP_OUTPUTVALUE
                                        << EncodeScriptNum(4000000000LL) << OP_GREATERTHAN,
                         OUTPUTVALUE_ARITH64_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == std::vector<unsigned char>{1});

    BOOST_CHECK(RunScript(tx, CScript() << CScriptNum(0) << OP_OUTPUTVALUE
                                        << EncodeScriptNum(5000000000LL) << OP_NUMEQUALVERIFY
                                        << OP_1,
                         OUTPUTVALUE_ARITH64_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == std::vector<unsigned char>{1});
}

BOOST_AUTO_TEST_CASE(arithmetic64_outputassetfield_amount_integrates_with_mul)
{
    CTransaction tx(BuildAssetTx());
    std::vector<std::vector<unsigned char>> result;

    BOOST_CHECK(RunScript(tx, CScript() << CScriptNum(0) << std::vector<unsigned char>{0x02}
                                        << OP_OUTPUTASSETFIELD << OP_2 << OP_MUL
                                        << EncodeScriptNum(50 * COIN) << OP_NUMEQUAL,
                         OUTPUTASSETFIELD_ARITH64_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == std::vector<unsigned char>{1});
}

BOOST_AUTO_TEST_CASE(arithmetic64_within_supports_large_values)
{
    CTransaction tx(BuildValueTx());
    std::vector<std::vector<unsigned char>> result;

    BOOST_CHECK(RunScript(tx, CScript() << EncodeScriptNum(5000000000LL)
                                        << EncodeScriptNum(1000000000LL)
                                        << EncodeScriptNum(9000000000LL)
                                        << OP_WITHIN,
                         ARITH64_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == std::vector<unsigned char>{1});
}

BOOST_AUTO_TEST_CASE(arithmetic64_cltv_keeps_5byte_limit)
{
    CTransaction tx(BuildValueTx());
    std::vector<std::vector<unsigned char>> result;
    ScriptError err = SCRIPT_ERR_OK;

    BOOST_CHECK(!RunScript(tx, CScript() << EncodeScriptNum(std::numeric_limits<int64_t>::max())
                                         << OP_CHECKLOCKTIMEVERIFY,
                           ARITH64_FLAGS | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY, result, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_UNKNOWN_ERROR);
}

BOOST_AUTO_TEST_SUITE_END()
