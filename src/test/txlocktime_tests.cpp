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

static constexpr script_verify_flags TXLOCKTIME_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TXLOCKTIME;
static constexpr script_verify_flags TXLOCKTIME_FLAGS_DISCOURAGE =
    TXLOCKTIME_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
static constexpr script_verify_flags NO_TXLOCKTIME_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
static constexpr script_verify_flags NO_TXLOCKTIME_FLAGS_DISCOURAGE =
    NO_TXLOCKTIME_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
static constexpr script_verify_flags TXLOCKTIME_REVERSEBYTES_FLAGS =
    TXLOCKTIME_FLAGS | SCRIPT_VERIFY_REVERSEBYTES;

namespace {

CMutableTransaction BuildTx(uint32_t locktime)
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = locktime;

    CTxIn vin;
    vin.prevout.hash = uint256S("4444444444444444444444444444444444444444444444444444444444444444");
    vin.prevout.n = 0;
    tx.vin.push_back(vin);

    CTxOut vout;
    vout.nValue = 1000;
    vout.scriptPubKey = CScript() << OP_1;
    tx.vout.push_back(vout);

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

bool DirectGetTxLockTime(const CTransaction& tx, std::vector<unsigned char>& result)
{
    TransactionSignatureChecker checker(&tx, 0, 0);
    return checker.GetTxLockTime(result);
}

std::vector<unsigned char> EncodeLockTimeLE(uint32_t value)
{
    std::vector<unsigned char> result(4);
    memcpy(result.data(), &value, 4);
    return result;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(txlocktime_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(txlocktime_disabled_is_bad_opcode)
{
    // flag off -> BAD_OPCODE (fail-closed, not NOP)
    CTransaction tx(BuildTx(12345));
    CScript script;
    script << OP_TXLOCKTIME;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunScript(tx, script, NO_TXLOCKTIME_FLAGS, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(txlocktime_disabled_discourage_still_bad_opcode)
{
    // flag off -> BAD_OPCODE even with DISCOURAGE_UPGRADABLE_NOPS set (fail-closed)
    CTransaction tx(BuildTx(12345));
    CScript script;
    script << OP_TXLOCKTIME;

    std::vector<std::vector<unsigned char>> result;
    ScriptError err;
    bool ok = RunScript(tx, script, NO_TXLOCKTIME_FLAGS_DISCOURAGE, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(txlocktime_zero_locktime)
{
    CTransaction tx(BuildTx(0));
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectGetTxLockTime(tx, result));
    BOOST_CHECK(result == EncodeLockTimeLE(0));
}

BOOST_AUTO_TEST_CASE(txlocktime_block_height_locktime)
{
    CTransaction tx(BuildTx(600000));
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectGetTxLockTime(tx, result));
    BOOST_CHECK(result == EncodeLockTimeLE(600000));
}

BOOST_AUTO_TEST_CASE(txlocktime_timestamp_locktime)
{
    CTransaction tx(BuildTx(1577836800U));
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectGetTxLockTime(tx, result));
    BOOST_CHECK(result == EncodeLockTimeLE(1577836800U));
}

BOOST_AUTO_TEST_CASE(txlocktime_returns_4_bytes)
{
    CTransaction tx(BuildTx(12345));
    std::vector<unsigned char> result;

    BOOST_CHECK(DirectGetTxLockTime(tx, result));
    BOOST_CHECK_EQUAL(result.size(), 4U);
}

BOOST_AUTO_TEST_CASE(txlocktime_evalscript_pushes_le_locktime)
{
    CTransaction tx(BuildTx(42));
    CScript script;
    script << OP_TXLOCKTIME;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, TXLOCKTIME_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == EncodeLockTimeLE(42));
}

BOOST_AUTO_TEST_CASE(txlocktime_with_reversebytes_produces_big_endian)
{
    CTransaction tx(BuildTx(42));
    CScript script;
    script << OP_TXLOCKTIME << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> result;
    BOOST_CHECK(RunScript(tx, script, TXLOCKTIME_REVERSEBYTES_FLAGS, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);

    std::vector<unsigned char> little = EncodeLockTimeLE(42);
    std::vector<unsigned char> big(little.rbegin(), little.rend());
    BOOST_CHECK(result[0] == big);
}

BOOST_AUTO_TEST_CASE(txlocktime_works_via_verifyscript)
{
    CMutableTransaction mtx = BuildTx(12345);
    CTransaction tx(mtx);

    CScript scriptSig;
    CScript scriptPubKey;
    scriptPubKey << OP_TXLOCKTIME << EncodeLockTimeLE(12345) << OP_EQUAL;

    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(VerifyScript(scriptSig, scriptPubKey, nullptr, TXLOCKTIME_FLAGS,
                             TransactionSignatureChecker(&tx, 0, 0), &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_SUITE_END()
