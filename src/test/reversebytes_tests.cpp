// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "primitives/transaction.h"
#include "test/test_neurai.h"

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

static const unsigned int REVERSEBYTES_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_REVERSEBYTES;
static const unsigned int NO_REVERSEBYTES_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
static const unsigned int NO_REVERSEBYTES_FLAGS_DISCOURAGE =
    NO_REVERSEBYTES_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
static const unsigned int SPLIT_REVERSEBYTES_FLAGS =
    REVERSEBYTES_FLAGS | SCRIPT_VERIFY_SPLIT;
static const unsigned int CAT_SPLIT_REVERSEBYTES_FLAGS =
    SPLIT_REVERSEBYTES_FLAGS | SCRIPT_VERIFY_CAT;

namespace {

bool RunScript(const CScript& script, unsigned int flags,
               std::vector<std::vector<unsigned char>> initialStack,
               std::vector<std::vector<unsigned char>>& resultStack,
               ScriptError* errOut = nullptr)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    CTxIn vin;
    vin.prevout.hash = uint256S("2222222222222222222222222222222222222222222222222222222222222222");
    vin.prevout.n = 0;
    mtx.vin.push_back(vin);
    CTxOut vout;
    vout.nValue = 1000;
    mtx.vout.push_back(vout);
    CTransaction tx(mtx);

    TransactionSignatureChecker checker(&tx, 0, 1000);
    ScriptError serror = SCRIPT_ERR_OK;

    std::vector<std::vector<unsigned char>> stack = initialStack;
    bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);

    if (errOut) *errOut = serror;
    resultStack = stack;
    return ok;
}

std::vector<unsigned char> Bytes(const std::string& s)
{
    return std::vector<unsigned char>(s.begin(), s.end());
}

std::vector<unsigned char> HexBytes(std::initializer_list<unsigned char> bytes)
{
    return std::vector<unsigned char>(bytes);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(reversebytes_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(reversebytes_disabled_treated_as_nop)
{
    CScript script;
    script << Bytes("abc") << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    ScriptError err;
    bool ok = RunScript(script, NO_REVERSEBYTES_FLAGS, stack, result, &err);
    BOOST_CHECK(ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == Bytes("abc"));
}

BOOST_AUTO_TEST_CASE(reversebytes_disabled_discourage_nops_fails)
{
    CScript script;
    script << Bytes("abc") << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    ScriptError err;
    bool ok = RunScript(script, NO_REVERSEBYTES_FLAGS_DISCOURAGE, stack, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

BOOST_AUTO_TEST_CASE(reversebytes_empty_stack_fails)
{
    CScript script;
    script << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    ScriptError err;
    bool ok = RunScript(script, REVERSEBYTES_FLAGS, stack, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(reversebytes_empty_vector_roundtrip)
{
    CScript script;
    script << std::vector<unsigned char>() << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, REVERSEBYTES_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0].empty());
}

BOOST_AUTO_TEST_CASE(reversebytes_single_byte_unchanged)
{
    CScript script;
    script << HexBytes({0x42}) << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, REVERSEBYTES_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == HexBytes({0x42}));
}

BOOST_AUTO_TEST_CASE(reversebytes_even_length)
{
    CScript script;
    script << Bytes("abcd") << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, REVERSEBYTES_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == Bytes("dcba"));
}

BOOST_AUTO_TEST_CASE(reversebytes_odd_length)
{
    CScript script;
    script << Bytes("abcde") << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, REVERSEBYTES_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == Bytes("edcba"));
}

BOOST_AUTO_TEST_CASE(reversebytes_32_byte_hash)
{
    std::vector<unsigned char> hash;
    for (unsigned char i = 0; i < 32; ++i) {
        hash.push_back(i);
    }
    std::vector<unsigned char> reversed(hash.rbegin(), hash.rend());

    CScript script;
    script << hash << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, REVERSEBYTES_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == reversed);
}

BOOST_AUTO_TEST_CASE(reversebytes_8_byte_amount)
{
    std::vector<unsigned char> amountLe = HexBytes({0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11});
    std::vector<unsigned char> amountBe = HexBytes({0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88});

    CScript script;
    script << amountLe << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, REVERSEBYTES_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == amountBe);
}

BOOST_AUTO_TEST_CASE(reversebytes_double_reverse_restores_original)
{
    std::vector<unsigned char> payload = Bytes("Neurai");
    CScript script;
    script << payload << OP_REVERSEBYTES << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, REVERSEBYTES_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == payload);
}

BOOST_AUTO_TEST_CASE(reversebytes_split_reverse_cat_roundtrip)
{
    std::vector<unsigned char> payload = Bytes("abcdef");
    CScript script;
    script << payload
           << CScriptNum(2) << OP_SPLIT
           << OP_REVERSEBYTES << OP_SWAP << OP_REVERSEBYTES
           << OP_CAT << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, CAT_SPLIT_REVERSEBYTES_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == payload);
}

BOOST_AUTO_TEST_CASE(reversebytes_split_extract_middle_prefix)
{
    std::vector<unsigned char> payload = Bytes("abcdef");
    CScript script;
    script << payload
           << CScriptNum(2) << OP_SPLIT
           << OP_NIP
           << OP_REVERSEBYTES
           << CScriptNum(2) << OP_SPLIT
           << OP_NIP
           << OP_REVERSEBYTES;

    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, SPLIT_REVERSEBYTES_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == Bytes("cd"));
}

BOOST_AUTO_TEST_SUITE_END()
