// Copyright (c) 2023-2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/standard.h"
#include "hash.h"
#include "primitives/transaction.h"
#include "test/test_neurai.h"

#include <vector>
#include <stdint.h>

#include <boost/test/unit_test.hpp>

// Flags for OP_CAT testing
static constexpr script_verify_flags CAT_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CAT;
static constexpr script_verify_flags NO_CAT_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;

namespace {

// Helper: build a minimal transaction for script evaluation
CMutableTransaction BuildMinimalTx()
{
    CMutableTransaction tx;
    tx.nVersion = 2;
    tx.nLockTime = 0;
    CTxIn vin;
    vin.prevout.hash = uint256S("0000000000000000000000000000000000000000000000000000000000000001");
    vin.prevout.n = 0;
    tx.vin.push_back(vin);
    CTxOut vout;
    vout.nValue = 1000;
    vout.scriptPubKey = CScript() << OP_TRUE;
    tx.vout.push_back(vout);
    return tx;
}

// Helper: evaluate a script with OP_CAT flags, return success and error
bool RunScript(const CScript& script, script_verify_flags flags, ScriptError* err = nullptr)
{
    CMutableTransaction mtx = BuildMinimalTx();
    CTransaction tx(mtx);
    TransactionSignatureChecker checker(&tx, 0, 0);

    ScriptError serror;
    std::vector<std::vector<unsigned char>> stack;
    bool result = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);

    if (err) *err = serror;
    return result;
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(opcat_tests, BasicTestingSetup)

// ============================================================================
// Basic concatenation
// ============================================================================

BOOST_AUTO_TEST_CASE(cat_basic_concatenation)
{
    // <"ab"> <"cd"> OP_CAT <"abcd"> OP_EQUAL
    std::vector<unsigned char> a = {'a', 'b'};
    std::vector<unsigned char> b = {'c', 'd'};
    std::vector<unsigned char> expected = {'a', 'b', 'c', 'd'};

    CScript script;
    script << a << b << OP_CAT << expected << OP_EQUAL;

    BOOST_CHECK(RunScript(script, CAT_FLAGS));
}

BOOST_AUTO_TEST_CASE(cat_empty_elements)
{
    // <"abc"> <""> OP_CAT <"abc"> OP_EQUAL
    std::vector<unsigned char> a = {'a', 'b', 'c'};
    std::vector<unsigned char> empty;
    CScript script;
    script << a << empty << OP_CAT << a << OP_EQUAL;

    BOOST_CHECK(RunScript(script, CAT_FLAGS));
}

BOOST_AUTO_TEST_CASE(cat_both_empty)
{
    // <""> <""> OP_CAT <""> OP_EQUAL
    std::vector<unsigned char> empty;
    CScript script;
    script << empty << empty << OP_CAT << empty << OP_EQUAL;

    BOOST_CHECK(RunScript(script, CAT_FLAGS));
}

// ============================================================================
// Size limit (MAX_SCRIPT_ELEMENT_SIZE = 520 bytes)
// ============================================================================

BOOST_AUTO_TEST_CASE(cat_at_520_byte_limit)
{
    // 260 + 260 = 520 bytes: should succeed
    std::vector<unsigned char> a(260, 0x41);
    std::vector<unsigned char> b(260, 0x42);

    CScript script;
    script << a << b << OP_CAT << OP_SIZE << CScriptNum(520) << OP_EQUALVERIFY << OP_DROP << OP_TRUE;

    BOOST_CHECK(RunScript(script, CAT_FLAGS));
}

BOOST_AUTO_TEST_CASE(cat_exceeds_520_byte_limit)
{
    // 261 + 260 = 521 bytes: should fail with PUSH_SIZE
    std::vector<unsigned char> a(261, 0x41);
    std::vector<unsigned char> b(260, 0x42);

    CScript script;
    script << a << b << OP_CAT;

    ScriptError err;
    BOOST_CHECK(!RunScript(script, CAT_FLAGS, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUSH_SIZE);
}

// ============================================================================
// Disabled path (flag not set)
// ============================================================================

BOOST_AUTO_TEST_CASE(cat_disabled_without_flag)
{
    // Without SCRIPT_VERIFY_CAT, OP_CAT should return DISABLED_OPCODE
    std::vector<unsigned char> a = {'a'};
    std::vector<unsigned char> b = {'b'};

    CScript script;
    script << a << b << OP_CAT;

    ScriptError err;
    BOOST_CHECK(!RunScript(script, NO_CAT_FLAGS, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISABLED_OPCODE);
}

// ============================================================================
// Stack underflow
// ============================================================================

BOOST_AUTO_TEST_CASE(cat_insufficient_stack_one_element)
{
    // Only one element on stack
    std::vector<unsigned char> a = {'a'};
    CScript script;
    script << a << OP_CAT;

    ScriptError err;
    BOOST_CHECK(!RunScript(script, CAT_FLAGS, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(cat_insufficient_stack_empty)
{
    // Empty stack
    CScript script;
    script << OP_CAT;

    ScriptError err;
    BOOST_CHECK(!RunScript(script, CAT_FLAGS, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

// ============================================================================
// Stack behavior: CAT pops second, modifies first in-place
// ============================================================================

BOOST_AUTO_TEST_CASE(cat_stack_depth)
{
    // <"x"> <"a"> <"b"> OP_CAT -> stack should be [<"x">, <"ab">]
    std::vector<unsigned char> x = {'x'};
    std::vector<unsigned char> a = {'a'};
    std::vector<unsigned char> b = {'b'};
    std::vector<unsigned char> ab = {'a', 'b'};

    CScript script;
    script << x << a << b << OP_CAT << ab << OP_EQUALVERIFY << x << OP_EQUAL;

    BOOST_CHECK(RunScript(script, CAT_FLAGS));
}

// ============================================================================
// P2WSH wrapper: OP_CAT inside a witness script
// ============================================================================

BOOST_AUTO_TEST_CASE(cat_p2wsh_basic)
{
    // witnessScript: OP_CAT <"abcd"> OP_EQUAL
    std::vector<unsigned char> expected = {'a', 'b', 'c', 'd'};
    CScript witnessScript;
    witnessScript << OP_CAT << expected << OP_EQUAL;

    // Witness data: ["ab", "cd"] (plus witnessScript appended)
    std::vector<unsigned char> a = {'a', 'b'};
    std::vector<unsigned char> b = {'c', 'd'};

    CScriptWitness witness;
    witness.stack.push_back(a);
    witness.stack.push_back(b);
    witness.stack.push_back(std::vector<unsigned char>(witnessScript.begin(), witnessScript.end()));

    // P2WSH scriptPubKey
    uint256 scriptHash;
    CSHA256().Write(witnessScript.data(), witnessScript.size()).Finalize(scriptHash.begin());
    CScript scriptPubKey;
    scriptPubKey << OP_0 << ToByteVector(scriptHash);

    CMutableTransaction mtx = BuildMinimalTx();
    CTransaction tx(mtx);

    CScript scriptSig;
    PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, 0, txdata);

    ScriptError serror;
    bool result = VerifyScript(scriptSig, scriptPubKey, &witness, CAT_FLAGS, checker, &serror);
    BOOST_CHECK(result);
}

BOOST_AUTO_TEST_SUITE_END()
