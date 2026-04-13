// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "primitives/transaction.h"
#include "test/test_neurai.h"

#include <vector>
#include <string>

#include <boost/test/unit_test.hpp>

// Flags used in tests
static const unsigned int SPLIT_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_SPLIT;
static const unsigned int SPLIT_FLAGS_DISCOURAGE =
    SPLIT_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
static const unsigned int NO_SPLIT_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
static const unsigned int NO_SPLIT_DISCOURAGE =
    NO_SPLIT_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
static const unsigned int CAT_SPLIT_FLAGS =
    SPLIT_FLAGS | SCRIPT_VERIFY_CAT;

namespace {

// Helper: run a script with a pre-built stack, return stack state on success.
// scriptPubKey is evaluated directly (no scriptSig).
bool RunScript(const CScript& script, unsigned int flags,
               std::vector<std::vector<unsigned char>> initialStack,
               std::vector<std::vector<unsigned char>>& resultStack,
               ScriptError* errOut = nullptr)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    CTxIn vin;
    vin.prevout.hash = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
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

// Helper: build bytes from a string
std::vector<unsigned char> Bytes(const std::string& s)
{
    return std::vector<unsigned char>(s.begin(), s.end());
}

// Helper: build a script that pushes data then n and runs OP_SPLIT
CScript SplitScript(const std::vector<unsigned char>& data, int n)
{
    CScript s;
    s << data << CScriptNum(n) << OP_SPLIT;
    return s;
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(split_tests, BasicTestingSetup)

// ============================================================================
// 1. Opcode disabled / NOP behavior
// ============================================================================

BOOST_AUTO_TEST_CASE(split_disabled_treated_as_nop)
{
    // Without SCRIPT_VERIFY_SPLIT, OP_SPLIT must act as NOP8 — stack unchanged.
    // Script: <"abc"> <1> OP_SPLIT OP_DROP OP_DROP OP_1
    // If SPLIT acts as NOP, stack = ["abc", 1] after OP_SPLIT, then two DROPs
    // remove both, then OP_1 leaves [1] → success.
    CScript script;
    script << Bytes("abc") << CScriptNum(1) << OP_SPLIT << OP_DROP << OP_DROP << OP_1;

    std::vector<std::vector<unsigned char>> stack, result;
    ScriptError err;
    bool ok = RunScript(script, NO_SPLIT_FLAGS, stack, result, &err);
    BOOST_CHECK(ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(split_disabled_discourage_nops_fails)
{
    // Without SPLIT but with DISCOURAGE_UPGRADABLE_NOPS, OP_SPLIT must fail.
    CScript script;
    script << Bytes("abc") << CScriptNum(1) << OP_SPLIT;

    std::vector<std::vector<unsigned char>> stack, result;
    ScriptError err;
    bool ok = RunScript(script, NO_SPLIT_DISCOURAGE, stack, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

// ============================================================================
// 2. Stack underflow errors
// ============================================================================

BOOST_AUTO_TEST_CASE(split_empty_stack_fails)
{
    CScript script;
    script << OP_SPLIT;

    std::vector<std::vector<unsigned char>> stack, result;
    ScriptError err;
    bool ok = RunScript(script, SPLIT_FLAGS, stack, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(split_one_element_fails)
{
    // Stack has data but no n → underflow
    CScript script;
    script << Bytes("hello") << OP_SPLIT;

    std::vector<std::vector<unsigned char>> stack, result;
    ScriptError err;
    bool ok = RunScript(script, SPLIT_FLAGS, stack, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

// ============================================================================
// 3. Boundary cases: n == 0 and n == len
// ============================================================================

BOOST_AUTO_TEST_CASE(split_at_zero)
{
    // <"abcde"> <0> OP_SPLIT → [""] ["abcde"]
    auto data = Bytes("abcde");
    CScript script = SplitScript(data, 0);

    std::vector<std::vector<unsigned char>> stack, result;
    bool ok = RunScript(script, SPLIT_FLAGS, stack, result);
    BOOST_CHECK(ok);
    BOOST_REQUIRE_EQUAL(result.size(), 2U);
    BOOST_CHECK(result[0].empty());
    BOOST_CHECK(result[1] == data);
}

BOOST_AUTO_TEST_CASE(split_at_end)
{
    // <"abcde"> <5> OP_SPLIT → ["abcde"] [""]
    auto data = Bytes("abcde");
    CScript script = SplitScript(data, (int)data.size());

    std::vector<std::vector<unsigned char>> stack, result;
    bool ok = RunScript(script, SPLIT_FLAGS, stack, result);
    BOOST_CHECK(ok);
    BOOST_REQUIRE_EQUAL(result.size(), 2U);
    BOOST_CHECK(result[0] == data);
    BOOST_CHECK(result[1].empty());
}

BOOST_AUTO_TEST_CASE(split_in_middle)
{
    // <"abcde"> <2> OP_SPLIT → ["ab"] ["cde"]
    auto data = Bytes("abcde");
    CScript script = SplitScript(data, 2);

    std::vector<std::vector<unsigned char>> stack, result;
    bool ok = RunScript(script, SPLIT_FLAGS, stack, result);
    BOOST_CHECK(ok);
    BOOST_REQUIRE_EQUAL(result.size(), 2U);
    BOOST_CHECK(result[0] == Bytes("ab"));
    BOOST_CHECK(result[1] == Bytes("cde"));
}

BOOST_AUTO_TEST_CASE(split_single_byte_left)
{
    // <"xyz"> <1> OP_SPLIT → ["x"] ["yz"]
    CScript script = SplitScript(Bytes("xyz"), 1);
    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, SPLIT_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 2U);
    BOOST_CHECK(result[0] == Bytes("x"));
    BOOST_CHECK(result[1] == Bytes("yz"));
}

BOOST_AUTO_TEST_CASE(split_single_byte_right)
{
    // <"xyz"> <2> OP_SPLIT → ["xy"] ["z"]
    CScript script = SplitScript(Bytes("xyz"), 2);
    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, SPLIT_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 2U);
    BOOST_CHECK(result[0] == Bytes("xy"));
    BOOST_CHECK(result[1] == Bytes("z"));
}

BOOST_AUTO_TEST_CASE(split_single_byte_data_at_one)
{
    // <0x42> <1> OP_SPLIT → [0x42] [""]
    std::vector<unsigned char> oneByte = {0x42};
    CScript script = SplitScript(oneByte, 1);
    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, SPLIT_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 2U);
    BOOST_CHECK(result[0] == oneByte);
    BOOST_CHECK(result[1].empty());
}

BOOST_AUTO_TEST_CASE(split_single_byte_data_at_zero)
{
    // <0x42> <0> OP_SPLIT → [""] [0x42]
    std::vector<unsigned char> oneByte = {0x42};
    CScript script = SplitScript(oneByte, 0);
    std::vector<std::vector<unsigned char>> stack, result;
    BOOST_CHECK(RunScript(script, SPLIT_FLAGS, stack, result));
    BOOST_REQUIRE_EQUAL(result.size(), 2U);
    BOOST_CHECK(result[0].empty());
    BOOST_CHECK(result[1] == oneByte);
}

// ============================================================================
// 4. Out-of-range errors
// ============================================================================

BOOST_AUTO_TEST_CASE(split_negative_position_fails)
{
    // <"abc"> <-1> OP_SPLIT → SCRIPT_ERR_SPLIT
    CScript script = SplitScript(Bytes("abc"), -1);
    std::vector<std::vector<unsigned char>> stack, result;
    ScriptError err;
    bool ok = RunScript(script, SPLIT_FLAGS, stack, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SPLIT);
}

BOOST_AUTO_TEST_CASE(split_beyond_end_fails)
{
    // <"abc"> <4> OP_SPLIT → SCRIPT_ERR_SPLIT (4 > len("abc") == 3)
    CScript script = SplitScript(Bytes("abc"), 4);
    std::vector<std::vector<unsigned char>> stack, result;
    ScriptError err;
    bool ok = RunScript(script, SPLIT_FLAGS, stack, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SPLIT);
}

BOOST_AUTO_TEST_CASE(split_way_beyond_end_fails)
{
    // <"abc"> <100> OP_SPLIT → SCRIPT_ERR_SPLIT
    CScript script = SplitScript(Bytes("abc"), 100);
    std::vector<std::vector<unsigned char>> stack, result;
    ScriptError err;
    bool ok = RunScript(script, SPLIT_FLAGS, stack, result, &err);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_SPLIT);
}

// ============================================================================
// 5. Round-trip with OP_CAT
// ============================================================================

BOOST_AUTO_TEST_CASE(split_cat_roundtrip)
{
    // <"abcde"> <2> OP_SPLIT OP_CAT → ["abcde"]
    auto data = Bytes("abcde");
    CScript script;
    script << data << CScriptNum(2) << OP_SPLIT << OP_CAT;

    std::vector<std::vector<unsigned char>> stack, result;
    bool ok = RunScript(script, CAT_SPLIT_FLAGS, stack, result);
    BOOST_CHECK(ok);
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == data);
}

BOOST_AUTO_TEST_CASE(split_cat_roundtrip_at_zero)
{
    // <"abc"> <0> OP_SPLIT OP_CAT → ["abc"]
    auto data = Bytes("abc");
    CScript script;
    script << data << CScriptNum(0) << OP_SPLIT << OP_CAT;

    std::vector<std::vector<unsigned char>> stack, result;
    bool ok = RunScript(script, CAT_SPLIT_FLAGS, stack, result);
    BOOST_CHECK(ok);
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == data);
}

BOOST_AUTO_TEST_CASE(split_cat_roundtrip_at_end)
{
    // <"abc"> <3> OP_SPLIT OP_CAT → ["abc"]
    auto data = Bytes("abc");
    CScript script;
    script << data << CScriptNum((int)data.size()) << OP_SPLIT << OP_CAT;

    std::vector<std::vector<unsigned char>> stack, result;
    bool ok = RunScript(script, CAT_SPLIT_FLAGS, stack, result);
    BOOST_CHECK(ok);
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == data);
}

BOOST_AUTO_TEST_CASE(cat_split_roundtrip)
{
    // <"ab"> <"cde"> OP_CAT <2> OP_SPLIT → ["ab"] ["cde"]
    auto a = Bytes("ab");
    auto b = Bytes("cde");
    CScript script;
    script << a << b << OP_CAT << CScriptNum(2) << OP_SPLIT;

    std::vector<std::vector<unsigned char>> stack, result;
    bool ok = RunScript(script, CAT_SPLIT_FLAGS, stack, result);
    BOOST_CHECK(ok);
    BOOST_REQUIRE_EQUAL(result.size(), 2U);
    BOOST_CHECK(result[0] == a);
    BOOST_CHECK(result[1] == b);
}

// ============================================================================
// 6. Interaction with OP_SIZE
// ============================================================================

BOOST_AUTO_TEST_CASE(split_size_equals_full_split)
{
    // <"hello"> OP_DUP OP_SIZE OP_SPLIT OP_NIP → ["hello"] (left=full, right=empty; NIP drops right)
    // OP_SIZE pushes len without consuming data → stack: ["hello", "hello", 5]
    // OP_SPLIT on top two → ["hello", "hello", ""]
    // OP_NIP removes second-to-top → ["hello", ""]
    // Then OP_DROP to remove "" and check top is original data
    auto data = Bytes("hello");
    CScript script;
    script << data << OP_DUP << OP_SIZE << OP_SPLIT << OP_NIP;
    // Stack: [data_orig, data_full, ""]  -- wait, let me re-think.
    // After script << data: stack = [data]
    // OP_DUP: [data, data]
    // OP_SIZE: [data, data, 5]  (does NOT consume data)
    // OP_SPLIT: pops 5 and data → [data[0..5], data[5..]] = [data, ""]
    // Stack is now: [data_orig, data, ""]
    // OP_NIP removes item below top: [data_orig, ""]
    // We want to verify data_orig == original data.
    // Let's add OP_DROP OP_EQUALVERIFY OP_1 -- wait, simpler: just check result.
    std::vector<std::vector<unsigned char>> stack, result;
    bool ok = RunScript(script, CAT_SPLIT_FLAGS, stack, result);
    BOOST_CHECK(ok);
    BOOST_REQUIRE_EQUAL(result.size(), 2U);
    BOOST_CHECK(result[0] == data);   // original data preserved at bottom
    BOOST_CHECK(result[1].empty());   // right fragment is empty (split at end)
}

// ============================================================================
// 7. Extraction pattern: get bytes [start..end]
// ============================================================================

BOOST_AUTO_TEST_CASE(split_extract_middle_bytes)
{
    // Extract bytes [2..4] (2 bytes) from "abcdef"
    // <"abcdef"> <2> OP_SPLIT OP_NIP <2> OP_SPLIT OP_DROP
    // Result: ["cd"]
    auto data = Bytes("abcdef");
    CScript script;
    script << data
           << CScriptNum(2) << OP_SPLIT << OP_NIP   // discard "ab", keep "cdef"
           << CScriptNum(2) << OP_SPLIT << OP_DROP;  // take "cd", discard "ef"

    std::vector<std::vector<unsigned char>> stack, result;
    bool ok = RunScript(script, SPLIT_FLAGS, stack, result);
    BOOST_CHECK(ok);
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    BOOST_CHECK(result[0] == Bytes("cd"));
}

// ============================================================================
// 8. Verify prefix check pattern
// ============================================================================

BOOST_AUTO_TEST_CASE(split_prefix_check)
{
    // Verify that "5120" is the first 2 bytes of a 34-byte AuthScript-style scriptPubKey.
    // Script: <data> <2> OP_SPLIT OP_DROP <prefix> OP_EQUAL
    std::vector<unsigned char> data(34, 0xAA);
    data[0] = 0x51;  // OP_1
    data[1] = 0x20;  // push 32 bytes

    std::vector<unsigned char> prefix = {0x51, 0x20};

    CScript script;
    script << data << CScriptNum(2) << OP_SPLIT << OP_DROP << prefix << OP_EQUAL;

    std::vector<std::vector<unsigned char>> stack, result;
    bool ok = RunScript(script, SPLIT_FLAGS, stack, result);
    BOOST_CHECK(ok);
    BOOST_REQUIRE_EQUAL(result.size(), 1U);
    // OP_EQUAL result: 1 (true) encoded as {0x01}
    BOOST_CHECK(!result[0].empty());
    BOOST_CHECK(result[0][0] == 1);
}

BOOST_AUTO_TEST_SUITE_END()
