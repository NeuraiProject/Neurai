// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-018: MAX_PQ_SCRIPT_ELEMENT_SIZE under SCRIPT_VERIFY_CHECKSIGFROMSTACK.
// Exercises the effective per-element size cap and the CSFS-gated total
// stack-bytes cap added to EvalScript.

#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "test/test_neurai.h"

#include <boost/test/unit_test.hpp>

#include <vector>

namespace {

// Flags with CSFS enabled (lifts element cap to 3072 and activates
// the 256 KiB total-stack-bytes cap).
static constexpr script_verify_flags CSFS_ON = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKSIGFROMSTACK;

// Flags without CSFS (legacy 520 element cap, no total-bytes cap).
static constexpr script_verify_flags CSFS_OFF = SCRIPT_VERIFY_P2SH;

// Flags with CSFS + OP_CAT enabled.
static constexpr script_verify_flags CSFS_ON_CAT = CSFS_ON | SCRIPT_VERIFY_CAT;
static constexpr script_verify_flags CSFS_OFF_CAT = CSFS_OFF | SCRIPT_VERIFY_CAT;

bool RunBare(const CScript& script, script_verify_flags flags, ScriptError* err = nullptr)
{
    // Dummy checker: no tx context needed for push/size tests.
    BaseSignatureChecker checker;
    ScriptError serror = SCRIPT_ERR_OK;
    std::vector<std::vector<unsigned char>> stack;
    bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    if (err) *err = serror;
    return ok;
}

CScript PushOfSize(size_t n)
{
    std::vector<unsigned char> data(n, 0xab);
    CScript s;
    s << data;
    return s;
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(pq_script_element_size_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// Per-element size cap: CSFS on
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(pq_push_3072_accepted_when_csfs_active)
{
    CScript s = PushOfSize(MAX_PQ_SCRIPT_ELEMENT_SIZE);
    s << OP_DROP << OP_1;
    BOOST_CHECK(RunBare(s, CSFS_ON));
}

BOOST_AUTO_TEST_CASE(pq_push_3073_rejected_when_csfs_active)
{
    CScript s = PushOfSize(MAX_PQ_SCRIPT_ELEMENT_SIZE + 1);
    ScriptError err;
    BOOST_CHECK(!RunBare(s, CSFS_ON, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUSH_SIZE);
}

// ---------------------------------------------------------------------------
// Per-element size cap: CSFS off (legacy 520 rule)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(pq_push_521_rejected_when_csfs_inactive)
{
    CScript s = PushOfSize(MAX_SCRIPT_ELEMENT_SIZE + 1);
    ScriptError err;
    BOOST_CHECK(!RunBare(s, CSFS_OFF, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUSH_SIZE);
}

BOOST_AUTO_TEST_CASE(pq_push_520_accepted_when_csfs_inactive)
{
    CScript s = PushOfSize(MAX_SCRIPT_ELEMENT_SIZE);
    s << OP_DROP << OP_1;
    BOOST_CHECK(RunBare(s, CSFS_OFF));
}

// ---------------------------------------------------------------------------
// OP_CAT respects the effective cap
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(cat_success_under_csfs)
{
    CScript s = PushOfSize(2000);
    s += PushOfSize(1000);
    s << OP_CAT << OP_DROP << OP_1;
    BOOST_CHECK(RunBare(s, CSFS_ON_CAT));
}

BOOST_AUTO_TEST_CASE(cat_overflow_limited_to_3072_when_csfs_active)
{
    CScript s = PushOfSize(2000);
    s += PushOfSize(1500);
    s << OP_CAT;
    ScriptError err;
    BOOST_CHECK(!RunBare(s, CSFS_ON_CAT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUSH_SIZE);
}

BOOST_AUTO_TEST_CASE(cat_overflow_limited_to_520_when_csfs_inactive)
{
    CScript s = PushOfSize(400);
    s += PushOfSize(200);
    s << OP_CAT;
    ScriptError err;
    BOOST_CHECK(!RunBare(s, CSFS_OFF_CAT, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_PUSH_SIZE);
}

// ---------------------------------------------------------------------------
// Total stack-bytes cap: CSFS-gated
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(stack_bytes_cap_hit)
{
    // 90 × 3072 B = 276480 B > MAX_STACK_BYTES (262144 B). Push one element
    // at a time; the cap check runs after each opcode.
    CScript s;
    for (int i = 0; i < 90; ++i) {
        std::vector<unsigned char> data(MAX_PQ_SCRIPT_ELEMENT_SIZE, 0xcd);
        s << data;
    }
    ScriptError err;
    BOOST_CHECK(!RunBare(s, CSFS_ON, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_STACK_SIZE);
}

BOOST_AUTO_TEST_CASE(stack_bytes_cap_not_hit_under_budget)
{
    // 80 × 3072 B = 245760 B ≤ MAX_STACK_BYTES (262144 B); fits.
    // Leave the last 3072 B blob on top — it's all 0xcd bytes, so truthy.
    CScript s;
    for (int i = 0; i < 80; ++i) {
        std::vector<unsigned char> data(MAX_PQ_SCRIPT_ELEMENT_SIZE, 0xcd);
        s << data;
    }
    for (int i = 0; i < 79; ++i) s << OP_DROP;
    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(RunBare(s, CSFS_ON, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(stack_bytes_cap_not_enforced_without_csfs)
{
    // Without CSFS the cap is not applied. Pile up 520 × 520 B = 270400 B
    // of stack (above MAX_STACK_BYTES) and confirm it is accepted. Item
    // count 520 stays within MAX_STACK_SIZE (1000).
    CScript s;
    for (int i = 0; i < 520; ++i) {
        std::vector<unsigned char> data(MAX_SCRIPT_ELEMENT_SIZE, 0xef);
        s << data;
    }
    for (int i = 0; i < 519; ++i) s << OP_DROP;
    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(RunBare(s, CSFS_OFF, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
}

// ---------------------------------------------------------------------------
// Boundary confirmation: the helper returns the expected value.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(effective_helper_returns_pq_under_csfs)
{
    BOOST_CHECK_EQUAL(EffectiveMaxScriptElementSize(CSFS_ON), MAX_PQ_SCRIPT_ELEMENT_SIZE);
}

BOOST_AUTO_TEST_CASE(effective_helper_returns_legacy_without_csfs)
{
    BOOST_CHECK_EQUAL(EffectiveMaxScriptElementSize(CSFS_OFF), MAX_SCRIPT_ELEMENT_SIZE);
}

BOOST_AUTO_TEST_SUITE_END()
