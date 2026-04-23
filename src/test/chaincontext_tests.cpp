// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for NIP-026: OP_CHAINCONTEXT.

#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "primitives/transaction.h"
#include "test/test_neurai.h"

#include <cstring>
#include <vector>

#include <boost/test/unit_test.hpp>

// Positive tests require CHAINCONTEXT + 64BIT co-activated — that
// pairing is the consensus invariant (NIP-026 §3.4 / §3.7), and the
// handler rejects a mis-configured flag set at runtime.
static constexpr script_verify_flags CC_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS
    | SCRIPT_VERIFY_CHAINCONTEXT | SCRIPT_VERIFY_64BIT_INTEGERS;
static constexpr script_verify_flags CC_FLAGS_DISCOURAGE =
    CC_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
static constexpr script_verify_flags CC_FLAGS_NO_64BIT =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CHAINCONTEXT;
static constexpr script_verify_flags NO_CC_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
static constexpr script_verify_flags NO_CC_FLAGS_DISCOURAGE =
    NO_CC_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;

namespace {

// Mock checker that synthesises a ChainContext response without any
// transaction or chain state. Drives the handler directly.
class MockChainChecker : public BaseSignatureChecker
{
public:
    MockChainChecker(int64_t h, int64_t m, uint8_t id, bool avail = true)
        : m_height(h), m_mtp(m), m_chainId(id), m_available(avail) {}

    bool GetChainContext(unsigned char selector, int64_t& result) const override
    {
        if (!m_available) return false;
        switch (selector) {
            case 0x01: result = m_height;  return true;
            case 0x02: result = m_mtp;     return true;
            case 0x03: result = (int64_t)m_chainId; return true;
            default: return false;
        }
    }
private:
    int64_t m_height;
    int64_t m_mtp;
    uint8_t m_chainId;
    bool m_available;
};

bool RunScript(const BaseSignatureChecker& checker, const CScript& script,
               script_verify_flags flags,
               std::vector<std::vector<unsigned char>>& resultStack,
               ScriptError* errOut = nullptr)
{
    ScriptError serror = SCRIPT_ERR_OK;
    std::vector<std::vector<unsigned char>> stack;
    bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_BASE, &serror);
    if (errOut) *errOut = serror;
    resultStack = stack;
    return ok;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(chaincontext_tests, BasicTestingSetup)

// --- Positive cases ---

BOOST_AUTO_TEST_CASE(ChainContext_Height_PushesExpectedValue)
{
    MockChainChecker checker(1500, 1'700'000'000, 0);
    CScript script = CScript() << std::vector<unsigned char>{0x01} << OP_CHAINCONTEXT;
    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(RunScript(checker, script, CC_FLAGS, stack));
    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
    BOOST_CHECK(stack[0] == CScriptNum(1500).getvch());
    BOOST_CHECK(checker.fChainContextObserved);
}

BOOST_AUTO_TEST_CASE(ChainContext_Mtp_PushesExpectedValue_Post2038)
{
    // Unix seconds past 2^31 — must round-trip through a CScriptNum wider
    // than 4 bytes, proving the 64-bit path is active.
    const int64_t mtp = 2'200'000'000LL;
    MockChainChecker checker(10, mtp, 1);
    CScript script = CScript() << std::vector<unsigned char>{0x02} << OP_CHAINCONTEXT;
    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(RunScript(checker, script, CC_FLAGS, stack));
    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
    BOOST_CHECK(stack[0] == CScriptNum(mtp).getvch());
    // Proves the encoding is >4 bytes — would be unusable without the
    // 64-bit flag.
    BOOST_CHECK(stack[0].size() > 4);
}

BOOST_AUTO_TEST_CASE(ChainContext_ChainId_PushesExpectedValue)
{
    for (uint8_t id : {uint8_t(0), uint8_t(1), uint8_t(2)}) {
        MockChainChecker checker(0, 0, id);
        CScript script = CScript() << std::vector<unsigned char>{0x03} << OP_CHAINCONTEXT;
        std::vector<std::vector<unsigned char>> stack;
        BOOST_CHECK(RunScript(checker, script, CC_FLAGS, stack));
        BOOST_REQUIRE_EQUAL(stack.size(), 1U);
        BOOST_CHECK(stack[0] == CScriptNum((int64_t)id).getvch());
    }
}

BOOST_AUTO_TEST_CASE(ChainContext_Height_ArithmeticRoundTrip)
{
    // Proves the pushed value composes with arithmetic opcodes under
    // the 64-bit flag — this is the whole reason 64BIT is a hard dep.
    MockChainChecker checker(100, 0, 0);
    // <1>     OP_CHAINCONTEXT    // → 100
    // OP_1 OP_ADD                 // → 101
    // <200> OP_LESSTHAN           // 101 < 200? → 1 (true)
    CScript script = CScript()
        << std::vector<unsigned char>{0x01} << OP_CHAINCONTEXT
        << OP_1 << OP_ADD
        << CScriptNum(200) << OP_LESSTHAN;
    std::vector<std::vector<unsigned char>> stack;
    BOOST_CHECK(RunScript(checker, script, CC_FLAGS, stack));
    BOOST_REQUIRE_EQUAL(stack.size(), 1U);
    BOOST_CHECK(stack[0] == CScriptNum(1).getvch());
}

// --- Selector validation ---

BOOST_AUTO_TEST_CASE(ChainContext_BadSelector_0x00_Fails)
{
    MockChainChecker checker(10, 0, 0);
    CScript script = CScript() << std::vector<unsigned char>{0x00} << OP_CHAINCONTEXT;
    std::vector<std::vector<unsigned char>> stack;
    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(!RunScript(checker, script, CC_FLAGS, stack, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_CHAINCONTEXT_BAD_SELECTOR);
}

BOOST_AUTO_TEST_CASE(ChainContext_BadSelector_0x04_Fails)
{
    MockChainChecker checker(10, 0, 0);
    CScript script = CScript() << std::vector<unsigned char>{0x04} << OP_CHAINCONTEXT;
    std::vector<std::vector<unsigned char>> stack;
    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(!RunScript(checker, script, CC_FLAGS, stack, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_CHAINCONTEXT_BAD_SELECTOR);
}

BOOST_AUTO_TEST_CASE(ChainContext_SelectorMultiByte_Fails)
{
    MockChainChecker checker(10, 0, 0);
    CScript script = CScript() << std::vector<unsigned char>{0x01, 0x00} << OP_CHAINCONTEXT;
    std::vector<std::vector<unsigned char>> stack;
    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(!RunScript(checker, script, CC_FLAGS, stack, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_CHAINCONTEXT_BAD_SELECTOR);
}

BOOST_AUTO_TEST_CASE(ChainContext_EmptyStack_Fails)
{
    MockChainChecker checker(10, 0, 0);
    CScript script = CScript() << OP_CHAINCONTEXT;
    std::vector<std::vector<unsigned char>> stack;
    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(!RunScript(checker, script, CC_FLAGS, stack, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

// --- Fail-closed path (no context) ---

BOOST_AUTO_TEST_CASE(ChainContext_NoContext_Fails)
{
    MockChainChecker checker(0, 0, 0, /*avail=*/false);
    CScript script = CScript() << std::vector<unsigned char>{0x01} << OP_CHAINCONTEXT;
    std::vector<std::vector<unsigned char>> stack;
    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(!RunScript(checker, script, CC_FLAGS, stack, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_CHAINCONTEXT);
    BOOST_CHECK(!checker.fChainContextObserved);
}

// --- Critical: flag-off MUST fail with BAD_OPCODE (no NOP short-circuit) ---

BOOST_AUTO_TEST_CASE(ChainContext_FlagOff_FailsBadOpcode)
{
    // The single most load-bearing test: proves the handler does not
    // fall into the NOP short-circuit pattern of NIPs 023/024.
    //
    // 0xd7 is a newly allocated opcode byte, so pre-upgrade nodes reject
    // it via the EvalScript `default:` branch (SCRIPT_ERR_BAD_OPCODE).
    // An upgraded but not-yet-activated node must match that, or any
    // mainnet tx containing 0xd7 would be consensus-split between
    // upgraded and pre-upgrade nodes. DISCOURAGE_UPGRADABLE_NOPS is
    // policy-only and cannot protect against a mined block.
    MockChainChecker checker(10, 0, 0);
    CScript script = CScript() << std::vector<unsigned char>{0x01} << OP_CHAINCONTEXT;
    std::vector<std::vector<unsigned char>> stack;
    ScriptError err = SCRIPT_ERR_OK;

    // Flag off, DISCOURAGE off → still fails with BAD_OPCODE.
    BOOST_CHECK(!RunScript(checker, script, NO_CC_FLAGS, stack, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);

    // Flag off, DISCOURAGE on → identical error (not DISCOURAGE_NOPS).
    BOOST_CHECK(!RunScript(checker, script, NO_CC_FLAGS_DISCOURAGE, stack, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(ChainContext_No64BitIntegers_Fails)
{
    // Runtime belt-and-braces for the ApplyConsensusOptIns co-set.
    // If someone calls EvalScript directly with CHAINCONTEXT set but
    // 64BIT unset, the handler refuses rather than pushing a value no
    // downstream opcode can consume.
    MockChainChecker checker(10, 0, 0);
    CScript script = CScript() << std::vector<unsigned char>{0x01} << OP_CHAINCONTEXT;
    std::vector<std::vector<unsigned char>> stack;
    ScriptError err = SCRIPT_ERR_OK;
    BOOST_CHECK(!RunScript(checker, script, CC_FLAGS_NO_64BIT, stack, &err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_CHAINCONTEXT);
}

// --- DEX expire end-to-end at the deadline boundary ---

BOOST_AUTO_TEST_CASE(ChainContext_DexExpire_EndToEnd)
{
    // Idiom from NIP-026 §10: `<deadline> HEIGHT OP_CHAINCONTEXT
    //                         OP_GREATERTHAN OP_VERIFY`.
    //
    // With strict OP_GREATERTHAN, the fill is valid only while
    // `deadline > height`. Boundary check:
    //   height = deadline - 1 → valid
    //   height = deadline     → invalid (deadline block is already past)
    //   height = deadline + 1 → invalid
    const int64_t deadline = 1000;
    auto build_script = [&]() {
        return CScript()
            << CScriptNum(deadline)
            << std::vector<unsigned char>{0x01} << OP_CHAINCONTEXT
            << OP_GREATERTHAN
            << OP_VERIFY
            << OP_1;
    };

    // Accepted one block before deadline.
    {
        MockChainChecker checker(deadline - 1, 0, 0);
        std::vector<std::vector<unsigned char>> stack;
        BOOST_CHECK(RunScript(checker, build_script(), CC_FLAGS, stack));
    }
    // Rejected at deadline (boundary is past).
    {
        MockChainChecker checker(deadline, 0, 0);
        std::vector<std::vector<unsigned char>> stack;
        ScriptError err = SCRIPT_ERR_OK;
        BOOST_CHECK(!RunScript(checker, build_script(), CC_FLAGS, stack, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_VERIFY);
    }
    // Rejected past deadline.
    {
        MockChainChecker checker(deadline + 1, 0, 0);
        std::vector<std::vector<unsigned char>> stack;
        ScriptError err = SCRIPT_ERR_OK;
        BOOST_CHECK(!RunScript(checker, build_script(), CC_FLAGS, stack, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_VERIFY);
    }
}

BOOST_AUTO_TEST_SUITE_END()
