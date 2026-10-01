// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#include "chainparams.h"
#include "crypto/public_tree_transition.h"
#include "policy/policy.h"
#include "script/interpreter.h"
#include "test/test_neurai.h"
#include "test/data/c5_public_tree.json.h"
#include "utilstrencodings.h"
#include <boost/test/unit_test.hpp>
#include <univalue.h>

namespace {
using Bytes = std::vector<unsigned char>;
using Stack = std::vector<Bytes>;
const auto FLAGS = SCRIPT_VERIFY_ZKVERIFY | SCRIPT_VERIFY_ZK_PUBLIC_TREE | SCRIPT_VERIFY_POSEIDON_WORK;
UniValue Fixtures()
{
    UniValue value;
    if (!value.read(std::string(json_tests::c5_public_tree, json_tests::c5_public_tree + sizeof(json_tests::c5_public_tree))))
        throw std::runtime_error("invalid C5 TEST fixtures");
    return value["forms"];
}
Stack Arguments(const UniValue& fixture)
{
    const auto transcript = ParseHex(fixture["transcript"].get_str());
    Stack stack;
    for (size_t i = 0; i < 5; ++i) {
        const size_t begin = std::min(i * 3072, transcript.size());
        const size_t end = std::min((i + 1) * 3072, transcript.size());
        stack.emplace_back(transcript.begin() + begin, transcript.begin() + end);
    }
    stack.push_back(CScriptNum(fixture["code"].get_int()).getvch());
    stack.push_back(ParseHex(fixture["proof"].get_str()));
    stack.push_back(ParseHex(fixture["vk"].get_str()));
    const auto inputs = ParseHex(fixture["inputs"].get_str());
    for (size_t i = 0; i < inputs.size(); i += 32)
        stack.emplace_back(inputs.begin() + i, inputs.begin() + i + 32);
    stack.push_back(CScriptNum(inputs.size() / 32).getvch());
    stack.push_back({2});
    return stack;
}
ScriptError Run(Stack stack, script_verify_flags flags = FLAGS, uint64_t cap = 20000,
                uint64_t* charged = nullptr, const CScript& script = CScript() << OP_ZKVERIFY << OP_VERIFY << OP_TRUE)
{
    PoseidonWorkBudget budget(cap);
    BaseSignatureChecker checker; checker.poseidonWorkBudget = &budget;
    ScriptExecutionCost cost;
    ScriptError error;
    const bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_AUTHSCRIPT, &error, nullptr, &cost);
    BOOST_CHECK_EQUAL(ok, error == SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(cost.poseidon_permutations, budget.Used());
    if (ok) BOOST_CHECK(stack == Stack{Bytes{1}});
    if (charged) *charged = budget.Used();
    return error;
}
}

BOOST_FIXTURE_TEST_SUITE(public_tree_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(all_real_proofs_require_both_predicates)
{
    const auto fixtures = Fixtures();
    for (const auto& fixture : fixtures.getValues()) {
        const auto stack = Arguments(fixture);
        BOOST_CHECK(Run(stack) == SCRIPT_ERR_OK);
        auto bad = stack; bad[0][300] ^= 1;
        BOOST_CHECK(Run(bad) == SCRIPT_ERR_ZK_PUBLIC_TREE);
        bad = stack; bad[6].clear();
        BOOST_CHECK(Run(bad) == SCRIPT_ERR_VERIFY);
        bad = stack; bad[6][0] ^= 1;
        BOOST_CHECK(Run(bad) != SCRIPT_ERR_OK);
        bad = stack; bad[6] = ParseHex(fixture["c4proof"].get_str());
        BOOST_CHECK(Run(bad) != SCRIPT_ERR_OK);
        bad = stack; bad[7] = ParseHex(fixture["c4vk"].get_str());
        BOOST_CHECK(Run(bad) != SCRIPT_ERR_OK);
        for (size_t i = 0; i < 6; ++i) {
            bad = stack; bad.erase(bad.begin() + i);
            BOOST_CHECK(Run(bad) == SCRIPT_ERR_ZK_STACK_SIZE);
        }
        for (size_t i = 8; i < stack.size() - 2; ++i) {
            bad = stack; bad[i].back() ^= 1;
            BOOST_CHECK(Run(bad) != SCRIPT_ERR_OK);
        }
    }
}

BOOST_AUTO_TEST_CASE(canonical_chunking_form_and_precharge)
{
    const auto fixtures = Fixtures();
    for (const auto& fixture : fixtures.getValues()) {
        const auto stack = Arguments(fixture);
        const auto transcript = ParseHex(fixture["transcript"].get_str());
        size_t cost = 0;
        BOOST_REQUIRE(neurai::public_tree::TransitionCost(transcript, fixture["code"].get_int(), cost));
        uint64_t charged;
        BOOST_CHECK(Run(stack, FLAGS, cost, &charged) == SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(charged, cost);
        BOOST_CHECK(Run(stack, FLAGS, cost - 1, &charged) == SCRIPT_ERR_POSEIDON_WORK_BUDGET);
        BOOST_CHECK_EQUAL(charged, 0U);
        auto bad = stack; bad[0][300] ^= 1;
        BOOST_CHECK(Run(bad, FLAGS, cost, &charged) == SCRIPT_ERR_ZK_PUBLIC_TREE);
        BOOST_CHECK_EQUAL(charged, cost);
        bad = stack; bad[0].push_back(0);
        BOOST_CHECK(Run(bad) == SCRIPT_ERR_ZK_PUBLIC_TREE);
        bad = stack; bad[5] = {8};
        BOOST_CHECK(Run(bad) == SCRIPT_ERR_ZK_PUBLIC_TREE);
        bad = stack; bad[5] = {0,0};
        BOOST_CHECK(Run(bad) == SCRIPT_ERR_ZK_PUBLIC_TREE);
        bad = stack; bad[4].push_back(0);
        BOOST_CHECK(Run(bad) == SCRIPT_ERR_ZK_PUBLIC_TREE);
    }
}

BOOST_AUTO_TEST_CASE(activation_and_profile_one_are_separate)
{
    const auto fixtures = Fixtures();
    for (const auto& fixture : fixtures.getValues()) {
        auto stack = Arguments(fixture);
        BOOST_CHECK(Run(stack, FLAGS & ~SCRIPT_VERIFY_ZK_PUBLIC_TREE) == SCRIPT_ERR_ZK_BAD_PROFILE);
        BOOST_CHECK(Run(stack, FLAGS & ~SCRIPT_VERIFY_POSEIDON_WORK) == SCRIPT_ERR_ZK_BAD_PROFILE);
        stack.erase(stack.begin(), stack.begin() + 6); stack.back() = {1};
        // A raw C5 proof is still a valid Groth16 proof. The C5 custody leaf
        // MUST pin profile 2. Changing it changes the MAST commitment.
        BOOST_CHECK(Run(stack, FLAGS & ~SCRIPT_VERIFY_ZK_PUBLIC_TREE) == SCRIPT_ERR_OK);
    }
    Consensus::Params params;
    params.nZKVerifyHeight = 1; params.nPoseidonWorkHeight = 1; params.nZKPublicTreeHeight = 120;
    BOOST_CHECK(!(ApplyConsensusOptIns(SCRIPT_VERIFY_NONE, params, false, 119) & SCRIPT_VERIFY_ZK_PUBLIC_TREE));
    BOOST_CHECK(ApplyConsensusOptIns(SCRIPT_VERIFY_NONE, params, false, 120) & SCRIPT_VERIFY_ZK_PUBLIC_TREE);
    BOOST_CHECK(!CreateChainParams(CBaseChainParams::MAIN)->GetConsensus().IsZKPublicTreeActive(1000000));
    const auto testnet = CreateChainParams(CBaseChainParams::TESTNET)->GetConsensus();
    BOOST_CHECK(!testnet.IsZKPublicTreeActive(9));
    BOOST_CHECK(testnet.IsZKPublicTreeActive(10));
    BOOST_CHECK(!(ApplyConsensusOptIns(SCRIPT_VERIFY_NONE, testnet, false, 9) & SCRIPT_VERIFY_ZK_PUBLIC_TREE));
    BOOST_CHECK(ApplyConsensusOptIns(SCRIPT_VERIFY_NONE, testnet, true, 10) & SCRIPT_VERIFY_ZK_PUBLIC_TREE);
}

BOOST_AUTO_TEST_SUITE_END()
