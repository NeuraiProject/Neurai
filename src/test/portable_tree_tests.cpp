// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#include "chainparams.h"
#include "crypto/public_tree_transition.h"
#include "policy/policy.h"
#include "script/interpreter.h"
#include "test/test_neurai.h"
#include "test/data/c6_public_tree.json.h"
#include "test/data/groth16_vectors.h"
#include "utilstrencodings.h"
#include <boost/test/unit_test.hpp>
#include <univalue.h>

namespace {
using Bytes = std::vector<unsigned char>;
using Stack = std::vector<Bytes>;
const auto FLAGS = SCRIPT_VERIFY_ZKVERIFY | SCRIPT_VERIFY_ZK_PORTABLE_TREE | SCRIPT_VERIFY_POSEIDON_WORK;
UniValue Fixtures()
{
    UniValue v;
    if (!v.read(std::string(json_tests::c6_public_tree, json_tests::c6_public_tree + sizeof(json_tests::c6_public_tree))))
        throw std::runtime_error("invalid C6 public fixtures");
    return v["forms"];
}
Stack Arguments(const UniValue& f)
{
    Stack stack{ParseHex(f["old"].get_str()), ParseHex(f["new"].get_str())};
    const auto raw = ParseHex(f["transcript"].get_str());
    for (size_t i = 0; i < 5; ++i) {
        const size_t a = std::min(i * 3072, raw.size()), b = std::min((i+1) * 3072, raw.size());
        stack.emplace_back(raw.begin()+a, raw.begin()+b);
    }
    stack.push_back(CScriptNum(f["form"].get_int()).getvch());
    // Empty proof deliberately cannot authorize a spend. The public predicate
    // must still run and charge its budget before returning false.
    stack.push_back({}); stack.push_back({});
    for (const auto& input : f["public"].getValues()) stack.push_back(ParseHex(input.get_str()));
    stack.push_back(CScriptNum(f["public"].size()).getvch()); stack.push_back({3});
    return stack;
}
ScriptError Run(Stack stack, script_verify_flags flags = FLAGS, uint64_t cap = 20000,
                uint64_t* charged = nullptr, bool requireProof = false,
                unsigned repetitions = 1)
{
    PoseidonWorkBudget budget(cap);
    BaseSignatureChecker checker; checker.poseidonWorkBudget = &budget;
    ScriptExecutionCost cost; ScriptError error;
    CScript script;
    for (unsigned i = 1; i < repetitions; ++i) script << OP_ZKVERIFY << OP_DROP;
    script << OP_ZKVERIFY;
    if (requireProof) script << OP_VERIFY;
    const bool ok = EvalScript(stack, script, flags, checker, SIGVERSION_AUTHSCRIPT, &error, nullptr, &cost);
    BOOST_CHECK_EQUAL(ok, error == SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(cost.poseidon_permutations, budget.Used());
    if (ok) BOOST_CHECK(stack == Stack{Bytes{}});
    if (charged) *charged = budget.Used();
    return error;
}
}

BOOST_FIXTURE_TEST_SUITE(portable_tree_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(public_predicate_is_not_authorization)
{
    const auto fixtures = Fixtures();
    for (const auto& f : fixtures.getValues()) {
        const auto raw = ParseHex(f["transcript"].get_str());
        const auto form = f["form"].get_int();
        Bytes inputs; for (const auto& x : f["public"].getValues()) {
            auto value = ParseHex(x.get_str()); inputs.insert(inputs.end(), value.begin(), value.end());
        }
        size_t cost = 0;
        BOOST_REQUIRE(neurai::public_tree::PortableTransitionCost(raw, form, cost));
        BOOST_CHECK(neurai::public_tree::VerifyPortableTransition(raw, form,
                    ParseHex(f["old"].get_str()), ParseHex(f["new"].get_str()), inputs));
        uint64_t charged = 0;
        const auto stack = Arguments(f);
        BOOST_CHECK(Run(stack, FLAGS, cost, &charged) == SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(charged, cost);
        BOOST_CHECK(Run(stack, FLAGS, cost, nullptr, true) == SCRIPT_ERR_VERIFY);
        BOOST_CHECK(Run(stack, FLAGS, cost-1) == SCRIPT_ERR_POSEIDON_WORK_BUDGET);
        auto bad = stack; bad[8] = ParseHex(groth16_vectors::PROOF);
        // Correct public transition cannot excuse missing/invalid Groth16 VK.
        BOOST_CHECK(Run(bad) == SCRIPT_ERR_ZK_VK_ENCODING);
        bad[9] = ParseHex(groth16_vectors::VK);
        BOOST_CHECK(Run(bad) != SCRIPT_ERR_OK);
    }
}

BOOST_AUTO_TEST_CASE(binding_chunks_and_profile_separation)
{
    const auto fixtures = Fixtures();
    for (const auto& f : fixtures.getValues()) {
        auto stack = Arguments(f);
        for (size_t i = 0; i < 2; ++i) {
            auto bad = stack; bad[i].back() ^= 1;
            BOOST_CHECK(Run(bad) == SCRIPT_ERR_ZK_PUBLIC_TREE);
            bad = stack; bad[i].resize(31);
            BOOST_CHECK(Run(bad) == SCRIPT_ERR_ZK_PUBLIC_TREE);
        }
        auto bad = stack; std::swap(bad[0], bad[1]);
        BOOST_CHECK(Run(bad) == SCRIPT_ERR_ZK_PUBLIC_TREE);
        bad = stack; bad[2][0] = 1;
        BOOST_CHECK(Run(bad) == SCRIPT_ERR_ZK_PUBLIC_TREE);
        bad = stack; bad[7] = {9};
        BOOST_CHECK(Run(bad) == SCRIPT_ERR_ZK_PUBLIC_TREE);
        bad = stack; bad[2].pop_back();
        BOOST_CHECK(Run(bad) == SCRIPT_ERR_ZK_PUBLIC_TREE);
        bad = stack; bad[6].push_back(0);
        BOOST_CHECK(Run(bad) == SCRIPT_ERR_ZK_PUBLIC_TREE);
        bad = stack; bad.back() = {2};
        BOOST_CHECK(Run(bad, FLAGS | SCRIPT_VERIFY_ZK_PUBLIC_TREE) == SCRIPT_ERR_ZK_PUBLIC_TREE);
        BOOST_CHECK(Run(stack, FLAGS & ~SCRIPT_VERIFY_ZK_PORTABLE_TREE) == SCRIPT_ERR_ZK_BAD_PROFILE);
        BOOST_CHECK(Run(stack, FLAGS & ~SCRIPT_VERIFY_POSEIDON_WORK) == SCRIPT_ERR_ZK_BAD_PROFILE);
        BOOST_CHECK(Run(stack, FLAGS & ~SCRIPT_VERIFY_ZKVERIFY) == SCRIPT_ERR_BAD_OPCODE);
        for (size_t n = 0; n < 10; ++n) {
            bad = stack; bad.resize(n);
            BOOST_CHECK(Run(bad) != SCRIPT_ERR_OK);
        }
    }
}

BOOST_AUTO_TEST_CASE(independent_height_gate)
{
    Consensus::Params params;
    params.nZKVerifyHeight = 0; params.nPoseidonWorkHeight = 0;
    params.nZKPortableTreeHeight = 120;
    BOOST_CHECK(!(ApplyConsensusOptIns(SCRIPT_VERIFY_NONE, params, false, 119) & SCRIPT_VERIFY_ZK_PORTABLE_TREE));
    BOOST_CHECK(ApplyConsensusOptIns(SCRIPT_VERIFY_NONE, params, false, 120) & SCRIPT_VERIFY_ZK_PORTABLE_TREE);
    params.nPoseidonWorkHeight = 121;
    BOOST_CHECK(!(ApplyConsensusOptIns(SCRIPT_VERIFY_NONE, params, false, 120) & SCRIPT_VERIFY_ZK_PORTABLE_TREE));
    BOOST_CHECK(CONSENSUS_OPT_IN_FLAGS & SCRIPT_VERIFY_ZK_PORTABLE_TREE);
}

BOOST_AUTO_TEST_CASE(network_activation_schedule)
{
    const auto testnet = CreateChainParams(CBaseChainParams::TESTNET);
    const auto& params = testnet->GetConsensus();
    BOOST_CHECK_EQUAL(params.nZKPortableTreeHeight, 100);
    BOOST_CHECK(!params.IsZKPortableTreeActive(99));
    BOOST_CHECK(params.IsZKPortableTreeActive(100));
    for (const int height : {99, 100, 101}) {
        const auto flags = ApplyConsensusOptIns(SCRIPT_VERIFY_NONE, params,
            params.IsStrictAuthScriptActive(height), height);
        BOOST_CHECK_EQUAL(bool(flags & SCRIPT_VERIFY_ZK_PORTABLE_TREE), height >= 100);
        // C6 activation must not move the existing C5 height gate.
        BOOST_CHECK(flags & SCRIPT_VERIFY_ZK_PUBLIC_TREE);
    }
    const auto mainnet = CreateChainParams(CBaseChainParams::MAIN);
    BOOST_CHECK(!mainnet->GetConsensus().IsZKPortableTreeActive(1000000));
    const auto regtest = CreateChainParams(CBaseChainParams::REGTEST);
    BOOST_CHECK(regtest->GetConsensus().IsZKPortableTreeActive(0));
}

BOOST_AUTO_TEST_CASE(join_sequential_budget_and_profile_boundary)
{
    bool found = false;
    const auto fixtures = Fixtures();
    for (const auto& fixture : fixtures.getValues()) {
        if (fixture["form"].get_int() != 8) continue;
        found = true;
        const auto stack = Arguments(fixture);
        uint64_t charged = 0;
        BOOST_CHECK(Run(stack, FLAGS, 568, &charged) == SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(charged, 568);
        BOOST_CHECK(Run(stack, FLAGS, 567) == SCRIPT_ERR_POSEIDON_WORK_BUDGET);
        Stack twice = stack;
        twice.insert(twice.end(), stack.begin(), stack.end());
        BOOST_CHECK(Run(twice, FLAGS, 20000, &charged, false, 2) == SCRIPT_ERR_ZK_PUBLIC_TREE_BUDGET);
        BOOST_CHECK_EQUAL(charged, 568);
        auto wrong = stack;
        wrong.back() = {2};
        BOOST_CHECK(Run(wrong, FLAGS | SCRIPT_VERIFY_ZK_PUBLIC_TREE) == SCRIPT_ERR_ZK_PUBLIC_TREE);
        wrong = stack;
        wrong[2][0] = 2; // A legacy profile-3 transcript cannot select J2.
        BOOST_CHECK(Run(wrong) == SCRIPT_ERR_ZK_PUBLIC_TREE);
    }
    BOOST_REQUIRE(found);
}

BOOST_AUTO_TEST_CASE(aggregate_leaf_budget_does_not_reset)
{
    const auto fixtures = Fixtures();
    const auto args = Arguments(fixtures[0]);
    Stack stack;
    // D costs 269. Three invocations fit; four exceed the same leaf's 1024
    // allowance even when the transaction budget has ample remaining work.
    for (unsigned i = 0; i < 3; ++i) stack.insert(stack.end(), args.begin(), args.end());
    uint64_t charged = 0;
    BOOST_CHECK(Run(stack, FLAGS, 20000, &charged, false, 3) == SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(charged, 3 * 269);
    stack.insert(stack.end(), args.begin(), args.end());
    BOOST_CHECK(Run(stack, FLAGS, 20000, &charged, false, 4) == SCRIPT_ERR_ZK_PUBLIC_TREE_BUDGET);
    BOOST_CHECK_EQUAL(charged, 3 * 269);
}

BOOST_AUTO_TEST_SUITE_END()
