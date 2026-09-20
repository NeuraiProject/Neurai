// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license.
#include "chainparams.h"
#include "crypto/poseidon_bn254.h"
#include "script/interpreter.h"
#include "policy/policy.h"
#include "test/test_neurai.h"
#include "utilstrencodings.h"
#include <boost/test/unit_test.hpp>
#include <algorithm>
#include <limits>

namespace {
using Bytes = std::vector<unsigned char>;
struct Setup : BasicTestingSetup { Setup():BasicTestingSetup(CBaseChainParams::REGTEST){} };
bool Run(std::vector<Bytes> stack, const CScript& script, script_verify_flags flags, SigVersion version, ScriptError& err) {
    return EvalScript(stack,script,flags,BaseSignatureChecker(),version,&err);
}
}
BOOST_FIXTURE_TEST_SUITE(authscript_budget_tests,Setup)
BOOST_AUTO_TEST_CASE(poseidon_permutation_cost_boundaries)
{
    // Independent chunk absorption model, including a padding-only chunk.
    for (size_t len = 0; len <= 3072; ++len) {
        size_t chunks = 1;
        for (size_t left = len; left >= 31; left -= 31) ++chunks;
        size_t permutations = 0;
        while (chunks) { chunks -= std::min(size_t{2}, chunks); ++permutations; }
        BOOST_CHECK_EQUAL(crypto::PoseidonPermutationCost(len), permutations);
    }
    BOOST_CHECK_EQUAL(crypto::PoseidonPermutationCost(std::numeric_limits<size_t>::max()),
                      std::numeric_limits<size_t>::max() / 62 + 1);
    const auto flags = GetStandardScriptVerifyFlagsWithConsensusOptIns(GetParams().GetConsensus());
    for (size_t len : {0, 1, 30, 31, 32, 61, 62, 63, 123, 124, 520, 3072}) {
        std::vector<Bytes> stack{Bytes(len, 0x42)}, control = stack;
        ScriptExecutionCost cost;
        ScriptError err, controlErr;
        const CScript script = CScript() << OP_POSEIDON;
        BOOST_REQUIRE(EvalScript(stack, script, flags, BaseSignatureChecker(), SIGVERSION_AUTHSCRIPT, &err, nullptr, &cost));
        BOOST_REQUIRE(EvalScript(control, script, flags, BaseSignatureChecker(), SIGVERSION_AUTHSCRIPT, &controlErr));
        BOOST_CHECK(stack == control);
        BOOST_CHECK_EQUAL(err, controlErr);
        BOOST_CHECK_EQUAL(cost.poseidon_permutations, len / 62 + 1);
    }
}

BOOST_AUTO_TEST_CASE(poseidon_work_dense_chain_and_reset)
{
    const auto flags = GetStandardScriptVerifyFlagsWithConsensusOptIns(GetParams().GetConsensus());
    ScriptExecutionCost cost;
    ScriptError err;
    std::vector<Bytes> stack{Bytes{}};
    CScript script;
    for (int i = 0; i < 511; ++i) script << OP_POSEIDON;
    script << OP_DROP << OP_TRUE;
    BOOST_REQUIRE(EvalScript(stack, script, flags, BaseSignatureChecker(), SIGVERSION_AUTHSCRIPT, &err, nullptr, &cost));
    BOOST_CHECK_EQUAL(cost.poseidon_permutations, 511);
    // Execution, not static opcode count: dead branches contribute nothing.
    script = CScript() << OP_0 << OP_IF << OP_POSEIDON << OP_ENDIF << OP_TRUE;
    stack.clear();
    BOOST_REQUIRE(EvalScript(stack, script, flags, BaseSignatureChecker(), SIGVERSION_AUTHSCRIPT, &err, nullptr, &cost));
    BOOST_CHECK_EQUAL(cost.poseidon_permutations, 0);
    for (bool enabled : {false, true}) {
        cost.poseidon_permutations = 999;
        stack.clear();
        BOOST_CHECK(!EvalScript(stack, CScript() << OP_POSEIDON, enabled ? flags : flags & ~SCRIPT_VERIFY_POSEIDON,
                                BaseSignatureChecker(), SIGVERSION_AUTHSCRIPT, &err, nullptr, &cost));
        BOOST_CHECK_EQUAL(err, enabled ? SCRIPT_ERR_INVALID_STACK_OPERATION : SCRIPT_ERR_BAD_OPCODE);
        BOOST_CHECK_EQUAL(cost.poseidon_permutations, 0);
    }
    // Existing byte guard rejects the eleventh large hash before any work.
    stack.assign(11, Bytes(3072));
    script.clear();
    for (int i = 0; i < 11; ++i) script << OP_POSEIDON << OP_DROP;
    BOOST_CHECK(!EvalScript(stack, script, flags, BaseSignatureChecker(), SIGVERSION_AUTHSCRIPT, &err, nullptr, &cost));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_POSEIDON_BUDGET);
    BOOST_CHECK_EQUAL(cost.poseidon_permutations, 500);
    // A subsequent invocation is independent, even after a failed script.
    stack = {Bytes{}};
    BOOST_REQUIRE(EvalScript(stack, CScript() << OP_POSEIDON, flags, BaseSignatureChecker(), SIGVERSION_AUTHSCRIPT, &err, nullptr, &cost));
    BOOST_CHECK_EQUAL(cost.poseidon_permutations, 1);
}

BOOST_AUTO_TEST_CASE(poseidon_work_merkle_and_sponge_share_units)
{
    const auto flags = GetStandardScriptVerifyFlagsWithConsensusOptIns(GetParams().GetConsensus());
    for (int depth : {1, 2, 8, 32}) {
        Bytes proof(1 + 32 * depth + (depth + 7) / 8);
        proof[0] = depth;
        Bytes root(32), zero(32);
        for (int i = 0; i < depth; ++i) {
            Bytes next(32);
            BOOST_REQUIRE(crypto::PoseidonMerkleNode(root.data(), zero.data(), next.data()));
            root = next;
        }
        // Good, wrong root, noncanonical leaf, truncated proof, bad depth,
        // unavailable scheme, wrong root length. Early-invalid shaped proofs
        // deliberately pay the full depth; this is not a timing profiler.
        for (int variant = 0; variant < 7; ++variant) {
            auto p = proof;
            auto r = root;
            Bytes leaf(32);
            auto vf = flags;
            if (variant == 1) r.assign(32, 0);
            if (variant == 2) leaf.assign(32, 0xff);
            if (variant == 3) p.pop_back();
            if (variant == 4) p[0] = 33;
            if (variant == 5) vf &= ~SCRIPT_VERIFY_MERKLE_POSEIDON;
            if (variant == 6) r.pop_back();
            std::vector<Bytes> stack{leaf, Bytes{5}, p, r, Bytes{}};
            const CScript script = CScript() << OP_POSEIDON << OP_DROP << OP_CHECKMERKLEINCLUSION;
            auto control = stack;
            ScriptExecutionCost cost;
            ScriptError err, controlErr;
            BOOST_REQUIRE(EvalScript(stack, script, vf, BaseSignatureChecker(), SIGVERSION_AUTHSCRIPT, &err, nullptr, &cost));
            BOOST_REQUIRE(EvalScript(control, script, vf, BaseSignatureChecker(), SIGVERSION_AUTHSCRIPT, &controlErr));
            BOOST_CHECK(stack == control);
            BOOST_CHECK(stack.back() == (variant == 0 ? Bytes{1} : Bytes{}));
            BOOST_CHECK_EQUAL(cost.poseidon_permutations, 1 + (variant <= 2 ? depth : 0));
        }
    }
}
BOOST_AUTO_TEST_CASE(op_count_scope_and_dynamic_charges)
{
    const auto flags=GetStandardScriptVerifyFlagsWithConsensusOptIns(GetParams().GetConsensus());
    for (auto version : {SIGVERSION_BASE,SIGVERSION_WITNESS_V0,SIGVERSION_AUTHSCRIPT}) {
        for (bool enabled : {false,true}) for (int n : {201,202,512,513}) {
            CScript script; for(int i=0;i<n;++i)script<<OP_NOP; script<<OP_TRUE;
            auto vf=enabled ? flags|SCRIPT_VERIFY_AUTHSCRIPT_BUDGET : flags&~SCRIPT_VERIFY_AUTHSCRIPT_BUDGET;
            ScriptError err;
            const bool expected=n<=(enabled && version==SIGVERSION_AUTHSCRIPT?512:201);
            BOOST_CHECK_EQUAL(Run({},script,vf,version,err),expected);
            BOOST_CHECK_EQUAL(err,expected?SCRIPT_ERR_OK:SCRIPT_ERR_OP_COUNT);
        }
    }
    CScript dead;dead<<OP_0<<OP_IF;for(int i=0;i<511;++i)dead<<OP_NOP;dead<<OP_ENDIF<<OP_1;
    ScriptError err;BOOST_CHECK(!Run({},dead,flags,SIGVERSION_AUTHSCRIPT,err));BOOST_CHECK_EQUAL(err,SCRIPT_ERR_OP_COUNT);
    // MULTISIG charges one key even when the signature count is zero.
    for(int n : {510,511}) {
        CScript script;for(int i=0;i<n;++i)script<<OP_NOP;
        script<<OP_0<<OP_0<<Bytes(33,2)<<OP_1<<OP_CHECKMULTISIG;
        BOOST_CHECK_EQUAL(Run({},script,flags,SIGVERSION_AUTHSCRIPT,err),n==510);
        BOOST_CHECK_EQUAL(err,n==510?SCRIPT_ERR_OK:SCRIPT_ERR_OP_COUNT);
    }
}
BOOST_AUTO_TEST_CASE(hash_and_initial_memory_boundaries)
{
    const auto flags=GetStandardScriptVerifyFlagsWithConsensusOptIns(GetParams().GetConsensus());
    for(bool enabled : {false,true}) {
        auto vf=enabled?flags:flags&~SCRIPT_VERIFY_AUTHSCRIPT_BUDGET;
        for(int last : {2751,2752,2753}) {
            std::vector<Bytes> stack(20,Bytes(3072,0x42));stack.emplace_back(last,0x42);
            CScript script;for(int i=0;i<21;++i)script<<OP_SHA256<<OP_DROP;script<<OP_1;
            ScriptError err;bool expected=!enabled||last<=2752;
            BOOST_CHECK_EQUAL(Run(stack,script,vf,SIGVERSION_AUTHSCRIPT,err),expected);
            BOOST_CHECK_EQUAL(err,expected?SCRIPT_ERR_OK:SCRIPT_ERR_AUTHSCRIPT_HASH_BUDGET);
        }
        for(int last : {1024,1025}) {
            std::vector<Bytes> stack(85,Bytes(3072,0x42));stack.emplace_back(last,0x42);
            CScript script;for(int i=0;i<86;++i)script<<OP_DROP;script<<OP_1;
            ScriptError err;bool expected=!enabled||last==1024;
            BOOST_CHECK_EQUAL(Run(stack,script,vf,SIGVERSION_AUTHSCRIPT,err),expected);
            BOOST_CHECK_EQUAL(err,expected?SCRIPT_ERR_OK:SCRIPT_ERR_STACK_SIZE);
        }
    }
    // HASH256 includes the second hash. 20*3232 + (736+160) = 65536.
    for(int last : {736,737}) {
        std::vector<Bytes> stack(20,Bytes(3072));stack.emplace_back(last);
        CScript script;for(int i=0;i<21;++i)script<<OP_HASH256<<OP_DROP;script<<OP_1;
        ScriptError err;BOOST_CHECK_EQUAL(Run(stack,script,flags,SIGVERSION_AUTHSCRIPT,err),last==736);
        BOOST_CHECK_EQUAL(err,last==736?SCRIPT_ERR_OK:SCRIPT_ERR_AUTHSCRIPT_HASH_BUDGET);
    }
}
BOOST_AUTO_TEST_CASE(merkle_csfs_and_extended_hashes_charge_before_work)
{
    const auto flags=GetStandardScriptVerifyFlagsWithConsensusOptIns(GetParams().GetConsensus());
    for(auto opcode : {OP_RIPEMD160,OP_SHA1,OP_SHA256,OP_KECCAK256,OP_BLAKE2B,OP_BLAKE3,OP_SHA3_256,OP_SHA512}) {
        for(int last : {2752,2753}) {
            std::vector<Bytes> stack(20,Bytes(3072));stack.emplace_back(last);
            CScript script;for(int i=0;i<21;++i)script<<opcode<<OP_DROP;script<<OP_1;
            ScriptError err;BOOST_CHECK_EQUAL(Run(stack,script,flags,SIGVERSION_AUTHSCRIPT,err),last==2752);
            BOOST_CHECK_EQUAL(err,last==2752?SCRIPT_ERR_OK:SCRIPT_ERR_AUTHSCRIPT_HASH_BUDGET);
        }
    }
    for(int scheme : {1,2,3,4}) for(bool malformed : {false,true}) {
        // 62720 units before Merkle. Depth 32 costs > remaining 2816 for all classic schemes.
        Bytes proof(1+32*32+4);proof[0]=32;if(malformed)proof.pop_back();
        std::vector<Bytes> stack{Bytes(32),Bytes{static_cast<unsigned char>(scheme)},proof,Bytes(32)};
        for(int i=0;i<20;++i)stack.emplace_back(3072);
        CScript script;for(int i=0;i<20;++i)script<<OP_SHA256<<OP_DROP;
        script<<OP_CHECKMERKLEINCLUSION<<OP_DROP<<OP_1;
        ScriptError err;BOOST_CHECK_EQUAL(Run(stack,script,flags,SIGVERSION_AUTHSCRIPT,err),malformed);
        BOOST_CHECK_EQUAL(err,malformed?SCRIPT_ERR_OK:SCRIPT_ERR_AUTHSCRIPT_HASH_BUDGET);
    }
    struct Checker : BaseSignatureChecker {
        mutable int calls=0;
        bool CheckSigFromStack(const Bytes&,const Bytes&,const Bytes&) const override { ++calls; return false; }
    };
    for(int last : {2752,2753}) {
        Checker checker;
        auto key=ParseHex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
        std::vector<Bytes> stack{Bytes{},Bytes(last),key};
        for(int i=0;i<20;++i)stack.emplace_back(3072);
        CScript script;for(int i=0;i<20;++i)script<<OP_SHA256<<OP_DROP;
        script<<OP_CHECKSIGFROMSTACK<<OP_DROP<<OP_1;
        ScriptError err;BOOST_CHECK_EQUAL(EvalScript(stack,script,flags,checker,SIGVERSION_AUTHSCRIPT,&err),last==2752);
        BOOST_CHECK_EQUAL(checker.calls,last==2752?1:0);
        BOOST_CHECK_EQUAL(err,last==2752?SCRIPT_ERR_OK:SCRIPT_ERR_AUTHSCRIPT_HASH_BUDGET);
    }
}
BOOST_AUTO_TEST_CASE(checksigadd_memory_and_dead_hashes)
{
    const auto flags=GetStandardScriptVerifyFlagsWithConsensusOptIns(GetParams().GetConsensus());
    auto key=ParseHex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    for(int padding : {503,504}) {
        CScript script;for(int i=0;i<padding;++i)script<<OP_NOP;
        script<<OP_0<<OP_0<<key<<OP_CHECKSIGADD;
        ScriptError err;BOOST_CHECK_EQUAL(Run({},script,flags,SIGVERSION_AUTHSCRIPT,err),padding==503);
        BOOST_CHECK_EQUAL(err,padding==503?SCRIPT_ERR_OK:SCRIPT_ERR_OP_COUNT);
    }
    // Budget alone does not widen elements; total-byte limit still applies with no widening flags.
    ScriptError err;
    BOOST_CHECK(!Run({Bytes(521)},CScript()<<OP_DROP<<OP_1,SCRIPT_VERIFY_NONE|SCRIPT_VERIFY_AUTHSCRIPT_BUDGET,SIGVERSION_AUTHSCRIPT,err));
    BOOST_CHECK_EQUAL(err,SCRIPT_ERR_PUSH_SIZE);
    std::vector<Bytes> stack(505,Bytes(520));
    BOOST_CHECK(!Run(stack,CScript()<<OP_DROP,SCRIPT_VERIFY_NONE|SCRIPT_VERIFY_AUTHSCRIPT_BUDGET,SIGVERSION_AUTHSCRIPT,err));
    BOOST_CHECK_EQUAL(err,SCRIPT_ERR_STACK_SIZE);
    // Exact initial total, then duplication while almost all bytes are on altstack.
    stack.assign(85,Bytes(3072));stack.emplace_back(1024);
    BOOST_CHECK(!Run(stack,CScript()<<OP_TOALTSTACK<<OP_DUP,flags,SIGVERSION_AUTHSCRIPT,err));
    BOOST_CHECK_EQUAL(err,SCRIPT_ERR_STACK_SIZE);
    CScript dead;dead<<OP_0<<OP_IF;for(int i=0;i<30;++i)dead<<OP_SHA256;dead<<OP_ENDIF<<OP_1;
    BOOST_CHECK(Run({},dead,flags,SIGVERSION_AUTHSCRIPT,err));
    BOOST_CHECK_EQUAL(err,SCRIPT_ERR_OK);
}
BOOST_AUTO_TEST_CASE(tree_envelope_is_exclusive_to_v1)
{
    auto flags=GetStandardScriptVerifyFlagsWithConsensusOptIns(GetParams().GetConsensus());
    const CScript leaf=CScript()<<OP_DROP<<OP_TRUE;
    const auto root=AuthScriptLeafHash(leaf);
    const auto commitment=AuthScriptTreeCommitment(Bytes{0},root);
    CScriptWitness witness;witness.stack={Bytes{0x10},Bytes{},Bytes(leaf.begin(),leaf.end()),Bytes{1}};
    for(bool enabled : {false,true}) for(int version : {1,2,3}) {
        auto vf=enabled?flags:flags&~SCRIPT_VERIFY_AUTHSCRIPT_BUDGET;
        const CScript output=CScript()<<CScript::EncodeOP_N(version)<<Bytes(commitment.begin(),commitment.end());
        ScriptError err;
        BOOST_CHECK_EQUAL(VerifyScript(CScript(),output,&witness,vf,BaseSignatureChecker(),&err),version==1);
        BOOST_CHECK_EQUAL(err,version==1?SCRIPT_ERR_OK:SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH);
    }
}
// Deterministic generated programs, with an independent sum over the input
// schedule (not over interpreter internals). Reproducible seed for failures.
BOOST_AUTO_TEST_CASE(generated_classic_hash_schedules)
{
    const auto flags=GetStandardScriptVerifyFlagsWithConsensusOptIns(GetParams().GetConsensus());
    uint32_t seed=0x0462026;
    auto next=[&]() { seed=1664525u*seed+1013904223u; return seed; };
    const opcodetype ops[]={OP_SHA256,OP_HASH160,OP_HASH256,OP_RIPEMD160};
    for (int sample=0;sample<256;++sample) {
        CScript script;
        std::vector<Bytes> inputs;
        size_t cost=0;
        const int count=20+next()%30;
        for(int i=0;i<count;++i) {
            const auto op=ops[(next()>>16)%4];
            const size_t size=(next()>>8)%3073;
            inputs.emplace_back(size,static_cast<unsigned char>(i));
            cost+=size+((op==OP_HASH160||op==OP_HASH256)?160:64);
            script<<op<<OP_DROP;
        }
        std::reverse(inputs.begin(),inputs.end());
        script<<OP_TRUE;
        for(bool enabled : {false,true}) {
            ScriptError err;
            const bool expected=!enabled||cost<=65536;
            BOOST_CHECK_EQUAL(Run(inputs,script,enabled?flags:flags&~SCRIPT_VERIFY_AUTHSCRIPT_BUDGET,SIGVERSION_AUTHSCRIPT,err),expected);
            BOOST_CHECK_EQUAL(err,expected?SCRIPT_ERR_OK:SCRIPT_ERR_AUTHSCRIPT_HASH_BUDGET);
        }
    }
}
BOOST_AUTO_TEST_CASE(classic_and_poseidon_budgets_are_independent)
{
    const auto flags=GetStandardScriptVerifyFlagsWithConsensusOptIns(GetParams().GetConsensus());
    // Cartesian boundary matrix in both execution orders. Each invocation has
    // fresh budgets, including after the preceding invocation has failed.
    for(int classic : {65535,65536,65537}) for(int poseidon : {30719,30720,30721})
    for(bool poseidonFirst : {false,true}) {
        CScript script;std::vector<Bytes> inputs;
        auto appendClassic=[&]() {
            for(int i=0;i<21;++i) {
                inputs.emplace_back(i<20?3072:classic-20*3136-64,0x42);
                script<<OP_SHA256<<OP_DROP;
            }
        };
        auto appendPoseidon=[&]() {
            for(int remaining=poseidon;remaining>0;) {
                const int size=std::min(3072,remaining);
                inputs.emplace_back(size,0x42);remaining-=size;
                script<<OP_POSEIDON<<OP_DROP;
            }
        };
        if(poseidonFirst) { appendPoseidon();appendClassic(); }
        else { appendClassic();appendPoseidon(); }
        std::reverse(inputs.begin(),inputs.end());script<<OP_TRUE;
        ScriptError err;
        const bool ok=classic<=65536&&poseidon<=30720;
        BOOST_CHECK_EQUAL(Run(inputs,script,flags,SIGVERSION_AUTHSCRIPT,err),ok);
        const auto expected=ok?SCRIPT_ERR_OK:
            ((poseidonFirst&&poseidon>30720)||classic<=65536?SCRIPT_ERR_POSEIDON_BUDGET:SCRIPT_ERR_AUTHSCRIPT_HASH_BUDGET);
        BOOST_CHECK_EQUAL(err,expected);
    }
}
BOOST_AUTO_TEST_CASE(generated_merkle_budget_schedules)
{
    const auto flags=GetStandardScriptVerifyFlagsWithConsensusOptIns(GetParams().GetConsensus());
    uint32_t seed=0x46abcd;
    auto next=[&]() { seed=1664525u*seed+1013904223u; return seed; };
    for(int sample=0;sample<512;++sample) {
        const int scheme=1+((next()>>16)%4), depth=(next()>>16)%33;
        const size_t leafSize=scheme==1?32:(next()>>8)%3073;
        const bool malformed=(next()>>16)&1;
        Bytes proof(1+depth*32+(depth+7)/8);proof[0]=depth;
        if(malformed)proof.pop_back();
        std::vector<Bytes> stack{Bytes(leafSize),Bytes{static_cast<unsigned char>(scheme)},proof,Bytes(32)};
        for(int i=0;i<20;++i)stack.emplace_back(3072);
        CScript script;for(int i=0;i<20;++i)script<<OP_SHA256<<OP_DROP;
        script<<OP_CHECKMERKLEINCLUSION<<OP_DROP<<OP_TRUE;
        const size_t merkle=scheme==1?224*depth:leafSize+64+128*depth;
        const bool expected=malformed||62720+merkle<=65536;
        ScriptError err;
        BOOST_CHECK_EQUAL(Run(stack,script,flags,SIGVERSION_AUTHSCRIPT,err),expected);
        BOOST_CHECK_EQUAL(err,expected?SCRIPT_ERR_OK:SCRIPT_ERR_AUTHSCRIPT_HASH_BUDGET);
    }
}
BOOST_AUTO_TEST_CASE(poseidon_merkle_shares_only_poseidon_budget)
{
    const auto flags=GetStandardScriptVerifyFlagsWithConsensusOptIns(GetParams().GetConsensus());
    for(int last : {3009,3010,3011}) for(bool malformed : {false,true}) {
        Bytes proof(34);proof[0]=1;if(malformed)proof.pop_back();
        std::vector<Bytes> inputs{Bytes(32),Bytes{5},proof,Bytes(32)};
        for(int i=0;i<9;++i)inputs.emplace_back(3072);
        inputs.emplace_back(last);
        for(int i=0;i<20;++i)inputs.emplace_back(3072);
        inputs.emplace_back(2752);
        CScript script;
        for(int i=0;i<21;++i)script<<OP_SHA256<<OP_DROP; // exactly 65536 classic units
        for(int i=0;i<10;++i)script<<OP_POSEIDON<<OP_DROP;
        script<<OP_CHECKMERKLEINCLUSION<<OP_DROP<<OP_TRUE;
        const bool expected=malformed||last<=3010; // 9*3072 + 3010 + 62 = 30720
        ScriptError err;
        BOOST_CHECK_EQUAL(Run(inputs,script,flags,SIGVERSION_AUTHSCRIPT,err),expected);
        BOOST_CHECK_EQUAL(err,expected?SCRIPT_ERR_OK:SCRIPT_ERR_POSEIDON_BUDGET);
    }
}
BOOST_AUTO_TEST_CASE(network_schedule)
{
    auto main=CreateChainParams(CBaseChainParams::MAIN);
    auto test=CreateChainParams(CBaseChainParams::TESTNET);
    BOOST_CHECK(!main->GetConsensus().IsAuthScriptBudgetActive(1000000));
    BOOST_CHECK(!test->GetConsensus().IsAuthScriptBudgetActive(0));
    BOOST_CHECK(test->GetConsensus().IsAuthScriptBudgetActive(1));
    BOOST_CHECK(GetParams().GetConsensus().IsAuthScriptBudgetActive(0));
    auto params=GetParams().GetConsensus();params.nAuthScriptBudgetHeight=120;
    BOOST_CHECK(!(ApplyConsensusOptIns(STANDARD_SCRIPT_VERIFY_FLAGS,params,true,119)&SCRIPT_VERIFY_AUTHSCRIPT_BUDGET));
    BOOST_CHECK(ApplyConsensusOptIns(STANDARD_SCRIPT_VERIFY_FLAGS,params,true,120)&SCRIPT_VERIFY_AUTHSCRIPT_BUDGET);
}
BOOST_AUTO_TEST_SUITE_END()
