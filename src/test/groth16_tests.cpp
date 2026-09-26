// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#include "crypto/groth16_bn254.h"
#include "test/data/groth16_vectors.h"
#include "utilstrencodings.h"
#include <boost/test/unit_test.hpp>
using neurai::zk::Result;
namespace {
struct Fixture {
    std::vector<unsigned char> vk=ParseHex(groth16_vectors::VK);
    std::vector<unsigned char> proof=ParseHex(groth16_vectors::PROOF);
    std::vector<unsigned char> inputs=ParseHex(groth16_vectors::INPUTS);
    Result Verify() const { return neurai::zk::Verify(vk,proof,inputs); }
};
}
BOOST_FIXTURE_TEST_SUITE(groth16_tests, Fixture)
BOOST_AUTO_TEST_CASE(real_proof) { BOOST_CHECK(Verify()==Result::VALID); }
BOOST_AUTO_TEST_CASE(rerandomized_proof) {
    proof=ParseHex(groth16_vectors::RERANDOMIZED);
    BOOST_CHECK(Verify()==Result::VALID);
}
BOOST_AUTO_TEST_CASE(wrong_statement) {
    inputs.back()^=1; BOOST_CHECK(Verify()==Result::INVALID);
}
BOOST_AUTO_TEST_CASE(other_circuit) {
    vk=ParseHex(groth16_vectors::OTHER_VK); BOOST_CHECK(Verify()==Result::INVALID);
}
BOOST_AUTO_TEST_CASE(input_range_and_count) {
    inputs.clear(); BOOST_CHECK(Verify()==Result::INPUT_COUNT);
    inputs.resize(32*17); BOOST_CHECK(Verify()==Result::INPUT_COUNT);
    inputs.resize(33); BOOST_CHECK(Verify()==Result::INPUT_COUNT);
    inputs=ParseHex(groth16_vectors::INPUTS);
    auto r=ParseHex("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    std::copy(r.begin(),r.end(),inputs.begin()); BOOST_CHECK(Verify()==Result::INPUT_RANGE);
}
BOOST_AUTO_TEST_CASE(proof_encoding) {
    proof.pop_back(); BOOST_CHECK(Verify()==Result::PROOF_ENCODING);
    proof=ParseHex(groth16_vectors::PROOF); proof.push_back(0); BOOST_CHECK(Verify()==Result::PROOF_ENCODING);
    proof.clear(); BOOST_CHECK(Verify()==Result::PROOF_ENCODING);
    proof=ParseHex(groth16_vectors::PROOF); proof[31]|=0x40; BOOST_CHECK(Verify()==Result::PROOF_ENCODING);
    proof=ParseHex(groth16_vectors::PROOF);
    auto q=ParseHex(groth16_vectors::G2_NON_SUBGROUP);
    std::copy(q.begin(),q.end(),proof.begin()+32); BOOST_CHECK(Verify()==Result::PROOF_ENCODING);
}
BOOST_AUTO_TEST_CASE(vk_encoding) {
    vk.push_back(0); BOOST_CHECK(Verify()==Result::VK_ENCODING);
    vk=ParseHex(groth16_vectors::VK); vk[225]=1; BOOST_CHECK(Verify()==Result::VK_ENCODING);
    vk=ParseHex(groth16_vectors::VK); vk[95]|=0x40; BOOST_CHECK(Verify()==Result::VK_ENCODING);
    vk=ParseHex(groth16_vectors::VK); std::fill(vk.begin(),vk.begin()+32,0xff); BOOST_CHECK(Verify()==Result::VK_ENCODING);
}
BOOST_AUTO_TEST_CASE(k_mismatch) {
    inputs.resize(32); BOOST_CHECK(Verify()==Result::INPUT_COUNT);
}
BOOST_AUTO_TEST_SUITE_END()

#include "script/interpreter.h"
#include "policy/policy.h"
#include "coins.h"

namespace {
using Stack = std::vector<std::vector<unsigned char>>;
Stack ZKStack()
{
    Stack stack{ParseHex(groth16_vectors::PROOF), ParseHex(groth16_vectors::VK)};
    const auto inputs = ParseHex(groth16_vectors::INPUTS);
    for (size_t i=0; i<inputs.size(); i+=32)
        stack.emplace_back(inputs.begin()+i, inputs.begin()+i+32);
    stack.push_back(CScriptNum(inputs.size()/32).getvch());
    stack.push_back({1});
    return stack;
}
ScriptError ExecuteZK(Stack& stack, script_verify_flags flags=SCRIPT_VERIFY_ZKVERIFY,
                      SigVersion version=SIGVERSION_AUTHSCRIPT)
{
    ScriptError error;
    const bool result = EvalScript(stack, CScript() << OP_ZKVERIFY, flags, BaseSignatureChecker(), version, &error);
    BOOST_CHECK_EQUAL(result, error == SCRIPT_ERR_OK);
    return error;
}
}
BOOST_AUTO_TEST_SUITE(zkverify_opcode_tests)
BOOST_AUTO_TEST_CASE(real_proof_and_nullfail)
{
    auto stack = ZKStack();
    BOOST_CHECK(ExecuteZK(stack)==SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(stack.size(),1U);
    BOOST_CHECK(stack[0]==std::vector<unsigned char>{1});
    stack=ZKStack(); stack[2].back()^=1;
    BOOST_CHECK(ExecuteZK(stack)==SCRIPT_ERR_ZK_VERIFY_FAILED);
    stack=ZKStack(); stack[0].pop_back();
    BOOST_CHECK(ExecuteZK(stack)==SCRIPT_ERR_ZK_PROOF_ENCODING);
    stack=ZKStack(); stack[1].push_back(0);
    BOOST_CHECK(ExecuteZK(stack)==SCRIPT_ERR_ZK_VK_ENCODING);
}
BOOST_AUTO_TEST_CASE(empty_proof_and_validation_order)
{
    auto stack=ZKStack(); stack[0].clear(); stack[1]={0xff};
    BOOST_CHECK(ExecuteZK(stack)==SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(stack.size(),1U); BOOST_CHECK(stack[0].empty());
    stack=ZKStack(); stack[0].clear(); stack[2].resize(31);
    BOOST_CHECK(ExecuteZK(stack)==SCRIPT_ERR_ZK_PUBLIC_INPUT_SIZE);
    stack=ZKStack(); stack[0].clear(); stack[2].assign(32,0xff);
    BOOST_CHECK(ExecuteZK(stack)==SCRIPT_ERR_ZK_PUBLIC_INPUT_RANGE);
    stack=ZKStack(); stack.back()={1,0};
    BOOST_CHECK(ExecuteZK(stack)==SCRIPT_ERR_ZK_BAD_PROFILE);
    stack=ZKStack(); stack[stack.size()-2]={1,0};
    BOOST_CHECK(ExecuteZK(stack)==SCRIPT_ERR_ZK_INPUT_COUNT);
    stack=ZKStack(); stack[stack.size()-2]={17};
    BOOST_CHECK(ExecuteZK(stack)==SCRIPT_ERR_ZK_INPUT_COUNT);
    stack={{1},{1}};
    BOOST_CHECK(ExecuteZK(stack)==SCRIPT_ERR_ZK_STACK_SIZE);
}
BOOST_AUTO_TEST_CASE(all_counts_and_underflow)
{
    for (int k=1; k<=16; ++k) {
        Stack stack{{}, {0xff}}; // empty proof deliberately skips malformed VK
        for (int j=0; j<k; ++j) stack.emplace_back(32,0);
        stack.push_back(CScriptNum(k).getvch()); stack.push_back({1});
        auto missing=stack; missing.erase(missing.begin());
        BOOST_CHECK(ExecuteZK(missing)==SCRIPT_ERR_ZK_STACK_SIZE);
        BOOST_CHECK(ExecuteZK(stack)==SCRIPT_ERR_OK);
        BOOST_REQUIRE_EQUAL(stack.size(),1U); BOOST_CHECK(stack[0].empty());
    }
}
BOOST_AUTO_TEST_CASE(error_precedence)
{
    Stack stack{{2}};
    BOOST_CHECK(ExecuteZK(stack)==SCRIPT_ERR_ZK_BAD_PROFILE);
    stack={{1}};
    BOOST_CHECK(ExecuteZK(stack)==SCRIPT_ERR_ZK_STACK_SIZE);
    stack=ZKStack(); stack[2].resize(31); stack[stack.size()-3].assign(32,0xff);
    BOOST_CHECK(ExecuteZK(stack)==SCRIPT_ERR_ZK_PUBLIC_INPUT_RANGE); // top input first
    stack=ZKStack(); stack[stack.size()-2]=CScriptNum(0).getvch();
    BOOST_CHECK(ExecuteZK(stack)==SCRIPT_ERR_ZK_INPUT_COUNT);
    stack=ZKStack(); stack[stack.size()-2]=CScriptNum(-1).getvch();
    BOOST_CHECK(ExecuteZK(stack)==SCRIPT_ERR_ZK_INPUT_COUNT);
    stack=ZKStack(); stack[stack.size()-2]=std::vector<unsigned char>{1,0,0,0,1};
    BOOST_CHECK(ExecuteZK(stack,SCRIPT_VERIFY_ZKVERIFY|SCRIPT_VERIFY_64BIT_INTEGERS)==SCRIPT_ERR_ZK_INPUT_COUNT);
    stack=ZKStack(); stack[2]=ParseHex("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    BOOST_CHECK(ExecuteZK(stack)==SCRIPT_ERR_ZK_PUBLIC_INPUT_RANGE);
}
BOOST_AUTO_TEST_CASE(gates_and_unexecuted_branch)
{
    Stack stack;
    BOOST_CHECK(ExecuteZK(stack,SCRIPT_VERIFY_NONE)==SCRIPT_ERR_BAD_OPCODE);
    BOOST_CHECK(ExecuteZK(stack,SCRIPT_VERIFY_ZKVERIFY,SIGVERSION_BASE)==SCRIPT_ERR_ZK_BAD_SIGVERSION);
    BOOST_CHECK(ExecuteZK(stack,SCRIPT_VERIFY_ZKVERIFY,SIGVERSION_WITNESS_V0)==SCRIPT_ERR_ZK_BAD_SIGVERSION);
    ScriptError error;
    BOOST_CHECK(EvalScript(stack,CScript()<<OP_0<<OP_IF<<OP_ZKVERIFY<<OP_ENDIF<<OP_1,
        SCRIPT_VERIFY_NONE,BaseSignatureChecker(),SIGVERSION_BASE,&error));
    BOOST_CHECK_EQUAL(EffectiveMaxScriptElementSize(SCRIPT_VERIFY_ZKVERIFY),3072U);
}
BOOST_AUTO_TEST_CASE(static_cost_and_policy)
{
    const CScript script=CScript()<<OP_0<<OP_IF<<OP_ZKVERIFY<<OP_ENDIF
        <<std::vector<unsigned char>{OP_ZKVERIFY}<<OP_DROP<<OP_1;
    BOOST_CHECK_EQUAL(script.CountZKVerify(),1U);
    CScriptWitness witness; witness.stack={{0},std::vector<unsigned char>(script.begin(),script.end())};
    const CScript output=CScript()<<OP_1<<std::vector<unsigned char>(32,1);
    const auto flags=SCRIPT_VERIFY_WITNESS|SCRIPT_VERIFY_P2SH|SCRIPT_VERIFY_AUTHSCRIPT|SCRIPT_VERIFY_ZKVERIFY;
    BOOST_CHECK_EQUAL(CountWitnessSigOps(CScript(),output,&witness,flags),ZKVERIFY_SIGOP_COST);
    BOOST_CHECK_EQUAL(CountWitnessSigOps(CScript(),output,&witness,flags & ~SCRIPT_VERIFY_ZKVERIFY),0U);
    CCoinsView base; CCoinsViewCache coins(&base);
    CMutableTransaction tx; tx.vin.resize(2);
    for (size_t i=0;i<2;++i) {
        tx.vin[i].prevout=COutPoint(uint256(),i);
        coins.AddCoin(tx.vin[i].prevout,Coin(CTxOut(10000,output),1,false),false);
        CScript leaf; for (int j=0;j<2;++j) leaf<<OP_ZKVERIFY;
        tx.vin[i].scriptWitness.stack={{0},std::vector<unsigned char>(leaf.begin(),leaf.end())};
    }
    BOOST_CHECK(IsWitnessStandard(CTransaction(tx),coins,true,flags));
    tx.vin[1].scriptWitness.stack.back().push_back(OP_ZKVERIFY);
    BOOST_CHECK(!IsWitnessStandard(CTransaction(tx),coins,true,flags));
    BOOST_CHECK(IsWitnessStandard(CTransaction(tx),coins,true,flags & ~SCRIPT_VERIFY_ZKVERIFY));
}
BOOST_AUTO_TEST_SUITE_END()

#include "script/standard.h"
#include "chainparams.h"
#include "test/test_neurai.h"
BOOST_FIXTURE_TEST_SUITE(zkverify_witness_tests, BasicTestingSetup)
BOOST_AUTO_TEST_CASE(flat_tree_and_wrapped_proofs)
{
    const CScript leaf=CScript()<<OP_ZKVERIFY;
    const auto flags=SCRIPT_VERIFY_WITNESS|SCRIPT_VERIFY_P2SH|SCRIPT_VERIFY_AUTHSCRIPT|
        SCRIPT_VERIFY_ZKVERIFY|SCRIPT_VERIFY_AUTHSCRIPT_TREE;
    for (bool tree : {false,true}) {
        const auto commitment=tree ? AuthScriptTreeCommitment({0},AuthScriptLeafHash(leaf)) :
            GetAuthScriptCommitment(0,nullptr,leaf);
        const CScript program=CScript()<<OP_1<<std::vector<unsigned char>(commitment.begin(),commitment.end());
        CScriptWitness witness; witness.stack={{static_cast<unsigned char>(tree?0x10:0)}};
        const auto args=ZKStack(); witness.stack.insert(witness.stack.end(),args.begin(),args.end());
        witness.stack.emplace_back(leaf.begin(),leaf.end());
        if(tree) witness.stack.push_back({1});
        for(bool wrapped : {false,true}) {
            const CScript output=wrapped ? GetScriptForDestination(CScriptID(program)) : program;
            const CScript scriptSig=wrapped ? CScript()<<std::vector<unsigned char>(program.begin(),program.end()) : CScript();
            ScriptError error;
            BOOST_CHECK(VerifyScript(scriptSig,output,&witness,flags,BaseSignatureChecker(),&error));
            BOOST_CHECK_EQUAL(CountWitnessSigOps(scriptSig,output,&witness,flags),ZKVERIFY_SIGOP_COST);
            BOOST_CHECK(!VerifyScript(scriptSig,output,&witness,flags & ~SCRIPT_VERIFY_ZKVERIFY,BaseSignatureChecker(),&error));
            BOOST_CHECK(error==SCRIPT_ERR_BAD_OPCODE);
        }
        if (tree) {
            witness.stack.back().insert(witness.stack.back().end(),32,OP_ZKVERIFY);
            BOOST_CHECK_EQUAL(CountWitnessSigOps(CScript(),program,&witness,flags),ZKVERIFY_SIGOP_COST);
        }
    }
}
BOOST_AUTO_TEST_CASE(height_gate)
{
    Consensus::Params params; params.nZKVerifyHeight=120;
    BOOST_CHECK(!(ApplyConsensusOptIns(SCRIPT_VERIFY_NONE,params,false,119)&SCRIPT_VERIFY_ZKVERIFY));
    BOOST_CHECK(ApplyConsensusOptIns(SCRIPT_VERIFY_NONE,params,false,120)&SCRIPT_VERIFY_ZKVERIFY);
    BOOST_CHECK(!(CreateChainParams(CBaseChainParams::MAIN)->GetConsensus().IsZKVerifyActive(440000)));
}
BOOST_AUTO_TEST_SUITE_END()

#include <thread>
#include <atomic>
namespace {
struct CacheFixture : Fixture {
    CacheFixture() { neurai::zk::ResetCaches(); }
    ~CacheFixture() { neurai::zk::ResetCaches(); }
};
}
BOOST_FIXTURE_TEST_SUITE(zkverify_cache_tests, CacheFixture)
BOOST_AUTO_TEST_CASE(independent_key_vector)
{
    const auto key=neurai::zk::VerificationCacheKey(vk,proof,inputs);
    BOOST_CHECK_EQUAL(HexStr(key.begin(),key.end()),"2bf05a83c548e9dd51ddae112aefa5b883fc121073f79ed3ad8df0ca9c4e7011");
}
BOOST_AUTO_TEST_CASE(disabled_cold_and_hot)
{
    neurai::zk::ResetCaches(0,0);
    BOOST_CHECK(Verify()==Result::VALID); BOOST_CHECK(Verify()==Result::VALID);
    BOOST_CHECK_EQUAL(neurai::zk::GetCacheInfo().result_hits,0U);
    neurai::zk::ResetCaches();
    BOOST_CHECK(Verify()==Result::VALID);
    BOOST_CHECK_EQUAL(neurai::zk::GetCacheInfo().result_hits,0U);
    BOOST_CHECK(Verify()==Result::VALID);
    BOOST_CHECK_EQUAL(neurai::zk::GetCacheInfo().result_hits,1U);
    BOOST_CHECK(neurai::zk::Verify(vk,proof,inputs,false)==Result::VALID);
    BOOST_CHECK_EQUAL(neurai::zk::GetCacheInfo().result_hits,1U);
    proof=ParseHex(groth16_vectors::RERANDOMIZED);
    BOOST_CHECK(Verify()==Result::VALID);
    BOOST_CHECK_EQUAL(neurai::zk::GetCacheInfo().vk_hits,1U);
}
BOOST_AUTO_TEST_CASE(full_cache_and_eviction)
{
    neurai::zk::ResetCaches(1,1);
    BOOST_CHECK(Verify()==Result::VALID);
    proof=ParseHex(groth16_vectors::RERANDOMIZED);
    BOOST_CHECK(Verify()==Result::VALID);
    BOOST_CHECK_EQUAL(neurai::zk::GetCacheInfo().result_evictions,1U);
    proof=ParseHex(groth16_vectors::PROOF);
    BOOST_CHECK(Verify()==Result::VALID);
    BOOST_CHECK_EQUAL(neurai::zk::GetCacheInfo().result_evictions,2U);
    vk=ParseHex(groth16_vectors::OTHER_VK);
    BOOST_CHECK(Verify()==Result::INVALID);
    BOOST_CHECK_EQUAL(neurai::zk::GetCacheInfo().vk_evictions,1U);
    vk=ParseHex(groth16_vectors::VK); inputs.resize(32);
    BOOST_CHECK(Verify()==Result::INPUT_COUNT);
    BOOST_CHECK(Verify()==Result::INPUT_COUNT); // hit must still check k
    BOOST_CHECK(neurai::zk::GetCacheInfo().vk_hits>0);
    BOOST_CHECK(neurai::zk::GetCacheInfo().bytes<2*1024*1024);
}
BOOST_AUTO_TEST_CASE(hits_do_not_hide_invalid_arguments)
{
    BOOST_CHECK(Verify()==Result::VALID);
    const auto goodInputs=inputs, goodVK=vk, goodProof=proof;
    for(int i=0;i<2;++i) {
        inputs.back()^=1; BOOST_CHECK(Verify()==Result::INVALID); inputs=goodInputs;
        inputs[0]=0xff; BOOST_CHECK(Verify()==Result::INPUT_RANGE); inputs=goodInputs;
        inputs.pop_back(); BOOST_CHECK(Verify()==Result::INPUT_COUNT); inputs=goodInputs;
        proof.pop_back(); BOOST_CHECK(Verify()==Result::PROOF_ENCODING); proof=goodProof;
        vk.push_back(0); BOOST_CHECK(Verify()==Result::VK_ENCODING); vk=goodVK;
    }
    BOOST_CHECK_EQUAL(neurai::zk::GetCacheInfo().result_hits,0U);
    auto stack=ZKStack();
    BOOST_CHECK(ExecuteZK(stack,SCRIPT_VERIFY_NONE)==SCRIPT_ERR_BAD_OPCODE);
    stack=ZKStack(); stack.back()={2};
    BOOST_CHECK(ExecuteZK(stack)==SCRIPT_ERR_ZK_BAD_PROFILE);
    stack=ZKStack();
    BOOST_CHECK(ExecuteZK(stack,SCRIPT_VERIFY_ZKVERIFY,SIGVERSION_BASE)==SCRIPT_ERR_ZK_BAD_SIGVERSION);
}
BOOST_AUTO_TEST_CASE(concurrent_eviction)
{
    neurai::zk::ResetCaches(1,1);
    std::atomic<bool> good{true}; std::vector<std::thread> threads;
    for(int t=0;t<16;++t) threads.emplace_back([&,t] {
        auto p=ParseHex(t%2 ? groth16_vectors::RERANDOMIZED : groth16_vectors::PROOF);
        for(int i=0;i<16;++i)
            if(neurai::zk::Verify(vk,p,inputs)!=Result::VALID) good=false;
    });
    for(auto& t:threads)t.join();
    BOOST_CHECK(good.load());
    const auto stats=neurai::zk::GetCacheInfo();
    BOOST_CHECK_EQUAL(stats.active,0U); BOOST_CHECK(stats.peak>0 && stats.peak<=4);
    BOOST_CHECK(stats.result_hits>0);
}
BOOST_AUTO_TEST_SUITE_END()
