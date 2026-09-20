// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license.
#include "chainparams.h"
#include "script/interpreter.h"
#include "policy/policy.h"
#include "test/test_neurai.h"
#include "utilstrencodings.h"
#include <boost/test/unit_test.hpp>

namespace {
using Bytes = std::vector<unsigned char>;
struct Setup : BasicTestingSetup { Setup():BasicTestingSetup(CBaseChainParams::REGTEST){} };
bool Run(std::vector<Bytes> stack, const CScript& script, script_verify_flags flags, SigVersion version, ScriptError& err) {
    return EvalScript(stack,script,flags,BaseSignatureChecker(),version,&err);
}
}
BOOST_FIXTURE_TEST_SUITE(authscript_budget_tests,Setup)
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
