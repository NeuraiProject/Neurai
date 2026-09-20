// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license; see COPYING.
#include "chainparams.h"
#include "crypto/poseidon_bn254.h"
#include "data/nip043_b3_fixture.json.h"
#include "policy/policy.h"
#include "script/interpreter.h"
#include "test/test_neurai.h"
#include "utilstrencodings.h"
#include <boost/test/unit_test.hpp>
#include <univalue.h>

namespace {
using Bytes=std::vector<unsigned char>;
struct Setup : BasicTestingSetup { Setup():BasicTestingSetup(CBaseChainParams::REGTEST){} };
CScript Asset(const Bytes& program,const std::string& name,uint64_t amount=100000000,const Bytes& message=Bytes{}) {
    Bytes data{'x','n','a','t',static_cast<unsigned char>(name.size())};
    data.insert(data.end(),name.begin(),name.end());
    for(unsigned i=0;i<8;++i)data.push_back((amount>>(8*i))&255);
    if(!message.empty()){data.push_back(0x54);data.push_back(32);data.insert(data.end(),message.begin(),message.end());}
    return CScript()<<OP_1<<program<<OP_XNA_ASSET<<data<<OP_DROP;
}
UniValue Fixture() {
    UniValue v;v.read(std::string(json_tests::nip043_b3_fixture,json_tests::nip043_b3_fixture+sizeof(json_tests::nip043_b3_fixture)));return v;
}
}
BOOST_FIXTURE_TEST_SUITE(contract_thread_b3_tests,Setup)
BOOST_AUTO_TEST_CASE(frozen_b3_commitment_and_real_poseidon)
{
    auto f=Fixture();auto old=ParseHex(f["old"].get_str());Bytes hash(32);
    crypto::PoseidonBN254(old.data(),old.size(),hash.data());
    BOOST_CHECK(hash==ParseHex(f["state_hash"].get_str()));
    auto bytes=ParseHex(f["leaf"].get_str());CScript script(bytes.begin(),bytes.end());
    auto control=ParseHex(f["control"].get_str());auto root=AuthScriptLeafHash(script);
    BOOST_REQUIRE_EQUAL(control[0],1);
    for(size_t i=1;i<control.size();i+=32){uint256 sibling;std::copy(control.begin()+i,control.begin()+i+32,sibling.begin());root=AuthScriptBranchHash(root,sibling);}
    auto commitment=AuthScriptTreeCommitment(Bytes{0},root);
    BOOST_CHECK(Bytes(commitment.begin(),commitment.end())==ParseHex(f["program"].get_str()));
    unsigned count=0;auto pc=script.begin();opcodetype opcode;Bytes data;
    while(pc!=script.end()){BOOST_REQUIRE(script.GetOp(pc,opcode,data));if(opcode>OP_16)++count;BOOST_CHECK(opcode!=static_cast<opcodetype>(0xc3));}
    BOOST_CHECK_EQUAL(count,189);
}
BOOST_AUTO_TEST_CASE(auxiliary_guards_real_interpreter)
{
    const auto f=Fixture();const auto flags=GetStandardScriptVerifyFlagsWithConsensusOptIns(GetParams().GetConsensus());
    auto c=ParseHex(f["program"].get_str());auto id=f["unique"].get_str();
    for(const std::string kind : {"vault","deposit"}) {
        auto bytes=ParseHex(f[kind].get_str());CScript script(bytes.begin(),bytes.end());
        auto program=ParseHex(f[kind+"_program"].get_str());
        const CScript own=Asset(program,f["name"].get_str());
        auto verify=[&](const CScript& state,script_verify_flags vf,const Bytes& extra=Bytes{}) {
            CMutableTransaction mut;mut.nVersion=3;mut.vin.resize(2);mut.vout.emplace_back(0,own);
            CTransaction tx(mut);PrecomputedTransactionData cache(tx);
            std::vector<CTxOut> prev{CTxOut(0,state),CTxOut(0,own)};
            TransactionSignatureChecker checker(&tx,1,0,cache,own,&prev);
            CScriptWitness w;w.stack={Bytes{0}};if(!extra.empty())w.stack.push_back(extra);w.stack.push_back(bytes);
            ScriptError error;return VerifyScript(CScript(),own,&w,vf,checker,&error);
        };
        BOOST_CHECK(verify(Asset(c,id),flags));
        auto wrong=c;wrong[0]^=1;
        BOOST_CHECK(!verify(Asset(wrong,id),flags));
        BOOST_CHECK(!verify(Asset(c,"RWAX#OTHER"),flags));
        BOOST_CHECK(!verify(CScript()<<OP_1<<c,flags));
        BOOST_CHECK(!verify(Asset(c,id),flags & ~SCRIPT_VERIFY_INPUTFIELD));
        BOOST_CHECK(!verify(Asset(c,id),flags,Bytes{1}));
    }
}

BOOST_AUTO_TEST_CASE(b3_templates_and_mode_with_real_poseidon)
{
    const auto f=Fixture();const auto standard=GetStandardScriptVerifyFlagsWithConsensusOptIns(GetParams().GetConsensus());
    const auto c=ParseHex(f["program"].get_str()),cv=ParseHex(f["vault_program"].get_str());
    for(int sponsorVersion : {0,2,3}) for(int mutation=0;mutation<=20;++mutation) {
        auto old=ParseHex(f["old"].get_str());
        if(mutation==1)old.back()=0; // Valid opening of mode 0, not merely a wrong digest.
        if(mutation==2)old.back()=2;
        if(mutation==3)old.pop_back();
        Bytes hash(32);crypto::PoseidonBN254(old.data(),old.size(),hash.data());
        auto state=Asset(c,f["unique"].get_str(),100000000,hash);
        CScript sponsor=sponsorVersion?CScript()<<CScript::EncodeOP_N(sponsorVersion)<<Bytes(32,7):CScript()<<OP_DUP<<OP_HASH160<<Bytes(20,7)<<OP_EQUALVERIFY<<OP_CHECKSIG;
        if(mutation==7)sponsor=CScript()<<OP_HASH160<<Bytes(20,7)<<OP_EQUAL;
        if(mutation==8)sponsor=CScript()<<OP_1<<Bytes(32,7);
        if(mutation==9)sponsor=Asset(Bytes(32,7),"OTHER");
        if(mutation==10)sponsor<<OP_NOP;
        if(mutation==11)state<<OP_NOP;
        // Exact sponsor templates: matching input/output bytes alone is insufficient.
        if(mutation==15)sponsor.pop_back();
        if(mutation==16)sponsor.insert(sponsor.begin(),OP_NOP);
        if(mutation==17) {
            auto wrapped=Asset(Bytes(32,7),"OTHER");
            sponsor.insert(sponsor.end(),wrapped.begin()+34,wrapped.end());
        }
        if(mutation==18)sponsor=CScript()<<OP_0<<Bytes(20,7);
        if(mutation==19)sponsor=CScript()<<OP_2<<Bytes(31,7);
        if(mutation==20)sponsor=CScript()<<OP_3<<Bytes(33,7);
        std::vector<CTxOut> prev{CTxOut(0,state),CTxOut(0,Asset(cv,f["name"].get_str())),CTxOut(0,Asset(cv,f["name"].get_str())),CTxOut(200000000,sponsor)};
        CMutableTransaction mut;mut.nVersion=3;mut.vin.resize(4);
        mut.vout={CTxOut(0,state),CTxOut(0,Asset(cv,f["name"].get_str(),200000000)),CTxOut(190000000,sponsor)};
        if(mutation==4)mut.vout[0].scriptPubKey=Asset(c,f["unique"].get_str(),100000000,Bytes(32));
        if(mutation==5){mut.vin.resize(5);prev.emplace_back(0,sponsor);}
        if(mutation==6)mut.vout.emplace_back(0,CScript()<<OP_RETURN);
        auto flags=standard;
        if(mutation==12)flags &= ~SCRIPT_VERIFY_64BIT_INTEGERS;
        if(mutation==13)flags &= ~SCRIPT_VERIFY_AUTHSCRIPT_TREE;
        if(mutation==14)flags &= ~SCRIPT_VERIFY_INPUTFIELD;
        CTransaction tx(mut);PrecomputedTransactionData cache(tx);
        TransactionSignatureChecker checker(&tx,0,0,cache,state,&prev);
        CScriptWitness w;w.stack={Bytes{0x10},old,ParseHex(f["leaf"].get_str()),ParseHex(f["control"].get_str())};
        ScriptError error;
        const bool ok=VerifyScript(CScript(),state,&w,flags,checker,&error);
        BOOST_CHECK_MESSAGE(ok==(mutation==0),"sponsor="<<sponsorVersion<<" mutation="<<mutation<<" error="<<ScriptErrorString(error));
    }
}
BOOST_AUTO_TEST_SUITE_END()

