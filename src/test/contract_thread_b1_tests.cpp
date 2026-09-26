// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license; see COPYING.
#include "chainparams.h"
#include "crypto/poseidon_bn254.h"
#include "data/nip043_b1_fixture.json.h"
#include "policy/policy.h"
#include "script/interpreter.h"
#include "test/test_neurai.h"
#include "utilstrencodings.h"
#include <boost/test/unit_test.hpp>
#include <univalue.h>
namespace {
using Bytes=std::vector<unsigned char>;
struct Setup:BasicTestingSetup { Setup():BasicTestingSetup(CBaseChainParams::REGTEST){} };
UniValue Fixture(){UniValue f;f.read(std::string(json_tests::nip043_b1_fixture,json_tests::nip043_b1_fixture+sizeof(json_tests::nip043_b1_fixture)));return f;}
Bytes Poseidon(const Bytes& blob){Bytes h(32);crypto::PoseidonBN254(blob.data(),blob.size(),h.data());return h;}
CScript State(const Bytes& c,const std::string& name,const Bytes& hash){
    Bytes p{'x','n','a','t',static_cast<unsigned char>(name.size())};p.insert(p.end(),name.begin(),name.end());
    uint64_t amount=100000000;for(unsigned i=0;i<8;++i)p.push_back((amount>>(8*i))&255);
    p.insert(p.end(),{0x54,32});p.insert(p.end(),hash.begin(),hash.end());
    return CScript()<<OP_1<<c<<OP_XNA_ASSET<<p<<OP_DROP;
}
}
BOOST_FIXTURE_TEST_SUITE(contract_thread_b1_tests,Setup)
BOOST_AUTO_TEST_CASE(frozen_leaf_and_poseidon)
{
    auto f=Fixture();BOOST_CHECK(Poseidon(ParseHex(f["old"].get_str()))==ParseHex(f["old_hash"].get_str()));
    BOOST_CHECK(Poseidon(ParseHex(f["new"].get_str()))==ParseHex(f["new_hash"].get_str()));
    auto bytes=ParseHex(f["leaf"].get_str()),control=ParseHex(f["control"].get_str());CScript script(bytes.begin(),bytes.end());
    auto root=AuthScriptLeafHash(script);
    BOOST_REQUIRE_EQUAL(control[0],1);
    for(size_t i=1;i<control.size();i+=32){uint256 sibling;std::copy(control.begin()+i,control.begin()+i+32,sibling.begin());root=AuthScriptBranchHash(root,sibling);}
    auto c=AuthScriptTreeCommitment(Bytes{0},root);BOOST_CHECK(Bytes(c.begin(),c.end())==ParseHex(f["program"].get_str()));
    auto pc=script.begin();opcodetype op;Bytes data;unsigned count=0,csv=0;
    while(pc!=script.end()){BOOST_REQUIRE(script.GetOp(pc,op,data));if(op>OP_16)++count;if(op==OP_CHECKSEQUENCEVERIFY)++csv;BOOST_CHECK(op!=static_cast<opcodetype>(0xc3));}
    BOOST_CHECK_EQUAL(count,164);BOOST_CHECK_EQUAL(csv,1);BOOST_CHECK_EQUAL(f["delay"].get_int(),1440);
}
BOOST_AUTO_TEST_CASE(real_openings_modes_shape_and_csv)
{
    auto f=Fixture();const auto c=ParseHex(f["program"].get_str());const auto flags=GetStandardScriptVerifyFlagsWithConsensusOptIns(GetParams().GetConsensus());
    for(int family : {0,2,3}) for(int mutation=0;mutation<=36;++mutation){
        auto old=ParseHex(f["old"].get_str()),next=ParseHex(f["new"].get_str());
        if(mutation==1)old.back()=1;
        if(mutation==2)next.back()=0;
        if(mutation==3)next.back()=2;
        if(mutation==4)next[0]=1; // Recomputed hashes: tests prefix preservation, not invalid openings.
        if(mutation==5)old.pop_back();
        if(mutation==6)next.push_back(0);
        CScript sponsor=family?CScript()<<CScript::EncodeOP_N(family)<<Bytes(32,7):CScript()<<OP_DUP<<OP_HASH160<<Bytes(20,7)<<OP_EQUALVERIFY<<OP_CHECKSIG;
        if(mutation==17)sponsor=CScript()<<OP_HASH160<<Bytes(20,7)<<OP_EQUAL;
        if(mutation==18)sponsor=CScript()<<OP_1<<Bytes(32,7);
        if(mutation==19)sponsor<<OP_NOP;
        // Keep input and refund identical: these reject the sponsor template,
        // not merely a mismatch between the two scripts.
        if(mutation==25)sponsor.pop_back();
        if(mutation==26)sponsor.insert(sponsor.begin(),OP_NOP);
        if(mutation==27){
            auto asset=State(Bytes(32,7),"RWAX#OTHER",Bytes(32,1));
            sponsor.insert(sponsor.end(),asset.begin()+34,asset.end());
        }
        if(mutation==28)sponsor=CScript()<<OP_0<<Bytes(20,7);
        if(mutation==29)sponsor=CScript()<<OP_2<<Bytes(31,7);
        if(mutation==30)sponsor=CScript()<<OP_2<<Bytes(33,7);
        if(mutation==31)sponsor=CScript()<<OP_3<<Bytes(31,7);
        if(mutation==32)sponsor=CScript()<<OP_3<<Bytes(33,7);
        if(mutation==33)sponsor=CScript()<<OP_0<<Bytes(32,7);
        CScript before=State(c,f["unique"].get_str(),Poseidon(old)),after=State(c,f["unique"].get_str(),Poseidon(next));
        if(mutation==20)after<<OP_NOP;
        if(mutation==34)before<<OP_NOP;
        if(mutation==35)before=State(c,"RWAX#OTHER",Poseidon(old));
        if(mutation==36)after=State(c,"RWAX#OTHER",Poseidon(next));
        CMutableTransaction mut;mut.nVersion=3;mut.vin.resize(2);mut.vin[0].nSequence=1440;
        mut.vout={CTxOut(0,after),CTxOut(190000000,sponsor)};
        std::vector<CTxOut> prev{CTxOut(0,before),CTxOut(200000000,sponsor)};
        if(mutation==7)mut.vin[0].nSequence=1439;
        if(mutation==8)mut.vin[0].nSequence=1440|CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG;
        if(mutation==9)mut.vin[0].nSequence=1440|CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG;
        if(mutation==10)mut.nVersion=1;
        if(mutation==11){mut.vin.resize(3);prev.emplace_back(0,sponsor);}
        if(mutation==12)mut.vout.emplace_back(0,CScript()<<OP_RETURN);
        if(mutation==13)mut.vout[0].nValue=1;
        if(mutation==14)prev[0].nValue=1;
        if(mutation==15)mut.vout[1].scriptPubKey=CScript()<<OP_3<<Bytes(32,8);
        auto vf=flags;
        if(mutation==21)vf &= ~SCRIPT_VERIFY_AUTHSCRIPT_TREE;
        if(mutation==22)vf &= ~SCRIPT_VERIFY_64BIT_INTEGERS;
        if(mutation==23)vf &= ~SCRIPT_VERIFY_INPUTFIELD;
        if(mutation==24)mut.vin[0].nSequence=1441; // Higher block delay still satisfies CSV.
        CTransaction tx(mut);PrecomputedTransactionData cache(tx);TransactionSignatureChecker checker(&tx,0,prev[0].nValue,cache,before,&prev);
        CScriptWitness w;w.stack={Bytes{0x10},old,next,ParseHex(f["leaf"].get_str()),ParseHex(f["control"].get_str())};
        if(mutation==16)w.stack.insert(w.stack.begin()+1,Bytes{1});
        ScriptError error;bool ok=VerifyScript(CScript(),before,&w,vf,checker,&error);
        BOOST_CHECK_MESSAGE(ok==(mutation==0||mutation==24),"family="<<family<<" mutation="<<mutation<<" error="<<ScriptErrorString(error));
    }
}
BOOST_AUTO_TEST_SUITE_END()
