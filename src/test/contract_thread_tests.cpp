// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license; see COPYING.
#include "assets/assettypes.h"
#include "chainparams.h"
#include "crypto/poseidon_bn254.h"
#include "policy/policy.h"
#include "script/interpreter.h"
#include "script/merkle_inclusion.h"
#include "test/test_neurai.h"
#include "utilstrencodings.h"
#include <boost/test/unit_test.hpp>

namespace {
using Bytes = std::vector<unsigned char>;
constexpr script_verify_flags FLAGS = SCRIPT_VERIFY_ASSETMESSAGEFIELD | SCRIPT_VERIFY_INPUTFIELD |
    SCRIPT_VERIFY_MERKLE_POSEIDON | SCRIPT_VERIFY_MERKLE_INCLUSION | SCRIPT_VERIFY_POSEIDON |
    SCRIPT_VERIFY_OUTPUTASSETFIELD | SCRIPT_VERIFY_INPUTASSETFIELD | SCRIPT_VERIFY_REFINPUTS |
    SCRIPT_VERIFY_AUTHSCRIPT_STRICT | SCRIPT_VERIFY_AUTHDEST;
struct Setup : BasicTestingSetup { Setup() : BasicTestingSetup(CBaseChainParams::REGTEST) {} };
Bytes Sequence() { Bytes b(32); for (unsigned i=0;i<32;++i) b[i]=i; return b; }
CScript Prefix(int v) {
    if (v == 0) return CScript() << OP_DUP << OP_HASH160 << Bytes(20, 3) << OP_EQUALVERIFY << OP_CHECKSIG;
    return CScript() << CScript::EncodeOP_N(v) << Sequence();
}
Bytes Payload(unsigned char tag = 0x54) {
    Bytes p{'x','n','a','t',3,'A','#','a',0,0xe1,0xf5,5,0,0,0,0,tag,32};
    auto msg = Sequence(); p.insert(p.end(),msg.begin(),msg.end()); return p;
}
CScript Asset(int version, const Bytes& payload) { return Prefix(version) << OP_XNA_ASSET << payload << OP_DROP; }
bool Run(const CScript& contract, const CScript& spk, script_verify_flags flags, Bytes& value, ScriptError& error) {
    CMutableTransaction mutableTx; mutableTx.vin.resize(2); mutableTx.vout.emplace_back(0,spk);
    mutableTx.nVersion=3; mutableTx.vrefin.emplace_back(uint256S("ab"),0);
    CTransaction tx(mutableTx); PrecomputedTransactionData data(tx);
    std::vector<CTxOut> prevouts{CTxOut(0x0102030405060708LL,spk), CTxOut(9,CScript()<<OP_TRUE)};
    std::vector<CTxOut> refs{CTxOut(17,spk)};
    TransactionSignatureChecker checker(&tx,0,prevouts[0].nValue,data,spk,&prevouts,&refs);
    std::vector<Bytes> stack;
    bool ok=EvalScript(stack,contract,flags,checker,SIGVERSION_AUTHSCRIPT,&error);
    value=stack.empty()?Bytes():stack.back(); return ok;
}
void Message(const CScript& spk, bool expected, const Bytes& message, script_verify_flags flags=FLAGS) {
    for (auto op : {OP_OUTPUTASSETFIELD,OP_INPUTASSETFIELD,OP_REFINPUTASSETFIELD}) {
        Bytes value; ScriptError error;
        BOOST_CHECK_EQUAL(Run(CScript()<<OP_0<<Bytes{8}<<op,spk,flags,value,error),expected);
        if (expected) BOOST_CHECK(value==message);
    }
}
Bytes Field(unsigned char n) { Bytes b(32); b.back()=n; return b; }
const Bytes ROOT12=ParseHex("115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a");
Bytes Proof(unsigned depth) { Bytes b(1+32*depth+(depth+7)/8);b[0]=depth; for(unsigned i=0;i<depth;++i)b[32*(i+1)]=2;return b; }
CScript Merkle(const Bytes& leaf, const Bytes& proof, const Bytes& root) {
    return CScript()<<leaf<<Bytes{5}<<proof<<root<<OP_CHECKMERKLEINCLUSION;
}
}
BOOST_FIXTURE_TEST_SUITE(contract_thread_tests, Setup)
BOOST_AUTO_TEST_CASE(message_grammar_all_queries)
{
    for (int v=0;v<=3;++v) {
        for (unsigned char tag : {0x54,0x12}) {
            Bytes p=Payload(tag), result=Sequence();
            if(tag==0x12) result.insert(result.begin(),{0x12,0x20});
            Message(Asset(v,p),true,result);
            auto legacy=p;legacy[0]='r';legacy[1]='v';legacy[2]='n';Message(Asset(v,legacy),true,result);
            Message(Asset(v,p),false,{},FLAGS & ~SCRIPT_VERIFY_ASSETMESSAGEFIELD);
            auto expiry=p;expiry.insert(expiry.end(),8,0);Message(Asset(v,expiry),true,result);
            for(unsigned length : {0u,1u,15u,16u,17u,18u,49u}) {
                Bytes truncated(p.begin(),p.begin()+length);Message(Asset(v,truncated),false,{});
            }
            for(unsigned extra : {1u,7u,9u}) { auto b=p;b.insert(b.end(),extra,0);Message(Asset(v,b),false,{}); }
            auto b=p;b[16]=0x55;Message(Asset(v,b),false,{});
            b=p;b[17]=31;Message(Asset(v,b),false,{});
            b=p;b.erase(b.begin()+17);b.insert(b.begin()+17,{0xfd,0x20,0x00});Message(Asset(v,b),false,{});
            b=p;b[3]='q';Message(Asset(v,b),false,{});
            b=p;b[0]='y';Message(Asset(v,b),false,{});
            Message(Asset(v,p)<<OP_NOP,false,{});
            Message(Prefix(v)<<OP_XNA_ASSET<<p,false,{});
        }
    }
}
BOOST_AUTO_TEST_CASE(historical_selectors_unchanged)
{
    Bytes p=Payload();p.resize(16); // ordinary transfer without message
    Bytes value;ScriptError error;
    for(auto op : {OP_OUTPUTASSETFIELD,OP_INPUTASSETFIELD,OP_REFINPUTASSETFIELD}) {
        for (auto flags : {FLAGS,FLAGS & ~SCRIPT_VERIFY_ASSETMESSAGEFIELD}) {
            BOOST_REQUIRE(Run(CScript()<<OP_0<<Bytes{1}<<op,Asset(1,p),flags,value,error));
            BOOST_CHECK(value==Bytes({'A','#','a'}));
        }
    }
    Message(Asset(1,p),false,{});
}
BOOST_AUTO_TEST_CASE(input_fields_and_errors)
{
    Bytes value;ScriptError error;
    BOOST_CHECK_EQUAL(int(OP_INPUTFIELD),0xc4);
    BOOST_CHECK_EQUAL(GetOpName(OP_INPUTFIELD),"OP_INPUTFIELD");
    for(auto flags : {FLAGS,FLAGS|SCRIPT_VERIFY_64BIT_INTEGERS}) {
        BOOST_REQUIRE(Run(CScript()<<OP_0<<Bytes{1}<<OP_INPUTFIELD,Prefix(1),flags,value,error));
        BOOST_CHECK(value==ParseHex("0807060504030201"));
    }
    BOOST_REQUIRE(Run(CScript()<<OP_0<<Bytes{2}<<OP_INPUTFIELD,Prefix(1),FLAGS,value,error));
    BOOST_CHECK(value==Sequence());
    auto script=Asset(2,Payload());
    BOOST_REQUIRE(Run(CScript()<<OP_0<<Bytes{3}<<OP_INPUTFIELD,script,FLAGS,value,error));
    BOOST_CHECK(value==Bytes(script.begin(),script.end()));
    BOOST_REQUIRE(Run(CScript()<<OP_0<<Bytes{4}<<OP_INPUTFIELD,script,FLAGS,value,error));
    auto expected=Sequence();expected.insert(expected.begin(),2);BOOST_CHECK(value==expected);
    BOOST_REQUIRE(Run(CScript()<<OP_1<<Bytes{1}<<OP_INPUTFIELD,script,FLAGS,value,error));
    BOOST_CHECK(value==ParseHex("0900000000000000"));
    for (int index : {-1,2}) BOOST_CHECK(!Run(CScript()<<index<<Bytes{1}<<OP_INPUTFIELD,script,FLAGS,value,error));
    for (Bytes selector : {Bytes{},Bytes{0},Bytes{5},Bytes{1,0}})
        BOOST_CHECK(!Run(CScript()<<OP_0<<selector<<OP_INPUTFIELD,script,FLAGS,value,error));
    BOOST_CHECK(!Run(CScript()<<OP_0<<Bytes{4}<<OP_INPUTFIELD,script,FLAGS & ~SCRIPT_VERIFY_AUTHDEST,value,error));
    BOOST_CHECK(!Run(CScript()<<OP_0<<Bytes{3}<<OP_INPUTFIELD,script,FLAGS & ~SCRIPT_VERIFY_INPUTFIELD,value,error));
    BOOST_CHECK_EQUAL(error,SCRIPT_ERR_BAD_OPCODE);
    BOOST_CHECK(!Run(CScript()<<OP_INPUTFIELD,script,FLAGS,value,error));
    BOOST_CHECK_EQUAL(error,SCRIPT_ERR_INVALID_STACK_OPERATION);
    CScript big;big.resize(3073);std::fill(big.begin(),big.end(),OP_NOP);
    BOOST_CHECK(!Run(CScript()<<OP_0<<Bytes{3}<<OP_INPUTFIELD,big,FLAGS,value,error));
    BOOST_CHECK_EQUAL(error,SCRIPT_ERR_INPUTFIELD);
    BaseSignatureChecker checker;BOOST_CHECK(!checker.GetInputField(0,1,value));
}
BOOST_AUTO_TEST_CASE(poseidon_vector_flags_and_canonicality)
{
    Bytes value;ScriptError error; auto leaf=Field(1),proof=Proof(1);
    BOOST_REQUIRE(Run(Merkle(leaf,proof,ROOT12),{},FLAGS,value,error));BOOST_CHECK(value==Bytes{1});
    for(auto flag : {SCRIPT_VERIFY_MERKLE_POSEIDON,SCRIPT_VERIFY_POSEIDON}) {
        BOOST_REQUIRE(Run(Merkle(leaf,proof,ROOT12),{},FLAGS & ~flag,value,error));BOOST_CHECK(value.empty());
    }
    BOOST_CHECK(!Run(Merkle(leaf,proof,ROOT12),{},FLAGS & ~SCRIPT_VERIFY_MERKLE_INCLUSION,value,error));
    BOOST_CHECK_EQUAL(error,SCRIPT_ERR_BAD_OPCODE);
    Bytes modulus=ParseHex("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    for (unsigned part=0;part<3;++part) {
        auto l=leaf,p=proof,r=ROOT12;
        if(part==0)l=modulus;if(part==1)std::copy(modulus.begin(),modulus.end(),p.begin()+1);if(part==2)r=modulus;
        BOOST_REQUIRE(Run(Merkle(l,p,r),{},FLAGS,value,error));BOOST_CHECK(value.empty());
    }
    for(auto p : {Bytes{},Bytes{0},Bytes{33},Bytes(35,0)}) {
        BOOST_REQUIRE(Run(Merkle(leaf,p,ROOT12),{},FLAGS,value,error));BOOST_CHECK(value.empty());
    }
    proof.back()=1;BOOST_REQUIRE(Run(Merkle(leaf,proof,ROOT12),{},FLAGS,value,error));BOOST_CHECK(value.empty());
    proof=Proof(1);proof.back()=0xfe; // unused bitmap bits follow historical NIP-031 semantics
    BOOST_REQUIRE(Run(Merkle(leaf,proof,ROOT12),{},FLAGS,value,error));BOOST_CHECK(value==Bytes{1});
}
BOOST_AUTO_TEST_CASE(independent_deep_poseidon_vectors)
{
    Bytes value; ScriptError error;
    {
        auto proof=Proof(1);
        for(unsigned i=0;i<1;++i) proof[1+32*1+i/8] |= (i%2) << (i%8);
        auto root=ParseHex("115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a");
        BOOST_REQUIRE(Run(Merkle(Field(1),proof,root),{},FLAGS,value,error));
        BOOST_CHECK(value==Bytes{1});
        root[31]^=1;
        BOOST_REQUIRE(Run(Merkle(Field(1),proof,root),{},FLAGS,value,error));
        BOOST_CHECK(value.empty());
    }
    {
        auto proof=Proof(2);
        for(unsigned i=0;i<2;++i) proof[1+32*2+i/8] |= (i%2) << (i%8);
        auto root=ParseHex("2abdd0030cc2d1fc71d54fadd3a0f3bdea23b4e409b929304d1bf464f672ddb1");
        BOOST_REQUIRE(Run(Merkle(Field(1),proof,root),{},FLAGS,value,error));
        BOOST_CHECK(value==Bytes{1});
        root[31]^=1;
        BOOST_REQUIRE(Run(Merkle(Field(1),proof,root),{},FLAGS,value,error));
        BOOST_CHECK(value.empty());
    }
    {
        auto proof=Proof(32);
        for(unsigned i=0;i<32;++i) proof[1+32*32+i/8] |= (i%2) << (i%8);
        auto root=ParseHex("12bc9c7f8ec0c90a157feb9131609258025d4026c8ce985c64e9d7d5181e65fd");
        BOOST_REQUIRE(Run(Merkle(Field(1),proof,root),{},FLAGS,value,error));
        BOOST_CHECK(value==Bytes{1});
        root[31]^=1;
        BOOST_REQUIRE(Run(Merkle(Field(1),proof,root),{},FLAGS,value,error));
        BOOST_CHECK(value.empty());
    }
}
BOOST_AUTO_TEST_CASE(shared_poseidon_budget)
{
    // 15 paths at depth 32 cost 29760; direct sponge fills the remaining 960.
    // Invalid roots still pay for the well-shaped proof. Script size stays <10k
    // by putting the reusable proof in the initial witness stack.
    auto run=[](unsigned tail, ScriptError& error) {
        std::vector<Bytes> stack{Field(1),Bytes{5},Proof(32),Field(0)};
        CScript script;
        for(unsigned i=0;i<15;++i) {
            for(unsigned j=0;j<4;++j) script<<OP_3<<OP_PICK;
            script<<OP_CHECKMERKLEINCLUSION<<OP_DROP;
        }
        script<<Bytes(tail,0)<<OP_POSEIDON;
        return EvalScript(stack,script,FLAGS,BaseSignatureChecker(),SIGVERSION_AUTHSCRIPT,&error);
    };
    ScriptError error;
    BOOST_CHECK(run(960,error));BOOST_CHECK(!run(961,error));BOOST_CHECK_EQUAL(error,SCRIPT_ERR_POSEIDON_BUDGET);
}
BOOST_AUTO_TEST_CASE(independent_activation_heights)
{
    auto params=GetParams().GetConsensus();params.nAssetMessageHeight=120;params.nInputFieldHeight=121;params.nMerklePoseidonHeight=122;
    for (int height=119;height<=123;++height) {
        auto flags=ApplyConsensusOptIns(SCRIPT_VERIFY_NONE,params,false,height);
        BOOST_CHECK_EQUAL(bool(flags & SCRIPT_VERIFY_ASSETMESSAGEFIELD),height>=120);
        BOOST_CHECK_EQUAL(bool(flags & SCRIPT_VERIFY_INPUTFIELD),height>=121);
        BOOST_CHECK_EQUAL(bool(flags & SCRIPT_VERIFY_MERKLE_POSEIDON),height>=122);
    }
    BOOST_CHECK_EQUAL((SCRIPT_VERIFY_NONE|SCRIPT_VERIFY_ASSETMESSAGEFIELD).as_int(),uint64_t{1}<<45);
    BOOST_CHECK_EQUAL((SCRIPT_VERIFY_NONE|SCRIPT_VERIFY_INPUTFIELD).as_int(),uint64_t{1}<<46);
    BOOST_CHECK_EQUAL((SCRIPT_VERIFY_NONE|SCRIPT_VERIFY_MERKLE_POSEIDON).as_int(),uint64_t{1}<<47);
}
// These are contract-template checks, not restrictions on all asset messages.
BOOST_AUTO_TEST_CASE(state_template_rejects_ipfs_and_nonexact_script)
{
    for (int version=0;version<=3;++version) {
        for (auto op : {OP_OUTPUTASSETFIELD,OP_INPUTASSETFIELD,OP_REFINPUTASSETFIELD}) {
            Bytes value;ScriptError error;
            CScript require32=CScript()<<OP_0<<Bytes{8}<<op<<OP_SIZE<<32<<OP_EQUALVERIFY<<OP_DROP<<OP_TRUE;
            BOOST_CHECK(Run(require32,Asset(version,Payload()),FLAGS,value,error));
            // IPFS is valid to the parser but not to this 32-byte state contract.
            BOOST_CHECK(!Run(require32,Asset(version,Payload(0x12)),FLAGS,value,error));
            BOOST_CHECK_EQUAL(error,SCRIPT_ERR_EQUALVERIFY);
        }
        auto exact=Asset(version,Payload());Bytes value;ScriptError error;
        CScript compare=CScript()<<OP_0<<Bytes{3}<<OP_INPUTFIELD<<Bytes(exact.begin(),exact.end())<<OP_EQUALVERIFY<<OP_TRUE;
        BOOST_CHECK(Run(compare,exact,FLAGS,value,error));
        BOOST_CHECK(!Run(compare,exact<<OP_NOP,FLAGS,value,error));
        BOOST_CHECK_EQUAL(error,SCRIPT_ERR_EQUALVERIFY);
    }
}
BOOST_AUTO_TEST_CASE(zero_carrier_requires_numeric_mode)
{
    Bytes value;ScriptError error;
    const auto flags=FLAGS|SCRIPT_VERIFY_OUTPUTVALUE;
    CScript equality=CScript()<<OP_0<<OP_OUTPUTVALUE<<OP_0<<OP_EQUALVERIFY<<OP_TRUE;
    BOOST_CHECK(Run(equality,Asset(1,Payload()),flags|SCRIPT_VERIFY_64BIT_INTEGERS,value,error));
    BOOST_CHECK(!Run(equality,Asset(1,Payload()),flags,value,error));
    BOOST_CHECK_EQUAL(error,SCRIPT_ERR_EQUALVERIFY);
    // NUMEQUAL is not a workaround: raw eight-byte zero exceeds the four-byte
    // numeric bound when the integer expansion flag is disabled.
    CScript numeric=CScript()<<OP_0<<OP_OUTPUTVALUE<<OP_0<<OP_NUMEQUALVERIFY<<OP_TRUE;
    BOOST_CHECK(Run(numeric,Asset(1,Payload()),flags|SCRIPT_VERIFY_64BIT_INTEGERS,value,error));
    BOOST_CHECK(!Run(numeric,Asset(1,Payload()),flags,value,error));
}
BOOST_AUTO_TEST_SUITE_END()
