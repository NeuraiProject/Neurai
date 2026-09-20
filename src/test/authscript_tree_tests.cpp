// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license; see COPYING.
#include "chainparams.h"
#include "crypto/sha256.h"
#include "key.h"
#include "keystore.h"
#include "policy/policy.h"
#include "script/interpreter.h"
#include "script/sign.h"
#include "script/sigcache.h"
#include "script/standard.h"
#include "test/test_neurai.h"
#include "utilstrencodings.h"
#include <boost/test/unit_test.hpp>
#include <type_traits>
#include <chrono>

namespace {
using Bytes = std::vector<unsigned char>;
constexpr script_verify_flags FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS |
    SCRIPT_VERIFY_AUTHSCRIPT | SCRIPT_VERIFY_AUTHSCRIPT_TREE | SCRIPT_VERIFY_CHECKSIGFROMSTACK |
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY | SCRIPT_VERIFY_CHECKSIGADD;
struct Setup : BasicTestingSetup { Setup() : BasicTestingSetup(CBaseChainParams::REGTEST) {} };
Bytes Raw(const uint256& h) { return Bytes(h.begin(),h.end()); }
uint256 Hash(const std::string& hex) { auto b=ParseHex(hex);uint256 h;std::copy(b.begin(),b.end(),h.begin());return h; }
CScript Program(const uint256& h) { return CScript()<<OP_1<<Raw(h); }
bool Verify(const CScript& script, const CScriptWitness& witness, const BaseSignatureChecker& checker,
            script_verify_flags flags=FLAGS, ScriptError* error=nullptr) {
    return VerifyScript(CScript(),script,&witness,flags,checker,error);
}
}
static_assert(!std::is_default_constructible<AuthScriptTreeContext>::value, "Tree context must be complete");
static_assert(!std::is_copy_assignable<AuthScriptTreeContext>::value, "Tree context must be immutable");
BOOST_FIXTURE_TEST_SUITE(authscript_tree_tests, Setup)
BOOST_AUTO_TEST_CASE(shape_paths_and_flags)
{
    CScript leaf=CScript()<<OP_TRUE;
    uint256 root=AuthScriptLeafHash(leaf);
    CScriptWitness witness;witness.stack={Bytes{0x10},Bytes(leaf.begin(),leaf.end()),Bytes{1}};
    CScript spk=Program(AuthScriptTreeCommitment(Bytes{0},root));
    BaseSignatureChecker checker;ScriptError error;
    BOOST_CHECK(Verify(spk,witness,checker));
    BOOST_CHECK(!Verify(spk,witness,checker,FLAGS & ~SCRIPT_VERIFY_AUTHSCRIPT_TREE));
    for (Bytes control : {Bytes{},Bytes{1,0},Bytes{2},Bytes(1057,1)}) {
        witness.stack.back()=control;BOOST_CHECK(!Verify(spk,witness,checker));
    }
    witness.stack.back()=Bytes{1};
    for(unsigned i=0;i<32;++i) {
        uint256 sibling=Hash("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        sibling.begin()[0]=i;auto bytes=Raw(sibling);
        witness.stack.back().insert(witness.stack.back().end(),bytes.begin(),bytes.end());
        root=AuthScriptBranchHash(root,sibling);
    }
    spk=Program(AuthScriptTreeCommitment(Bytes{0},root));
    BOOST_CHECK(Verify(spk,witness,checker));
    witness.stack.back()[32]^=1;BOOST_CHECK(!Verify(spk,witness,checker));
    witness.stack[0]=Bytes{0x13};BOOST_CHECK(!Verify(spk,witness,checker));
}
BOOST_AUTO_TEST_CASE(initial_stack_rule_and_sigops)
{
    // 1001 initial args would pass historical post-op checking after the first DROP.
    CScript leaf;for(unsigned i=0;i<1000;++i) leaf<<OP_DROP;
    // The MAST failure must be STACK_SIZE before any OP_COUNT failure.
    CScriptWitness w;w.stack={Bytes{0x10}};
    for(unsigned i=0;i<1001;++i)w.stack.push_back(Bytes{1});
    w.stack.push_back(Bytes(leaf.begin(),leaf.end()));w.stack.push_back(Bytes{1});
    CScript spk=Program(AuthScriptTreeCommitment(Bytes{0},AuthScriptLeafHash(leaf)));
    ScriptError e;BOOST_CHECK(!Verify(spk,w,BaseSignatureChecker(),FLAGS,&e));
    BOOST_CHECK_EQUAL(e,SCRIPT_ERR_STACK_SIZE);
    std::vector<Bytes> historicalStack(1001,Bytes{1});
    BOOST_CHECK(EvalScript(historicalStack,CScript()<<OP_DROP,FLAGS,BaseSignatureChecker(),SIGVERSION_AUTHSCRIPT));
    BOOST_CHECK_EQUAL(historicalStack.size(),1000);
    leaf=CScript()<<OP_CHECKSIG<<OP_CHECKSIG;
    w.stack={Bytes{0x10},Bytes(leaf.begin(),leaf.end()),Bytes{1}};
    spk=Program(AuthScriptTreeCommitment(Bytes{0},AuthScriptLeafHash(leaf)));
    BOOST_CHECK_EQUAL(CountWitnessSigOps(CScript(),spk,&w,FLAGS),2);
    w.stack={Bytes{0x12},Bytes{},Bytes{},Bytes(leaf.begin(),leaf.end()),Bytes{1}};
    BOOST_CHECK_EQUAL(CountWitnessSigOps(CScript(),spk,&w,FLAGS),3);
    // Control bytes containing CHECKSIG never count as script.
    w.stack.back().insert(w.stack.back().end(),32,OP_CHECKSIG);
    BOOST_CHECK_EQUAL(CountWitnessSigOps(CScript(),spk,&w,FLAGS),3);
}
BOOST_AUTO_TEST_CASE(real_signatures_and_domains)
{
    for (bool pq : {false,true}) {
        CKey key;if(pq)key.MakeNewKeyPQ(Bytes(32,7));else key.MakeNewKey(true);
        CPubKey pub=key.GetPubKey();Bytes pk(pub.begin(),pub.end());
        CBasicKeyStore store;BOOST_REQUIRE(store.AddKey(key));
        for(uint8_t type : {uint8_t(0x10),uint8_t(pq?0x11:0x12)}) {
            CScript leaf=CScript()<<pk<<OP_CHECKSIG;
            const uint256 leafHash=AuthScriptLeafHash(leaf);
            Bytes descriptor;BOOST_REQUIRE(GetAuthScriptDescriptor(type&15,type==0x10?nullptr:&pub,descriptor));
            const AuthScriptTreeContext ctx(type,AuthScriptTreeCommitment(descriptor,leafHash),leafHash);
            CMutableTransaction mut;mut.nVersion=2;mut.vin.resize(1);mut.vin[0].prevout=COutPoint(uint256S("abcd"),0);
            mut.vin[0].nSequence=144;mut.vout.emplace_back(9000,CScript()<<OP_TRUE);
            CTransaction tx(mut);TransactionSignatureChecker checker(&tx,0,10000);
            TransactionSignatureCreator creator(&store,&tx,0,10000);
            Bytes sig;BOOST_REQUIRE(creator.CreateTreeSig(sig,pub.GetID(),leaf,ctx,1));
            CScriptWitness w;w.stack={Bytes{type}};
            if(type!=0x10){Bytes global;BOOST_REQUIRE(creator.CreateTreeSig(global,pub.GetID(),leaf,ctx,0));w.stack.push_back(global);w.stack.push_back(pk);}
            w.stack.push_back(sig);w.stack.push_back(Bytes(leaf.begin(),leaf.end()));w.stack.push_back(Bytes{1});
            BOOST_REQUIRE(Verify(Program(ctx.program),w,checker));
            if (pq) {
                ScriptError error;
                BOOST_CHECK(!Verify(Program(ctx.program),w,checker,
                    FLAGS & ~(SCRIPT_VERIFY_CHECKSIGFROMSTACK | SCRIPT_VERIFY_MERKLE_INCLUSION | SCRIPT_VERIFY_CHECKSIGADD), &error));
                BOOST_CHECK_EQUAL(error,SCRIPT_ERR_PUSH_SIZE);
            }
            uint256 base=SignatureHash(leaf,tx,0,SIGHASH_ALL,10000,SIGVERSION_AUTHSCRIPT,nullptr,type);
            Bytes historical;BOOST_REQUIRE(key.Sign(base,historical));historical.push_back(SIGHASH_ALL);
            PrecomputedTransactionData cache(tx);
            CachingTransactionSignatureChecker cached(&tx,0,10000,true,cache);
            BOOST_REQUIRE(cached.CheckSig(historical,pk,leaf,SIGVERSION_AUTHSCRIPT,type));
            BOOST_CHECK(!cached.CheckTreeSig(historical,pk,leaf,ctx,1));
            BOOST_CHECK(cached.CheckTreeSig(sig,pk,leaf,ctx,1));
            w.stack[w.stack.size()-3]=historical;BOOST_CHECK(!Verify(Program(ctx.program),w,checker));
            AuthScriptTreeContext invalid(0,uint256(),uint256());uint256 out;
            BOOST_CHECK(!checker.GetTreeSigHash(leaf,SIGHASH_ALL,invalid,1,out));
            BOOST_CHECK(!creator.CreateTreeSig(sig,pub.GetID(),leaf,invalid,1));
            BOOST_CHECK(!BaseSignatureChecker().CheckTreeSig(sig,pk,leaf,ctx,1));
        }
    }
}
BOOST_AUTO_TEST_CASE(activation_height)
{
    Consensus::Params params=GetParams().GetConsensus();params.nAuthScriptTreeHeight=120;
    BOOST_CHECK(!(ApplyConsensusOptIns(SCRIPT_VERIFY_NONE,params,true,119)&SCRIPT_VERIFY_AUTHSCRIPT_TREE));
    BOOST_CHECK(ApplyConsensusOptIns(SCRIPT_VERIFY_NONE,params,true,120)&SCRIPT_VERIFY_AUTHSCRIPT_TREE);
    params.nPQWitnessEnabled=false;
    BOOST_CHECK(!(ApplyConsensusOptIns(SCRIPT_VERIFY_NONE,params,true,120)&SCRIPT_VERIFY_AUTHSCRIPT_TREE));
}
BOOST_AUTO_TEST_CASE(frozen_hash_vectors)
{
{ auto s=ParseHex("0200007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("2d0fe640fbf6fd223c469d29ad76f4d4420ff83f27b121bf6d5e5f885dfb85dd")); }
{ auto s=ParseHex("0200007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("2d0fe640fbf6fd223c469d29ad76f4d4420ff83f27b121bf6d5e5f885dfb85dd")); }
{ auto s=ParseHex("0201007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("7aa813dc8914713f3ddc94599a0499574c9eec68e2da88c8b56b34848d043d16")); }
{ auto s=ParseHex("0200007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("2d0fe640fbf6fd223c469d29ad76f4d4420ff83f27b121bf6d5e5f885dfb85dd")); }
{ auto s=ParseHex("0201007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("7aa813dc8914713f3ddc94599a0499574c9eec68e2da88c8b56b34848d043d16")); }
{ auto s=ParseHex("0202007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("22da75fea959a29ed93eb4c7aea4a94a31bce58720cb4036983b22d8100b31ae")); }
{ auto s=ParseHex("0200007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("2d0fe640fbf6fd223c469d29ad76f4d4420ff83f27b121bf6d5e5f885dfb85dd")); }
{ auto s=ParseHex("0201007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("7aa813dc8914713f3ddc94599a0499574c9eec68e2da88c8b56b34848d043d16")); }
{ auto s=ParseHex("0202007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("22da75fea959a29ed93eb4c7aea4a94a31bce58720cb4036983b22d8100b31ae")); }
{ auto s=ParseHex("0203007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("5e6292a088a76fabb4c7e0450db6f6e4b60a0d40ecd88707d97190bf17df53d9")); }
{ auto s=ParseHex("0204007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("53a9a1d82a58f7277124a6d4e937a4ae0a9d42aaf02c6ac1a66d2836bdbb34ef")); }
{ auto s=ParseHex("0205007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("bd0bd5e5a6f1cac32eb6318ce69f7916cf2a39d2bfd8bac5474f5b425821a6f7")); }
{ auto s=ParseHex("0206007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("89727e712cfc8cd2327c828b172cd99d315e46c08b652cbb460252a5279c3202")); }
{ auto s=ParseHex("0207007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("7574893d15690bdf30ac8bc64a0b7c309acfa865d5fb5875b72167666a2e891b")); }
{ auto s=ParseHex("0208007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("27dc758ddb16a6d525be574dd5fc358c2901b8190ae86be5e415f5f03f49e9a9")); }
{ auto s=ParseHex("0209007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("16a8d0ed769e37612fe0b779cd849477c00352257ccb77cee62e32124f506632")); }
{ auto s=ParseHex("020a007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("86651ddf4abe517a1705795ef3ddb9b607e4dea3f6847445be2ff3bd97d7362d")); }
{ auto s=ParseHex("020b007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("b596e144aa5d8655b7f7d25ee5ab3b47657dcdbded43e928f12fe43f01862b70")); }
{ auto s=ParseHex("020c007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("34e260de19843d56472a3fd5aa342ebd35cc12824b86df14274f8dc0d48ac254")); }
{ auto s=ParseHex("020d007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("1babe982437b4e130b541e5f4f267203c353687add4fb5dedd54cda0ef3e7a93")); }
{ auto s=ParseHex("020e007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("740848657674a178ea81a316f2e11a8fa2af446748554002353fc43c5aeaa7a7")); }
{ auto s=ParseHex("020f007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("7da04465dcd7436a4685dbc56bb00f9d94fb7e7c561b6c6d185d010df30a8d5a")); }
{ auto s=ParseHex("0210007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("815c4f475c8acacd3c6f2161242262562df65fea058537c5f4e54ba5b10e4727")); }
{ auto s=ParseHex("0211007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("381b3277b4b91444a48e5a190c3a39c67278c80228d451d40b08172bd0ce6846")); }
{ auto s=ParseHex("0212007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("f1cff0c3527a5d45c59fc5444c5361b5d4604651d251c56dac775451cff4dcaa")); }
{ auto s=ParseHex("0213007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("f933d6dda3bcaa3afb077c137a771fe3f565d741c27d94df51ea73df94aa8a41")); }
{ auto s=ParseHex("0214007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("010b14acd1204bc7170d4eb25bed0ed88516374cb557ee90cf10641e45b12fd1")); }
{ auto s=ParseHex("0215007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("63947b14794942d415f7115328d285b21fc45cb8ca9b42f806a6c9186d6fd4f6")); }
{ auto s=ParseHex("0216007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("13dd335c678ed0dd93297cd6120f188b2687eadbf04b5af84d40ac9a66098efd")); }
{ auto s=ParseHex("0217007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("752b7d8d0562d4ce823d1cd2ac1fd590ceb056edba8aac79470de6080c292193")); }
{ auto s=ParseHex("0218007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("3a5ec700e3f33d51d927bff6081ae3b16938dd559a490ef9a8a49d283c939d6e")); }
{ auto s=ParseHex("0219007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("b6e7c717468e08078d8520dece4d8d8b32183c1dbea1935403978a6254487ba5")); }
{ auto s=ParseHex("021a007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("2c8ba673a0e9059b98fe3c4a0a916a83e9a35ae6f4cadc2334139e3a248f0f66")); }
{ auto s=ParseHex("021b007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("89e4e424e2a1ff2f9b560f3c074af4dbf1c9fd917e351b13b39d80e14fe87c8a")); }
{ auto s=ParseHex("021c007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("f3348a2265fcf1b829ddf3e81c0ef3be24eb670af52179f685acf7ae483aed48")); }
{ auto s=ParseHex("021d007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("86feb6e442f81eca03f3ed0fe56c8aa4c9ed8a6bacf32496ed210b718fc14c52")); }
{ auto s=ParseHex("021e007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("877c03334a942d2ca03e68173caac314f1daa13ca7501a92c2373b6e27f66e32")); }
{ auto s=ParseHex("021f007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("ec2ca9bea5ffdde30e4b7aa0decaed7a7da1c93ece85860b1460dc98573aa42d")); }
{ auto s=ParseHex("0220007551"); CScript script(s.begin(),s.end()); BOOST_CHECK(AuthScriptLeafHash(script)==Hash("54c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")); }
{ const AuthScriptTreeContext c(16,Hash("1e5ef8e6843c98452c9be5e97c374784aabfaad16d32a137c7dfcec026124b33"),Hash("161e590ccc45d804496ce178ccda4988d6fd75dca2d4c63022e4a00d0dc360f8"));uint256 out;BOOST_REQUIRE(AuthScriptTreeSignatureHash(Hash("78633858d8f9673a68e98241095f41204da1a9d7015077d07e6e35cc1727a153"),c,1,out));BOOST_CHECK(out==Hash("cb954366eb24fd1076a6ade24b0814c091ee3099728123225a6f052d748c68a5"));}
{ const AuthScriptTreeContext c(17,Hash("6790a4e5d8056df1ea2d9fd2e37c77e82aca1484ea5e2ee3382904185f8f97ae"),Hash("161e590ccc45d804496ce178ccda4988d6fd75dca2d4c63022e4a00d0dc360f8"));uint256 out;BOOST_REQUIRE(AuthScriptTreeSignatureHash(Hash("43c8ee79bdf5965fe7443986408a6c8d36b4b6333ea140229963699819fe8f16"),c,0,out));BOOST_CHECK(out==Hash("5461ae5a27cb3a533419dde174ffc873c91bb7e2c82d121ca5ad6b3174a06aea"));}
{ const AuthScriptTreeContext c(17,Hash("6790a4e5d8056df1ea2d9fd2e37c77e82aca1484ea5e2ee3382904185f8f97ae"),Hash("161e590ccc45d804496ce178ccda4988d6fd75dca2d4c63022e4a00d0dc360f8"));uint256 out;BOOST_REQUIRE(AuthScriptTreeSignatureHash(Hash("43c8ee79bdf5965fe7443986408a6c8d36b4b6333ea140229963699819fe8f16"),c,1,out));BOOST_CHECK(out==Hash("18df2885cdcd2481bddc27a43738f8a8b7556e9db190925b59d51c72ec33b5b8"));}
{ const AuthScriptTreeContext c(18,Hash("5af9a958723f02a6104cd6e8741ceb989b7331b3343fc41d2e23fb51a2bcf1a9"),Hash("161e590ccc45d804496ce178ccda4988d6fd75dca2d4c63022e4a00d0dc360f8"));uint256 out;BOOST_REQUIRE(AuthScriptTreeSignatureHash(Hash("5372fcab7decd32a780dc6d39e135ec38fdee6f5dde38aa264fc20d324a43e9a"),c,0,out));BOOST_CHECK(out==Hash("f5d92d8402ed37814df68772cf5c0b38b1f5b66b181178b04464a7408a961e6b"));}
{ const AuthScriptTreeContext c(18,Hash("5af9a958723f02a6104cd6e8741ceb989b7331b3343fc41d2e23fb51a2bcf1a9"),Hash("161e590ccc45d804496ce178ccda4988d6fd75dca2d4c63022e4a00d0dc360f8"));uint256 out;BOOST_REQUIRE(AuthScriptTreeSignatureHash(Hash("5372fcab7decd32a780dc6d39e135ec38fdee6f5dde38aa264fc20d324a43e9a"),c,1,out));BOOST_CHECK(out==Hash("c6607bb767eba5f27267ff35ba190f1b10283f1f1d42a0513eb4168025e4bafb"));}
{ const AuthScriptTreeContext c(16,Hash("1e5ef8e6843c98452c9be5e97c374784aabfaad16d32a137c7dfcec026124b33"),Hash("161e590ccc45d804496ce178ccda4988d6fd75dca2d4c63022e4a00d0dc360f8"));uint256 out;BOOST_REQUIRE(AuthScriptTreeSignatureHash(Hash("103ff993aecf5ad13058babac90190ff1cfdd39fbe7d6e95af27c3c9db6e9917"),c,1,out));BOOST_CHECK(out==Hash("0d019db1a9b9b92c63fc40c96629ca50512fefee2727d1326d6e81566b5d8829"));}
{ const AuthScriptTreeContext c(17,Hash("6790a4e5d8056df1ea2d9fd2e37c77e82aca1484ea5e2ee3382904185f8f97ae"),Hash("161e590ccc45d804496ce178ccda4988d6fd75dca2d4c63022e4a00d0dc360f8"));uint256 out;BOOST_REQUIRE(AuthScriptTreeSignatureHash(Hash("1cc01736ad1193cd2fd2e738ec3d30b82788233c0fd1acfdd04b39662c9603af"),c,0,out));BOOST_CHECK(out==Hash("2db5e54d93d66c9334b652bb26bc45b33dab094fbb9f99599b1e328256980ef4"));}
{ const AuthScriptTreeContext c(17,Hash("6790a4e5d8056df1ea2d9fd2e37c77e82aca1484ea5e2ee3382904185f8f97ae"),Hash("161e590ccc45d804496ce178ccda4988d6fd75dca2d4c63022e4a00d0dc360f8"));uint256 out;BOOST_REQUIRE(AuthScriptTreeSignatureHash(Hash("1cc01736ad1193cd2fd2e738ec3d30b82788233c0fd1acfdd04b39662c9603af"),c,1,out));BOOST_CHECK(out==Hash("69afe8c2387f79afd23b7ecd09084bd5909883440b4773db4d9a392609d69bd9"));}
{ const AuthScriptTreeContext c(18,Hash("5af9a958723f02a6104cd6e8741ceb989b7331b3343fc41d2e23fb51a2bcf1a9"),Hash("161e590ccc45d804496ce178ccda4988d6fd75dca2d4c63022e4a00d0dc360f8"));uint256 out;BOOST_REQUIRE(AuthScriptTreeSignatureHash(Hash("c0a0c63db79dc95dba7db054a174bd432f60ebdef7849d9eb6a98548647da5ff"),c,0,out));BOOST_CHECK(out==Hash("e3e30f505e880f62c8e9fbe50afed406dc639b979e282866ea5c80167bf0f631"));}
{ const AuthScriptTreeContext c(18,Hash("5af9a958723f02a6104cd6e8741ceb989b7331b3343fc41d2e23fb51a2bcf1a9"),Hash("161e590ccc45d804496ce178ccda4988d6fd75dca2d4c63022e4a00d0dc360f8"));uint256 out;BOOST_REQUIRE(AuthScriptTreeSignatureHash(Hash("c0a0c63db79dc95dba7db054a174bd432f60ebdef7849d9eb6a98548647da5ff"),c,1,out));BOOST_CHECK(out==Hash("6e7f335716f011f71762c49f3f69bca040bb0f3442433d6eb32ed847450c55a9"));}
}


BOOST_AUTO_TEST_CASE(frozen_transaction_preimages)
{
{
 CMutableTransaction mut;mut.nVersion=2;mut.vin.emplace_back(COutPoint(Hash("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),7));
 mut.vin[0].nSequence=144;mut.vout.emplace_back(9000,CScript()<<OP_TRUE);
auto bytes=ParseHex("210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac");CScript script(bytes.begin(),bytes.end());CTransaction tx(mut);
BOOST_CHECK(SignatureHash(script,tx,0,SIGHASH_ALL,10000,SIGVERSION_AUTHSCRIPT,nullptr,16)==Hash("78633858d8f9673a68e98241095f41204da1a9d7015077d07e6e35cc1727a153"));
}
{
 CMutableTransaction mut;mut.nVersion=2;mut.vin.emplace_back(COutPoint(Hash("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),7));
 mut.vin[0].nSequence=144;mut.vout.emplace_back(9000,CScript()<<OP_TRUE);
auto bytes=ParseHex("210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac");CScript script(bytes.begin(),bytes.end());CTransaction tx(mut);
BOOST_CHECK(SignatureHash(script,tx,0,SIGHASH_ALL,10000,SIGVERSION_AUTHSCRIPT,nullptr,17)==Hash("43c8ee79bdf5965fe7443986408a6c8d36b4b6333ea140229963699819fe8f16"));
}
{
 CMutableTransaction mut;mut.nVersion=2;mut.vin.emplace_back(COutPoint(Hash("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),7));
 mut.vin[0].nSequence=144;mut.vout.emplace_back(9000,CScript()<<OP_TRUE);
auto bytes=ParseHex("210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac");CScript script(bytes.begin(),bytes.end());CTransaction tx(mut);
BOOST_CHECK(SignatureHash(script,tx,0,SIGHASH_ALL,10000,SIGVERSION_AUTHSCRIPT,nullptr,17)==Hash("43c8ee79bdf5965fe7443986408a6c8d36b4b6333ea140229963699819fe8f16"));
}
{
 CMutableTransaction mut;mut.nVersion=2;mut.vin.emplace_back(COutPoint(Hash("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),7));
 mut.vin[0].nSequence=144;mut.vout.emplace_back(9000,CScript()<<OP_TRUE);
auto bytes=ParseHex("210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac");CScript script(bytes.begin(),bytes.end());CTransaction tx(mut);
BOOST_CHECK(SignatureHash(script,tx,0,SIGHASH_ALL,10000,SIGVERSION_AUTHSCRIPT,nullptr,18)==Hash("5372fcab7decd32a780dc6d39e135ec38fdee6f5dde38aa264fc20d324a43e9a"));
}
{
 CMutableTransaction mut;mut.nVersion=2;mut.vin.emplace_back(COutPoint(Hash("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),7));
 mut.vin[0].nSequence=144;mut.vout.emplace_back(9000,CScript()<<OP_TRUE);
auto bytes=ParseHex("210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac");CScript script(bytes.begin(),bytes.end());CTransaction tx(mut);
BOOST_CHECK(SignatureHash(script,tx,0,SIGHASH_ALL,10000,SIGVERSION_AUTHSCRIPT,nullptr,18)==Hash("5372fcab7decd32a780dc6d39e135ec38fdee6f5dde38aa264fc20d324a43e9a"));
}
{
 CMutableTransaction mut;mut.nVersion=3;mut.vin.emplace_back(COutPoint(Hash("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),7));
 mut.vin[0].nSequence=144;mut.vout.emplace_back(9000,CScript()<<OP_TRUE);
mut.vrefin.emplace_back(Hash("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),2);
auto bytes=ParseHex("210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac");CScript script(bytes.begin(),bytes.end());CTransaction tx(mut);
BOOST_CHECK(SignatureHash(script,tx,0,SIGHASH_ALL,10000,SIGVERSION_AUTHSCRIPT,nullptr,16)==Hash("103ff993aecf5ad13058babac90190ff1cfdd39fbe7d6e95af27c3c9db6e9917"));
}
{
 CMutableTransaction mut;mut.nVersion=3;mut.vin.emplace_back(COutPoint(Hash("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),7));
 mut.vin[0].nSequence=144;mut.vout.emplace_back(9000,CScript()<<OP_TRUE);
mut.vrefin.emplace_back(Hash("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),2);
auto bytes=ParseHex("210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac");CScript script(bytes.begin(),bytes.end());CTransaction tx(mut);
BOOST_CHECK(SignatureHash(script,tx,0,SIGHASH_ALL,10000,SIGVERSION_AUTHSCRIPT,nullptr,17)==Hash("1cc01736ad1193cd2fd2e738ec3d30b82788233c0fd1acfdd04b39662c9603af"));
}
{
 CMutableTransaction mut;mut.nVersion=3;mut.vin.emplace_back(COutPoint(Hash("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),7));
 mut.vin[0].nSequence=144;mut.vout.emplace_back(9000,CScript()<<OP_TRUE);
mut.vrefin.emplace_back(Hash("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),2);
auto bytes=ParseHex("210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac");CScript script(bytes.begin(),bytes.end());CTransaction tx(mut);
BOOST_CHECK(SignatureHash(script,tx,0,SIGHASH_ALL,10000,SIGVERSION_AUTHSCRIPT,nullptr,17)==Hash("1cc01736ad1193cd2fd2e738ec3d30b82788233c0fd1acfdd04b39662c9603af"));
}
{
 CMutableTransaction mut;mut.nVersion=3;mut.vin.emplace_back(COutPoint(Hash("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),7));
 mut.vin[0].nSequence=144;mut.vout.emplace_back(9000,CScript()<<OP_TRUE);
mut.vrefin.emplace_back(Hash("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),2);
auto bytes=ParseHex("210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac");CScript script(bytes.begin(),bytes.end());CTransaction tx(mut);
BOOST_CHECK(SignatureHash(script,tx,0,SIGHASH_ALL,10000,SIGVERSION_AUTHSCRIPT,nullptr,18)==Hash("c0a0c63db79dc95dba7db054a174bd432f60ebdef7849d9eb6a98548647da5ff"));
}
{
 CMutableTransaction mut;mut.nVersion=3;mut.vin.emplace_back(COutPoint(Hash("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),7));
 mut.vin[0].nSequence=144;mut.vout.emplace_back(9000,CScript()<<OP_TRUE);
mut.vrefin.emplace_back(Hash("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),2);
auto bytes=ParseHex("210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac");CScript script(bytes.begin(),bytes.end());CTransaction tx(mut);
BOOST_CHECK(SignatureHash(script,tx,0,SIGHASH_ALL,10000,SIGVERSION_AUTHSCRIPT,nullptr,18)==Hash("c0a0c63db79dc95dba7db054a174bd432f60ebdef7849d9eb6a98548647da5ff"));
}
}
BOOST_AUTO_TEST_CASE(frozen_controls)
{
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0200007551"),ParseHex("01")};BOOST_CHECK(Verify(Program(Hash("331faddaae8126920f1261295eea96502d539eb4187db844aa049a468c6d7595")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0200007551"),ParseHex("017aa813dc8914713f3ddc94599a0499574c9eec68e2da88c8b56b34848d043d16")};BOOST_CHECK(Verify(Program(Hash("046bbca743bb5f7644d9c2e849ceded35f7096348798954d36f925a8c8dc7615")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0201007551"),ParseHex("012d0fe640fbf6fd223c469d29ad76f4d4420ff83f27b121bf6d5e5f885dfb85dd")};BOOST_CHECK(Verify(Program(Hash("046bbca743bb5f7644d9c2e849ceded35f7096348798954d36f925a8c8dc7615")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0200007551"),ParseHex("017aa813dc8914713f3ddc94599a0499574c9eec68e2da88c8b56b34848d043d1622da75fea959a29ed93eb4c7aea4a94a31bce58720cb4036983b22d8100b31ae")};BOOST_CHECK(Verify(Program(Hash("105e6dbcf7f38dbc691f6107c1da7847eeeeca99013ab25c6bce1788e3bea063")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0201007551"),ParseHex("012d0fe640fbf6fd223c469d29ad76f4d4420ff83f27b121bf6d5e5f885dfb85dd22da75fea959a29ed93eb4c7aea4a94a31bce58720cb4036983b22d8100b31ae")};BOOST_CHECK(Verify(Program(Hash("105e6dbcf7f38dbc691f6107c1da7847eeeeca99013ab25c6bce1788e3bea063")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0202007551"),ParseHex("01d52785c85bbb5bec23b1d068bc2037365ca1eb7291f16824b92b3a8130a60dc5")};BOOST_CHECK(Verify(Program(Hash("105e6dbcf7f38dbc691f6107c1da7847eeeeca99013ab25c6bce1788e3bea063")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0200007551"),ParseHex("017aa813dc8914713f3ddc94599a0499574c9eec68e2da88c8b56b34848d043d16aa2ec7bd0b61231b677e15d56941e3583baa95866827280d8f402b6ccf928e48150a6d76174f223ca63f4846058379da8b0c8ce755831cbb36c5d950305d2ea2e222757c4bb416df6c27f010701d0de25a67f300fcd709341fd3d7cc21700cb86cc55728ba0fc6e2dd2bdc5ae4308d3c327ecaccde98529c21fad6e9ce95e1d254c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0201007551"),ParseHex("012d0fe640fbf6fd223c469d29ad76f4d4420ff83f27b121bf6d5e5f885dfb85ddaa2ec7bd0b61231b677e15d56941e3583baa95866827280d8f402b6ccf928e48150a6d76174f223ca63f4846058379da8b0c8ce755831cbb36c5d950305d2ea2e222757c4bb416df6c27f010701d0de25a67f300fcd709341fd3d7cc21700cb86cc55728ba0fc6e2dd2bdc5ae4308d3c327ecaccde98529c21fad6e9ce95e1d254c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0202007551"),ParseHex("015e6292a088a76fabb4c7e0450db6f6e4b60a0d40ecd88707d97190bf17df53d9d52785c85bbb5bec23b1d068bc2037365ca1eb7291f16824b92b3a8130a60dc5150a6d76174f223ca63f4846058379da8b0c8ce755831cbb36c5d950305d2ea2e222757c4bb416df6c27f010701d0de25a67f300fcd709341fd3d7cc21700cb86cc55728ba0fc6e2dd2bdc5ae4308d3c327ecaccde98529c21fad6e9ce95e1d254c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0203007551"),ParseHex("0122da75fea959a29ed93eb4c7aea4a94a31bce58720cb4036983b22d8100b31aed52785c85bbb5bec23b1d068bc2037365ca1eb7291f16824b92b3a8130a60dc5150a6d76174f223ca63f4846058379da8b0c8ce755831cbb36c5d950305d2ea2e222757c4bb416df6c27f010701d0de25a67f300fcd709341fd3d7cc21700cb86cc55728ba0fc6e2dd2bdc5ae4308d3c327ecaccde98529c21fad6e9ce95e1d254c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0204007551"),ParseHex("01bd0bd5e5a6f1cac32eb6318ce69f7916cf2a39d2bfd8bac5474f5b425821a6f7af3420205790ab6f197baada93dd874ae46a0cfe0ee2718dec578c1bbc71201bffab5c97cd7cbaaed2b5db4d59159906a9c4eaf6e7f8471b800ee29cf5916eafe222757c4bb416df6c27f010701d0de25a67f300fcd709341fd3d7cc21700cb86cc55728ba0fc6e2dd2bdc5ae4308d3c327ecaccde98529c21fad6e9ce95e1d254c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0205007551"),ParseHex("0153a9a1d82a58f7277124a6d4e937a4ae0a9d42aaf02c6ac1a66d2836bdbb34efaf3420205790ab6f197baada93dd874ae46a0cfe0ee2718dec578c1bbc71201bffab5c97cd7cbaaed2b5db4d59159906a9c4eaf6e7f8471b800ee29cf5916eafe222757c4bb416df6c27f010701d0de25a67f300fcd709341fd3d7cc21700cb86cc55728ba0fc6e2dd2bdc5ae4308d3c327ecaccde98529c21fad6e9ce95e1d254c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0206007551"),ParseHex("017574893d15690bdf30ac8bc64a0b7c309acfa865d5fb5875b72167666a2e891bf1c52dcb28ac421767b5d2fdfd3725b0dca9aaaa4be67e60054cb6e78c84a9efffab5c97cd7cbaaed2b5db4d59159906a9c4eaf6e7f8471b800ee29cf5916eafe222757c4bb416df6c27f010701d0de25a67f300fcd709341fd3d7cc21700cb86cc55728ba0fc6e2dd2bdc5ae4308d3c327ecaccde98529c21fad6e9ce95e1d254c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0207007551"),ParseHex("0189727e712cfc8cd2327c828b172cd99d315e46c08b652cbb460252a5279c3202f1c52dcb28ac421767b5d2fdfd3725b0dca9aaaa4be67e60054cb6e78c84a9efffab5c97cd7cbaaed2b5db4d59159906a9c4eaf6e7f8471b800ee29cf5916eafe222757c4bb416df6c27f010701d0de25a67f300fcd709341fd3d7cc21700cb86cc55728ba0fc6e2dd2bdc5ae4308d3c327ecaccde98529c21fad6e9ce95e1d254c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0208007551"),ParseHex("0116a8d0ed769e37612fe0b779cd849477c00352257ccb77cee62e32124f5066328662d181f57ee8adb5ee3589839dfbafd81f2acc8d5380ca411f7f217f46ef91c10ef0a6ffa898b3a16e62b74cbb392e49cf1905406fa8f29ad6e570b2a4bb44fa402a79b21df8d146431c8d38190591d60f732816307ed7dac47f6de358ffa66cc55728ba0fc6e2dd2bdc5ae4308d3c327ecaccde98529c21fad6e9ce95e1d254c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0209007551"),ParseHex("0127dc758ddb16a6d525be574dd5fc358c2901b8190ae86be5e415f5f03f49e9a98662d181f57ee8adb5ee3589839dfbafd81f2acc8d5380ca411f7f217f46ef91c10ef0a6ffa898b3a16e62b74cbb392e49cf1905406fa8f29ad6e570b2a4bb44fa402a79b21df8d146431c8d38190591d60f732816307ed7dac47f6de358ffa66cc55728ba0fc6e2dd2bdc5ae4308d3c327ecaccde98529c21fad6e9ce95e1d254c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("020a007551"),ParseHex("01b596e144aa5d8655b7f7d25ee5ab3b47657dcdbded43e928f12fe43f01862b7097d9cdbd7cd96dce2349b16ea5bd5efe307dc1780911bba7e05c7d7270dc630bc10ef0a6ffa898b3a16e62b74cbb392e49cf1905406fa8f29ad6e570b2a4bb44fa402a79b21df8d146431c8d38190591d60f732816307ed7dac47f6de358ffa66cc55728ba0fc6e2dd2bdc5ae4308d3c327ecaccde98529c21fad6e9ce95e1d254c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("020b007551"),ParseHex("0186651ddf4abe517a1705795ef3ddb9b607e4dea3f6847445be2ff3bd97d7362d97d9cdbd7cd96dce2349b16ea5bd5efe307dc1780911bba7e05c7d7270dc630bc10ef0a6ffa898b3a16e62b74cbb392e49cf1905406fa8f29ad6e570b2a4bb44fa402a79b21df8d146431c8d38190591d60f732816307ed7dac47f6de358ffa66cc55728ba0fc6e2dd2bdc5ae4308d3c327ecaccde98529c21fad6e9ce95e1d254c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("020c007551"),ParseHex("011babe982437b4e130b541e5f4f267203c353687add4fb5dedd54cda0ef3e7a93553e4ec962ddb3fbeaabb5b9edc4aeddbdc9fb2429b9a9df15f89055c37147966965be339ea497aec6e8fd65f3e9ffb96dfafa548ab406f5f9fd5c583981554cfa402a79b21df8d146431c8d38190591d60f732816307ed7dac47f6de358ffa66cc55728ba0fc6e2dd2bdc5ae4308d3c327ecaccde98529c21fad6e9ce95e1d254c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("020d007551"),ParseHex("0134e260de19843d56472a3fd5aa342ebd35cc12824b86df14274f8dc0d48ac254553e4ec962ddb3fbeaabb5b9edc4aeddbdc9fb2429b9a9df15f89055c37147966965be339ea497aec6e8fd65f3e9ffb96dfafa548ab406f5f9fd5c583981554cfa402a79b21df8d146431c8d38190591d60f732816307ed7dac47f6de358ffa66cc55728ba0fc6e2dd2bdc5ae4308d3c327ecaccde98529c21fad6e9ce95e1d254c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("020e007551"),ParseHex("017da04465dcd7436a4685dbc56bb00f9d94fb7e7c561b6c6d185d010df30a8d5a561779e01f14074a3e28733bef8cdb732228af63c669388e57dfb856851822016965be339ea497aec6e8fd65f3e9ffb96dfafa548ab406f5f9fd5c583981554cfa402a79b21df8d146431c8d38190591d60f732816307ed7dac47f6de358ffa66cc55728ba0fc6e2dd2bdc5ae4308d3c327ecaccde98529c21fad6e9ce95e1d254c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("020f007551"),ParseHex("01740848657674a178ea81a316f2e11a8fa2af446748554002353fc43c5aeaa7a7561779e01f14074a3e28733bef8cdb732228af63c669388e57dfb856851822016965be339ea497aec6e8fd65f3e9ffb96dfafa548ab406f5f9fd5c583981554cfa402a79b21df8d146431c8d38190591d60f732816307ed7dac47f6de358ffa66cc55728ba0fc6e2dd2bdc5ae4308d3c327ecaccde98529c21fad6e9ce95e1d254c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0210007551"),ParseHex("01381b3277b4b91444a48e5a190c3a39c67278c80228d451d40b08172bd0ce6846b6c4e7fc16c975562202a58dcd19db93698fbbb11cc97fb64e4bd608c1e41aab7bb72db5e22fa792a6a68d39511ccda4269aebb10462f3d7f9a0fc70d3f830421d7060e92864e3749f05b15179a644b8b88dd81db540288b27980d45661e0961eb8a7ceec906dec1cb9a593f884b77f25548045bd170fc46b72927ef87394fb854c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0211007551"),ParseHex("01815c4f475c8acacd3c6f2161242262562df65fea058537c5f4e54ba5b10e4727b6c4e7fc16c975562202a58dcd19db93698fbbb11cc97fb64e4bd608c1e41aab7bb72db5e22fa792a6a68d39511ccda4269aebb10462f3d7f9a0fc70d3f830421d7060e92864e3749f05b15179a644b8b88dd81db540288b27980d45661e0961eb8a7ceec906dec1cb9a593f884b77f25548045bd170fc46b72927ef87394fb854c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0212007551"),ParseHex("01f933d6dda3bcaa3afb077c137a771fe3f565d741c27d94df51ea73df94aa8a41d988191581821ae20b96b5019dc4ff711fd1fae2e006962ba5a9adb6fadcd8eb7bb72db5e22fa792a6a68d39511ccda4269aebb10462f3d7f9a0fc70d3f830421d7060e92864e3749f05b15179a644b8b88dd81db540288b27980d45661e0961eb8a7ceec906dec1cb9a593f884b77f25548045bd170fc46b72927ef87394fb854c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0213007551"),ParseHex("01f1cff0c3527a5d45c59fc5444c5361b5d4604651d251c56dac775451cff4dcaad988191581821ae20b96b5019dc4ff711fd1fae2e006962ba5a9adb6fadcd8eb7bb72db5e22fa792a6a68d39511ccda4269aebb10462f3d7f9a0fc70d3f830421d7060e92864e3749f05b15179a644b8b88dd81db540288b27980d45661e0961eb8a7ceec906dec1cb9a593f884b77f25548045bd170fc46b72927ef87394fb854c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0214007551"),ParseHex("0163947b14794942d415f7115328d285b21fc45cb8ca9b42f806a6c9186d6fd4f69e43bc9a52b48c97b2e4090ff119806fcede78d2168b5f470a9f1c37d14968a4ba65a7afa20f4d8d1ba7d6b683aeb50bb713f6504b04400f368e72bfd79cc89f1d7060e92864e3749f05b15179a644b8b88dd81db540288b27980d45661e0961eb8a7ceec906dec1cb9a593f884b77f25548045bd170fc46b72927ef87394fb854c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0215007551"),ParseHex("01010b14acd1204bc7170d4eb25bed0ed88516374cb557ee90cf10641e45b12fd19e43bc9a52b48c97b2e4090ff119806fcede78d2168b5f470a9f1c37d14968a4ba65a7afa20f4d8d1ba7d6b683aeb50bb713f6504b04400f368e72bfd79cc89f1d7060e92864e3749f05b15179a644b8b88dd81db540288b27980d45661e0961eb8a7ceec906dec1cb9a593f884b77f25548045bd170fc46b72927ef87394fb854c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0216007551"),ParseHex("01752b7d8d0562d4ce823d1cd2ac1fd590ceb056edba8aac79470de6080c29219385ab8d458c2acf9409bb73098267fc55206ae418792cacd6091fe8440ecd7c5fba65a7afa20f4d8d1ba7d6b683aeb50bb713f6504b04400f368e72bfd79cc89f1d7060e92864e3749f05b15179a644b8b88dd81db540288b27980d45661e0961eb8a7ceec906dec1cb9a593f884b77f25548045bd170fc46b72927ef87394fb854c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0217007551"),ParseHex("0113dd335c678ed0dd93297cd6120f188b2687eadbf04b5af84d40ac9a66098efd85ab8d458c2acf9409bb73098267fc55206ae418792cacd6091fe8440ecd7c5fba65a7afa20f4d8d1ba7d6b683aeb50bb713f6504b04400f368e72bfd79cc89f1d7060e92864e3749f05b15179a644b8b88dd81db540288b27980d45661e0961eb8a7ceec906dec1cb9a593f884b77f25548045bd170fc46b72927ef87394fb854c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0218007551"),ParseHex("01b6e7c717468e08078d8520dece4d8d8b32183c1dbea1935403978a6254487ba56857e51b4bb4f25a1ef16d2e5a564c6a4d8d1d5eaf6422045a82006b1211ded85a7959cf4ce1039561598ffda02613dc994b1ddb9fc05d47ecb4a1c96eff1586def614b306c7ba95853ccef5830558dd881a95656020a3315261e8bb2ab31a71eb8a7ceec906dec1cb9a593f884b77f25548045bd170fc46b72927ef87394fb854c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0219007551"),ParseHex("013a5ec700e3f33d51d927bff6081ae3b16938dd559a490ef9a8a49d283c939d6e6857e51b4bb4f25a1ef16d2e5a564c6a4d8d1d5eaf6422045a82006b1211ded85a7959cf4ce1039561598ffda02613dc994b1ddb9fc05d47ecb4a1c96eff1586def614b306c7ba95853ccef5830558dd881a95656020a3315261e8bb2ab31a71eb8a7ceec906dec1cb9a593f884b77f25548045bd170fc46b72927ef87394fb854c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("021a007551"),ParseHex("0189e4e424e2a1ff2f9b560f3c074af4dbf1c9fd917e351b13b39d80e14fe87c8a7e098bea9ff5e62fc2f22ef67cc189867765a4c9c0a8e192e33abf734d3038805a7959cf4ce1039561598ffda02613dc994b1ddb9fc05d47ecb4a1c96eff1586def614b306c7ba95853ccef5830558dd881a95656020a3315261e8bb2ab31a71eb8a7ceec906dec1cb9a593f884b77f25548045bd170fc46b72927ef87394fb854c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("021b007551"),ParseHex("012c8ba673a0e9059b98fe3c4a0a916a83e9a35ae6f4cadc2334139e3a248f0f667e098bea9ff5e62fc2f22ef67cc189867765a4c9c0a8e192e33abf734d3038805a7959cf4ce1039561598ffda02613dc994b1ddb9fc05d47ecb4a1c96eff1586def614b306c7ba95853ccef5830558dd881a95656020a3315261e8bb2ab31a71eb8a7ceec906dec1cb9a593f884b77f25548045bd170fc46b72927ef87394fb854c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("021c007551"),ParseHex("0186feb6e442f81eca03f3ed0fe56c8aa4c9ed8a6bacf32496ed210b718fc14c52e2dfa65fb0664d2c35634365ffe92018af7823e6a90f4cf62f3a2cc1800b8188b268f1d74f4fc7046450d2f2563658669a6671b67edf796d87a12f788ed63517def614b306c7ba95853ccef5830558dd881a95656020a3315261e8bb2ab31a71eb8a7ceec906dec1cb9a593f884b77f25548045bd170fc46b72927ef87394fb854c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("021d007551"),ParseHex("01f3348a2265fcf1b829ddf3e81c0ef3be24eb670af52179f685acf7ae483aed48e2dfa65fb0664d2c35634365ffe92018af7823e6a90f4cf62f3a2cc1800b8188b268f1d74f4fc7046450d2f2563658669a6671b67edf796d87a12f788ed63517def614b306c7ba95853ccef5830558dd881a95656020a3315261e8bb2ab31a71eb8a7ceec906dec1cb9a593f884b77f25548045bd170fc46b72927ef87394fb854c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("021e007551"),ParseHex("01ec2ca9bea5ffdde30e4b7aa0decaed7a7da1c93ece85860b1460dc98573aa42dc270732210361a28d8e76a0156cad032d6aff9134dc146a973ee22aa54eae88bb268f1d74f4fc7046450d2f2563658669a6671b67edf796d87a12f788ed63517def614b306c7ba95853ccef5830558dd881a95656020a3315261e8bb2ab31a71eb8a7ceec906dec1cb9a593f884b77f25548045bd170fc46b72927ef87394fb854c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("021f007551"),ParseHex("01877c03334a942d2ca03e68173caac314f1daa13ca7501a92c2373b6e27f66e32c270732210361a28d8e76a0156cad032d6aff9134dc146a973ee22aa54eae88bb268f1d74f4fc7046450d2f2563658669a6671b67edf796d87a12f788ed63517def614b306c7ba95853ccef5830558dd881a95656020a3315261e8bb2ab31a71eb8a7ceec906dec1cb9a593f884b77f25548045bd170fc46b72927ef87394fb854c6a657ad7a1badc1e634541dd36ca2298f34bd061c6bf841e45c3e8915f641")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
{ CScriptWitness w;w.stack={Bytes{0x10},ParseHex("0220007551"),ParseHex("01a6a8da8db3d245de97aeb8e58527378642d218a86d4f4b386a4338f8e80b69ea")};BOOST_CHECK(Verify(Program(Hash("a4b907e885f30d1a61d0e0ed3f3fcebb54e9d6df685158ab009f8d3a2176a3b3")),w,BaseSignatureChecker()));}
}


BOOST_AUTO_TEST_CASE(internal_opcodes_hash_types_and_codeseparator)
{
    CKey key;key.MakeNewKey(true);CPubKey pub=key.GetPubKey();Bytes pk(pub.begin(),pub.end());
    CBasicKeyStore store;BOOST_REQUIRE(store.AddKey(key));
    for (int kind : {0,1,2}) {
        CScript suffix;
        if (kind==0) suffix<<pk<<OP_CHECKSIG;
        if (kind==1) suffix<<OP_0<<pk<<OP_CHECKSIGADD<<OP_1<<OP_NUMEQUAL;
        if (kind==2) suffix<<OP_1<<pk<<OP_1<<OP_CHECKMULTISIG;
        CScript leafA;leafA<<OP_1<<OP_DROP<<OP_CODESEPARATOR;leafA+=suffix;
        CScript leafB;leafB<<OP_2<<OP_DROP<<OP_CODESEPARATOR;leafB+=suffix;
        auto ha=AuthScriptLeafHash(leafA), hb=AuthScriptLeafHash(leafB);
        auto program=AuthScriptTreeCommitment(Bytes{0},AuthScriptBranchHash(ha,hb));
        for(int version : {2,3}) for(int hashType : {1,2,3,0x81,0x82,0x83}) {
            CMutableTransaction mut;mut.nVersion=version;mut.vin.resize(1);mut.vin[0].prevout=COutPoint(uint256S("1234"),1);
            mut.vout.emplace_back(9000,CScript()<<OP_TRUE);
            if(version==3)mut.vrefin.emplace_back(uint256S("abcd"),2);
            CTransaction tx(mut);TransactionSignatureChecker checker(&tx,0,10000);
            TransactionSignatureCreator creator(&store,&tx,0,10000,hashType);
            const AuthScriptTreeContext context(0x10,program,ha);
            Bytes sig;BOOST_REQUIRE(creator.CreateTreeSig(sig,pub.GetID(),suffix,context,1));
            CScriptWitness w;w.stack={Bytes{0x10}};
            if(kind==2)w.stack.push_back(Bytes{});
            w.stack.push_back(sig);w.stack.push_back(Bytes(leafA.begin(),leafA.end()));
            Bytes control{1};auto other=Raw(hb);control.insert(control.end(),other.begin(),other.end());w.stack.push_back(control);
            BOOST_REQUIRE(Verify(Program(program),w,checker));
            w.stack[w.stack.size()-2]=Bytes(leafB.begin(),leafB.end());
            control=Bytes{1};other=Raw(ha);control.insert(control.end(),other.begin(),other.end());w.stack.back()=control;
            BOOST_CHECK(!Verify(Program(program),w,checker));
        }
    }
}
BOOST_AUTO_TEST_CASE(resource_and_script_boundaries)
{
    auto run = [](const CScript& leaf, const std::vector<Bytes>& args, script_verify_flags flags, ScriptError& error) {
        CScriptWitness w; w.stack={Bytes{0x10}};
        w.stack.insert(w.stack.end(),args.begin(),args.end());
        w.stack.push_back(Bytes(leaf.begin(),leaf.end()));w.stack.push_back(Bytes{1});
        return Verify(Program(AuthScriptTreeCommitment(Bytes{0},AuthScriptLeafHash(leaf))),w,BaseSignatureChecker(),flags,&error);
    };
    ScriptError error;
    const auto narrow=FLAGS & ~(SCRIPT_VERIFY_CHECKSIGFROMSTACK|SCRIPT_VERIFY_MERKLE_INCLUSION|SCRIPT_VERIFY_CHECKSIGADD);
    for (auto flags : {narrow,FLAGS}) {
        size_t limit=flags==narrow?520:3072;
        BOOST_CHECK(run(CScript()<<OP_DROP<<OP_TRUE,{Bytes(limit,7)},flags,error));
        BOOST_CHECK(!run(CScript()<<OP_DROP<<OP_TRUE,{Bytes(limit+1,7)},flags,error));
        BOOST_CHECK_EQUAL(error,SCRIPT_ERR_PUSH_SIZE);
    }
    for (unsigned count : {201,202}) {
        CScript leaf; for(unsigned i=0;i<count;++i)leaf<<OP_NOP;leaf<<OP_TRUE;
        BOOST_CHECK_EQUAL(run(leaf,{},FLAGS,error),count==201);
        if(count==202)BOOST_CHECK_EQUAL(error,SCRIPT_ERR_OP_COUNT);
    }
    // Valid large leaf: four pushed elements, each within the effective element limit.
    CScript leaf; for(int i=0;i<3;++i)leaf<<Bytes(3000,7)<<OP_DROP;
    leaf<<Bytes(983,7)<<OP_DROP<<OP_TRUE;
    BOOST_REQUIRE_EQUAL(leaf.size(),10000);
    BOOST_CHECK(run(leaf,{},FLAGS,error));
    leaf<<OP_NOP;
    BOOST_CHECK(!run(leaf,{},FLAGS,error));BOOST_CHECK_EQUAL(error,SCRIPT_ERR_SCRIPT_SIZE);
    BOOST_CHECK(!run(CScript()<<OP_TRUE<<OP_TRUE,{},FLAGS,error));
    BOOST_CHECK(run(CScript()<<OP_1<<OP_TOALTSTACK<<OP_FROMALTSTACK,{},FLAGS,error));
    BOOST_CHECK(!run(CScript()<<OP_FROMALTSTACK,{},FLAGS,error));
    // NoAuth must not accidentally consume signature-shaped arguments as an envelope.
    BOOST_CHECK(run(CScript()<<OP_2DROP<<OP_TRUE,{Bytes(2421,7),Bytes(1313,5)},FLAGS,error));
    for(unsigned count : {1000,1001}) {
        BOOST_CHECK(!run(CScript()<<OP_RETURN,std::vector<Bytes>(count),FLAGS,error));
        BOOST_CHECK_EQUAL(error,count==1000?SCRIPT_ERR_OP_RETURN:SCRIPT_ERR_STACK_SIZE);
    }
}

BOOST_AUTO_TEST_CASE(mixed_authentication_and_context_mutations)
{
    CKey ec,pq;ec.MakeNewKey(true);pq.MakeNewKeyPQ(Bytes(32,21));
    CBasicKeyStore store;BOOST_REQUIRE(store.AddKey(ec));BOOST_REQUIRE(store.AddKey(pq));
    for(bool pqGlobal : {false,true}) {
        const CKey& global=pqGlobal?pq:ec;const CKey& inner=pqGlobal?ec:pq;
        CPubKey gp=global.GetPubKey(),ip=inner.GetPubKey();Bytes gpk(gp.begin(),gp.end()),pk(ip.begin(),ip.end());
        for(int kind : {0,1,2}) {
            CScript leaf;
            if(kind==0)leaf<<pk<<OP_CHECKSIG;
            if(kind==1)leaf<<OP_0<<pk<<OP_CHECKSIGADD<<OP_1<<OP_NUMEQUAL;
            if(kind==2)leaf<<OP_1<<pk<<OP_1<<OP_CHECKMULTISIG;
            Bytes descriptor;BOOST_REQUIRE(GetAuthScriptDescriptor(pqGlobal?1:2,&gp,descriptor));
            const uint8_t type=pqGlobal?0x11:0x12;
            const auto lh=AuthScriptLeafHash(leaf),program=AuthScriptTreeCommitment(descriptor,lh);
            const AuthScriptTreeContext ctx(type,program,lh);
            CMutableTransaction mut;mut.nVersion=3;mut.vin.emplace_back(COutPoint(uint256S("77"),0));
            mut.vrefin.emplace_back(uint256S("88"),1);mut.vrefin.emplace_back(uint256S("99"),2);
            // SINGLE with a missing corresponding output must still be domain-bound.
            for(int hashType : {1,2,3,0x81,0x82,0x83}) {
                CTransaction tx(mut);TransactionSignatureChecker checker(&tx,0,10000);
                TransactionSignatureCreator creator(&store,&tx,0,10000,hashType);
                Bytes sig,gsig;BOOST_REQUIRE(creator.CreateTreeSig(sig,ip.GetID(),leaf,ctx,1));
                BOOST_REQUIRE(creator.CreateTreeSig(gsig,gp.GetID(),leaf,ctx,0));
                CScriptWitness w;w.stack={Bytes{type},gsig,gpk};if(kind==2)w.stack.push_back(Bytes{});
                w.stack.push_back(sig);w.stack.push_back(Bytes(leaf.begin(),leaf.end()));w.stack.push_back(Bytes{1});
                BOOST_REQUIRE(Verify(Program(program),w,checker));
                auto changed=mut;std::swap(changed.vrefin[0],changed.vrefin[1]);CTransaction changedTx(changed);
                BOOST_CHECK(!Verify(Program(program),w,TransactionSignatureChecker(&changedTx,0,10000)));
                BOOST_CHECK(!checker.CheckTreeSig(sig,pk,leaf,ctx,0));
                BOOST_CHECK(!checker.CheckTreeSig(sig,pk,leaf,AuthScriptTreeContext(type,program,uint256S("1")),1));
                BOOST_CHECK(!checker.CheckTreeSig(sig,pk,leaf,AuthScriptTreeContext(type,uint256S("1"),lh),1));
                BOOST_CHECK(!checker.CheckTreeSig(sig,pk,leaf,AuthScriptTreeContext(pqGlobal?0x12:0x11,program,lh),1));
                w.stack[1].clear();BOOST_CHECK(!Verify(Program(program),w,checker));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(explicit_message_signatures_and_csv)
{
    CMutableTransaction mut;mut.nVersion=2;mut.vin.resize(1);mut.vin[0].nSequence=144;
    CTransaction tx(mut);TransactionSignatureChecker checker(&tx,0,10000);
    auto run=[&](const CScript& leaf,const Bytes& sig,script_verify_flags flags=FLAGS) {
        CScriptWitness w;w.stack={Bytes{0x10},sig,Bytes(leaf.begin(),leaf.end()),Bytes{1}};
        return Verify(Program(AuthScriptTreeCommitment(Bytes{0},AuthScriptLeafHash(leaf))),w,checker,flags);
    };
    for(bool pq : {false,true}) {
        CKey key;if(pq)key.MakeNewKeyPQ(Bytes(32,19));else key.MakeNewKey(true);
        auto pub=key.GetPubKey();Bytes pk(pub.begin(),pub.end()),msg{0,1,2,3},sig;
        uint256 digest;CSHA256().Write(msg.data(),msg.size()).Finalize(digest.begin());
        BOOST_REQUIRE(key.Sign(digest,sig));sig.push_back(SIGHASH_ALL);
        BOOST_CHECK(run(CScript()<<msg<<pk<<OP_CHECKSIGFROMSTACK,sig));
        // Different tree/leaf, same explicit message: CSFS is intentionally not tree-bound.
        BOOST_CHECK(run(CScript()<<OP_1<<OP_DROP<<msg<<pk<<OP_CHECKSIGFROMSTACK,sig));
        msg[0]^=1;BOOST_CHECK(!run(CScript()<<msg<<pk<<OP_CHECKSIGFROMSTACK,sig));
    }
    Bytes pk=ParseHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    Bytes sig=ParseHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    BOOST_CHECK(run(CScript()<<Bytes{}<<pk<<OP_CHECKSIG_ED25519,sig,FLAGS|SCRIPT_VERIFY_ED25519));
    BOOST_CHECK(!run(CScript()<<Bytes{1}<<pk<<OP_CHECKSIG_ED25519,sig,FLAGS|SCRIPT_VERIFY_ED25519));
    for(int delay : {143,144,145})
        BOOST_CHECK_EQUAL(run(CScript()<<OP_DROP<<delay<<OP_CHECKSEQUENCEVERIFY<<OP_DROP<<OP_TRUE,Bytes{}),delay<=144);
}

BOOST_AUTO_TEST_CASE(cold_leaf_global_header_and_combiner)
{
    CKey key;key.MakeNewKeyPQ(Bytes(32,23));auto pub=key.GetPubKey();Bytes pk(pub.begin(),pub.end());
    CBasicKeyStore store;BOOST_REQUIRE(store.AddKey(key));
    CMutableTransaction mut;mut.nVersion=2;mut.vin.resize(1);mut.vout.emplace_back(9000,CScript()<<OP_TRUE);
    CTransaction tx(mut);TransactionSignatureChecker checker(&tx,0,10000);TransactionSignatureCreator creator(&store,&tx,0,10000);
    auto id=pub.GetID();CScript cold=CScript()<<OP_DUP<<OP_HASH160<<Bytes(id.begin(),id.end())<<OP_EQUALVERIFY<<OP_CHECKSIG;
    auto lh=AuthScriptLeafHash(cold);AuthScriptTreeContext ctx(0x10,AuthScriptTreeCommitment(Bytes{0},lh),lh);
    Bytes sig;BOOST_REQUIRE(creator.CreateTreeSig(sig,pub.GetID(),cold,ctx,1));
    CScriptWitness w;w.stack={Bytes{0x10},sig,pk,Bytes(cold.begin(),cold.end()),Bytes{1}};
    BOOST_CHECK(Verify(Program(ctx.program),w,checker));
    auto narrow=FLAGS & ~(SCRIPT_VERIFY_CHECKSIGFROMSTACK|SCRIPT_VERIFY_MERKLE_INCLUSION|SCRIPT_VERIFY_CHECKSIGADD);
    BOOST_CHECK(!Verify(Program(ctx.program),w,checker,narrow));
    SignatureData valid;valid.scriptWitness=w;SignatureData bad=valid;bad.scriptWitness.stack[1].clear();
    BOOST_CHECK(CombineSignatures(Program(ctx.program),checker,bad,valid).scriptWitness.stack==w.stack);
    BOOST_CHECK(CombineSignatures(Program(ctx.program),checker,valid,bad).scriptWitness.stack==w.stack);
    BOOST_CHECK(CombineSignatures(Program(ctx.program),checker,bad,bad).scriptWitness.IsNull());
    DummySignatureCreator dummy(&store);BOOST_CHECK(!dummy.CreateTreeSig(sig,pub.GetID(),cold,ctx,1));
    // Global PQ material is an envelope header, not an initial Script argument.
    CScript leaf=CScript()<<OP_TRUE;lh=AuthScriptLeafHash(leaf);Bytes desc;BOOST_REQUIRE(GetAuthScriptDescriptor(1,&pub,desc));
    AuthScriptTreeContext global(0x11,AuthScriptTreeCommitment(desc,lh),lh);
    BOOST_REQUIRE(creator.CreateTreeSig(sig,pub.GetID(),leaf,global,0));
    w.stack={Bytes{0x11},sig,pk,Bytes(leaf.begin(),leaf.end()),Bytes{1}};
    BOOST_CHECK(Verify(Program(global.program),w,checker,narrow));
    w.stack[2][0]^=1;BOOST_CHECK(!Verify(Program(global.program),w,checker));
}

BOOST_AUTO_TEST_CASE(duplicate_leaves_path_order_and_budgets)
{
    CScript leaf=CScript()<<OP_TRUE;auto lh=AuthScriptLeafHash(leaf);
    CScriptWitness w;w.stack={Bytes{0x10},Bytes(leaf.begin(),leaf.end()),Bytes{1}};
    auto b=Raw(lh);w.stack.back().insert(w.stack.back().end(),b.begin(),b.end());
    auto root=AuthScriptBranchHash(lh,lh);
    BOOST_CHECK(Verify(Program(AuthScriptTreeCommitment(Bytes{0},root)),w,BaseSignatureChecker()));
    auto other=Hash("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");b=Raw(other);
    w.stack.back().insert(w.stack.back().end(),b.begin(),b.end());root=AuthScriptBranchHash(root,other);
    auto spk=Program(AuthScriptTreeCommitment(Bytes{0},root));
    BOOST_CHECK(Verify(spk,w,BaseSignatureChecker()));
    std::swap_ranges(w.stack.back().begin()+1,w.stack.back().begin()+33,w.stack.back().begin()+33);
    BOOST_CHECK(!Verify(spk,w,BaseSignatureChecker()));
    for(unsigned calls : {10,11}) {
        leaf.clear();for(unsigned i=0;i<calls;++i)leaf<<OP_DUP<<OP_POSEIDON<<OP_DROP;
        leaf<<OP_DROP<<OP_TRUE;
        w.stack={Bytes{0x10},Bytes(3072,7),Bytes(leaf.begin(),leaf.end()),Bytes{1}};
        ScriptError error;
        BOOST_CHECK_EQUAL(Verify(Program(AuthScriptTreeCommitment(Bytes{0},AuthScriptLeafHash(leaf))),w,
            BaseSignatureChecker(),FLAGS|SCRIPT_VERIFY_POSEIDON,&error),calls==10);
        if(calls==11)BOOST_CHECK_EQUAL(error,SCRIPT_ERR_POSEIDON_BUDGET);
    }
    // Boundary includes altstack; do not reset the existing byte budget at a tree leaf.
    for(unsigned excess : {0,1}) {
        leaf=CScript()<<OP_TOALTSTACK;for(unsigned i=0;i<85;++i)leaf<<OP_DROP;leaf<<OP_FROMALTSTACK<<OP_DROP<<OP_TRUE;
        w.stack={Bytes{0x10}};for(unsigned i=0;i<85;++i)w.stack.push_back(Bytes(3072,1));
        w.stack.push_back(Bytes(1024+excess,1));w.stack.push_back(Bytes(leaf.begin(),leaf.end()));w.stack.push_back(Bytes{1});
        ScriptError error;
        BOOST_CHECK_EQUAL(Verify(Program(AuthScriptTreeCommitment(Bytes{0},AuthScriptLeafHash(leaf))),w,BaseSignatureChecker(),FLAGS,&error),excess==0);
        if(excess)BOOST_CHECK_EQUAL(error,SCRIPT_ERR_STACK_SIZE);
    }
}

BOOST_AUTO_TEST_CASE(bounded_cost_measurements)
{
    // Informational timings, not flaky wall-clock pass/fail thresholds. Verification
    // results and sizes are asserted. Run --log_level=message to retain measurements.
    CScript leaf;for(int i=0;i<3;++i)leaf<<Bytes(3000,7)<<OP_DROP;
    leaf<<Bytes(983,7)<<OP_DROP<<OP_TRUE;BOOST_REQUIRE_EQUAL(leaf.size(),10000);
    for(unsigned depth : {0,32}) {
        auto root=AuthScriptLeafHash(leaf);Bytes control{1};
        for(unsigned d=0;d<depth;++d){uint256 sibling;sibling.begin()[0]=d;auto b=Raw(sibling);control.insert(control.end(),b.begin(),b.end());root=AuthScriptBranchHash(root,sibling);}
        CScriptWitness w;w.stack={Bytes{0x10},Bytes(leaf.begin(),leaf.end()),control};auto spk=Program(AuthScriptTreeCommitment(Bytes{0},root));
        for(bool invalid : {false,true}) {
            if(invalid)w.stack[1][100]^=1;
            auto start=std::chrono::steady_clock::now();unsigned valid=0;
            for(unsigned i=0;i<1000;++i)valid+=Verify(spk,w,BaseSignatureChecker());
            auto us=std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now()-start).count();
            BOOST_CHECK_EQUAL(valid,invalid?0:1000);
            BOOST_TEST_MESSAGE("MAST_COST leaf=10000 depth="<<depth<<" invalid="<<invalid<<" iterations=1000 total_us="<<us);
        }
    }
    for(bool pq : {false,true}) {
        CKey key;if(pq)key.MakeNewKeyPQ(Bytes(32,31));else key.MakeNewKey(true);
        auto pub=key.GetPubKey();Bytes pk(pub.begin(),pub.end());CBasicKeyStore store;BOOST_REQUIRE(store.AddKey(key));
        CMutableTransaction mut;mut.nVersion=3;mut.vin.resize(1);mut.vout.emplace_back(9000,CScript()<<OP_TRUE);
        CTransaction tx(mut);PrecomputedTransactionData cache(tx);TransactionSignatureChecker checker(&tx,0,10000,cache);
        TransactionSignatureCreator creator(&store,&tx,0,10000);
        CScript script=CScript()<<pk<<OP_CHECKSIG;auto lh=AuthScriptLeafHash(script);
        AuthScriptTreeContext ctx(0x10,AuthScriptTreeCommitment(Bytes{0},lh),lh);
        Bytes sig;BOOST_REQUIRE(creator.CreateTreeSig(sig,pub.GetID(),script,ctx,1));
        auto begin=std::chrono::steady_clock::now();unsigned verified=0;
        for(unsigned i=0;i<1000;++i)verified+=checker.CheckTreeSig(sig,pk,script,ctx,1);
        auto us=std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now()-begin).count();
        BOOST_CHECK_EQUAL(verified,1000);
        BOOST_TEST_MESSAGE("MAST_SIGNATURE_COST pq="<<pq<<" iterations=1000 total_us="<<us);
    }
}

BOOST_AUTO_TEST_SUITE_END()
