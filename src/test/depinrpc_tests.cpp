// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#include "depinrpc.h"
#include "depinchallenge.h"
#include "depinpoolkey.h"
#include "test/depin_rpc_test_client.h"
#include "test/test_neurai.h"
#include "data/depin_rpc_v5.json.h"
#include "utilstrencodings.h"
#include <boost/test/unit_test.hpp>
#include <atomic>
#include <future>
#include "tinyformat.h"

struct DepinRpcCodecSetup : BasicTestingSetup { DepinRpcCodecSetup() : BasicTestingSetup(CBaseChainParams::REGTEST) {} };
BOOST_FIXTURE_TEST_SUITE(depinrpc_tests, DepinRpcCodecSetup)
BOOST_AUTO_TEST_CASE(independent_canonical_byte_and_hash_vectors)
{
    UniValue data;BOOST_REQUIRE(data.read(std::string(json_tests::depin_rpc_v5,json_tests::depin_rpc_v5+sizeof(json_tests::depin_rpc_v5))));
    for (const auto& c:data["cases"].getValues()) {
        const auto r=ParseDepinRpcRequest(c["method"].get_str(),c["request"]);
        BOOST_CHECK_EQUAL(HexStr(r.Bytes()),c["bytes"].get_str());BOOST_CHECK_EQUAL(r.Hash(),c["hash"].get_str());BOOST_CHECK_EQUAL(r.Preimage(),c["preimage"].get_str());
        if (r.kind) {
            const auto changed=DepinTestReplace(c["request"],"signature",UniValue("different encoding"));
            BOOST_CHECK_EQUAL(ParseDepinRpcRequest(c["method"].get_str(),changed).Hash(),r.Hash());
        }
    }
}
BOOST_AUTO_TEST_CASE(strict_shapes_defaults_and_integer_precision)
{
    UniValue data;BOOST_REQUIRE(data.read(std::string(json_tests::depin_rpc_v5,json_tests::depin_rpc_v5+sizeof(json_tests::depin_rpc_v5))));
    const auto legacy=DepinTestReplace(data["cases"][1]["request"],"protocol",UniValue(4));
    BOOST_CHECK_THROW(ParseDepinRpcRequest("depinreceivemsg",legacy),UniValue);
    const auto object=data["cases"][1]["request"];const auto original=ParseDepinRpcRequest("depinreceivemsg",object);
    UniValue args(UniValue::VOBJ);args.pushKV("limit",NullUniValue);args.pushKV("timestamp",NullUniValue);args.pushKV("after_hash",NullUniValue);
    BOOST_CHECK_EQUAL(ParseDepinRpcRequest("depinreceivemsg",DepinTestReplace(object,"args",args)).Hash(),original.Hash());
    auto duplicate=object;duplicate.__pushKV("protocol",UniValue(5));BOOST_CHECK_THROW(ParseDepinRpcRequest("depinreceivemsg",duplicate),UniValue);
    for (const auto& bad:{UniValue("10"),UniValue(true),UniValue(int64_t(-1)),UniValue(int64_t(1001))}) {
        UniValue a(UniValue::VOBJ);a.pushKV("limit",bad);BOOST_CHECK_THROW(ParseDepinRpcRequest("depinreceivemsg",DepinTestReplace(object,"args",a)),UniValue);
    }
    for (const auto* text:{"1.0","1e0","9223372036854775808"}) {
        UniValue a;BOOST_REQUIRE(a.read(std::string("{\"limit\":")+text+"}"));
        BOOST_CHECK_THROW(ParseDepinRpcRequest("depinreceivemsg",DepinTestReplace(object,"args",a)),UniValue);
    }
    args=UniValue(UniValue::VOBJ);args.pushKV("limit",1);args.__pushKV("limit",UniValue(2));
    BOOST_CHECK_THROW(ParseDepinRpcRequest("depinreceivemsg",DepinTestReplace(object,"args",args)),UniValue);
    const auto sequence=ParseDepinRpcRequest("depinreceiveseq",data["cases"][4]["request"]);
    BOOST_CHECK_EQUAL(sequence.args["cursor"]["after_seq"].get_int64(),INT64_C(9007199254740993));
    auto badCursor=sequence.args["cursor"];badCursor.__pushKV("after_seq",UniValue(1));
    BOOST_CHECK_THROW(ParseDepinRpcRequest("depinreceiveseq",DepinTestReplace(data["cases"][4]["request"],"args",DepinTestReplace(sequence.args,"cursor",badCursor))),UniValue);
}
BOOST_AUTO_TEST_CASE(replay_capacity_concurrency_and_clock_rollback)
{
    CKey key;key.MakeNewKey(true);SetDepinPoolKey(key,"unit");ResetDepinRpcInstance();ObserveDepinRpcClock(100000);
    const auto epoch=GetDepinRpcIdentity().instance;
    UniValue data;BOOST_REQUIRE(data.read(std::string(json_tests::depin_rpc_v5,json_tests::depin_rpc_v5+sizeof(json_tests::depin_rpc_v5))));
    auto r=ParseDepinRpcRequest("depinchallenge",data["cases"][0]["request"]);r.timestamp=100000;
    std::atomic<unsigned> accepted{0};std::vector<std::future<void>> work;
    for (unsigned i=0;i<12;++i) work.emplace_back(std::async(std::launch::async,[&]{std::string e;if(RememberDepinRpcRequest(r,e))++accepted;}));
    for (auto& task:work) task.get();BOOST_CHECK_EQUAL(accepted.load(),1U);BOOST_CHECK_EQUAL(DepinRpcReplaySize(),1U);
    for (unsigned i=1;i<10000;++i) { r.id=std::string(56,'0')+strprintf("%08x",i);std::string e;BOOST_REQUIRE(RememberDepinRpcRequest(r,e)); }
    r.id=std::string(64,'f');std::string error;BOOST_CHECK(!RememberDepinRpcRequest(r,error));BOOST_CHECK_EQUAL(DepinRpcReplaySize(),10000U);
    ObserveDepinRpcClock(160000);BOOST_CHECK_EQUAL(DepinRpcReplaySize(),10000U);
    ObserveDepinRpcClock(160001);BOOST_CHECK_EQUAL(DepinRpcReplaySize(),0U);BOOST_CHECK_EQUAL(GetDepinRpcIdentity().instance,epoch);
    g_depinChallenges.Issue("&TEST","test",DepinChallengeType::RECEIVE,error);
    ObserveDepinRpcClock(100000);BOOST_CHECK(GetDepinRpcIdentity().instance!=epoch);BOOST_CHECK_EQUAL(g_depinChallenges.Size(),0U);
    ClearDepinPoolKey();
}
BOOST_AUTO_TEST_CASE(response_domain_binds_request_identity_body_and_kind)
{
    CKey pool;pool.MakeNewKey(true);SetDepinPoolKey(pool,"unit");
    const auto object=MakeDepinRpcRequest("depinpoolstats",GetDepinRpcIdentity(),GetDepinRpcIdentity().root,"","",UniValue(UniValue::VOBJ));
    const auto request=ParseDepinRpcRequest("depinpoolstats",object);
    UniValue body(UniValue::VOBJ);body.pushKV("messages",0);
    const auto response=FinishDepinRpcResponse(body,request);std::string error;
    BOOST_CHECK(VerifyDepinRpcResponse(response,request,pool.GetPubKey(),error));
    for (const auto& field:{"network","instance_id","membership_revision","membership_blockhash","request_hash"}) {
        auto changed=DepinTestReplace(response,field,UniValue(std::string(64,'f')));
        BOOST_CHECK(!VerifyDepinRpcResponse(changed,request,pool.GetPubKey(),error));
    }
    for (const auto& field:{"body","pool_root","poolsig"}) {
        auto changed=DepinTestReplace(response,field,UniValue(field==std::string("body")?"7b7d":"different"));
        BOOST_CHECK(!VerifyDepinRpcResponse(changed,request,pool.GetPubKey(),error));
    }
    auto wrongHeight=DepinTestReplace(response,"membership_height",UniValue(response["membership_height"].get_int64()+1));
    BOOST_CHECK(!VerifyDepinRpcResponse(wrongHeight,request,pool.GetPubKey(),error));
    auto duplicate=response;duplicate.__pushKV("body",response["body"]);
    BOOST_CHECK(!VerifyDepinRpcResponse(duplicate,request,pool.GetPubKey(),error));
    auto other=request;other.method="depinmcpstatus";BOOST_CHECK(!VerifyDepinRpcResponse(response,other,pool.GetPubKey(),error));
    other=request;other.id=std::string(64,'f');BOOST_CHECK(!VerifyDepinRpcResponse(response,other,pool.GetPubKey(),error));
    ClearDepinPoolKey();
}
BOOST_AUTO_TEST_SUITE_END()
