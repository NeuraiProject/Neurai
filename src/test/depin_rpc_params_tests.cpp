// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Argument plumbing for the DePIN RPCs: the CLI conversion table
// (vRPCConvertParams, rpc/client.cpp) and the parameter names declared in the
// command table (rpc/depin.cpp).
//
// This is the layer a normal RPC unit test cannot see. Building the UniValue by
// hand -- which is what every other test here does -- skips the conversion
// entirely, so a missing table entry looks fine under test and dies on the
// command line with "JSON value is not an integer as expected". That defect was
// found by a functional walkthrough, not by the suite; these tests exist so the
// next one is found here.
//
// Protocol 4 converts one complete request object. Field types and defaults
// are checked by its common parser; numeric strings are deliberately rejected.

// amount.h first: assets/assetdb.h declares CAmount parameters without
// including it, so it only compiles when the includer got there first.
#include "amount.h"

#include "assets/assetdb.h"
#include "assets/assets.h"
#include "assets/assettypes.h"
#include "assets/restricteddb.h"
#include "base58.h"
#include "chainparams.h"
#include "depinchallenge.h"
#include "depinecies.h"
#include "depinmsgpool.h"
#include "depinpoolkey.h"
#include "pubkeyindex.h"
#include "streams.h"
#include "txdb.h"
#include "utilstrencodings.h"
#include "version.h"
#include "key.h"
#include "rpc/client.h"
#include "rpc/protocol.h"
#include "rpc/server.h"
#include "test/test_neurai.h"
#include "test/depin_test_utils.h"
#include "test/depin_rpc_test_client.h"
#include "utiltime.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <string>
#include <univalue.h>
#include <vector>

namespace {

const std::string POOL_TOKEN = "&TEST";

// Every DePIN RPC parameter that must survive the CLI's string-to-JSON
// conversion, as (method, index, name). Data-driven so adding a numeric
// parameter to a DePIN RPC is one line here.
struct ConvertCase {
    const char* method;
    int index;
    const char* name;
};

const ConvertCase CONVERT_CASES[] = {
    {"depingetancestorrecipients", 1, "max_results"},
    {"depinchallenge", 2, "timestamp"},
    {"depinreceivemsg", 4, "timestamp"},
    {"depinreceivemsg", 6, "limit"},
};

// Declared parameter names per RPC. Checked one by one, not just counted: a
// misspelling passes an arity check and still breaks invocation by name.
struct ArgNamesCase {
    const char* method;
    std::vector<std::string> names;
};

UniValue CallRpc(const std::string& method, const UniValue& params)
{
    JSONRPCRequest request;
    request.strMethod = method;
    request.params = params;
    request.fHelp = false;

    BOOST_REQUIRE_MESSAGE(tableRPC[method], "RPC not registered: " + method);
    return CallDepinTestRpc(method,params);
}

UniValue StrParams(const std::vector<std::string>& args)
{
    UniValue params(UniValue::VARR);
    for (const std::string& arg : args) params.push_back(arg);
    return params;
}

// The positional vector a named call actually produces: convert on the client
// side, then resolve names to positions exactly as CRPCTable::execute() does.
// Going through execute() itself is not an option here -- it refuses every call
// while fRPCInWarmup, which nothing clears in a unit-test binary.
UniValue NamedToPositional(const std::string& method, const std::vector<std::string>& nameEqualsValue)
{
    BOOST_REQUIRE_MESSAGE(tableRPC[method], "RPC not registered: " + method);

    JSONRPCRequest request;
    request.strMethod = method;
    request.params = RPCConvertNamedValues(method, nameEqualsValue);
    request.fHelp = false;

    return transformNamedArguments(request, tableRPC[method]->argNames).params;
}

// ...and then run it, so the test covers the whole named path.
UniValue CallNamed(const std::string& method, const std::vector<std::string>& nameEqualsValue)
{
    JSONRPCRequest request;
    request.strMethod = method;
    request.params = NamedToPositional(method, nameEqualsValue);
    request.fHelp = false;
    return CallDepinTestRpc(method,request.params);
}

UniValue OpenResponse(const UniValue& response, const CKey& key, const std::string& address);

struct DepinRpcParamsSetup : public TestingSetup {
    ScopedDepinTestTipTime currentTip;
    bool prevAssetIndex;
    bool prevPubKeyIndex;
    CAssetsDB* prevAssetsDb;
    CLRUCache<std::string, CDatabasedAssetData>* prevAssetsCache;
    CRestrictedDB* prevRestrictedDb;
    std::unique_ptr<CDepinMsgPool> prevPool;

    CKey senderKey;
    std::string senderAddress;
    CKey ownerKey;
    std::string ownerAddress;
    CKey poolKey;

    // REGTEST because DEPIN names only validate on testnet/regtest, and
    // Initialize() rejects anything that is not a DEPIN token.
    DepinRpcParamsSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        prevAssetIndex = fAssetIndex;
        prevPubKeyIndex = fPubKeyIndex;
        prevAssetsDb = passetsdb;
        prevAssetsCache = passetsCache;
        prevRestrictedDb = prestricteddb;

        fAssetIndex = true;
        fPubKeyIndex = true;
        passetsdb = new CAssetsDB(1 << 20, true, true);
        passetsCache = new CLRUCache<std::string, CDatabasedAssetData>(MAX_CACHE_ASSETS_SIZE);
        // AddMessage() authorization (sections) refuses to run without the
        // restriction database -- a null prestricteddb would fail OPEN.
        prestricteddb = new CRestrictedDB(1 << 20, true, true);

        senderKey.MakeNewKey(true);
        senderAddress = EncodeDestination(senderKey.GetPubKey().GetID());
        RememberDepinTestKey(senderKey);
        // AddMessage() checks token ownership against the asset index.
        BOOST_REQUIRE(passetsdb->WriteAssetAddressQuantity(POOL_TOKEN, senderAddress, 1));
        // depinreceivemsg encrypts its reply for the address's revealed pubkey.
        RevealPubKey(senderAddress, senderKey.GetPubKey());
        // depinclearmsg is owner-level: an owner address with a revealed key.
        ownerKey.MakeNewKey(true);
        ownerAddress = EncodeDestination(ownerKey.GetPubKey().GetID());
        RememberDepinTestKey(ownerKey);
        BOOST_REQUIRE(passetsdb->WriteAssetAddressQuantity(POOL_TOKEN + OWNER_TAG, ownerAddress, 1));
        RevealPubKey(ownerAddress, ownerKey.GetPubKey());
        // Every DePIN response is signed with the pool key.
        poolKey.MakeNewKey(true);
        SetDepinPoolKey(poolKey, "test");
        g_depinChallenges.Clear();

        prevPool = std::move(pDepinMsgPool);
        pDepinMsgPool.reset(new CDepinMsgPool());
        BOOST_REQUIRE(pDepinMsgPool->Initialize(POOL_TOKEN,
                                                DEFAULT_MAX_DEPIN_RECIPIENTS,
                                                DEFAULT_DEPIN_MESSAGE_SIZE,
                                                DEFAULT_DEPIN_MESSAGE_EXPIRY_HOURS,
                                                DEFAULT_DEPIN_POOL_SIZE_MB));
    }

    static void RevealPubKey(const std::string& address, const CPubKey& pubkey)
    {
        CDestinationIndexData addressData;
        BOOST_REQUIRE(GetDestinationIndexData(DecodeDestination(address), addressData));
        std::vector<std::pair<CPubKeyIndexKey, CPubKeyIndexValue> > entries;
        entries.emplace_back(CPubKeyIndexKey(addressData), CPubKeyIndexValue(pubkey, 1, uint256()));
        BOOST_REQUIRE(pblocktree->WritePubKeyIndex(entries));
    }

    // Owner-level proof for `scope` ("" = root), fresh each call:
    // [scope, owner, nonce, signature, (mode)].
    UniValue AdminParams(const std::string& scope, const UniValue& mode = NullUniValue)
    {
        const std::string token = scope.empty() ? POOL_TOKEN : scope;
        std::string nonce, sig, error;
        CPubKey pubkey;
        BOOST_REQUIRE_MESSAGE(IssueDepinChallengeForAddress(token, ownerAddress, DepinChallengeType::ADMIN,
                                                            POOL_TOKEN, nonce, pubkey, error), error);
        BOOST_REQUIRE(SignDepinChallengePreimage(ownerKey,
            DepinChallengePreimage(DepinChallengeType::ADMIN, token, ownerAddress, nonce), sig, error));
        UniValue params(UniValue::VARR);
        params.push_back(scope);
        params.push_back(ownerAddress);
        params.push_back(nonce);
        params.push_back(sig);
        if (!mode.isNull()) params.push_back(mode);
        return params;
    }

    UniValue Clear(const std::string& scope, const UniValue& mode = NullUniValue)
    {
        return OpenResponse(CallRpc("depinclearmsg", AdminParams(scope, mode)), ownerKey, ownerAddress);
    }

    // Holder proof for depinreceivemsg on the pool root.
    void ReceiveAuth(std::string& nonce, std::string& sig)
    {
        std::string error;
        CPubKey pubkey;
        BOOST_REQUIRE_MESSAGE(IssueDepinChallengeForAddress(POOL_TOKEN, senderAddress, DepinChallengeType::RECEIVE,
                                                            POOL_TOKEN, nonce, pubkey, error), error);
        BOOST_REQUIRE(SignDepinChallengePreimage(senderKey,
            DepinChallengePreimage(DepinChallengeType::RECEIVE, POOL_TOKEN, senderAddress, nonce), sig, error));
    }

    ~DepinRpcParamsSetup()
    {
        g_depinChallenges.Clear();
        ClearDepinPoolKey();
        pDepinMsgPool = std::move(prevPool);

        delete prestricteddb;
        delete passetsCache;
        delete passetsdb;
        prestricteddb = prevRestrictedDb;
        passetsCache = prevAssetsCache;
        passetsdb = prevAssetsDb;

        fPubKeyIndex = prevPubKeyIndex;
        fAssetIndex = prevAssetIndex;
    }

    // A message `ageSeconds` old. The payload varies so each one hashes
    // differently; signature checking is skipped because these tests are about
    // argument plumbing, not authentication.
    void AddMessage(int64_t ageSeconds, unsigned char tag)
    {
        CDepinMessage msg;
        msg.token = POOL_TOKEN;
        msg.senderAddress = senderAddress;
        msg.timestamp = GetTime() - ageSeconds;
        msg.messageType = 0x02;
        const CPubKey pubkey = senderKey.GetPubKey();
        CECIESEncryptedMessage ecies;
        std::string error;
        BOOST_REQUIRE_MESSAGE(ECIESEncryptMessage(std::string(32, tag),
            {{EncodeDestination(pubkey.GetID()), pubkey}}, ecies, error), error);
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << ecies;
        msg.encryptedPayload.assign(ss.begin(), ss.end());
        msg.signature.assign(8, tag);

        BOOST_REQUIRE_MESSAGE(pDepinMsgPool->AddMessage(msg, error, /*skipSignatureCheck=*/true), error);
    }
};

// Opens an encrypted DePIN response with the recipient's key.
UniValue OpenResponse(const UniValue& response, const CKey& key, const std::string& address)
{
    BOOST_REQUIRE_MESSAGE(response.exists("encrypted"), response.write());
    CECIESEncryptedMessage ecies;
    CDataStream ss(ParseHex(response["encrypted"].get_str()), SER_NETWORK, PROTOCOL_VERSION);
    ss >> ecies;
    std::string plaintext, error;
    BOOST_REQUIRE_MESSAGE(ECIESDecryptMessage(ecies, key, address, plaintext, error), error);
    UniValue inner;
    BOOST_REQUIRE(inner.read(plaintext));
    return inner;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(depin_rpc_params_tests, DepinRpcParamsSetup)

BOOST_AUTO_TEST_CASE(cli_converts_complete_request_objects)
{
    for (const auto* method:{"depingetmsginfo","depinchallenge","depinpoolstats","depinsubmitmsg","depinreceiveseq","depinreceivemsg","depinmcpstatus","depingetancestorrecipients","depinlistsections","depinclearmsg"}) {
        const std::string json="{\"protocol\":4,\"args\":{\"limit\":10,\"label\":\"7\"}}";
        const auto positional=RPCConvertValues(method,{json});
        BOOST_REQUIRE_EQUAL(positional.size(),1U);BOOST_CHECK(positional[0].isObject());
        BOOST_CHECK(positional[0]["args"]["limit"].isNum());BOOST_CHECK(positional[0]["args"]["label"].isStr());
        const auto named=NamedToPositional(method,{"request="+json});
        BOOST_CHECK_EQUAL(named.write(),positional.write());
    }
}
BOOST_AUTO_TEST_CASE(clearmsg_numeric_hours_and_all_have_distinct_effects)
{
    AddMessage(3600,1);AddMessage(10*3600,2);
    BOOST_CHECK_EQUAL(Clear("",UniValue(int64_t(7)))["removed"].get_int(),1);
    BOOST_CHECK_EQUAL(Clear("",UniValue(int64_t(7)))["removed"].get_int(),0);
    BOOST_CHECK_EQUAL(Clear("",UniValue("all"))["removed"].get_int(),1);
}
BOOST_AUTO_TEST_CASE(legacy_cli_arguments_and_signers_are_rejected)
{
    BOOST_CHECK_THROW(RPCConvertValues("depinclearmsg",{"&TEST","address","nonce","sig","all"}),std::exception);
    BOOST_CHECK(!tableRPC["depinsignchallenge"]);BOOST_CHECK(!tableRPC["depinsignrequest"]);BOOST_CHECK(!tableRPC["depinsignreadseq"]);
    BOOST_REQUIRE(tableRPC["depinsignrpc"]);
    const auto p=RPCConvertValues("depinsignrpc",{"depinclearmsg","{\"protocol\":4}"});
    BOOST_CHECK(p[0].isStr());BOOST_CHECK(p[1].isObject());
}
BOOST_AUTO_TEST_CASE(clearmsg_rejects_noninteger_hours_without_consuming_nonce)
{
    AddMessage(3600,4);
    auto object=DepinTestRequest("depinclearmsg",AdminParams("",UniValue(int64_t(7))));
    const auto nonce=object["challenge"].get_str();
    for (const auto& bad:{UniValue("7"),UniValue("7x"),UniValue(""),UniValue(true),UniValue(int64_t(-1))}) {
        auto args=object["args"];args=DepinTestReplace(args,"hours",bad);
        BOOST_CHECK_THROW(CallRpc("depinclearmsg",DepinTestParams(DepinTestReplace(object,"args",args))),UniValue);
        std::string error;BOOST_CHECK(g_depinChallenges.Peek(nonce,error));BOOST_CHECK_EQUAL(pDepinMsgPool->Size(),1U);
    }
    BOOST_CHECK_EQUAL(DepinTestOpen(CallRpc("depinclearmsg",DepinTestParams(object)),ownerAddress)["removed"].get_int(),0);
}
BOOST_AUTO_TEST_CASE(argnames_match_v4_objects_and_local_wallet_helpers)
{
    for (const auto* method:{"depingetmsginfo","depinchallenge","depinpoolstats","depinsubmitmsg","depinreceiveseq","depinreceivemsg","depinmcpstatus","depingetancestorrecipients","depinlistsections","depinclearmsg"}) {
        BOOST_REQUIRE(tableRPC[method]);const auto& names=tableRPC[method]->argNames;
        BOOST_REQUIRE_EQUAL(names.size(),1U);BOOST_CHECK_EQUAL(names[0],"request");
    }
    const auto& signer=tableRPC["depinsignrpc"]->argNames;BOOST_REQUIRE_EQUAL(signer.size(),2U);BOOST_CHECK_EQUAL(signer[0],"method");BOOST_CHECK_EQUAL(signer[1],"request");
}
BOOST_AUTO_TEST_CASE(named_invocation_reaches_authenticated_read)
{
    AddMessage(60,0xcc);std::string nonce,sig;ReceiveAuth(nonce,sig);
    UniValue old(UniValue::VARR);for (const auto& v:{UniValue(POOL_TOKEN),UniValue(senderAddress),UniValue(nonce),UniValue(sig)}) old.push_back(v);
    auto object=DepinTestRequest("depinreceivemsg",old);
    const auto result=OpenResponse(CallNamed("depinreceivemsg",{"request="+object.write()}),senderKey,senderAddress);
    BOOST_CHECK_EQUAL(result["messages"].size(),1U);
    BOOST_CHECK_THROW(NamedToPositional("depinreceivemsg",{"token=&TEST"}),UniValue);
}
BOOST_AUTO_TEST_CASE(optional_nulls_hash_like_omitted_defaults)
{
    std::string nonce,sig;ReceiveAuth(nonce,sig);
    UniValue old(UniValue::VARR);for (const auto& v:{UniValue(POOL_TOKEN),UniValue(senderAddress),UniValue(nonce),UniValue(sig)}) old.push_back(v);
    const auto object=DepinTestRequest("depinreceivemsg",old);UniValue args(UniValue::VOBJ);
    args.pushKV("timestamp",NullUniValue);args.pushKV("after_hash",NullUniValue);args.pushKV("limit",NullUniValue);
    const auto withNulls=DepinTestReplace(object,"args",args);
    BOOST_CHECK_EQUAL(ParseDepinRpcRequest("depinreceivemsg",object).Hash(),ParseDepinRpcRequest("depinreceivemsg",withNulls).Hash());
    BOOST_CHECK_NO_THROW(CallRpc("depinreceivemsg",DepinTestParams(withNulls)));
}
BOOST_AUTO_TEST_SUITE_END()
