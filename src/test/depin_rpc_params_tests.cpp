// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Argument plumbing for the DePIN RPCs: the CLI conversion table
// (vRPCConvertParams, rpc/client.cpp) and the parameter names declared in the
// command table (rpc/messages.cpp).
//
// This is the layer a normal RPC unit test cannot see. Building the UniValue by
// hand -- which is what every other test here does -- skips the conversion
// entirely, so a missing table entry looks fine under test and dies on the
// command line with "JSON value is not an integer as expected". That defect was
// found by a functional walkthrough, not by the suite; these tests exist so the
// next one is found here.
//
// One parameter cannot live in the conversion table at all (depinclearmsg's
// `mode` accepts a word as well as a number, and ParseNonRFCJSONValue throws on
// non-JSON), so it is normalised inside the RPC. For it the tests assert
// SEMANTICS, not acceptance: "7" must do what the number 7 does. A test that
// only checked "does not throw" would measure nothing.

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
    return (*tableRPC[method]->actor)(request);
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
    return (*tableRPC[method]->actor)(request);
}

UniValue OpenResponse(const UniValue& response, const CKey& key, const std::string& address);

struct DepinRpcParamsSetup : public TestingSetup {
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
        // AddMessage() checks token ownership against the asset index.
        BOOST_REQUIRE(passetsdb->WriteAssetAddressQuantity(POOL_TOKEN, senderAddress, 1));
        // depinreceivemsg encrypts its reply for the address's revealed pubkey.
        RevealPubKey(senderAddress, senderKey.GetPubKey());
        // depinclearmsg is owner-level: an owner address with a revealed key.
        ownerKey.MakeNewKey(true);
        ownerAddress = EncodeDestination(ownerKey.GetPubKey().GetID());
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
        msg.encryptedPayload.assign(32, tag);
        msg.signature.assign(8, tag);

        std::string error;
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

// (1) Every numeric DePIN parameter survives the CLI conversion as a number,
// and the parameters around it stay strings.
BOOST_AUTO_TEST_CASE(cli_conversion_table_covers_every_numeric_parameter)
{
    for (const ConvertCase& c : CONVERT_CASES) {
        // Enough positional arguments to reach the index under test; "1" is
        // valid JSON as a number and valid as a string, so it works for both.
        std::vector<std::string> args((size_t)c.index + 1, "1");
        args[0] = POOL_TOKEN;

        const UniValue converted = RPCConvertValues(c.method, args);
        BOOST_REQUIRE_EQUAL(converted.size(), args.size());

        BOOST_CHECK_MESSAGE(converted[c.index].isNum(),
                            std::string(c.method) + " parameter " + c.name +
                                " must reach the RPC as a number, not a string");

        // Index 0 is a token/name in every case listed, so it must stay a
        // string; this catches an entry landing on the wrong index.
        BOOST_CHECK_MESSAGE(converted[0].isStr(),
                            std::string(c.method) + " parameter 0 must stay a string");
    }
}

// (2c) depinclearmsg: both forms must reach the pool and do different things.
// Measured by how many messages survive, not by the call returning.
BOOST_AUTO_TEST_CASE(clearmsg_accepts_word_and_numeric_string)
{
    const int64_t kHour = 3600;

    // One recent message and one ten hours old.
    AddMessage(/*ageSeconds=*/kHour, 0x01);
    AddMessage(/*ageSeconds=*/10 * kHour, 0x02);
    BOOST_REQUIRE_EQUAL(pDepinMsgPool->Size(), 2U);

    // "7" as a string must behave like the number 7: drop the old one only.
    const UniValue sevenAsString = Clear("", UniValue("7"));
    BOOST_CHECK_EQUAL(find_value(sevenAsString, "removed").get_int(), 1);
    BOOST_CHECK_EQUAL(find_value(sevenAsString, "remaining").get_int(), 1);
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 1U);

    // The numeric form is unaffected: nothing left older than 7 hours.
    BOOST_CHECK_EQUAL(find_value(Clear("", UniValue((int64_t)7)), "removed").get_int(), 0);

    // "all" still empties the pool.
    AddMessage(/*ageSeconds=*/2 * kHour, 0x03);
    BOOST_REQUIRE_EQUAL(pDepinMsgPool->Size(), 2U);
    const UniValue cleared = Clear("", UniValue("all"));
    BOOST_CHECK_EQUAL(find_value(cleared, "remaining").get_int(), 0);
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 0U);
}

// RPC into vRPCConvertParams: ParseNonRFCJSONValue("all") throws.
BOOST_AUTO_TEST_CASE(polymorphic_parameters_are_not_in_the_conversion_table)
{
    // scope, address, challenge, signature, then the polymorphic mode.
    auto withMode = [](const std::string& mode) {
        return std::vector<std::string>{"", "NXaddress", std::string(64, 'a'), "c2ln", mode};
    };
    BOOST_CHECK_NO_THROW(RPCConvertValues("depinclearmsg", withMode("all")));

    // They arrive as strings, which is exactly why the RPC normalises them.
    BOOST_CHECK(RPCConvertValues("depinclearmsg", withMode("all"))[4].isStr());
    BOOST_CHECK(RPCConvertValues("depinclearmsg", withMode("7"))[4].isStr());
}

// (4) Making the CLI work must not soften validation.
BOOST_AUTO_TEST_CASE(clearmsg_rejects_partial_numbers)
{
    AddMessage(/*ageSeconds=*/3600, 0x04);

    for (const std::string& bad : {std::string("7x"), std::string(""),
                                   std::string("1.5"), std::string(" 7"),
                                   std::string("0x10"), std::string("seven")}) {
        BOOST_CHECK_MESSAGE(([&]() {
                                try {
                                    CallRpc("depinclearmsg", AdminParams("", UniValue(bad)));
                                    return false;
                                } catch (const UniValue&) {
                                    return true;
                                }
                            })(),
                            "depinclearmsg must reject \"" + bad + "\" rather than coerce it");
    }

    // Nothing was silently removed on the way.
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 1U);

    // A negative threshold is still refused.
    BOOST_CHECK_THROW(CallRpc("depinclearmsg", AdminParams("", UniValue("-1"))), UniValue);
}

// (5) and (6): the declared names match the implementation, one by one.
BOOST_AUTO_TEST_CASE(argnames_match_the_implementation)
{
    std::vector<ArgNamesCase> cases = {
        {"depinchallenge", {"token", "address", "type"}},
        {"depinreceivemsg", {"token", "address", "challenge", "signature", "timestamp", "after_hash", "limit"}},
        {"depinclearmsg", {"scope", "address", "challenge", "signature", "mode"}},
        {"depingetancestorrecipients", {"token", "max_results", "stop_at"}},
        {"depinlistsections", {"address", "scope", "challenge", "signature"}},
        {"depinsubmitmsg", {"message"}},
    };
#ifdef ENABLE_WALLET
    // Wallet RPCs over the local pool; only registered in a wallet build.
    cases.push_back({"depinsendmsg", {"token", "message", "fromaddress"}});
    cases.push_back({"depingetmsg", {"token", "fromaddress"}});
    cases.push_back({"depinsignchallenge", {"address", "token", "challenge", "type"}});
    cases.push_back({"depindecrypt", {"address", "encrypted"}});
#endif

    for (const ArgNamesCase& c : cases) {
        BOOST_REQUIRE_MESSAGE(tableRPC[c.method], std::string("RPC not registered: ") + c.method);
        const std::vector<std::string>& declared = tableRPC[c.method]->argNames;
        BOOST_REQUIRE_EQUAL_COLLECTIONS(declared.begin(), declared.end(),
                                        c.names.begin(), c.names.end());
    }
}

// (7) Named invocation, end to end. The only thing that exercises the join
// between the conversion table and the command table.
BOOST_AUTO_TEST_CASE(named_invocation_converts_and_positions_arguments)
{
    AddMessage(/*ageSeconds=*/60, 0xCC);

    // Numeric parameters arrive converted and in the right slots.
    const UniValue named = RPCConvertNamedValues("depinreceivemsg", {"limit=10", "timestamp=0"});
    BOOST_REQUIRE(named.isObject());
    BOOST_CHECK(find_value(named, "limit").isNum());
    BOOST_CHECK_EQUAL(find_value(named, "limit").get_int(), 10);
    BOOST_CHECK(find_value(named, "timestamp").isNum());

    // Skipping the middle parameters fills them with JSON nulls, which is the
    // shape that used to make an RPC throw a type error before it did any
    // work.
    std::string nonce, sig;
    ReceiveAuth(nonce, sig);
    const UniValue positional = NamedToPositional("depinreceivemsg",
                                                  {"token=" + POOL_TOKEN,
                                                   "address=" + senderAddress,
                                                   "challenge=" + nonce,
                                                   "signature=" + sig,
                                                   "limit=10"});
    BOOST_REQUIRE_EQUAL(positional.size(), 7U);  // token .. limit, holes filled
    BOOST_CHECK(positional[0].isStr());
    BOOST_CHECK_MESSAGE(positional[4].isNull(), "gaps are filled with JSON nulls");
    BOOST_CHECK(positional[5].isNull());
    BOOST_CHECK(positional[6].isNum());
    BOOST_CHECK_EQUAL(positional[6].get_int(), 10);

    // And the call goes through, nulls and all. limit > 0 selects the
    // paginated shape, which is how we know the value reached the RPC.
    UniValue namedResponse;
    BOOST_REQUIRE_NO_THROW(namedResponse = CallNamed("depinreceivemsg",
                                                     {"token=" + POOL_TOKEN,
                                                      "address=" + senderAddress,
                                                      "challenge=" + nonce,
                                                      "signature=" + sig,
                                                      "limit=10"}));
    const UniValue namedResult = OpenResponse(namedResponse, senderKey, senderAddress);
    BOOST_CHECK_MESSAGE(namedResult.isObject() && find_value(namedResult, "messages").isArray(),
                        "limit=10 must reach the RPC as limit");

    // An unknown name is still rejected.
    BOOST_CHECK_THROW(NamedToPositional("depinreceivemsg", {"noexiste=1"}), UniValue);

    // Explicit nulls from a JSON-RPC caller behave the same way as the gaps.
    ReceiveAuth(nonce, sig);
    UniValue withNulls(UniValue::VARR);
    withNulls.push_back(POOL_TOKEN);
    withNulls.push_back(senderAddress);
    withNulls.push_back(nonce);
    withNulls.push_back(sig);
    withNulls.push_back(UniValue());
    withNulls.push_back(UniValue());
    withNulls.push_back((int64_t)10);
    BOOST_CHECK_NO_THROW(CallRpc("depinreceivemsg", withNulls));
}

#ifdef ENABLE_WALLET
// (7b) depingetmsg by name: fromaddress binds to the second slot and unknown
// names are still rejected.
BOOST_AUTO_TEST_CASE(getmsg_named_fromaddress_binds_to_the_second_slot)
{
    const UniValue local = NamedToPositional("depingetmsg",
                                             {"token=" + POOL_TOKEN,
                                              "fromaddress=" + senderAddress});
    BOOST_REQUIRE_EQUAL(local.size(), 2U);
    BOOST_CHECK_EQUAL(local[0].get_str(), POOL_TOKEN);
    BOOST_CHECK_EQUAL(local[1].get_str(), senderAddress);

    BOOST_CHECK_THROW(NamedToPositional("depingetmsg", {"token=" + POOL_TOKEN, "noexiste=1"}),
                      UniValue);
}
#endif

// (8) The join between the two tables: a parameter must convert under the same
// NAME the command table declares at that index.
//
// Test 1 probes the conversion table by index, which is the path neurai-cli
// takes positionally. This one probes it by name, which is the path
// RPCConvertNamedValues takes, and then checks that argNames agrees. Both
// halves are needed: an entry can be present by index and absent by name only
// if the two tables disagree, and that disagreement is exactly what makes a
// named call convert the wrong argument.
BOOST_AUTO_TEST_CASE(conversion_table_agrees_with_command_table)
{
    for (const ConvertCase& c : CONVERT_CASES) {
        // Probe the real vRPCConvertParams rather than trusting this file's
        // copy of it: a registered name has its value parsed as JSON, an
        // unregistered one is passed through as a string.
        const UniValue byName = RPCConvertNamedValues(c.method, {std::string(c.name) + "=1"});
        BOOST_CHECK_MESSAGE(find_value(byName, c.name).isNum(),
                            std::string(c.method) + " does not convert parameter \"" + c.name +
                                "\" by name; vRPCConvertParams is missing it or spells it "
                                "differently");

        const CRPCCommand* cmd = tableRPC[c.method];
        if (!cmd) continue;  // wallet-only RPC, not registered in this build

        BOOST_REQUIRE_MESSAGE(cmd->argNames.size() > (size_t)c.index,
                              std::string(c.method) + " declares fewer argNames than index " +
                                  std::to_string(c.index));
        BOOST_CHECK_MESSAGE(cmd->argNames[c.index] == c.name,
                            std::string(c.method) + " argNames[" + std::to_string(c.index) +
                                "] is \"" + cmd->argNames[c.index] + "\", conversion table says \"" +
                                c.name + "\"");
    }
}

BOOST_AUTO_TEST_SUITE_END()
