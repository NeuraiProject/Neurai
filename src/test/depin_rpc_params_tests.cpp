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
// Two of the parameters cannot live in the conversion table at all
// (depingetpoolcontent's `verbose` and depinclearmsg's `mode` accept a word as
// well as a number, and ParseNonRFCJSONValue throws on non-JSON), so they are
// normalised inside the RPC. For those the tests assert SEMANTICS, not
// acceptance: "120" was already accepted before this change -- it just meant
// false, while the number 120 meant true. A test that only checked "does not
// throw" would have passed before and after, measuring nothing.

// amount.h first: assets/assetdb.h declares CAmount parameters without
// including it, so it only compiles when the includer got there first.
#include "amount.h"

#include "assets/assetdb.h"
#include "assets/assets.h"
#include "assets/assettypes.h"
#include "assets/restricteddb.h"
#include "base58.h"
#include "chainparams.h"
#include "depinmsgpool.h"
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
    {"depingetpoolcontent", 3, "start_time"},
    {"depingetpoolcontent", 4, "end_time"},
    {"depingetpoolcontent", 5, "limit"},
    {"depingetpoolcontent", 6, "offset"},
    {"depinreceivemsg", 2, "timestamp"},
    {"depinreceivemsg", 4, "limit"},
    {"depinsendmsg", 4, "port"},
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

struct DepinRpcParamsSetup : public TestingSetup {
    bool prevAssetIndex;
    bool prevPubKeyIndex;
    CAssetsDB* prevAssetsDb;
    CLRUCache<std::string, CDatabasedAssetData>* prevAssetsCache;
    CRestrictedDB* prevRestrictedDb;
    std::unique_ptr<CDepinMsgPool> prevPool;

    CKey senderKey;
    std::string senderAddress;

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

        prevPool = std::move(pDepinMsgPool);
        pDepinMsgPool.reset(new CDepinMsgPool());
        BOOST_REQUIRE(pDepinMsgPool->Initialize(POOL_TOKEN, DEFAULT_DEPIN_MSG_PORT,
                                                DEFAULT_MAX_DEPIN_RECIPIENTS,
                                                DEFAULT_DEPIN_MESSAGE_SIZE,
                                                DEFAULT_DEPIN_MESSAGE_EXPIRY_HOURS,
                                                DEFAULT_DEPIN_POOL_SIZE_MB));
    }

    ~DepinRpcParamsSetup()
    {
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

// Verbose mode reports encrypted_payload_size; plain mode reports size instead.
// That is the observable difference the semantics tests hang on.
bool IsVerboseEntry(const UniValue& entry)
{
    return !find_value(entry, "encrypted_payload_size").isNull();
}

bool AllVerbose(const UniValue& result)
{
    BOOST_REQUIRE(result.isArray() && result.size() > 0);
    for (size_t i = 0; i < result.size(); ++i) {
        if (!IsVerboseEntry(result[i])) return false;
    }
    return true;
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

// (2a) depingetpoolcontent: a numeric string must mean what the number means.
//
// This is the case that a naive test gets wrong. Before this change "120" was
// already accepted without error -- it fell through to
// `fVerbose = (val == "true" || val == "1")` and meant FALSE, while the number
// 120 meant true. So the assertion has to be on the effect, not on the call
// returning.
BOOST_AUTO_TEST_CASE(poolcontent_numeric_string_has_numeric_semantics)
{
    AddMessage(/*ageSeconds=*/60, 0xAA);

    // Control: the two forms that already agreed before the change.
    BOOST_CHECK(!AllVerbose(CallRpc("depingetpoolcontent", StrParams({"0"}))));
    BOOST_CHECK(AllVerbose(CallRpc("depingetpoolcontent", StrParams({"1"}))));

    // The divergence: any numeric string other than 0 and 1.
    BOOST_CHECK_MESSAGE(AllVerbose(CallRpc("depingetpoolcontent", StrParams({"120"}))),
                        "\"120\" must behave like the number 120, i.e. verbose");
    BOOST_CHECK_MESSAGE(AllVerbose(CallRpc("depingetpoolcontent", StrParams({"-1"}))),
                        "\"-1\" must behave like the number -1, i.e. verbose");
    BOOST_CHECK(AllVerbose(CallRpc("depingetpoolcontent", StrParams({"2"}))));

    // And the number itself is unchanged.
    UniValue numeric(UniValue::VARR);
    numeric.push_back((int64_t)120);
    BOOST_CHECK(AllVerbose(CallRpc("depingetpoolcontent", numeric)));

    UniValue zero(UniValue::VARR);
    zero.push_back((int64_t)0);
    BOOST_CHECK(!AllVerbose(CallRpc("depingetpoolcontent", zero)));
}

// (2b) The words keep their meaning and keep priority over the numeric reading.
BOOST_AUTO_TEST_CASE(poolcontent_words_are_unchanged)
{
    AddMessage(/*ageSeconds=*/60, 0xBB);

    BOOST_CHECK(AllVerbose(CallRpc("depingetpoolcontent", StrParams({"true"}))));
    BOOST_CHECK(!AllVerbose(CallRpc("depingetpoolcontent", StrParams({"false"}))));

    // "all" and "raw" imply verbose; "raw" additionally exposes the hex.
    const UniValue all = CallRpc("depingetpoolcontent", StrParams({"all"}));
    BOOST_CHECK(AllVerbose(all));

    const UniValue raw = CallRpc("depingetpoolcontent", StrParams({"raw"}));
    BOOST_REQUIRE(raw.isArray() && raw.size() == 1);
    BOOST_CHECK_MESSAGE(!find_value(raw[0], "encrypted_payload_hex").isNull(),
                        "\"raw\" must still expose the payload hex");

    // A word that is neither a keyword nor a number stays false, as today.
    BOOST_CHECK(!AllVerbose(CallRpc("depingetpoolcontent", StrParams({"7x"}))));
    BOOST_CHECK(!AllVerbose(CallRpc("depingetpoolcontent", StrParams({"1.5"}))));
    BOOST_CHECK(!AllVerbose(CallRpc("depingetpoolcontent", StrParams({" 7"}))));
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
    const UniValue sevenAsString = CallRpc("depinclearmsg", StrParams({"7"}));
    BOOST_CHECK_EQUAL(find_value(sevenAsString, "removed").get_int(), 1);
    BOOST_CHECK_EQUAL(find_value(sevenAsString, "remaining").get_int(), 1);
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 1U);

    // The numeric form is unaffected: nothing left older than 7 hours.
    UniValue seven(UniValue::VARR);
    seven.push_back((int64_t)7);
    BOOST_CHECK_EQUAL(find_value(CallRpc("depinclearmsg", seven), "removed").get_int(), 0);

    // "all" still empties the pool.
    AddMessage(/*ageSeconds=*/2 * kHour, 0x03);
    BOOST_REQUIRE_EQUAL(pDepinMsgPool->Size(), 2U);
    const UniValue cleared = CallRpc("depinclearmsg", StrParams({"all"}));
    BOOST_CHECK_EQUAL(find_value(cleared, "remaining").get_int(), 0);
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 0U);
}

// (3) The word form must survive the conversion layer untouched. This is the
// test that fails if someone "simplifies" the fix by putting index 0 of these
// two RPCs into vRPCConvertParams: ParseNonRFCJSONValue("all") throws.
BOOST_AUTO_TEST_CASE(polymorphic_parameters_are_not_in_the_conversion_table)
{
    BOOST_CHECK_NO_THROW(RPCConvertValues("depinclearmsg", {"all"}));
    BOOST_CHECK_NO_THROW(RPCConvertValues("depingetpoolcontent", {"all"}));
    BOOST_CHECK_NO_THROW(RPCConvertValues("depingetpoolcontent", {"raw"}));

    // They arrive as strings, which is exactly why the RPCs normalise them.
    BOOST_CHECK(RPCConvertValues("depinclearmsg", {"all"})[0].isStr());
    BOOST_CHECK(RPCConvertValues("depinclearmsg", {"7"})[0].isStr());
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
                                    CallRpc("depinclearmsg", StrParams({bad}));
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
    BOOST_CHECK_THROW(CallRpc("depinclearmsg", StrParams({"-1"})), UniValue);
}

// (5) and (6): the declared names match the implementation, one by one.
BOOST_AUTO_TEST_CASE(argnames_match_the_implementation)
{
    std::vector<ArgNamesCase> cases = {
        {"depingetpoolcontent", {"verbose", "sender_address", "recipient_address",
                                 "start_time", "end_time", "limit", "offset"}},
        {"depinreceivemsg", {"token", "address", "timestamp", "after_hash", "limit"}},
        {"depinclearmsg", {"mode", "scope"}},
        {"depingetancestorrecipients", {"token", "max_results", "stop_at"}},
        {"depinlistsections", {"address"}},
    };
#ifdef ENABLE_DEPIN_GATEWAY
    // Only registered in a gateway build.
    cases.push_back({"depinsendmsg", {"token", "ip", "message", "fromaddress", "port"}});
    cases.push_back({"depingetmsg", {"token", "destination_or_address|fromaddress", "fromaddress"}});
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
    const UniValue named = RPCConvertNamedValues("depingetpoolcontent", {"limit=10", "offset=0"});
    BOOST_REQUIRE(named.isObject());
    BOOST_CHECK(find_value(named, "limit").isNum());
    BOOST_CHECK_EQUAL(find_value(named, "limit").get_int(), 10);
    BOOST_CHECK(find_value(named, "offset").isNum());

    // Skipping the middle parameters fills them with JSON nulls, which is the
    // shape that used to make the RPC throw a type error before it did any
    // work. `verbose` stays a STRING on purpose: it is polymorphic and
    // therefore absent from the conversion table, so the RPC normalises it.
    const UniValue positional = NamedToPositional("depingetpoolcontent",
                                                  {"verbose=true", "limit=10"});
    BOOST_REQUIRE_EQUAL(positional.size(), 6U);  // verbose .. limit, holes filled
    BOOST_CHECK_MESSAGE(positional[0].isStr(),
                        "verbose must not be converted: it also accepts \"all\" and \"raw\"");
    BOOST_CHECK_MESSAGE(positional[1].isNull(), "gaps are filled with JSON nulls");
    BOOST_CHECK(positional[5].isNum());
    BOOST_CHECK_EQUAL(positional[5].get_int(), 10);

    // And the call goes through, nulls and all.
    UniValue namedResult;
    BOOST_REQUIRE_NO_THROW(namedResult = CallNamed("depingetpoolcontent", {"verbose=true", "limit=10"}));
    BOOST_CHECK_MESSAGE(AllVerbose(namedResult), "verbose=true must reach the RPC as verbose");

    // An unknown name is still rejected.
    BOOST_CHECK_THROW(NamedToPositional("depingetpoolcontent", {"noexiste=1"}), UniValue);

    // Explicit nulls from a JSON-RPC caller behave the same way as the gaps.
    UniValue withNulls(UniValue::VARR);
    withNulls.push_back("true");
    withNulls.push_back(UniValue());
    withNulls.push_back(UniValue());
    withNulls.push_back(UniValue());
    withNulls.push_back(UniValue());
    withNulls.push_back((int64_t)10);
    BOOST_CHECK_NO_THROW(CallRpc("depingetpoolcontent", withNulls));
}

#ifdef ENABLE_DEPIN_GATEWAY
// (7b) The depingetmsg alias, the first "a|b" in this codebase.
//
// Asserts the LENGTH of the positional vector, not just that nothing throws:
// without the alias the local form yields [token, null, address] -- three
// entries with a hole -- and depingetmsg dies on an unguarded
// params[1].get_str(). An implementation that did not throw would still be
// wrong, so the shape is what has to be pinned.
BOOST_AUTO_TEST_CASE(getmsg_alias_binds_fromaddress_to_the_second_slot)
{
    const UniValue local = NamedToPositional("depingetmsg",
                                             {"token=" + POOL_TOKEN,
                                              "fromaddress=" + senderAddress});
    BOOST_REQUIRE_EQUAL(local.size(), 2U);
    BOOST_CHECK_EQUAL(local[0].get_str(), POOL_TOKEN);
    BOOST_CHECK_EQUAL(local[1].get_str(), senderAddress);

    // The three-parameter form is unaffected: the alias consumed `fromaddress`
    // at slot 1 only because slot 1 had no other candidate.
    const UniValue remote = NamedToPositional("depingetmsg",
                                              {"token=" + POOL_TOKEN,
                                               "destination_or_address=1.2.3.4",
                                               "fromaddress=" + senderAddress});
    BOOST_REQUIRE_EQUAL(remote.size(), 3U);
    BOOST_CHECK_EQUAL(remote[1].get_str(), "1.2.3.4");
    BOOST_CHECK_EQUAL(remote[2].get_str(), senderAddress);

    // The alias widens the accepted names; it must not soften the rejection of
    // unknown ones.
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
        if (!cmd) continue;  // gateway-only RPC, not registered in this build

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
