// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// The authenticated DePIN RPCs end to end: depinchallenge -> sign ->
// depinreceivemsg / depinlistsections / depinclearmsg, through the real
// command table. These pin the breaking contract of the new model: there is
// no unauthenticated form, every reply bound to an address is encrypted for
// it, and a challenge authorises exactly what it was issued for.

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
#include "key.h"
#include "pubkey.h"
#include "pubkeyindex.h"
#include "rpc/client.h"
#include "rpc/server.h"
#include "streams.h"
#include "test/test_neurai.h"
#include "txdb.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "validation.h"
#include "version.h"

#include <boost/test/unit_test.hpp>

#include <map>
#include <string>
#include <univalue.h>
#include <vector>

namespace {

const std::string ROOT = "&TEST";
const std::string SECTION_A = "&TEST/GENERAL";
const std::string SECTION_B = "&TEST/OTHERS";

struct Holder {
    CKey key;
    CPubKey pubkey;
    std::string address;
};

struct DepinAuthRpcSetup : public TestingSetup {
    bool prevAssetIndex;
    bool prevPubKeyIndex;
    CAssetsDB* prevAssetsDb;
    CLRUCache<std::string, CDatabasedAssetData>* prevAssetsCache;
    CRestrictedDB* prevRestrictedDb;
    std::unique_ptr<CDepinMsgPool> prevPool;
    CKey poolKey;

    // REGTEST: DEPIN names only validate on testnet/regtest.
    DepinAuthRpcSetup() : TestingSetup(CBaseChainParams::REGTEST)
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
        prestricteddb = new CRestrictedDB(1 << 20, true, true);

        poolKey.MakeNewKey(true);
        SetDepinPoolKey(poolKey, "", "", "test");
        g_depinChallenges.Clear();

        for (const std::string& name : {ROOT, SECTION_A, SECTION_B}) {
            CNewAsset asset(name, 1000 * COIN, DEPIN_ASSET_UNITS, 0, 0, "");
            BOOST_REQUIRE(passetsdb->WriteAssetData(asset, 1, uint256()));
        }

        prevPool = std::move(pDepinMsgPool);
        pDepinMsgPool.reset(new CDepinMsgPool());
        BOOST_REQUIRE(pDepinMsgPool->Initialize(ROOT, 20, DEFAULT_DEPIN_MESSAGE_SIZE,
                                                DEFAULT_DEPIN_MESSAGE_EXPIRY_HOURS,
                                                DEFAULT_DEPIN_POOL_SIZE_MB));
    }

    ~DepinAuthRpcSetup()
    {
        pDepinMsgPool = std::move(prevPool);
        g_depinChallenges.Clear();
        ClearDepinPoolKey();
        delete prestricteddb;
        delete passetsCache;
        delete passetsdb;
        prestricteddb = prevRestrictedDb;
        passetsCache = prevAssetsCache;
        passetsdb = prevAssetsDb;
        fPubKeyIndex = prevPubKeyIndex;
        fAssetIndex = prevAssetIndex;
    }

    Holder NewHolder(bool reveal, const std::string& asset = "", CAmount amount = 0)
    {
        Holder h;
        h.key.MakeNewKey(true);
        h.pubkey = h.key.GetPubKey();
        h.address = EncodeDestination(h.pubkey.GetID());
        if (reveal) {
            CDestinationIndexData addressData;
            BOOST_REQUIRE(GetDestinationIndexData(DecodeDestination(h.address), addressData));
            std::vector<std::pair<CPubKeyIndexKey, CPubKeyIndexValue> > entries;
            entries.emplace_back(CPubKeyIndexKey(addressData), CPubKeyIndexValue(h.pubkey, 1, uint256()));
            BOOST_REQUIRE(pblocktree->WritePubKeyIndex(entries));
        }
        if (!asset.empty()) {
            BOOST_REQUIRE(passetsdb->WriteAssetAddressQuantity(asset, h.address, amount));
        }
        return h;
    }

    // A message whose payload is a real ECIES structure for `recipients`, so
    // depinreceivemsg's recipientKeys filter sees them.
    void AddMessage(const std::string& token, const Holder& sender,
                    const std::vector<Holder>& recipients, const std::string& text)
    {
        std::map<std::string, CPubKey> keys;
        for (const Holder& r : recipients) keys[r.address] = r.pubkey;
        CECIESEncryptedMessage ecies;
        std::string error;
        BOOST_REQUIRE_MESSAGE(ECIESEncryptMessage(text, keys, ecies, error), error);

        CDepinMessage msg;
        msg.token = token;
        msg.senderAddress = sender.address;
        msg.timestamp = GetTime();
        msg.messageType = 0x02;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << ecies;
        msg.encryptedPayload.assign(ss.begin(), ss.end());
        msg.signature.assign(8, (unsigned char)text.size());
        BOOST_REQUIRE_MESSAGE(pDepinMsgPool->AddMessage(msg, error, /*skipSignatureCheck=*/true), error);
    }

    static UniValue Call(const std::string& method, const UniValue& params)
    {
        JSONRPCRequest request;
        request.strMethod = method;
        request.params = params;
        request.fHelp = false;
        BOOST_REQUIRE(tableRPC[method]);
        return (*tableRPC[method]->actor)(request);
    }

    // JSONRPCError throws a UniValue, type errors throw std::runtime_error:
    // for "the call is refused" both count.
    static bool Throws(const std::string& method, const UniValue& params)
    {
        try {
            Call(method, params);
            return false;
        } catch (...) {
            return true;
        }
    }

    static UniValue Params(std::initializer_list<UniValue> values)
    {
        UniValue params(UniValue::VARR);
        for (const UniValue& v : values) params.push_back(v);
        return params;
    }

    static UniValue Open(const UniValue& response, const Holder& holder)
    {
        BOOST_REQUIRE_MESSAGE(response.exists("encrypted"), response.write());
        BOOST_REQUIRE(response.exists("poolsig"));
        CECIESEncryptedMessage ecies;
        CDataStream ss(ParseHex(response["encrypted"].get_str()), SER_NETWORK, PROTOCOL_VERSION);
        ss >> ecies;
        std::string plaintext, error;
        BOOST_REQUIRE_MESSAGE(ECIESDecryptMessage(ecies, holder.key, holder.address, plaintext, error), error);
        UniValue inner;
        BOOST_REQUIRE(inner.read(plaintext));
        return inner;
    }

    std::string Challenge(const std::string& token, const Holder& holder, DepinChallengeType type)
    {
        const UniValue response = Call("depinchallenge", Params({token, holder.address, DepinChallengeTypeName(type)}));
        const UniValue inner = Open(response, holder);
        BOOST_CHECK_EQUAL(inner["type"].get_str(), DepinChallengeTypeName(type));
        BOOST_CHECK_EQUAL(inner["expires_in"].get_int(), (int)DEPIN_CHALLENGE_TIMEOUT);
        const std::string nonce = inner["challenge"].get_str();
        BOOST_REQUIRE_EQUAL(nonce.size(), 64U);
        return nonce;
    }

    static std::string Sign(const Holder& h, DepinChallengeType type, const std::string& token, const std::string& nonce)
    {
        std::string sig, error;
        BOOST_REQUIRE_MESSAGE(SignDepinChallengePreimage(h.key, DepinChallengePreimage(type, token, h.address, nonce), sig, error), error);
        return sig;
    }

    bool PoolSigVerifies(const UniValue& response, const std::string& method, const std::string& token,
                         const std::string& address, const std::string& nonce)
    {
        std::string error;
        return VerifyDepinResponseSignature(poolKey.GetPubKey(), method, token, address, nonce,
                                            response["encrypted"].get_str(), response["poolsig"].get_str(), error);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(depin_auth_rpc_tests, DepinAuthRpcSetup)

// (7) The happy path, and the two ways a valid-looking request must fail
// without burning the holder's nonce.
BOOST_AUTO_TEST_CASE(receivemsg_with_valid_auth)
{
    const Holder holder = NewHolder(true, SECTION_A, 10);
    const Holder sender = NewHolder(true, SECTION_A, 10);
    const Holder other = NewHolder(true, SECTION_A, 10);
    AddMessage(SECTION_A, sender, {holder}, "hola");

    const std::string nonce = Challenge(SECTION_A, holder, DepinChallengeType::RECEIVE);
    const std::string sig = Sign(holder, DepinChallengeType::RECEIVE, SECTION_A, nonce);

    const UniValue response = Call("depinreceivemsg", Params({SECTION_A, holder.address, nonce, sig}));
    BOOST_CHECK(PoolSigVerifies(response, "depinreceivemsg", SECTION_A, holder.address, nonce));
    const UniValue messages = Open(response, holder);
    BOOST_REQUIRE(messages.isArray());
    BOOST_REQUIRE_EQUAL(messages.size(), 1U);
    BOOST_CHECK_EQUAL(messages[0]["sender"].get_str(), sender.address);
    BOOST_CHECK_EQUAL(messages[0]["token"].get_str(), SECTION_A);

    // Consumed: the same nonce is refused.
    BOOST_CHECK(Throws("depinreceivemsg", Params({SECTION_A, holder.address, nonce, sig})));

    // Someone else's signature over the holder's nonce is refused and leaves
    // the nonce usable by the holder.
    const std::string nonce2 = Challenge(SECTION_A, holder, DepinChallengeType::RECEIVE);
    BOOST_CHECK(Throws("depinreceivemsg", Params({SECTION_A, holder.address, nonce2,
                                                  Sign(other, DepinChallengeType::RECEIVE, SECTION_A, nonce2)})));
    BOOST_CHECK(Throws("depinreceivemsg", Params({SECTION_A, holder.address, nonce2, "garbage"})));
    const UniValue again = Call("depinreceivemsg", Params({SECTION_A, holder.address, nonce2,
                                                           Sign(holder, DepinChallengeType::RECEIVE, SECTION_A, nonce2)}));
    BOOST_CHECK_EQUAL(Open(again, holder).size(), 1U);
}

// (8) There is no unauthenticated form. The old shapes fail by arity or type
// before the pool is touched.
BOOST_AUTO_TEST_CASE(legacy_receivemsg_without_auth_is_rejected)
{
    const Holder holder = NewHolder(true, SECTION_A, 10);
    const Holder sender = NewHolder(true, SECTION_A, 10);
    AddMessage(SECTION_A, sender, {holder}, "secreto");

    BOOST_CHECK(Throws("depinreceivemsg", Params({SECTION_A, holder.address})));
    BOOST_CHECK(Throws("depinreceivemsg", Params({SECTION_A, holder.address, (int64_t)1730000000})));
    BOOST_CHECK(Throws("depinreceivemsg", Params({SECTION_A, holder.address, "", ""})));
    BOOST_CHECK(Throws("depinreceivemsg", Params({SECTION_A, holder.address, "1730000000", "x"})));
    BOOST_CHECK(Throws("depinreceivemsg", Params({SECTION_A, holder.address, (int64_t)0, "", (int64_t)5})));
    BOOST_CHECK_EQUAL(g_depinChallenges.Size(), 0U);
}

// (9) + (23) Names are free; access and counters need a challenge for a
// scope, and report that scope's subtree only.
BOOST_AUTO_TEST_CASE(listsections_names_free_address_mode_authenticated)
{
    const Holder sectionHolder = NewHolder(true, SECTION_A, 10);
    const Holder rootHolder = NewHolder(true, ROOT, 10);
    const Holder sender = NewHolder(true, ROOT, 10);
    AddMessage(SECTION_A, sender, {sectionHolder}, "a");
    AddMessage(SECTION_B, sender, {rootHolder}, "b");

    // Names only: a signed plain body, not encrypted.
    const UniValue namesReply = Call("depinlistsections", Params({}));
    BOOST_REQUIRE(namesReply.exists("poolsig"));
    BOOST_REQUIRE(namesReply.exists("body"));
    const UniValue names = DepinPlainBody(namesReply);
    BOOST_REQUIRE_EQUAL(names["sections"].size(), 3U);
    BOOST_CHECK(!names["sections"][0].exists("access"));

    // One to three arguments: refused.
    BOOST_CHECK(Throws("depinlistsections", Params({sectionHolder.address})));
    BOOST_CHECK(Throws("depinlistsections", Params({sectionHolder.address, SECTION_A})));
    BOOST_CHECK(Throws("depinlistsections", Params({sectionHolder.address, SECTION_A, std::string(64, 'a')})));

    // A section holder never gets a root challenge...
    BOOST_CHECK(Throws("depinchallenge", Params({ROOT, sectionHolder.address})));
    // ...and with a section challenge sees that subtree only.
    {
        const std::string nonce = Challenge(SECTION_A, sectionHolder, DepinChallengeType::RECEIVE);
        const UniValue response = Call("depinlistsections",
            Params({sectionHolder.address, SECTION_A, nonce, Sign(sectionHolder, DepinChallengeType::RECEIVE, SECTION_A, nonce)}));
        BOOST_CHECK(PoolSigVerifies(response, "depinlistsections", SECTION_A, sectionHolder.address, nonce));
        const UniValue sections = Open(response, sectionHolder)["sections"];
        BOOST_REQUIRE_EQUAL(sections.size(), 1U);
        BOOST_CHECK_EQUAL(sections[0]["name"].get_str(), SECTION_A);
        BOOST_CHECK_EQUAL(sections[0]["access"].get_bool(), true);
        BOOST_CHECK_EQUAL(sections[0]["messages"].get_int(), 1);
    }
    // The root holder sees everything.
    {
        const std::string nonce = Challenge(ROOT, rootHolder, DepinChallengeType::RECEIVE);
        const UniValue response = Call("depinlistsections",
            Params({rootHolder.address, ROOT, nonce, Sign(rootHolder, DepinChallengeType::RECEIVE, ROOT, nonce)}));
        const UniValue sections = Open(response, rootHolder)["sections"];
        BOOST_REQUIRE_EQUAL(sections.size(), 3U);
        for (size_t i = 0; i < sections.size(); ++i) {
            BOOST_CHECK_EQUAL(sections[i]["access"].get_bool(), true);
        }
        BOOST_CHECK_EQUAL(sections[0]["name"].get_str(), ROOT);
        BOOST_CHECK_EQUAL(sections[0]["messages"].get_int(), 2);
    }
    // A challenge for one scope does not serve another.
    {
        const std::string nonce = Challenge(SECTION_A, rootHolder, DepinChallengeType::RECEIVE);
        BOOST_CHECK(Throws("depinlistsections",
            Params({rootHolder.address, ROOT, nonce, Sign(rootHolder, DepinChallengeType::RECEIVE, ROOT, nonce)})));
    }
}

// (10) depinclearmsg is owner-level, always authenticated, and a bad mode
// does not burn the nonce.
BOOST_AUTO_TEST_CASE(clearmsg_admin_requires_owner_signature)
{
    const Holder owner = NewHolder(true, ROOT + OWNER_TAG, 1);
    const Holder holder = NewHolder(true, SECTION_A, 10);
    const Holder rootHolder = NewHolder(true, ROOT, 10);
    AddMessage(ROOT, rootHolder, {rootHolder}, "root");
    AddMessage(SECTION_A, holder, {holder}, "a1");
    AddMessage(SECTION_A, holder, {holder}, "a2");
    BOOST_REQUIRE_EQUAL(pDepinMsgPool->Size(), 3U);

    // A holder is not an owner: no admin challenge, and a receive challenge
    // does not pass as one.
    BOOST_CHECK(Throws("depinchallenge", Params({SECTION_A, holder.address, "admin"})));
    const std::string receiveNonce = Challenge(SECTION_A, holder, DepinChallengeType::RECEIVE);
    BOOST_CHECK(Throws("depinclearmsg", Params({SECTION_A, holder.address, receiveNonce,
                                                Sign(holder, DepinChallengeType::ADMIN, SECTION_A, receiveNonce), "all"})));
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 3U);

    // The legacy shapes are gone.
    BOOST_CHECK(Throws("depinclearmsg", Params({})));
    BOOST_CHECK(Throws("depinclearmsg", Params({"all"})));
    BOOST_CHECK(Throws("depinclearmsg", Params({(int64_t)7})));
    BOOST_CHECK(Throws("depinclearmsg", Params({"all", SECTION_A})));
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 3U);

    // A bad mode is refused before the nonce is consumed...
    const std::string nonce = Challenge(SECTION_A, owner, DepinChallengeType::ADMIN);
    const std::string sig = Sign(owner, DepinChallengeType::ADMIN, SECTION_A, nonce);
    BOOST_CHECK(Throws("depinclearmsg", Params({SECTION_A, owner.address, nonce, sig, "7x"})));
    BOOST_CHECK(Throws("depinclearmsg", Params({SECTION_A, owner.address, nonce, sig, ""})));
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 3U);
    // ...so the same nonce then purges the section, and only the section.
    const UniValue response = Call("depinclearmsg", Params({SECTION_A, owner.address, nonce, sig, "all"}));
    BOOST_CHECK(PoolSigVerifies(response, "depinclearmsg", SECTION_A, owner.address, nonce));
    const UniValue result = Open(response, owner);
    BOOST_CHECK_EQUAL(result["removed"].get_int(), 2);
    BOOST_CHECK_EQUAL(result["remaining"].get_int(), 1);
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetAllMessages()[0].token, ROOT);
}

// (11) depinchallenge never answers in the clear, and an address without a
// revealed key takes no part at all.
BOOST_AUTO_TEST_CASE(challenge_reply_always_encrypted)
{
    const Holder holder = NewHolder(true, SECTION_A, 10);
    const Holder unrevealed = NewHolder(false, SECTION_A, 10);

    const UniValue response = Call("depinchallenge", Params({SECTION_A, holder.address}));
    BOOST_CHECK(response.exists("encrypted"));
    BOOST_CHECK(response.exists("poolsig"));
    BOOST_CHECK(!response.exists("challenge"));
    BOOST_CHECK(PoolSigVerifies(response, "depinchallenge", SECTION_A, holder.address, ""));
    const UniValue inner = Open(response, holder);
    BOOST_CHECK_EQUAL(inner["challenge"].get_str().size(), 64U);
    BOOST_CHECK_EQUAL(inner["type"].get_str(), "receive");
    BOOST_CHECK(Throws("depinchallenge", Params({SECTION_A, holder.address, "send"})));

    BOOST_CHECK(Throws("depinchallenge", Params({SECTION_A, unrevealed.address})));
    BOOST_CHECK(Throws("depinreceivemsg", Params({SECTION_A, unrevealed.address, std::string(64, 'a'), "sig"})));
    BOOST_CHECK_EQUAL(g_depinChallenges.CountForAddress(unrevealed.address), 0U);
}

// (22) An admin challenge authorises exactly its scope: equality, not
// subtree; "" is the root, requested for the root by name, and the root's
// subtree is the whole pool.
BOOST_AUTO_TEST_CASE(clearmsg_challenge_scope_must_match_exactly)
{
    const Holder owner = NewHolder(true, ROOT + OWNER_TAG, 1);
    const Holder rootHolder = NewHolder(true, ROOT, 10);
    auto fill = [&]() {
        AddMessage(ROOT, rootHolder, {rootHolder}, "root");
        AddMessage(SECTION_A, rootHolder, {rootHolder}, "a");
        AddMessage(SECTION_B, rootHolder, {rootHolder}, "b");
    };
    fill();
    BOOST_REQUIRE_EQUAL(pDepinMsgPool->Size(), 3U);

    // A section challenge clears neither the pool nor a sibling.
    const std::string nonceA = Challenge(SECTION_A, owner, DepinChallengeType::ADMIN);
    BOOST_CHECK(Throws("depinclearmsg", Params({"", owner.address, nonceA, Sign(owner, DepinChallengeType::ADMIN, ROOT, nonceA), "all"})));
    BOOST_CHECK(Throws("depinclearmsg", Params({SECTION_B, owner.address, nonceA, Sign(owner, DepinChallengeType::ADMIN, SECTION_B, nonceA), "all"})));
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 3U);
    Open(Call("depinclearmsg", Params({SECTION_A, owner.address, nonceA, Sign(owner, DepinChallengeType::ADMIN, SECTION_A, nonceA), "all"})), owner);
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 2U);

    // A root challenge does not clear a section by name either (equality).
    const std::string nonceRoot = Challenge(ROOT, owner, DepinChallengeType::ADMIN);
    BOOST_CHECK(Throws("depinclearmsg", Params({SECTION_B, owner.address, nonceRoot, Sign(owner, DepinChallengeType::ADMIN, SECTION_B, nonceRoot), "all"})));
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 2U);

    // The positive case of the normalisation: "" with a root challenge.
    const UniValue cleared = Open(Call("depinclearmsg",
        Params({"", owner.address, nonceRoot, Sign(owner, DepinChallengeType::ADMIN, ROOT, nonceRoot), "all"})), owner);
    BOOST_CHECK_EQUAL(cleared["removed"].get_int(), 2);
    BOOST_CHECK_EQUAL(cleared["remaining"].get_int(), 0);

    // And the explicit root is the same operation.
    fill();
    const std::string nonceRoot2 = Challenge(ROOT, owner, DepinChallengeType::ADMIN);
    const UniValue cleared2 = Open(Call("depinclearmsg",
        Params({ROOT, owner.address, nonceRoot2, Sign(owner, DepinChallengeType::ADMIN, ROOT, nonceRoot2), "all"})), owner);
    BOOST_CHECK_EQUAL(cleared2["removed"].get_int(), 3);
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(), 0U);

    // A scope outside the pool is refused before any authentication.
    BOOST_CHECK(Throws("depinclearmsg", Params({"&OTRO", owner.address, std::string(64, 'a'), "sig", "all"})));
}

// (24) Named invocation with holes: the optional parameters after the
// signature arrive as JSON nulls and the RPCs treat them as absent.
BOOST_AUTO_TEST_CASE(named_params_with_null_holes)
{
    const Holder holder = NewHolder(true, SECTION_A, 10);
    const Holder sender = NewHolder(true, SECTION_A, 10);
    AddMessage(SECTION_A, sender, {holder}, "x");

    auto namedToPositional = [](const std::string& method, const std::vector<std::string>& nameEqualsValue) {
        JSONRPCRequest request;
        request.strMethod = method;
        request.params = RPCConvertNamedValues(method, nameEqualsValue);
        request.fHelp = false;
        return transformNamedArguments(request, tableRPC[method]->argNames).params;
    };

    const std::string nonce = Challenge(SECTION_A, holder, DepinChallengeType::RECEIVE);
    const std::string sig = Sign(holder, DepinChallengeType::RECEIVE, SECTION_A, nonce);
    const UniValue positional = namedToPositional("depinreceivemsg",
        {"token=" + SECTION_A, "address=" + holder.address, "challenge=" + nonce, "signature=" + sig, "limit=10"});
    BOOST_REQUIRE_EQUAL(positional.size(), 7U);
    BOOST_CHECK(positional[4].isNull());
    BOOST_CHECK(positional[5].isNull());
    BOOST_CHECK(positional[6].isNum());
    const UniValue paged = Open(Call("depinreceivemsg", positional), holder);
    BOOST_REQUIRE(paged.isObject());
    BOOST_CHECK_EQUAL(paged["messages"].size(), 1U);

    const std::string nonce2 = Challenge(SECTION_A, holder, DepinChallengeType::RECEIVE);
    const UniValue listing = namedToPositional("depinlistsections",
        {"address=" + holder.address, "scope=" + SECTION_A, "challenge=" + nonce2,
         "signature=" + Sign(holder, DepinChallengeType::RECEIVE, SECTION_A, nonce2)});
    BOOST_REQUIRE_EQUAL(listing.size(), 4U);
    BOOST_CHECK_EQUAL(Open(Call("depinlistsections", listing), holder)["sections"].size(), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
