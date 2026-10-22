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
#include "test/depin_test_utils.h"
#include "test/depin_rpc_test_client.h"
#include "txdb.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "validation.h"
#include "version.h"

#include <boost/test/unit_test.hpp>

#include <map>
#include <future>
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
    ScopedDepinTestTipTime currentTip;
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
        SetDepinPoolKey(poolKey, "test");
        g_depinChallenges.Clear();
        g_depinRateLimiter.Clear();
        g_depinRateLimiter.SetLimit(DEFAULT_DEPIN_RATE_LIMIT);
        g_depinRequestGuard.Clear();

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
        SetMockTime(0);
        pDepinMsgPool = std::move(prevPool);
        g_depinChallenges.Clear();
        g_depinRateLimiter.Clear();
        g_depinRateLimiter.SetLimit(DEFAULT_DEPIN_RATE_LIMIT);
        g_depinRequestGuard.Clear();
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
        RememberDepinTestKey(h.key);
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
        RefreshDepinTestTipTime();
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
        return CallDepinTestRpc(method,params);
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

    // A signed challenge request: [token, address, timestamp, signature, type].
    // `signer` defaults to the holder; `skewSeconds` shifts the signed
    // timestamp. Under mock time the clock stands still, so a counter keeps
    // consecutive requests distinct (as real milliseconds would).
    static UniValue ChallengeParams(const std::string& token, const Holder& holder, DepinChallengeType type,
                                    const Holder* signer = nullptr, int64_t skewSeconds = 0)
    {
        RefreshDepinTestTipTime();
        static int64_t sequence = 0;
        const int64_t timestamp = DepinRequestClockMillis() + (++sequence % 1000) + skewSeconds * 1000;
        std::string sig, error;
        BOOST_REQUIRE_MESSAGE(SignDepinChallengePreimage((signer ? *signer : holder).key,
            DepinChallengeRequestPreimage(type, token, holder.address, timestamp), sig, error), error);
        return Params({token, holder.address, timestamp, sig, DepinChallengeTypeName(type)});
    }

    std::string Challenge(const std::string& token, const Holder& holder, DepinChallengeType type)
    {
        const UniValue response = Call("depinchallenge", ChallengeParams(token, holder, type));
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

    UniValue Receive(const Holder& holder, int64_t limit = 0,
                     const std::string& afterHash = "", int64_t timestamp = 0)
    {
        const std::string nonce = Challenge(SECTION_A, holder, DepinChallengeType::RECEIVE);
        return Open(Call("depinreceivemsg", Params({SECTION_A, holder.address, nonce,
            Sign(holder, DepinChallengeType::RECEIVE, SECTION_A, nonce), timestamp, afterHash, limit})), holder);
    }

    bool PoolSigVerifies(const UniValue& response, const std::string& method, const std::string& token,
                         const std::string& address, const std::string& nonce)
    {
        std::string error;
        const auto it=DepinTestRequests().find(response["request_hash"].get_str());
        return it!=DepinTestRequests().end() && it->second.method==method && it->second.token==token &&
               it->second.address==address && it->second.nonce==nonce &&
               VerifyDepinRpcResponse(response,it->second,poolKey.GetPubKey(),error);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(depin_auth_rpc_tests, DepinAuthRpcSetup)

BOOST_AUTO_TEST_CASE(receivemsg_pagination_limits_and_cursor)
{
    SetMockTime(1800000000);
    const Holder holder = NewHolder(true, SECTION_A, 10);
    const Holder sender = NewHolder(true, SECTION_A, 10);
    UniValue page = Receive(holder, 1);
    BOOST_CHECK_EQUAL(page["messages"].size(), 0U);
    BOOST_CHECK(!page["has_more"].get_bool());

    // Equal timestamps retain the existing mapByTime order and hash cursor.
    AddMessage(SECTION_A, sender, {holder}, "first");
    AddMessage(SECTION_A, sender, {holder}, "second");
    AddMessage(SECTION_A, sender, {holder}, "third");
    const UniValue all = Receive(holder);
    BOOST_REQUIRE_EQUAL(all["messages"].size(), 3U);
    BOOST_CHECK(!all["has_more"].get_bool());
    for (int limit : {4, 3}) {
        page = Receive(holder, limit);
        BOOST_CHECK_EQUAL(page["messages"].size(), 3U);
        BOOST_CHECK(!page["has_more"].get_bool());
    }
    page = Receive(holder, 2);
    BOOST_REQUIRE_EQUAL(page["messages"].size(), 2U);
    BOOST_CHECK(page["has_more"].get_bool());
    const std::string anchor = page["messages"][1]["hash"].get_str();
    page = Receive(holder, 1, anchor);
    BOOST_REQUIRE_EQUAL(page["messages"].size(), 1U);
    BOOST_CHECK_EQUAL(page["messages"][0]["hash"].get_str(), all["messages"][2]["hash"].get_str());
    BOOST_CHECK(!page["has_more"].get_bool());
    page = Receive(holder, 1, page["messages"][0]["hash"].get_str());
    BOOST_CHECK_EQUAL(page["messages"].size(), 0U);
    BOOST_CHECK(!page["has_more"].get_bool());
    BOOST_CHECK_THROW(Receive(holder, 1, std::string(64, 'f')), UniValue);
}

BOOST_AUTO_TEST_CASE(receivemsg_has_more_uses_delivery_filters)
{
    const int64_t start = 1800000000;
    SetMockTime(start);
    const Holder holder = NewHolder(true, SECTION_A, 10);
    const Holder sender = NewHolder(true, ROOT, 10);
    const Holder other = NewHolder(true, SECTION_A, 10);
    AddMessage(SECTION_A, sender, {holder}, "expired");
    SetMockTime(start + pDepinMsgPool->GetMessageExpiryTime() + 1);
    const int64_t fresh = GetTime();
    AddMessage(SECTION_A, sender, {holder}, "before timestamp filter");
    SetMockTime(fresh + 2);
    AddMessage(SECTION_A, sender, {holder}, "eligible");
    // Neither an extra recipient-excluded message nor the holder's own
    // message in a sibling section may set has_more for this tab.
    AddMessage(SECTION_A, sender, {other}, "other recipient");
    BOOST_REQUIRE(passetsdb->WriteAssetAddressQuantity(SECTION_B, holder.address, 10));
    AddMessage(SECTION_B, sender, {holder}, "other section");
    AddMessage(SECTION_B, holder, {holder}, "own sibling message");
    const UniValue filtered = Receive(holder, 1, "", fresh + 2);
    BOOST_REQUIRE_EQUAL(filtered["messages"].size(), 1U);
    BOOST_CHECK_EQUAL(filtered["messages"][0]["timestamp"].get_int64(), fresh + 2);
    BOOST_CHECK(!filtered["has_more"].get_bool());
    const UniValue unbounded = Receive(holder);
    BOOST_CHECK_EQUAL(unbounded["messages"].size(), 2U);
    BOOST_CHECK(!unbounded["has_more"].get_bool());
    BOOST_CHECK(Receive(holder, 1)["has_more"].get_bool());
}

BOOST_AUTO_TEST_CASE(expiry_applies_before_cleanup_and_sender_shortcut)
{
    const int64_t start = 1800000000;
    SetMockTime(start);
    // Exercise a configured TTL shorter than the MCP worker's separate 24 h
    // command-age cap; delivery must honor the pool's own setting.
    BOOST_REQUIRE(pDepinMsgPool->Initialize(ROOT, 20, DEFAULT_DEPIN_MESSAGE_SIZE,
                                           1, DEFAULT_DEPIN_POOL_SIZE_MB));
    const Holder holder = NewHolder(true, SECTION_A, 10);
    const Holder sender = NewHolder(true, SECTION_A, 10);
    AddMessage(SECTION_A, sender, {holder}, "received");
    AddMessage(SECTION_A, holder, {sender}, "own without recipient entry");
    SetMockTime(start + pDepinMsgPool->GetMessageExpiryTime() - 1);
    BOOST_CHECK_EQUAL(Receive(holder)["messages"].size(), 2U);
    SetMockTime(start + pDepinMsgPool->GetMessageExpiryTime());
    BOOST_CHECK_EQUAL(Receive(holder)["messages"].size(), 2U);
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetAllMessages(false).size(), 2U);
    const std::string expiredAnchor = Receive(holder)["messages"][0]["hash"].get_str();
    SetMockTime(GetTime() + 1);
    BOOST_CHECK_EQUAL(Receive(holder)["messages"].size(), 0U);
    BOOST_CHECK(pDepinMsgPool->GetMessagesForAddress(holder.address).empty());
    BOOST_CHECK(pDepinMsgPool->GetAllMessages(false).empty());
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetMessageCount(), 2U);
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetAllMessages().size(), 2U);
    BOOST_CHECK_EQUAL(pDepinMsgPool->CountMessagesInScope(SECTION_A, GetTime()), 0U);

    AddMessage(SECTION_A, sender, {holder}, "fresh");
    const UniValue page = Receive(holder, 1);
    BOOST_CHECK_EQUAL(page["messages"].size(), 1U);
    BOOST_CHECK(!page["has_more"].get_bool());
    BOOST_CHECK_THROW(Receive(holder, 1, expiredAnchor), UniValue);
    const std::string nonce = Challenge(SECTION_A, holder, DepinChallengeType::RECEIVE);
    const UniValue sections = Open(Call("depinlistsections", Params({holder.address, SECTION_A, nonce,
        Sign(holder, DepinChallengeType::RECEIVE, SECTION_A, nonce)})), holder);
    BOOST_REQUIRE_EQUAL(sections["sections"].size(), 1U);
    BOOST_CHECK_EQUAL(sections["sections"][0]["messages"].get_int(), 1);

    pDepinMsgPool->RemoveExpiredMessages(GetTime());
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetMessageCount(), 1U);
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetAllMessages().size(), 1U);
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetMessagesForAddress(holder.address).size(), 1U);
    BOOST_CHECK_EQUAL(Receive(holder)["messages"].size(), 1U);
}

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
    const UniValue opened = Open(response, holder);
    BOOST_REQUIRE(opened.isObject());
    BOOST_CHECK_EQUAL(opened["has_more"].get_bool(), false);
    const UniValue messages = opened["messages"];
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
    BOOST_CHECK_EQUAL(Open(again, holder)["messages"].size(), 1U);
}

// Nonce chaining: every authenticated reply carries the next challenge for
// the same bindings, with a longer life, so a client that keeps reading calls
// depinchallenge once and still signs every request. A chained nonce is a
// normal nonce: single-use, bound, and useless for other bindings.
BOOST_AUTO_TEST_CASE(replies_chain_the_next_challenge)
{
    // Keep expiration checks independent of wall-clock second boundaries.
    SetMockTime(1700000000);
    const Holder holder = NewHolder(true, SECTION_A, 10);
    const Holder sender = NewHolder(true, SECTION_A, 10);
    AddMessage(SECTION_A, sender, {holder}, "uno");

    const std::string first = Challenge(SECTION_A, holder, DepinChallengeType::RECEIVE);
    const UniValue r1 = Open(Call("depinreceivemsg", Params({SECTION_A, holder.address, first,
                                                             Sign(holder, DepinChallengeType::RECEIVE, SECTION_A, first)})), holder);
    BOOST_REQUIRE(r1.exists("next_challenge"));
    const std::string next = r1["next_challenge"].get_str();
    BOOST_CHECK_EQUAL(next.size(), 64U);
    BOOST_CHECK_EQUAL(r1["next_expires_in"].get_int(), (int)DEPIN_CHAINED_CHALLENGE_TIMEOUT);

    // Not for another token; not after the window; usable within it.
    BOOST_CHECK(Throws("depinreceivemsg", Params({ROOT, holder.address, next, Sign(holder, DepinChallengeType::RECEIVE, ROOT, next)})));
    SetMockTime(GetTime() + DEPIN_CHAINED_CHALLENGE_TIMEOUT - 1);
    const UniValue r2 = Open(Call("depinreceivemsg", Params({SECTION_A, holder.address, next,
                                                             Sign(holder, DepinChallengeType::RECEIVE, SECTION_A, next)})), holder);
    BOOST_CHECK_EQUAL(r2["messages"].size(), 1U);
    BOOST_REQUIRE(r2.exists("next_challenge"));
    const std::string next2 = r2["next_challenge"].get_str();
    BOOST_CHECK_NE(next2, next);
    // Consumed by its use.
    BOOST_CHECK(Throws("depinreceivemsg", Params({SECTION_A, holder.address, next, Sign(holder, DepinChallengeType::RECEIVE, SECTION_A, next)})));

    // depinlistsections chains too, and its nonce serves depinreceivemsg as
    // well: same bindings (scope, address, receive).
    const UniValue l = Open(Call("depinlistsections", Params({holder.address, SECTION_A, next2,
                                                              Sign(holder, DepinChallengeType::RECEIVE, SECTION_A, next2)})), holder);
    BOOST_REQUIRE(l.exists("next_challenge"));
    const std::string next3 = l["next_challenge"].get_str();
    BOOST_CHECK_EQUAL(Open(Call("depinreceivemsg", Params({SECTION_A, holder.address, next3,
                                                          Sign(holder, DepinChallengeType::RECEIVE, SECTION_A, next3)})), holder)["messages"].size(), 1U);

    // A chained nonce that is never used expires like any other.
    const std::string stale = Challenge(SECTION_A, holder, DepinChallengeType::RECEIVE);
    const UniValue r4 = Open(Call("depinreceivemsg", Params({SECTION_A, holder.address, stale,
                                                             Sign(holder, DepinChallengeType::RECEIVE, SECTION_A, stale)})), holder);
    SetMockTime(GetTime() + DEPIN_CHAINED_CHALLENGE_TIMEOUT + 1);
    const std::string expired = r4["next_challenge"].get_str();
    BOOST_CHECK(Throws("depinreceivemsg", Params({SECTION_A, holder.address, expired, Sign(holder, DepinChallengeType::RECEIVE, SECTION_A, expired)})));
}

// Issuance is limited per address and minute; another address is unaffected
// and the window slides.
BOOST_AUTO_TEST_CASE(challenge_issuance_is_rate_limited_per_address)
{
    g_depinRateLimiter.SetLimit(3);
    SetMockTime(1700000000);
    const Holder holder = NewHolder(true, SECTION_A, 10);
    const Holder other = NewHolder(true, SECTION_A, 10);

    for (int i = 0; i < 3; ++i) Challenge(SECTION_A, holder, DepinChallengeType::RECEIVE);
    BOOST_CHECK(Throws("depinchallenge", ChallengeParams(SECTION_A, holder, DepinChallengeType::RECEIVE)));
    BOOST_CHECK_EQUAL(g_depinChallenges.CountForAddress(holder.address), 3U);
    Challenge(SECTION_A, other, DepinChallengeType::RECEIVE);

    SetMockTime(GetTime() + DEPIN_RATE_WINDOW);
    Challenge(SECTION_A, holder, DepinChallengeType::RECEIVE);

    // Unlimited when configured so.
    g_depinRateLimiter.SetLimit(0);
    for (int i = 0; i < 10; ++i) Challenge(SECTION_A, holder, DepinChallengeType::RECEIVE);
}

// Only a request that passes the access checks counts against its address:
// anyone can name a holder in depinchallenge, so requests that are refused
// (a token it does not hold, an admin challenge it is not owner for) must not
// spend the holder's quota, or a third party could exhaust it for free.
BOOST_AUTO_TEST_CASE(refused_challenge_requests_do_not_consume_quota)
{
    g_depinRateLimiter.SetLimit(2);
    SetMockTime(1700000000);
    const Holder holder = NewHolder(true, SECTION_A, 10);

    for (int i = 0; i < 5; ++i) {
        BOOST_CHECK(Throws("depinchallenge", ChallengeParams(ROOT, holder, DepinChallengeType::RECEIVE)));                 // no access to the root
        BOOST_CHECK(Throws("depinchallenge", ChallengeParams(SECTION_A, holder, DepinChallengeType::ADMIN)));   // not an owner
        BOOST_CHECK(Throws("depinchallenge", ChallengeParams("&OTHER", holder, DepinChallengeType::RECEIVE)));             // foreign token
    }
    BOOST_CHECK_EQUAL(g_depinChallenges.CountForAddress(holder.address), 0U);

    // The quota is intact: the limit's worth of valid requests still succeeds,
    // and only then does the limiter bite.
    Challenge(SECTION_A, holder, DepinChallengeType::RECEIVE);
    Challenge(SECTION_A, holder, DepinChallengeType::RECEIVE);
    BOOST_CHECK(Throws("depinchallenge", ChallengeParams(SECTION_A, holder, DepinChallengeType::RECEIVE)));
    BOOST_CHECK_EQUAL(g_depinChallenges.CountForAddress(holder.address), 2U);
}

// The request for a challenge is itself authenticated: signed by the address
// over a timestamp, accepted once and only near the node's clock. A request
// forged in someone else's name costs that address nothing -- no quota, no
// evicted nonce -- and the unsigned shape no longer exists.
BOOST_AUTO_TEST_CASE(challenge_requests_are_signed_and_not_replayable)
{
    g_depinRateLimiter.SetLimit(3);
    SetMockTime(1700000000);
    const Holder holder = NewHolder(true, SECTION_A, 10);
    const Holder stranger = NewHolder(true, SECTION_A, 10);
    const Holder nonHolder = NewHolder(true);

    // The holder's one live nonce, which nobody else must be able to evict.
    const std::string mine = Challenge(SECTION_A, holder, DepinChallengeType::RECEIVE);

    // Forged: signed by the stranger, naming the holder. Refused at the
    // signature, before access, quota or the store.
    for (int i = 0; i < 10; ++i) {
        BOOST_CHECK(Throws("depinchallenge", ChallengeParams(SECTION_A, holder, DepinChallengeType::RECEIVE, &stranger)));
    }
    std::string error;
    BOOST_CHECK(g_depinChallenges.Peek(mine, error));
    BOOST_CHECK_EQUAL(g_depinChallenges.CountForAddress(holder.address), 1U);
    BOOST_CHECK_EQUAL(DepinRpcReplaySize(), 1U); // only the holder's own request was recorded

    // Even a cryptographically valid request from its own address must not
    // consume global replay capacity if that address has no access to the
    // requested section. Otherwise an attacker could fill the 10,000-entry
    // guard with freshly generated keys and block every real holder.
    for (int i = 0; i < 10; ++i) {
        BOOST_CHECK(Throws("depinchallenge", ChallengeParams(SECTION_A, nonHolder, DepinChallengeType::RECEIVE)));
    }
    BOOST_CHECK_EQUAL(DepinRpcReplaySize(), 1U);

    // Unsigned / malformed shapes.
    BOOST_CHECK(Throws("depinchallenge", Params({SECTION_A, holder.address})));
    BOOST_CHECK(Throws("depinchallenge", Params({SECTION_A, holder.address, DepinRequestClockMillis(), ""})));
    BOOST_CHECK(Throws("depinchallenge", Params({SECTION_A, holder.address, DepinRequestClockMillis(), "garbage"})));
    // Outside the window, either way.
    const int64_t windowSeconds = DEPIN_REQUEST_WINDOW_MS / 1000;
    BOOST_CHECK(Throws("depinchallenge", ChallengeParams(SECTION_A, holder, DepinChallengeType::RECEIVE, nullptr, -(windowSeconds + 1))));
    BOOST_CHECK(Throws("depinchallenge", ChallengeParams(SECTION_A, holder, DepinChallengeType::RECEIVE, nullptr, windowSeconds + 1)));
    // A signature for one type does not request the other.
    const UniValue adminReq = ChallengeParams(SECTION_A, holder, DepinChallengeType::ADMIN);
    BOOST_CHECK(Throws("depinchallenge", Params({adminReq[0], adminReq[1], adminReq[2], adminReq[3], "receive"})));
    BOOST_CHECK_EQUAL(g_depinChallenges.CountForAddress(holder.address), 1U);

    // Replay: the same signed request is accepted once.
    const UniValue once = ChallengeParams(SECTION_A, holder, DepinChallengeType::RECEIVE);
    Open(Call("depinchallenge", once), holder);
    BOOST_CHECK(Throws("depinchallenge", once));
    // ...even later inside the window; and after the window it is stale anyway.
    SetMockTime(GetTime() + windowSeconds - 1);
    BOOST_CHECK(Throws("depinchallenge", once));
    BOOST_CHECK_EQUAL(g_depinChallenges.CountForAddress(holder.address), 2U);

    // The quota counted exactly the holder's own two accepted requests.
    Challenge(SECTION_A, holder, DepinChallengeType::RECEIVE);
    BOOST_CHECK(Throws("depinchallenge", ChallengeParams(SECTION_A, holder, DepinChallengeType::RECEIVE)));
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
    BOOST_CHECK(Throws("depinchallenge", ChallengeParams(ROOT, sectionHolder, DepinChallengeType::RECEIVE)));
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
    BOOST_CHECK(Throws("depinchallenge", ChallengeParams(SECTION_A, holder, DepinChallengeType::ADMIN)));
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

    const UniValue response = Call("depinchallenge", ChallengeParams(SECTION_A, holder, DepinChallengeType::RECEIVE));
    BOOST_CHECK(response.exists("encrypted"));
    BOOST_CHECK(response.exists("poolsig"));
    BOOST_CHECK(!response.exists("challenge"));
    BOOST_CHECK(PoolSigVerifies(response, "depinchallenge", SECTION_A, holder.address, ""));
    const UniValue inner = Open(response, holder);
    BOOST_CHECK_EQUAL(inner["challenge"].get_str().size(), 64U);
    BOOST_CHECK_EQUAL(inner["type"].get_str(), "receive");
    BOOST_CHECK(Throws("depinchallenge", Params({SECTION_A, holder.address, DepinRequestClockMillis(), "sig", "send"})));

    BOOST_CHECK(Throws("depinchallenge", ChallengeParams(SECTION_A, unrevealed, DepinChallengeType::RECEIVE)));
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
BOOST_AUTO_TEST_CASE(named_request_preserves_optional_nulls)
{
    const Holder holder=NewHolder(true,SECTION_A,10), sender=NewHolder(true,SECTION_A,10);
    AddMessage(SECTION_A,sender,{holder},"named");
    const auto nonce=Challenge(SECTION_A,holder,DepinChallengeType::RECEIVE);
    UniValue args(UniValue::VOBJ);args.pushKV("limit",10);args.pushKV("timestamp",NullUniValue);args.pushKV("after_hash",NullUniValue);
    auto object=MakeDepinRpcRequest("depinreceivemsg",GetDepinRpcIdentity(),SECTION_A,holder.address,nonce,args);
    object=DepinTestSign("depinreceivemsg",object,holder.key);
    JSONRPCRequest request;request.strMethod="depinreceivemsg";
    request.params=RPCConvertNamedValues(request.strMethod,{"request="+object.write()});
    const auto positional=transformNamedArguments(request,tableRPC[request.strMethod]->argNames).params;
    BOOST_REQUIRE_EQUAL(positional.size(),1U);BOOST_CHECK(positional[0].isObject());
    const auto result=Open(Call("depinreceivemsg",positional),holder);
    BOOST_CHECK_EQUAL(result["messages"].size(),1U);
}

BOOST_AUTO_TEST_CASE(pending_freeze_denies_existing_nonce_after_restore)
{
    const Holder sender = NewHolder(true, SECTION_A, 10);
    const Holder frozen = NewHolder(true, SECTION_A, 10);
    const Holder remaining = NewHolder(true, SECTION_A, 10);
    AddMessage(SECTION_A, sender, {frozen, remaining}, "history before freeze");
    CDepinMessage msg = pDepinMsgPool->GetAllMessages()[0];
    BOOST_REQUIRE(sender.key.Sign(msg.GetHash(), msg.signature));
    pDepinMsgPool->Clear();
    std::string error;
    BOOST_REQUIRE(pDepinMsgPool->AddMessage(msg, error));
    const std::string nonce = Challenge(SECTION_A, frozen, DepinChallengeType::RECEIVE);
    BOOST_REQUIRE(pDepinMsgPool->SaveToDisk());
    const uint64_t flushes = nFullStateFlushes.load();
    {
        LOCK(cs_main);
        passets->setNewRestrictedAddressToAdd.insert(CAssetCacheRestrictedAddress(
            SECTION_A, frozen.address, RestrictedType::FREEZE_ADDRESS));
        // The restriction is still absent from disk.
        BOOST_CHECK(!prestricteddb->ReadRestrictedAddress(frozen.address, SECTION_A));
    }
    pDepinMsgPool->Clear();
    BOOST_REQUIRE(pDepinMsgPool->LoadFromDisk());
    BOOST_CHECK(Throws("depinreceivemsg", Params({SECTION_A, frozen.address, nonce,
        Sign(frozen, DepinChallengeType::RECEIVE, SECTION_A, nonce)})));
    BOOST_CHECK_EQUAL(Receive(remaining)["messages"].size(), 1U);
    BOOST_CHECK_EQUAL(nFullStateFlushes.load(), flushes);
}

BOOST_AUTO_TEST_CASE(freshness_gate_blocks_ibd_stale_tip_and_header_lag_without_flush)
{
    const Holder holder = NewHolder(true, SECTION_A, 10);
    const UniValue request = ChallengeParams(SECTION_A, holder, DepinChallengeType::RECEIVE);
    const uint64_t flushes = nFullStateFlushes.load();
    LOCK(cs_main);
    BOOST_REQUIRE(GetDepinServiceStatus().ready);
    CCoinsViewCache* coins = pcoinsTip;
    pcoinsTip = nullptr;
    BOOST_CHECK(!GetDepinServiceStatus().ready);
    pcoinsTip = coins;
    CAssetsCache* assets = passets;
    passets = nullptr;
    BOOST_CHECK(!GetDepinServiceStatus().ready);
    passets = assets;
    const uint32_t savedTime = chainActive.Tip()->nTime;
    chainActive.Tip()->nTime = GetTime() - DEFAULT_DEPIN_MAX_TIP_AGE;
    BOOST_CHECK(GetDepinServiceStatus().ready); // Exact threshold is allowed.
    chainActive.Tip()->nTime--;
    BOOST_CHECK(!GetDepinServiceStatus().ready);
    BOOST_CHECK(Throws("depinchallenge", request));
    const UniValue info = DepinPlainBody(Call("depingetmsginfo", Params({})));
    BOOST_CHECK(!info["ready"].get_bool());
    chainActive.Tip()->nTime = savedTime;
    CBlockIndex header;
    header.nHeight = chainActive.Height() + DEFAULT_DEPIN_MAX_HEADER_LAG + 1;
    CBlockIndex* oldHeader = pindexBestHeader;
    pindexBestHeader = &header;
    BOOST_CHECK(!GetDepinServiceStatus().ready);
    BOOST_CHECK(Throws("depinchallenge", request));
    pindexBestHeader = oldHeader;
    const bool importing = fImporting;
    fImporting = true;
    BOOST_CHECK(!GetDepinServiceStatus().ready);
    BOOST_CHECK(Throws("depinchallenge", request));
    CDepinAncestorRecipients recipients;
    std::string error;
    BOOST_CHECK(!GetDepinAncestorRecipients(SECTION_A, 20, recipients, error, ROOT));
    std::vector<std::string> sections;
    BOOST_CHECK(!pDepinMsgPool->GetSections(sections, error));
    fImporting = importing;
    BOOST_CHECK(GetDepinServiceStatus().ready);
    BOOST_CHECK_EQUAL(nFullStateFlushes.load(), flushes);
}

BOOST_AUTO_TEST_CASE(v4_clear_binds_mode_hours_and_every_service_field)
{
    const auto owner=NewHolder(true,SECTION_A+OWNER_TAG,1);
    const auto sender=NewHolder(true,SECTION_A,1), reader=NewHolder(true,SECTION_A,1);
    AddMessage(SECTION_A,sender,{reader},"keep-one");AddMessage(SECTION_A,sender,{reader},"keep-two");
    const auto nonce=Challenge(SECTION_A,owner,DepinChallengeType::ADMIN);
    auto object=MakeDepinRpcRequest("depinclearmsg",GetDepinRpcIdentity(),SECTION_A,owner.address,nonce,UniValue(UniValue::VOBJ));
    object=DepinTestSign("depinclearmsg",object,owner.key);
    for (const auto& name:{"all","hours"}) {
        UniValue args(UniValue::VOBJ);args.pushKV("mode",name);if (name==std::string("hours"))args.pushKV("hours",0);
        BOOST_CHECK(Throws("depinclearmsg",DepinTestParams(DepinTestReplace(object,"args",args))));
        std::string error;BOOST_CHECK(g_depinChallenges.Peek(nonce,error));BOOST_CHECK_EQUAL(pDepinMsgPool->Size(),2U);
    }
    CKey otherPool;otherPool.MakeNewKey(true);const auto otherPub=otherPool.GetPubKey();
    for (const auto& field:{"network","instance_id","request_id","pool_pubkey","pool_root","membership_revision","token","timestamp_ms","protocol"}) {
        UniValue value=field==std::string("pool_pubkey")?UniValue(HexStr(otherPub.begin(),otherPub.end())):
            field==std::string("pool_root")?UniValue(ROOT+"/OTHER"):
            field==std::string("token")?UniValue(ROOT):
            field==std::string("timestamp_ms")?UniValue(object["timestamp_ms"].get_int64()+1):
            field==std::string("protocol")?UniValue(2):UniValue(std::string(64,'f'));
        BOOST_REQUIRE(value.write()!=object[field].write());
        BOOST_CHECK(Throws("depinclearmsg",DepinTestParams(DepinTestReplace(object,field,value))));
        std::string error;BOOST_CHECK(g_depinChallenges.Peek(nonce,error));BOOST_CHECK_EQUAL(pDepinMsgPool->Size(),2U);
    }
    auto legacy=object;legacy=DepinTestReplace(legacy,"signature",UniValue(Sign(owner,DepinChallengeType::ADMIN,SECTION_A,nonce)));
    BOOST_CHECK(Throws("depinclearmsg",DepinTestParams(legacy)));
    const auto result=Open(Call("depinclearmsg",DepinTestParams(object)),owner);
    BOOST_CHECK_EQUAL(result["removed"].get_int(),0);BOOST_CHECK_EQUAL(result["remaining"].get_int(),2);
    BOOST_CHECK(Throws("depinclearmsg",DepinTestParams(object)));
}

BOOST_AUTO_TEST_CASE(v4_nonce_cannot_authorize_a_different_method_or_two_concurrent_reads)
{
    const auto holder=NewHolder(true,SECTION_A,1);
    const auto nonce=Challenge(SECTION_A,holder,DepinChallengeType::RECEIVE);
    auto object=MakeDepinRpcRequest("depinreceivemsg",GetDepinRpcIdentity(),SECTION_A,holder.address,nonce,UniValue(UniValue::VOBJ));
    object=DepinTestSign("depinreceivemsg",object,holder.key);
    BOOST_CHECK(Throws("depinlistsections",DepinTestParams(object)));
    std::string error;BOOST_REQUIRE(g_depinChallenges.Peek(nonce,error));
    auto run=[&] {
        JSONRPCRequest r;r.strMethod="depinreceivemsg";r.params=DepinTestParams(object);
        return (*tableRPC[r.strMethod]->actor)(r);
    };
    auto first=std::async(std::launch::async,run),second=std::async(std::launch::async,run);
    const auto a=Open(first.get(),holder),b=Open(second.get(),holder);
    BOOST_CHECK(a.exists("error")!=b.exists("error"));
    BOOST_CHECK(!g_depinChallenges.Peek(nonce,error));
}

BOOST_AUTO_TEST_CASE(v4_restart_and_clock_rollback_invalidate_old_requests)
{
    SetMockTime(1800000000);RefreshDepinTestTipTime();
    const auto holder=NewHolder(true,SECTION_A,1);const auto nonce=Challenge(SECTION_A,holder,DepinChallengeType::RECEIVE);
    const auto epoch=GetDepinRpcIdentity().instance;
    auto object=MakeDepinRpcRequest("depinreceivemsg",GetDepinRpcIdentity(),SECTION_A,holder.address,nonce,UniValue(UniValue::VOBJ));
    object=DepinTestSign("depinreceivemsg",object,holder.key);
    ResetDepinRpcInstance();BOOST_CHECK(GetDepinRpcIdentity().instance!=epoch);
    BOOST_CHECK(Throws("depinreceivemsg",DepinTestParams(object)));
    const auto fresh=Challenge(SECTION_A,holder,DepinChallengeType::RECEIVE);const auto before=GetDepinRpcIdentity().instance;
    SetMockTime(1799999999);ObserveDepinRpcClock(DepinRequestClockMillis());RefreshDepinTestTipTime();
    BOOST_CHECK(GetDepinRpcIdentity().instance!=before);std::string error;BOOST_CHECK(!g_depinChallenges.Peek(fresh,error));
    BOOST_CHECK_NO_THROW(Challenge(SECTION_A,holder,DepinChallengeType::RECEIVE));
}

BOOST_AUTO_TEST_CASE(v4_signed_purge_failure_keeps_messages_and_never_reports_success)
{
    const auto owner=NewHolder(true,SECTION_A+OWNER_TAG,1);
    const auto sender=NewHolder(true,SECTION_A,1), reader=NewHolder(true,SECTION_A,1);
    std::string error;BOOST_REQUIRE(pDepinMsgPool->InitializeStorage(false,error,1));
    AddMessage(SECTION_A,sender,{reader},"retained-one");AddMessage(SECTION_A,sender,{reader},"retained-two");
    const auto nonce=Challenge(SECTION_A,owner,DepinChallengeType::ADMIN);
    UniValue args(UniValue::VOBJ);args.pushKV("mode","all");
    auto object=DepinTestSign("depinclearmsg",MakeDepinRpcRequest("depinclearmsg",GetDepinRpcIdentity(),SECTION_A,owner.address,nonce,args),owner.key);
    const auto parsed=ParseDepinRpcRequest("depinclearmsg",object);
    JSONRPCRequest rpc;rpc.strMethod="depinclearmsg";rpc.params=DepinTestParams(object);
    const auto response=(*tableRPC[rpc.strMethod]->actor)(rpc);
    BOOST_CHECK(response.exists("encrypted"));BOOST_CHECK(!response.exists("body"));
    BOOST_CHECK(VerifyDepinRpcResponse(response,parsed,poolKey.GetPubKey(),error));
    const auto body=Open(response,owner);BOOST_REQUIRE(body.exists("error"));
    BOOST_CHECK_EQUAL(body["error"]["code"].get_int(),RPC_DATABASE_ERROR);
    BOOST_CHECK_EQUAL(body["error"]["data"]["depin_error"].get_str(),"storage_failure");
    BOOST_CHECK(!body.exists("removed"));BOOST_CHECK(!body.exists("result"));
    BOOST_CHECK_EQUAL(pDepinMsgPool->Size(),2U);BOOST_CHECK_EQUAL(pDepinMsgPool->GetTombstoneCount(),0U);
    BOOST_CHECK(pDepinMsgPool->StorageHealthy());BOOST_CHECK(!g_depinChallenges.Peek(nonce,error));
}


BOOST_AUTO_TEST_CASE(membership_invalidates_receive_admin_and_pending_timestamp_proofs)
{
    const auto holder = NewHolder(true, SECTION_A, 1);
    const auto owner = NewHolder(true, ROOT + OWNER_TAG, 1);
    const auto receive = Challenge(SECTION_A, holder, DepinChallengeType::RECEIVE);
    const auto admin = Challenge(ROOT, owner, DepinChallengeType::ADMIN);
    const auto before = GetDepinRpcIdentity();
    const auto oldRead = DepinTestSign("depinreceivemsg", MakeDepinRpcRequest(
        "depinreceivemsg", before, SECTION_A, holder.address, receive, UniValue(UniValue::VOBJ)), holder.key);
    const auto oldAdmin = DepinTestSign("depinclearmsg", MakeDepinRpcRequest(
        "depinclearmsg", before, ROOT, owner.address, admin, UniValue(UniValue::VOBJ)), owner.key);
    const auto oldChallenge = DepinTestSign("depinchallenge", MakeDepinRpcRequest(
        "depinchallenge", before, SECTION_A, holder.address, "", UniValue(UniValue::VOBJ)), holder.key);
    const auto oldPublic = MakeDepinRpcRequest("depinlistsections", before, ROOT, "", "", UniValue(UniValue::VOBJ));
    {
        LOCK(cs_main);
        NotifyDepinMembershipTip(chainActive.Tip()->GetBlockHash(), true);
    }
    const auto after = GetDepinRpcIdentity();
    BOOST_CHECK(before.membership.revision != after.membership.revision);
    BOOST_CHECK_EQUAL(before.instance, after.instance);
    BOOST_CHECK_EQUAL(g_depinChallenges.Size(), 0U);
    for (const auto& entry : std::vector<std::pair<std::string, UniValue>>{
             {"depinreceivemsg", oldRead}, {"depinclearmsg", oldAdmin}, {"depinchallenge", oldChallenge}}) {
        JSONRPCRequest rpc; rpc.strMethod = entry.first; rpc.params = DepinTestParams(entry.second);
        const auto response = (*tableRPC[rpc.strMethod]->actor)(rpc);
        std::string error;
        BOOST_REQUIRE(VerifyDepinRpcResponse(response, ParseDepinRpcRequest(entry.first, entry.second), poolKey.GetPubKey(), error));
        const auto body = Open(response, entry.first == "depinclearmsg" ? owner : holder);
        BOOST_CHECK_EQUAL(body["error"]["data"]["depin_error"].get_str(), "membership_stale");
        BOOST_CHECK_EQUAL(body["error"]["data"]["membership_revision"].get_str(), after.membership.revision);
        BOOST_CHECK(body["error"]["data"]["renew_challenge"].get_bool());
        BOOST_CHECK(!body.exists("messages"));
    }
    // Refreshing a public directory is allowed with the previous revision.
    const auto publicReply = Call("depinlistsections", DepinTestParams(oldPublic));
    BOOST_CHECK_EQUAL(publicReply["membership_revision"].get_str(), after.membership.revision);
    const auto fresh = Challenge(SECTION_A, holder, DepinChallengeType::RECEIVE);
    const auto freshRead = DepinTestSign("depinreceivemsg", MakeDepinRpcRequest(
        "depinreceivemsg", after, SECTION_A, holder.address, fresh, UniValue(UniValue::VOBJ)), holder.key);
    BOOST_CHECK_NO_THROW(Call("depinreceivemsg", DepinTestParams(freshRead)));
    // Another relevant transition never restores the earlier epoch/nonces.
    { LOCK(cs_main); NotifyDepinMembershipTip(chainActive.Tip()->GetBlockHash(), true); }
    const auto third = GetDepinRpcIdentity();
    BOOST_CHECK(third.membership.revision != before.membership.revision);
    BOOST_CHECK(third.membership.revision != after.membership.revision);
    BOOST_CHECK(Throws("depinreceivemsg", DepinTestParams(oldRead)));
}

BOOST_AUTO_TEST_CASE(membership_unrelated_events_and_invalid_requests_preserve_current_challenges)
{
    const auto holder = NewHolder(true, SECTION_A, 1);
    const auto nonce = Challenge(SECTION_A, holder, DepinChallengeType::RECEIVE);
    const auto initial = GetDepinRpcIdentity();
    const auto read = DepinTestSign("depinreceivemsg", MakeDepinRpcRequest(
        "depinreceivemsg", initial, SECTION_A, holder.address, nonce, UniValue(UniValue::VOBJ)), holder.key);
    {
        LOCK(cs_main);
        CAssetsCache changes;
        changes.mapAssetsAddressAmount[{"&TESTING", holder.address}] = 1;
        BOOST_CHECK(!DepinMembershipAffected(changes));
        NotifyDepinMembershipTip(chainActive.Tip()->GetBlockHash(), false);
    }
    BOOST_CHECK_EQUAL(GetDepinRpcIdentity().membership.revision, initial.membership.revision);
    const auto malformed = DepinTestReplace(read, "membership_revision", UniValue(std::string(64, 'f')));
    BOOST_CHECK(Throws("depinreceivemsg", DepinTestParams(malformed)));
    const auto deliberatelyStale = DepinTestSign("depinreceivemsg", malformed, holder.key);
    const auto quota = g_depinRateLimiter.Size(), replay = DepinRpcReplaySize();
    BOOST_CHECK(Throws("depinreceivemsg", DepinTestParams(deliberatelyStale)));
    BOOST_CHECK_EQUAL(g_depinRateLimiter.Size(), quota);
    BOOST_CHECK_EQUAL(DepinRpcReplaySize(), replay);
    std::string error; BOOST_CHECK(g_depinChallenges.Peek(nonce, error));
    BOOST_CHECK_EQUAL(GetDepinRpcIdentity().membership.revision, initial.membership.revision);
    BOOST_CHECK_NO_THROW(Call("depinreceivemsg", DepinTestParams(read)));
}

BOOST_AUTO_TEST_CASE(membership_observer_covers_sections_owners_restrictions_and_key_reveals_without_flush)
{
    LOCK(cs_main);
    const auto unknown = NewHolder(false);
    const auto known = NewHolder(true, SECTION_A, 1);
    GetDepinRpcIdentity();
    const auto flushes = nFullStateFlushes.load();
    CAssetsCache changes;
    changes.mapAssetsAddressAmount[{SECTION_A, unknown.address}] = 1;
    BOOST_CHECK(DepinMembershipAffected(changes));
    changes.ClearDirtyCache(); changes.mapAssetsAddressAmount.clear();
    changes.setNewOwnerAssetsToAdd.insert(CAssetCacheNewOwner(SECTION_B + OWNER_TAG, known.address));
    BOOST_CHECK(DepinMembershipAffected(changes));
    changes.ClearDirtyCache();
    changes.setNewSelfRestrictionToAdd.insert(CAssetCacheSelfRestriction(SECTION_A, known.address, true));
    BOOST_CHECK(DepinMembershipAffected(changes));
    changes.ClearDirtyCache();
    changes.setNewRestrictedAddressToAdd.insert(CAssetCacheRestrictedAddress(ROOT, known.address, RestrictedType::FREEZE_ADDRESS));
    BOOST_CHECK(DepinMembershipAffected(changes));
    changes.ClearDirtyCache();
    BOOST_CHECK(!DepinMembershipAffected(changes, {unknown.address}));
    passets->mapAssetsAddressAmount[{SECTION_B, unknown.address}] = 1;
    BOOST_CHECK(DepinMembershipAffected(changes, {unknown.address}));
    passets->mapAssetsAddressAmount.erase({SECTION_B, unknown.address});
    BOOST_REQUIRE(passetsdb->WriteAddressAssetQuantity(unknown.address, SECTION_B, 1));
    BOOST_CHECK(DepinMembershipAffected(changes, {unknown.address}));
    passets->mapAssetsAddressAmount[{SECTION_B, unknown.address}] = 0;
    BOOST_CHECK(!DepinMembershipAffected(changes, {unknown.address}));
    passets->mapAssetsAddressAmount.erase({SECTION_B, unknown.address});
    // The reverse address index is length-ordered, not lexicographic by asset.
    BOOST_REQUIRE(passetsdb->WriteAddressAssetQuantity(unknown.address, "UNRELATED", 1));
    std::vector<std::pair<std::string,CAmount>> rows; bool limited = false; size_t budget = 1;
    BOOST_REQUIRE(passetsdb->ReadAddressAssets(unknown.address, budget, rows, limited));
    BOOST_CHECK(limited); BOOST_CHECK_EQUAL(budget, 0U); BOOST_CHECK_EQUAL(rows.size(), 1U);
    CDestinationIndexData destination;
    BOOST_REQUIRE(GetDestinationIndexData(DecodeDestination(unknown.address), destination));
    std::vector<std::pair<CPubKeyIndexKey,CPubKeyIndexValue>> entries{
        {CPubKeyIndexKey(destination), CPubKeyIndexValue(unknown.pubkey, 1, uint256())}};
    std::set<std::string> revealed;
    CaptureDepinMembershipKeys(entries, revealed); BOOST_CHECK(revealed.count(unknown.address));
    BOOST_REQUIRE(pblocktree->WritePubKeyIndex(entries));
    revealed.clear(); CaptureDepinMembershipKeys(entries, revealed); BOOST_CHECK(revealed.empty());
    BOOST_CHECK_EQUAL(nFullStateFlushes.load(), flushes);
}

BOOST_AUTO_TEST_SUITE_END()
