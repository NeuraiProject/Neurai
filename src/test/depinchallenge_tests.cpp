// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// The DePIN challenge store and its signature scheme (depinchallenge.{h,cpp}).
// These pin the properties the RPC layer relies on: a nonce is single-use,
// bound to (token, address, type), expires, and -- the one the legacy server
// got wrong -- is never erased by a request that fails verification.

#include "depinchallenge.h"

// amount.h first: assets/assetdb.h declares CAmount parameters without
// including it, so it only compiles when the includer got there first.
#include "amount.h"
#include "assets/assetdb.h"
#include "assets/assets.h"
#include "assets/restricteddb.h"
#include "base58.h"
#include "pubkeyindex.h"
#include "txdb.h"
#include "validation.h"
#include "key.h"
#include "pubkey.h"
#include "test/test_neurai.h"
#include "utilstrencodings.h"
#include "utiltime.h"

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

const std::string TOKEN = "&TEST";
const std::string SECTION = "&TEST/SEC";

struct Holder {
    CKey key;
    std::string address;
};

Holder NewHolder()
{
    Holder h;
    h.key.MakeNewKey(true);
    h.address = EncodeDestination(h.key.GetPubKey().GetID());
    return h;
}

struct DepinChallengeSetup : public BasicTestingSetup {
    CDepinChallengeManager store;
    DepinChallengeSetup() { SetMockTime(1700000000); }
    ~DepinChallengeSetup() { SetMockTime(0); }
};

// Issuance and authentication with access checks read the asset index, the
// restriction index and the revealed-pubkey index. REGTEST: DEPIN names only
// validate on testnet/regtest.
struct DepinChallengeAccessSetup : public TestingSetup {
    bool prevAssetIndex;
    bool prevPubKeyIndex;
    CAssetsDB* prevAssetsDb;
    CLRUCache<std::string, CDatabasedAssetData>* prevAssetsCache;
    CRestrictedDB* prevRestrictedDb;

    DepinChallengeAccessSetup() : TestingSetup(CBaseChainParams::REGTEST)
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
        g_depinChallenges.Clear();
        SetMockTime(1700000000);
    }

    ~DepinChallengeAccessSetup()
    {
        SetMockTime(0);
        g_depinChallenges.Clear();
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
        Holder h = ::NewHolder();
        if (reveal) {
            CDestinationIndexData addressData;
            BOOST_REQUIRE(GetDestinationIndexData(DecodeDestination(h.address), addressData));
            std::vector<std::pair<CPubKeyIndexKey, CPubKeyIndexValue> > entries;
            entries.emplace_back(CPubKeyIndexKey(addressData), CPubKeyIndexValue(h.key.GetPubKey(), 1, uint256()));
            BOOST_REQUIRE(pblocktree->WritePubKeyIndex(entries));
        }
        if (!asset.empty()) {
            BOOST_REQUIRE(passetsdb->WriteAssetAddressQuantity(asset, h.address, amount));
        }
        return h;
    }

    std::string Sign(const Holder& h, DepinChallengeType type, const std::string& token, const std::string& nonce)
    {
        std::string sig, error;
        BOOST_REQUIRE_MESSAGE(SignDepinChallengePreimage(h.key, DepinChallengePreimage(type, token, h.address, nonce), sig, error), error);
        return sig;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(depinchallenge_tests, DepinChallengeSetup)

// (1) A nonce is 32 random bytes in hex and is consumed exactly once.
BOOST_AUTO_TEST_CASE(challenge_single_use)
{
    const Holder h = NewHolder();
    std::string error;
    const std::string nonce = store.Issue(TOKEN, h.address, DepinChallengeType::RECEIVE, error);
    BOOST_REQUIRE_MESSAGE(!nonce.empty(), error);
    BOOST_CHECK_EQUAL(nonce.size(), 64U);
    BOOST_CHECK(IsHex(nonce));
    BOOST_CHECK_EQUAL(store.Size(), 1U);

    BOOST_CHECK(store.Peek(nonce, error));
    BOOST_CHECK(store.Consume(nonce, TOKEN, h.address, DepinChallengeType::RECEIVE, error));
    BOOST_CHECK_EQUAL(store.Size(), 0U);

    // Second use: gone.
    BOOST_CHECK(!store.Consume(nonce, TOKEN, h.address, DepinChallengeType::RECEIVE, error));
    BOOST_CHECK_EQUAL(error, "Challenge not found");
    BOOST_CHECK(!store.Peek(nonce, error));

    // Two nonces issued back to back differ.
    const std::string a = store.Issue(TOKEN, h.address, DepinChallengeType::RECEIVE, error);
    const std::string b = store.Issue(TOKEN, h.address, DepinChallengeType::RECEIVE, error);
    BOOST_CHECK_NE(a, b);
}

// (2) + (20) Bound to token, address and type -- and a mismatch does NOT
// consume: the nonce stays usable for what it was issued for.
BOOST_AUTO_TEST_CASE(challenge_bound_to_token_address_type_without_erase)
{
    const Holder h = NewHolder();
    const Holder other = NewHolder();
    std::string error;
    const std::string nonce = store.Issue(SECTION, h.address, DepinChallengeType::RECEIVE, error);
    BOOST_REQUIRE(!nonce.empty());

    BOOST_CHECK(!store.Consume(nonce, TOKEN, h.address, DepinChallengeType::RECEIVE, error));
    BOOST_CHECK_EQUAL(error, "Challenge does not match token/address");
    BOOST_CHECK(!store.Consume(nonce, SECTION, other.address, DepinChallengeType::RECEIVE, error));
    BOOST_CHECK(!store.Consume(nonce, SECTION, h.address, DepinChallengeType::ADMIN, error));
    BOOST_CHECK_EQUAL(error, "Challenge type mismatch");

    // Still there, still valid for its own bindings.
    BOOST_CHECK_EQUAL(store.Size(), 1U);
    BOOST_CHECK(store.Peek(nonce, error));
    BOOST_CHECK(store.Consume(nonce, SECTION, h.address, DepinChallengeType::RECEIVE, error));
    BOOST_CHECK_EQUAL(store.Size(), 0U);
}

// (3) Expiry: after DEPIN_CHALLENGE_TIMEOUT the nonce is refused and purged.
BOOST_AUTO_TEST_CASE(challenge_expires)
{
    const Holder h = NewHolder();
    std::string error;
    const std::string nonce = store.Issue(TOKEN, h.address, DepinChallengeType::RECEIVE, error);
    BOOST_REQUIRE(!nonce.empty());

    SetMockTime(GetTime() + DEPIN_CHALLENGE_TIMEOUT - 1);
    BOOST_CHECK(store.Peek(nonce, error));

    SetMockTime(GetTime() + 1);
    BOOST_CHECK(!store.Peek(nonce, error));
    BOOST_CHECK_EQUAL(error, "Challenge expired");
    BOOST_CHECK(!store.Consume(nonce, TOKEN, h.address, DepinChallengeType::RECEIVE, error));
    BOOST_CHECK_EQUAL(error, "Challenge expired");
    BOOST_CHECK_EQUAL(store.Size(), 0U);
}

// (5) Per-address cap evicts the oldest nonce of that address; the global cap
// refuses issuance once reached.
BOOST_AUTO_TEST_CASE(challenge_per_address_and_global_caps)
{
    const Holder h = NewHolder();
    std::string error;
    std::vector<std::string> nonces;
    for (size_t i = 0; i < DEPIN_CHALLENGE_MAX_PER_ADDRESS; ++i) {
        nonces.push_back(store.Issue(TOKEN, h.address, DepinChallengeType::RECEIVE, error));
        BOOST_REQUIRE(!nonces.back().empty());
    }
    BOOST_CHECK_EQUAL(store.CountForAddress(h.address), DEPIN_CHALLENGE_MAX_PER_ADDRESS);

    // One more: the first one is evicted, the others survive.
    const std::string extra = store.Issue(TOKEN, h.address, DepinChallengeType::RECEIVE, error);
    BOOST_REQUIRE(!extra.empty());
    BOOST_CHECK_EQUAL(store.CountForAddress(h.address), DEPIN_CHALLENGE_MAX_PER_ADDRESS);
    BOOST_CHECK(!store.Peek(nonces[0], error));
    BOOST_CHECK(store.Peek(nonces[1], error));
    BOOST_CHECK(store.Peek(extra, error));

    // Global cap: one address at its per-address cap, the rest of the store
    // filled with distinct addresses (the store does not validate them).
    store.Clear();
    for (size_t i = 0; i < DEPIN_CHALLENGE_MAX_PER_ADDRESS; ++i) {
        BOOST_REQUIRE(!store.Issue(TOKEN, "addr-full", DepinChallengeType::RECEIVE, error).empty());
    }
    for (size_t i = store.Size(); i < DEPIN_CHALLENGE_MAX_TOTAL; ++i) {
        const std::string addr = strprintf("addr-%u", (unsigned)i);
        BOOST_REQUIRE(!store.Issue(TOKEN, addr, DepinChallengeType::RECEIVE, error).empty());
    }
    BOOST_CHECK_EQUAL(store.Size(), DEPIN_CHALLENGE_MAX_TOTAL);

    // A new address cannot get a slot...
    BOOST_CHECK(store.Issue(TOKEN, "addr-new", DepinChallengeType::RECEIVE, error).empty());
    BOOST_CHECK_EQUAL(error, "Too many pending challenges");
    BOOST_CHECK_EQUAL(store.CountForAddress("addr-new"), 0U);
    // ...nor can one below its own cap grow the store...
    BOOST_CHECK(store.Issue(TOKEN, "addr-5", DepinChallengeType::RECEIVE, error).empty());
    BOOST_CHECK_EQUAL(store.CountForAddress("addr-5"), 1U);
    // ...but an address at its cap recycles its own oldest slot: a holder
    // re-requesting never counts against the global limit.
    BOOST_CHECK(!store.Issue(TOKEN, "addr-full", DepinChallengeType::RECEIVE, error).empty());
    BOOST_CHECK_EQUAL(store.CountForAddress("addr-full"), DEPIN_CHALLENGE_MAX_PER_ADDRESS);
    BOOST_CHECK_EQUAL(store.Size(), DEPIN_CHALLENGE_MAX_TOTAL);
}

// (6) Abandoned nonces disappear with the periodic sweep even if nobody ever
// tries to validate them.
BOOST_AUTO_TEST_CASE(challenge_cleanup_without_validation)
{
    const Holder h = NewHolder();
    std::string error;
    BOOST_REQUIRE(!store.Issue(TOKEN, h.address, DepinChallengeType::RECEIVE, error).empty());
    BOOST_REQUIRE(!store.Issue(TOKEN, h.address, DepinChallengeType::ADMIN, error).empty());
    BOOST_CHECK_EQUAL(store.Size(), 2U);

    BOOST_CHECK_EQUAL(store.CleanupExpired(GetTime() + DEPIN_CHALLENGE_TIMEOUT - 1), 0U);
    BOOST_CHECK_EQUAL(store.Size(), 2U);
    BOOST_CHECK_EQUAL(store.CleanupExpired(GetTime() + DEPIN_CHALLENGE_TIMEOUT), 2U);
    BOOST_CHECK_EQUAL(store.Size(), 0U);
    BOOST_CHECK_EQUAL(store.CountForAddress(h.address), 0U);
}

// (15) Signer and verifier share one preimage helper; the preimage carries the
// type, token, address and nonce, and signing is signmessage-compatible.
BOOST_AUTO_TEST_CASE(preimage_shared_between_sign_and_verify)
{
    const Holder h = NewHolder();
    const Holder other = NewHolder();
    const std::string nonce(64, 'a');

    const std::string preimage = DepinChallengePreimage(DepinChallengeType::RECEIVE, SECTION, h.address, nonce);
    BOOST_CHECK_EQUAL(preimage, "DEPIN-GET|" + SECTION + "|" + h.address + "|" + nonce);
    BOOST_CHECK_EQUAL(DepinChallengePreimage(DepinChallengeType::ADMIN, TOKEN, h.address, nonce),
                      "DEPIN-CLEAR|" + TOKEN + "|" + h.address + "|" + nonce);

    std::string sig, error;
    BOOST_REQUIRE_MESSAGE(SignDepinChallengePreimage(h.key, preimage, sig, error), error);
    BOOST_CHECK(VerifyDepinChallengeSignature(h.address, sig, preimage, error));

    // Another key, another preimage, a malformed signature: all refused.
    BOOST_CHECK(!VerifyDepinChallengeSignature(other.address, sig, preimage, error));
    BOOST_CHECK_EQUAL(error, "Signature does not match address");
    BOOST_CHECK(!VerifyDepinChallengeSignature(h.address, sig,
                DepinChallengePreimage(DepinChallengeType::ADMIN, SECTION, h.address, nonce), error));
    BOOST_CHECK(!VerifyDepinChallengeSignature(h.address, "not-base64!", preimage, error));
    BOOST_CHECK(!VerifyDepinChallengeSignature("not-an-address", sig, preimage, error));

    // Type names round-trip and reject anything else.
    DepinChallengeType parsed;
    BOOST_CHECK(ParseDepinChallengeType("ADMIN", parsed) && parsed == DepinChallengeType::ADMIN);
    BOOST_CHECK(ParseDepinChallengeType("receive", parsed) && parsed == DepinChallengeType::RECEIVE);
    BOOST_CHECK(!ParseDepinChallengeType("send", parsed));
    BOOST_CHECK_EQUAL(DepinChallengeTypeName(DepinChallengeType::ADMIN), "admin");
}

// The signed challenge request: window, signature, single acceptance.
BOOST_AUTO_TEST_CASE(challenge_request_auth_window_signature_replay)
{
    g_depinRequestGuard.Clear();
    const Holder h = NewHolder();
    const Holder other = NewHolder();
    const int64_t now = DepinRequestClockMillis();
    const int64_t W = DEPIN_REQUEST_WINDOW_MS;
    std::string error;

    auto signReq = [&](const Holder& who, DepinChallengeType type, int64_t ts) {
        std::string sig;
        BOOST_REQUIRE(SignDepinChallengePreimage(who.key, DepinChallengeRequestPreimage(type, SECTION, h.address, ts), sig, error));
        return sig;
    };
    BOOST_CHECK_EQUAL(DepinChallengeRequestPreimage(DepinChallengeType::ADMIN, SECTION, h.address, 42),
                      "DEPIN-REQ|admin|" + SECTION + "|" + h.address + "|42");

    const std::string sig = signReq(h, DepinChallengeType::RECEIVE, now);
    BOOST_CHECK(CheckDepinChallengeRequestAuth(DepinChallengeType::RECEIVE, SECTION, h.address, now, sig, now, error));
    // Replay, even later inside the window.
    BOOST_CHECK(!CheckDepinChallengeRequestAuth(DepinChallengeType::RECEIVE, SECTION, h.address, now, sig, now + 10000, error));
    BOOST_CHECK_EQUAL(error, "Request already used");
    // Other signer, other type, other token, other timestamp than signed.
    BOOST_CHECK(!CheckDepinChallengeRequestAuth(DepinChallengeType::RECEIVE, SECTION, h.address, now + 1, signReq(other, DepinChallengeType::RECEIVE, now + 1), now, error));
    BOOST_CHECK(!CheckDepinChallengeRequestAuth(DepinChallengeType::ADMIN, SECTION, h.address, now + 1, signReq(h, DepinChallengeType::RECEIVE, now + 1), now, error));
    BOOST_CHECK(!CheckDepinChallengeRequestAuth(DepinChallengeType::RECEIVE, TOKEN, h.address, now + 1, signReq(h, DepinChallengeType::RECEIVE, now + 1), now, error));
    BOOST_CHECK(!CheckDepinChallengeRequestAuth(DepinChallengeType::RECEIVE, SECTION, h.address, now + 2, signReq(h, DepinChallengeType::RECEIVE, now + 1), now, error));
    // Only the one valid request was recorded: forgeries leave no trace.
    BOOST_CHECK_EQUAL(g_depinRequestGuard.Size(), 1U);
    // Window, both sides.
    BOOST_CHECK(!CheckDepinChallengeRequestAuth(DepinChallengeType::RECEIVE, SECTION, h.address, now - W - 1,
                                                signReq(h, DepinChallengeType::RECEIVE, now - W - 1), now, error));
    BOOST_CHECK(!CheckDepinChallengeRequestAuth(DepinChallengeType::RECEIVE, SECTION, h.address, now + W + 1,
                                                signReq(h, DepinChallengeType::RECEIVE, now + W + 1), now, error));
    BOOST_CHECK(CheckDepinChallengeRequestAuth(DepinChallengeType::RECEIVE, SECTION, h.address, now - W,
                                               signReq(h, DepinChallengeType::RECEIVE, now - W), now, error));
    // The record outlives the window, then is pruned.
    g_depinRequestGuard.Prune(now + 2 * W - 1);
    BOOST_CHECK_EQUAL(g_depinRequestGuard.Size(), 2U);
    g_depinRequestGuard.Prune(now + 2 * W);
    BOOST_CHECK_EQUAL(g_depinRequestGuard.Size(), 0U);
    g_depinRequestGuard.Clear();
}

// The per-key sliding window behind -depinratelimit.
BOOST_AUTO_TEST_CASE(rate_limiter_per_key_per_window)
{
    CDepinRateLimiter rl;
    rl.SetLimit(2);
    const int64_t now = 1700000000;
    BOOST_CHECK(rl.Allow("a", now));
    BOOST_CHECK(rl.Allow("a", now + 1));
    BOOST_CHECK(!rl.Allow("a", now + 2));
    BOOST_CHECK(rl.Allow("b", now + 2));          // other keys are independent
    BOOST_CHECK(!rl.Allow("a", now + DEPIN_RATE_WINDOW - 1));
    BOOST_CHECK(rl.Allow("a", now + DEPIN_RATE_WINDOW)); // the first hit left the window
    BOOST_CHECK(!rl.Allow("a", now + DEPIN_RATE_WINDOW));
    BOOST_CHECK_EQUAL(rl.Size(), 2U);
    rl.Prune(now + 2 * DEPIN_RATE_WINDOW + 1);
    BOOST_CHECK_EQUAL(rl.Size(), 0U);

    rl.SetLimit(0);
    for (int i = 0; i < 50; ++i) BOOST_CHECK(rl.Allow("a", now));
}

// The limiter never tracks more than DEPIN_RATE_LIMITER_MAX_KEYS keys: once
// full of live keys a new one is refused (not stored), a known key is still
// judged by its own window, and capacity returns as keys leave the window.
BOOST_AUTO_TEST_CASE(rate_limiter_caps_distinct_keys)
{
    CDepinRateLimiter rl;
    rl.SetLimit(2);
    const int64_t now = 1700000000;
    for (size_t i = 0; i < DEPIN_RATE_LIMITER_MAX_KEYS; ++i) {
        BOOST_REQUIRE(rl.Allow("k" + std::to_string(i), now));
    }
    BOOST_CHECK_EQUAL(rl.Size(), DEPIN_RATE_LIMITER_MAX_KEYS);

    // Full and nothing expired: a new key is refused and the map does not grow.
    BOOST_CHECK(!rl.Allow("new", now + 1));
    BOOST_CHECK(!rl.Allow("new", now + 1));
    BOOST_CHECK_EQUAL(rl.Size(), DEPIN_RATE_LIMITER_MAX_KEYS);

    // A key already tracked still has its own window: one more hit allowed,
    // then its limit applies.
    BOOST_CHECK(rl.Allow("k0", now + 1));
    BOOST_CHECK(!rl.Allow("k0", now + 2));
    BOOST_CHECK_EQUAL(rl.Size(), DEPIN_RATE_LIMITER_MAX_KEYS);

    // Once the window has passed, the sweep frees everything and the new key
    // gets in.
    BOOST_CHECK(rl.Allow("new", now + DEPIN_RATE_WINDOW + 1));
    BOOST_CHECK_EQUAL(rl.Size(), 1U);
}

// (4) Only holders get a nonce: access, revealed key and the pool's subtree
// are all checked BEFORE anything is stored.
BOOST_FIXTURE_TEST_CASE(challenge_not_issued_without_access, DepinChallengeAccessSetup)
{
    const Holder sectionHolder = NewHolder(true, SECTION, 10);
    const Holder rootHolder = NewHolder(true, TOKEN, 10);
    const Holder owner = NewHolder(true, TOKEN + OWNER_TAG, 1);
    const Holder stranger = NewHolder(true);
    const Holder unrevealed = NewHolder(false, SECTION, 10);

    std::string nonce, error;
    CPubKey pubkey;

    // A section holder gets a challenge for its section, not for the root.
    BOOST_CHECK_MESSAGE(IssueDepinChallengeForAddress(SECTION, sectionHolder.address, DepinChallengeType::RECEIVE, TOKEN, nonce, pubkey, error), error);
    BOOST_CHECK(pubkey == sectionHolder.key.GetPubKey());
    BOOST_CHECK(!IssueDepinChallengeForAddress(TOKEN, sectionHolder.address, DepinChallengeType::RECEIVE, TOKEN, nonce, pubkey, error));
    // A root holder gets both (the root grants the whole branch).
    BOOST_CHECK(IssueDepinChallengeForAddress(TOKEN, rootHolder.address, DepinChallengeType::RECEIVE, TOKEN, nonce, pubkey, error));
    BOOST_CHECK(IssueDepinChallengeForAddress(SECTION, rootHolder.address, DepinChallengeType::RECEIVE, TOKEN, nonce, pubkey, error));

    // No balance, no revealed key, foreign token, wrong type: no nonce.
    const size_t before = g_depinChallenges.Size();
    BOOST_CHECK(!IssueDepinChallengeForAddress(SECTION, stranger.address, DepinChallengeType::RECEIVE, TOKEN, nonce, pubkey, error));
    BOOST_CHECK(!IssueDepinChallengeForAddress(SECTION, unrevealed.address, DepinChallengeType::RECEIVE, TOKEN, nonce, pubkey, error));
    BOOST_CHECK_MESSAGE(error.find("public key") != std::string::npos, error);
    BOOST_CHECK(!IssueDepinChallengeForAddress("&OTHER", rootHolder.address, DepinChallengeType::RECEIVE, TOKEN, nonce, pubkey, error));
    BOOST_CHECK(!IssueDepinChallengeForAddress(SECTION, sectionHolder.address, DepinChallengeType::ADMIN, TOKEN, nonce, pubkey, error));
    BOOST_CHECK(!IssueDepinChallengeForAddress(SECTION, "not-an-address", DepinChallengeType::RECEIVE, TOKEN, nonce, pubkey, error));
    BOOST_CHECK_EQUAL(g_depinChallenges.Size(), before);

    // ADMIN goes to the owner, for the root and for any section under it.
    BOOST_CHECK(IssueDepinChallengeForAddress(TOKEN, owner.address, DepinChallengeType::ADMIN, TOKEN, nonce, pubkey, error));
    BOOST_CHECK(IssueDepinChallengeForAddress(SECTION, owner.address, DepinChallengeType::ADMIN, TOKEN, nonce, pubkey, error));
}

// (19) A failed verification never consumes: the nonce stays usable by its
// owner after garbage, after someone else's valid signature, after a
// binding mismatch.
BOOST_FIXTURE_TEST_CASE(invalid_signature_does_not_consume_nonce, DepinChallengeAccessSetup)
{
    const Holder holder = NewHolder(true, SECTION, 10);
    const Holder other = NewHolder(true, SECTION, 10);

    std::string nonce, error;
    CPubKey pubkey;
    BOOST_REQUIRE(IssueDepinChallengeForAddress(SECTION, holder.address, DepinChallengeType::RECEIVE, TOKEN, nonce, pubkey, error));

    BOOST_CHECK(!CheckDepinChallengeAuth(DepinChallengeType::RECEIVE, SECTION, holder.address, nonce, "garbage", TOKEN, error));
    BOOST_CHECK(g_depinChallenges.Peek(nonce, error));
    // `other` signs the same preimage with its own key: valid signature, wrong address.
    BOOST_CHECK(!CheckDepinChallengeAuth(DepinChallengeType::RECEIVE, SECTION, holder.address, nonce, Sign(other, DepinChallengeType::RECEIVE, SECTION, nonce), TOKEN, error));
    BOOST_CHECK(g_depinChallenges.Peek(nonce, error));
    // `other` presents holder's nonce as its own: signature ok for `other`, nonce was not issued to it.
    BOOST_CHECK(!CheckDepinChallengeAuth(DepinChallengeType::RECEIVE, SECTION, other.address, nonce, Sign(other, DepinChallengeType::RECEIVE, SECTION, nonce), TOKEN, error));
    BOOST_CHECK(g_depinChallenges.Peek(nonce, error));
    // Right signer, wrong token / type.
    BOOST_CHECK(!CheckDepinChallengeAuth(DepinChallengeType::RECEIVE, TOKEN, holder.address, nonce, Sign(holder, DepinChallengeType::RECEIVE, TOKEN, nonce), TOKEN, error));
    BOOST_CHECK(!CheckDepinChallengeAuth(DepinChallengeType::ADMIN, SECTION, holder.address, nonce, Sign(holder, DepinChallengeType::ADMIN, SECTION, nonce), TOKEN, error));
    BOOST_CHECK(g_depinChallenges.Peek(nonce, error));
    // Malformed nonce / missing signature never reach the store.
    BOOST_CHECK(!CheckDepinChallengeAuth(DepinChallengeType::RECEIVE, SECTION, holder.address, "abc", "x", TOKEN, error));
    BOOST_CHECK(!CheckDepinChallengeAuth(DepinChallengeType::RECEIVE, SECTION, holder.address, nonce, "", TOKEN, error));

    // The owner's own use succeeds exactly once.
    const std::string sig = Sign(holder, DepinChallengeType::RECEIVE, SECTION, nonce);
    BOOST_CHECK_MESSAGE(CheckDepinChallengeAuth(DepinChallengeType::RECEIVE, SECTION, holder.address, nonce, sig, TOKEN, error), error);
    BOOST_CHECK(!CheckDepinChallengeAuth(DepinChallengeType::RECEIVE, SECTION, holder.address, nonce, sig, TOKEN, error));
    BOOST_CHECK_EQUAL(error, "Challenge not found");
}

// (21) Access is re-validated when the challenge is used, not only when it
// was issued.
BOOST_FIXTURE_TEST_CASE(access_revalidated_at_consumption, DepinChallengeAccessSetup)
{
    const Holder holder = NewHolder(true, SECTION, 10);
    const Holder owner = NewHolder(true, TOKEN + OWNER_TAG, 1);

    std::string nonce, error;
    CPubKey pubkey;
    BOOST_REQUIRE(IssueDepinChallengeForAddress(SECTION, holder.address, DepinChallengeType::RECEIVE, TOKEN, nonce, pubkey, error));
    const std::string sig = Sign(holder, DepinChallengeType::RECEIVE, SECTION, nonce);

    // The balance moves away between issuance and use.
    BOOST_REQUIRE(passetsdb->WriteAssetAddressQuantity(SECTION, holder.address, 0));
    BOOST_CHECK(!CheckDepinChallengeAuth(DepinChallengeType::RECEIVE, SECTION, holder.address, nonce, sig, TOKEN, error));
    BOOST_CHECK(g_depinChallenges.Peek(nonce, error)); // not consumed by the refusal
    // Back in time for the 30 s window: the same nonce works again.
    BOOST_REQUIRE(passetsdb->WriteAssetAddressQuantity(SECTION, holder.address, 10));
    BOOST_CHECK_MESSAGE(CheckDepinChallengeAuth(DepinChallengeType::RECEIVE, SECTION, holder.address, nonce, sig, TOKEN, error), error);

    // An owner that stops being one before using its ADMIN challenge.
    std::string adminNonce;
    BOOST_REQUIRE(IssueDepinChallengeForAddress(TOKEN, owner.address, DepinChallengeType::ADMIN, TOKEN, adminNonce, pubkey, error));
    const std::string adminSig = Sign(owner, DepinChallengeType::ADMIN, TOKEN, adminNonce);
    BOOST_REQUIRE(passetsdb->WriteAssetAddressQuantity(TOKEN + OWNER_TAG, owner.address, 0));
    BOOST_CHECK(!CheckDepinChallengeAuth(DepinChallengeType::ADMIN, TOKEN, owner.address, adminNonce, adminSig, TOKEN, error));
    BOOST_CHECK(g_depinChallenges.Peek(adminNonce, error));
}

BOOST_AUTO_TEST_SUITE_END()
