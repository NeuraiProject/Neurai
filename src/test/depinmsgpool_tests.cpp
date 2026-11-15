// Copyright (c) 2024 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "depinmsgpool.h"
#include "depinecies.h"
#include "test/test_neurai.h"
#include "test/depin_test_utils.h"
#include "assets/assetdb.h"
#include "assets/assets.h"
#include "assets/restricteddb.h"
#include "chainparams.h"
#include "hash.h"
#include "key.h"
#include "pubkey.h"
#include "pubkeyindex.h"
#include "base58.h"
#include "script/standard.h"
#include "streams.h"
#include "random.h"
#include "txdb.h"
#include "utiltime.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>
#include <string>
#include <vector>

namespace {

// RAII guard: SelectParams mutates the global CChainParams; restore it so the
// switch does not leak into later test cases. Mirrors the same helper already
// duplicated per test file in asset_activation_gating_tests.cpp /
// xna_asset_gating_tests.cpp (no shared header for it yet).
struct NetworkGuard {
    std::string previous;
    explicit NetworkGuard(const std::string& net) : previous(GetParams().NetworkIDString()) {
        SelectParams(net);
    }
    ~NetworkGuard() {
        if (previous == "main") SelectParams(CBaseChainParams::MAIN);
        else if (previous == "test") SelectParams(CBaseChainParams::TESTNET);
        else SelectParams(CBaseChainParams::REGTEST);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(depinmsgpool_tests, BasicTestingSetup)

// Mirrors the address -> hash160 decode that GetMessagesForAddress performs
// once per call, so tests can build the same addressHash160 pointer callers pass in.
static bool AddressToHash160(const std::string& address, DepinRecipient& hashOut)
{
    CTxDestination dest = DecodeDestination(address);
    const CKeyID* keyID = boost::get<CKeyID>(&dest);
    if (!keyID) {
        return false;
    }
    hashOut = uint160(*keyID);
    return true;
}

static std::string NewAddress(CKey& keyOut)
{
    keyOut.MakeNewKey(true);
    return EncodeDestination(keyOut.GetPubKey().GetID());
}

static CDepinMessage BuildMessage(uint8_t messageType, const std::string& senderAddress,
                                   const CECIESEncryptedMessage& eciesMsg)
{
    CDepinMessage msg;
    msg.SetNull();
    msg.token = "TESTTOKEN";
    msg.senderAddress = senderAddress;
    msg.timestamp = 1700000000;
    msg.messageType = messageType;

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << eciesMsg;
    msg.encryptedPayload.assign(ss.begin(), ss.end());
    return msg;
}

// (a) Group message, address in recipientKeys -> delivered
BOOST_AUTO_TEST_CASE(group_message_recipient_is_delivered)
{
    CKey senderKey;
    std::string senderAddress = NewAddress(senderKey);

    std::map<std::string, CPubKey> recipients;
    std::vector<std::string> recipientAddresses;
    for (int i = 0; i < 3; i++) {
        CKey key;
        std::string address = NewAddress(key);
        recipients[address] = key.GetPubKey();
        recipientAddresses.push_back(address);
    }

    CECIESEncryptedMessage eciesMsg;
    std::string error;
    BOOST_REQUIRE(ECIESEncryptMessage("hello group", recipients, eciesMsg, error));

    CDepinMessage msg = BuildMessage(0x02, senderAddress, eciesMsg);

    for (const std::string& address : recipientAddresses) {
        DepinRecipient hash;
        BOOST_REQUIRE(AddressToHash160(address, hash));
        BOOST_CHECK(ShouldDeliverDepinMessageToAddress(msg, address, &hash));
    }
}

// (b) Group message, address NOT in recipientKeys -> excluded.
// Core regression guard: before the fix, group messages were delivered to
// every requester unconditionally, regardless of recipientKeys membership.
BOOST_AUTO_TEST_CASE(group_message_non_recipient_is_not_delivered)
{
    CKey senderKey;
    std::string senderAddress = NewAddress(senderKey);

    std::map<std::string, CPubKey> recipients;
    for (int i = 0; i < 3; i++) {
        CKey key;
        std::string address = NewAddress(key);
        recipients[address] = key.GetPubKey();
    }

    CECIESEncryptedMessage eciesMsg;
    std::string error;
    BOOST_REQUIRE(ECIESEncryptMessage("hello group", recipients, eciesMsg, error));

    CDepinMessage msg = BuildMessage(0x02, senderAddress, eciesMsg);

    // A holder who joined later / was never part of the recipient snapshot.
    CKey outsiderKey;
    std::string outsiderAddress = NewAddress(outsiderKey);
    DepinRecipient outsiderHash;
    BOOST_REQUIRE(AddressToHash160(outsiderAddress, outsiderHash));

    BOOST_CHECK(!ShouldDeliverDepinMessageToAddress(msg, outsiderAddress, &outsiderHash));
}

// (c) Sender always sees their own message, independent of messageType,
// recipientKeys contents, or payload validity.
BOOST_AUTO_TEST_CASE(sender_always_sees_own_message)
{
    CKey senderKey;
    std::string senderAddress = NewAddress(senderKey);

    // Empty recipientKeys (sender not included) and an otherwise valid ECIES structure.
    CECIESEncryptedMessage eciesMsg;
    eciesMsg.SetNull();

    for (uint8_t messageType : {(uint8_t)0x01, (uint8_t)0x02}) {
        CDepinMessage msg = BuildMessage(messageType, senderAddress, eciesMsg);
        BOOST_CHECK(ShouldDeliverDepinMessageToAddress(msg, senderAddress, nullptr));
    }

    // Even with a corrupted payload, the sender shortcut is checked first
    // and short-circuits before any deserialization is attempted.
    CDepinMessage corrupted = BuildMessage(0x02, senderAddress, eciesMsg);
    corrupted.encryptedPayload = {0xDE, 0xAD, 0xBE, 0xEF};
    BOOST_CHECK(ShouldDeliverDepinMessageToAddress(corrupted, senderAddress, nullptr));
}

// (d) Malformed input must fail closed without throwing.
BOOST_AUTO_TEST_CASE(malformed_input_is_rejected_without_throwing)
{
    CKey senderKey;
    std::string senderAddress = NewAddress(senderKey);

    CKey queryKey;
    std::string queryAddress = NewAddress(queryKey);
    DepinRecipient queryHash;
    BOOST_REQUIRE(AddressToHash160(queryAddress, queryHash));

    // Payload is not a valid serialized CECIESEncryptedMessage.
    CDepinMessage msg;
    msg.SetNull();
    msg.token = "TESTTOKEN";
    msg.senderAddress = senderAddress;
    msg.timestamp = 1700000000;
    msg.messageType = 0x02;
    msg.encryptedPayload = {0x01, 0x02, 0x03};

    BOOST_CHECK_NO_THROW(BOOST_CHECK(!ShouldDeliverDepinMessageToAddress(msg, queryAddress, &queryHash)));

    // Syntactically invalid address string never resolves to a hash160;
    // callers pass nullptr for addressHash160 in that case (mirrors GetMessagesForAddress).
    std::map<std::string, CPubKey> recipients;
    recipients[queryAddress] = queryKey.GetPubKey();
    CECIESEncryptedMessage eciesMsg;
    std::string error;
    BOOST_REQUIRE(ECIESEncryptMessage("hello", recipients, eciesMsg, error));
    CDepinMessage validMsg = BuildMessage(0x02, senderAddress, eciesMsg);

    DepinRecipient unusedHash;
    BOOST_CHECK(!AddressToHash160("not-a-valid-address", unusedHash));
    BOOST_CHECK(!ShouldDeliverDepinMessageToAddress(validMsg, "not-a-valid-address", nullptr));
}

// FilterDepinMessagesForAddress: the collection-level behaviour that
// GetMessagesForAddress delegates to. Covers ordering and a mix of
// deliverable/undeliverable messages, which the single-message tests above
// cannot catch.
BOOST_AUTO_TEST_CASE(filter_keeps_only_deliverable_messages_in_order)
{
    // Two wallets: `mine` is the querying address, `other` is a stranger.
    CKey mineKey;
    std::string mineAddress = NewAddress(mineKey);
    DepinRecipient mineHash;
    BOOST_REQUIRE(AddressToHash160(mineAddress, mineHash));

    CKey otherKey;
    std::string otherAddress = NewAddress(otherKey);

    CKey senderKey;
    std::string senderAddress = NewAddress(senderKey);

    std::string error;

    // (1) Addressed to me -> delivered
    std::map<std::string, CPubKey> toMe;
    toMe[mineAddress] = mineKey.GetPubKey();
    CECIESEncryptedMessage eciesToMe;
    BOOST_REQUIRE(ECIESEncryptMessage("for me", toMe, eciesToMe, error));
    CDepinMessage msgToMe = BuildMessage(0x02, senderAddress, eciesToMe);

    // (2) Addressed to somebody else -> filtered out
    std::map<std::string, CPubKey> toOther;
    toOther[otherAddress] = otherKey.GetPubKey();
    CECIESEncryptedMessage eciesToOther;
    BOOST_REQUIRE(ECIESEncryptMessage("not for me", toOther, eciesToOther, error));
    CDepinMessage msgToOther = BuildMessage(0x02, senderAddress, eciesToOther);

    // (3) Sent by me, addressed to somebody else -> delivered (sender shortcut)
    CDepinMessage msgFromMe = BuildMessage(0x02, mineAddress, eciesToOther);

    // (4) Corrupted payload from a third party -> filtered out, no throw
    CDepinMessage msgCorrupted = BuildMessage(0x02, senderAddress, eciesToOther);
    msgCorrupted.encryptedPayload = {0xDE, 0xAD};

    // Pointers, mirroring how GetMessagesForAddress feeds the pool contents in
    // without copying them.
    std::vector<const CDepinMessage*> all = {&msgToMe, &msgToOther, &msgFromMe, &msgCorrupted};
    std::vector<CDepinMessage> filtered = FilterDepinMessagesForAddress(all, mineAddress, &mineHash);

    BOOST_REQUIRE_EQUAL(filtered.size(), 2u);
    // Input order is preserved: the message addressed to me comes before the one I sent.
    BOOST_CHECK(filtered[0].GetHash() == msgToMe.GetHash());
    BOOST_CHECK(filtered[1].GetHash() == msgFromMe.GetHash());

    // A stranger with no hash160 available gets nothing at all here.
    std::vector<CDepinMessage> none = FilterDepinMessagesForAddress(all, "not-a-valid-address", nullptr);
    BOOST_CHECK(none.empty());

    // Empty input stays empty, and null entries are skipped rather than crashing.
    BOOST_CHECK(FilterDepinMessagesForAddress({}, mineAddress, &mineHash).empty());
    std::vector<const CDepinMessage*> withNull = {nullptr, &msgToMe};
    BOOST_CHECK_EQUAL(FilterDepinMessagesForAddress(withNull, mineAddress, &mineHash).size(), 1u);
}

// IsValidDepinMessagingToken: token-type gating for -depinmsgtoken.
// These call the free function directly (no fAssetIndex/fPubKeyIndex/
// passetsdb setup needed), same isolation approach as the
// ShouldDeliverDepinMessageToAddress tests above.

// A syntactically valid ROOT token is rejected: DePIN messaging requires
// a DEPIN (soulbound) token, not just any valid asset name.
BOOST_AUTO_TEST_CASE(token_root_rejected_not_depin)
{
    NetworkGuard g(CBaseChainParams::MAIN);
    std::string error;
    BOOST_CHECK(!IsValidDepinMessagingToken("MYTOKEN", error));
    BOOST_CHECK(error.find("DEPIN") != std::string::npos);
}

// A syntactically valid QUALIFIER token is rejected for the same reason.
BOOST_AUTO_TEST_CASE(token_qualifier_rejected_not_depin)
{
    NetworkGuard g(CBaseChainParams::MAIN);
    std::string error;
    BOOST_CHECK(!IsValidDepinMessagingToken("#TEAM", error));
    BOOST_CHECK(error.find("DEPIN") != std::string::npos);
}

// A DEPIN token ("&...") is accepted where DEPIN assets are scheduled, also
// before the tip reaches the fork height (here testnet with no chain).
BOOST_AUTO_TEST_CASE(token_depin_accepted_on_testnet)
{
    NetworkGuard g(CBaseChainParams::TESTNET);
    BOOST_REQUIRE(!AreDepinAssetsActiveInContext());
    std::string error;
    BOOST_CHECK(IsValidDepinMessagingToken("&VALIDTOKEN", error));
    BOOST_CHECK(error.empty());
}

// Sub-DEPIN tokens ("&TOKEN/SUB") share AssetType::DEPIN with plain DEPIN
// tokens (there is no separate SUB_DEPIN enum value) and must be accepted too.
BOOST_AUTO_TEST_CASE(token_sub_depin_accepted_on_regtest)
{
    NetworkGuard g(CBaseChainParams::REGTEST);
    std::string error;
    BOOST_CHECK(IsValidDepinMessagingToken("&VALIDTOKEN/DEVICE", error));
    BOOST_CHECK(error.empty());
}

// The same DEPIN-named token is rejected on mainnet while the fork has no
// height -- but by the activation gate inside IsAssetNameValid(), not by our
// type check. Assert on the *activation* wording so a future regression that
// swaps in the generic "not a DEPIN token" message gets caught.
BOOST_AUTO_TEST_CASE(token_depin_rejected_on_mainnet_by_activation_gate)
{
    NetworkGuard g(CBaseChainParams::MAIN);
    std::string error;
    BOOST_CHECK(!IsValidDepinMessagingToken("&VALIDTOKEN", error));
    BOOST_CHECK(error.find("not active yet") != std::string::npos);
}

// ---------------------------------------------------------------------------
// Signature format: the signed hash IS the message identifier (GetHash), so
// the signature covers messageType. The pre-v2.1.3 preimage -- the same
// fields without messageType -- is no longer accepted anywhere.
// ---------------------------------------------------------------------------

// VerifyDepinMessageSignature reads the pubkey index, and the AddMessage path
// additionally reads the asset and restriction databases. Mirrors
// DepinSectionsSetup in depin_sections_tests.cpp (helpers are duplicated per
// test file, same as NetworkGuard above).
struct DepinSignatureSetup : public TestingSetup {
    ScopedDepinTestTipTime currentTip;
    bool prevAssetIndex;
    bool prevPubKeyIndex;
    CAssetsDB* prevAssetsDb;
    CLRUCache<std::string, CDatabasedAssetData>* prevAssetsCache;
    CRestrictedDB* prevRestrictedDb;

    DepinSignatureSetup() : TestingSetup(CBaseChainParams::REGTEST)
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
    }

    ~DepinSignatureSetup()
    {
        delete prestricteddb;
        delete passetsCache;
        delete passetsdb;

        prestricteddb = prevRestrictedDb;
        passetsCache = prevAssetsCache;
        passetsdb = prevAssetsDb;

        fPubKeyIndex = prevPubKeyIndex;
        fAssetIndex = prevAssetIndex;
    }

    // A sender whose pubkey is revealed in the index -- what
    // VerifyDepinMessageSignature reads to verify.
    CKey NewRevealedSender(std::string& addressOut)
    {
        CKey key;
        key.MakeNewKey(true);
        const CPubKey pubkey = key.GetPubKey();
        addressOut = EncodeDestination(pubkey.GetID());

        CTxDestination dest = DecodeDestination(addressOut);
        CDestinationIndexData addressData;
        BOOST_REQUIRE(GetDestinationIndexData(dest, addressData));
        std::vector<std::pair<CPubKeyIndexKey, CPubKeyIndexValue> > entries;
        entries.emplace_back(CPubKeyIndexKey(addressData), CPubKeyIndexValue(pubkey, 1, uint256()));
        BOOST_REQUIRE(pblocktree->WritePubKeyIndex(entries));
        return key;
    }

    CDepinMessage BuildSignableMessage(const std::string& token, const std::string& sender)
    {
        CDepinMessage msg;
        msg.token = token;
        msg.senderAddress = sender;
        msg.timestamp = GetTime();
        msg.messageType = 0x02;
        CECIESEncryptedMessage ecies;
        std::string error;
        CPubKey pubkey;
        BOOST_REQUIRE_MESSAGE(CheckAddressHasPublicKey(sender, pubkey, error), error);
        BOOST_REQUIRE_MESSAGE(ECIESEncryptMessage("signature test",
            {{EncodeDestination(pubkey.GetID()), pubkey}}, ecies, error), error);
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << ecies;
        msg.encryptedPayload.assign(ss.begin(), ss.end());
        return msg;
    }

    // The pre-v2.1.3 preimage: same fields, without messageType.
    uint256 LegacyPreimageHash(const CDepinMessage& msg)
    {
        CHashWriter ss(SER_GETHASH, 0);
        ss << msg.token;
        ss << msg.senderAddress;
        ss << msg.timestamp;
        ss << msg.encryptedPayload;
        return ss.GetHash();
    }
};

// RAII: swap in an Initialize()d global pool, restore the previous one
// (duplicated per test file, same as in depin_sections_tests.cpp).
struct ScopedInitializedPool {
    std::unique_ptr<CDepinMsgPool> previous;

    explicit ScopedInitializedPool(const std::string& token)
        : previous(std::move(pDepinMsgPool))
    {
        pDepinMsgPool.reset(new CDepinMsgPool());
        BOOST_REQUIRE(pDepinMsgPool->Initialize(token,
                                                DEFAULT_MAX_DEPIN_RECIPIENTS,
                                                DEFAULT_DEPIN_MESSAGE_SIZE,
                                                DEFAULT_DEPIN_MESSAGE_EXPIRY_HOURS,
                                                DEFAULT_DEPIN_POOL_SIZE_MB));
    }

    ~ScopedInitializedPool()
    {
        pDepinMsgPool = std::move(previous);
    }
};

// A signature over GetHash verifies, and flipping messageType afterwards
// invalidates it. Under the old fallback that mutation kept verifying (the
// legacy preimage ignored the type), which also let the mutated copy re-enter
// the pool as a "new" message: GetHash does include messageType.
BOOST_FIXTURE_TEST_CASE(signature_covers_messagetype, DepinSignatureSetup)
{
    std::string sender;
    CKey key = NewRevealedSender(sender);

    CDepinMessage msg = BuildSignableMessage("&TEST", sender);
    BOOST_REQUIRE(key.Sign(msg.GetHash(), msg.signature));
    BOOST_CHECK(VerifyDepinMessageSignature(msg));

    msg.messageType = 0x01;
    BOOST_CHECK(!VerifyDepinMessageSignature(msg));
}

// A signature produced over the legacy preimage is rejected outright.
BOOST_FIXTURE_TEST_CASE(legacy_preimage_is_rejected, DepinSignatureSetup)
{
    std::string sender;
    CKey key = NewRevealedSender(sender);

    CDepinMessage msg = BuildSignableMessage("&TEST", sender);
    BOOST_REQUIRE(key.Sign(LegacyPreimageHash(msg), msg.signature));

    BOOST_CHECK(!VerifyDepinMessageSignature(msg));
}

// The pool write path (what depinsendmsg and depinsubmitmsg funnel into)
// accepts the current format and rejects the legacy one.
BOOST_FIXTURE_TEST_CASE(addmessage_enforces_current_signature_format, DepinSignatureSetup)
{
    ScopedInitializedPool pool("&TEST");

    std::string sender;
    CKey key = NewRevealedSender(sender);
    BOOST_REQUIRE(passetsdb->WriteAssetAddressQuantity("&TEST", sender, 10));

    std::string error;

    CDepinMessage good = BuildSignableMessage("&TEST", sender);
    BOOST_REQUIRE(key.Sign(good.GetHash(), good.signature));
    BOOST_CHECK_MESSAGE(pDepinMsgPool->AddMessage(good, error, /*skipSignatureCheck=*/false), error);

    CDepinMessage legacy = BuildSignableMessage("&TEST", sender);
    legacy.timestamp += 1;  // distinct hash, so rejection cannot come from dedup
    BOOST_REQUIRE(key.Sign(LegacyPreimageHash(legacy), legacy.signature));
    error.clear();
    BOOST_CHECK(!pDepinMsgPool->AddMessage(legacy, error, /*skipSignatureCheck=*/false));
    BOOST_CHECK_MESSAGE(error.find("signature") != std::string::npos, error);
}

// What ties an encrypted payload to its sender is the signature of the message
// that carries it, and nothing inside the encryption. A member that received a
// group message can therefore publish the same payload again under its own
// name: the pool admits it as a new message and the recipients read the same
// text from the new sender. The pool hands a payload only to its sender and to
// the addresses it is encrypted for, so whoever can do this could also have
// read the text and encrypted it again. This test records that behaviour: it
// has to change with the message format if the sender and the token are ever
// authenticated inside the encryption.
BOOST_FIXTURE_TEST_CASE(payload_is_tied_to_its_sender_by_the_message_signature_only, DepinSignatureSetup)
{
    ScopedInitializedPool pool("&TEST");

    std::string alice, mallory, bob;
    CKey aliceKey = NewRevealedSender(alice);
    CKey malloryKey = NewRevealedSender(mallory);
    CKey bobKey = NewRevealedSender(bob);
    for (const std::string& holder : {alice, mallory, bob})
        BOOST_REQUIRE(passetsdb->WriteAssetAddressQuantity("&TEST", holder, 10));

    const auto message = [&](const std::string& sender, const CKey& key, const std::string& text,
                             const std::map<std::string, CPubKey>& recipients, int64_t timestamp) {
        CECIESEncryptedMessage ecies;
        std::string error;
        BOOST_REQUIRE_MESSAGE(ECIESEncryptMessage(text, recipients, ecies, error), error);
        CDepinMessage msg;
        msg.token = "&TEST";
        msg.senderAddress = sender;
        msg.timestamp = timestamp;
        msg.messageType = 0x02;
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << ecies;
        msg.encryptedPayload.assign(ss.begin(), ss.end());
        BOOST_REQUIRE(key.Sign(msg.GetHash(), msg.signature));
        return msg;
    };
    const auto recipientOf = [](const std::string& address) {
        DepinRecipient recipient;
        BOOST_REQUIRE(DepinRecipient::FromAddress(address, recipient));
        return recipient;
    };

    // Alice writes to the three of them
    const int64_t now = GetTime();
    const CDepinMessage original = message(alice, aliceKey, "written by alice",
        {{alice, aliceKey.GetPubKey()}, {mallory, malloryKey.GetPubKey()}, {bob, bobKey.GetPubKey()}}, now);
    std::string error;
    BOOST_REQUIRE_MESSAGE(pDepinMsgPool->AddMessage(original, error, /*skipSignatureCheck=*/false), error);

    // Mallory publishes the same payload as hers: a new message for the pool
    CDepinMessage copy = original;
    copy.senderAddress = mallory;
    copy.timestamp = now + 1;
    copy.signature.clear();
    BOOST_REQUIRE(malloryKey.Sign(copy.GetHash(), copy.signature));
    BOOST_CHECK(copy.GetHash() != original.GetHash());
    BOOST_CHECK_MESSAGE(pDepinMsgPool->AddMessage(copy, error, /*skipSignatureCheck=*/false), error);

    // ...and Bob reads Alice's text in it
    CECIESEncryptedMessage received;
    CDataStream in(copy.encryptedPayload, SER_NETWORK, PROTOCOL_VERSION);
    in >> received;
    std::string plaintext;
    BOOST_REQUIRE_MESSAGE(ECIESDecryptMessage(received, bobKey, bob, plaintext, error), error);
    BOOST_CHECK_EQUAL(plaintext, "written by alice");

    // Alice's signature does not carry over: the copy is not hers
    copy.senderAddress = alice;
    BOOST_CHECK(!VerifyDepinMessageSignature(copy));

    // A payload that is not encrypted for Mallory is not handed to her
    const CDepinMessage forBob = message(alice, aliceKey, "for bob only",
        {{alice, aliceKey.GetPubKey()}, {bob, bobKey.GetPubKey()}}, now + 2);
    const DepinRecipient malloryId = recipientOf(mallory), bobId = recipientOf(bob);
    BOOST_CHECK(!ShouldDeliverDepinMessageToAddress(forBob, mallory, &malloryId));
    BOOST_CHECK(ShouldDeliverDepinMessageToAddress(forBob, bob, &bobId));
}

namespace {
// A pool of `poolMB` that takes the largest messages, so that few of them fill it
struct ScopedSizedPool {
    std::unique_ptr<CDepinMsgPool> previous;

    explicit ScopedSizedPool(unsigned int poolMB) : previous(std::move(pDepinMsgPool))
    {
        pDepinMsgPool.reset(new CDepinMsgPool());
        BOOST_REQUIRE(pDepinMsgPool->Initialize("&TEST", DEFAULT_MAX_DEPIN_RECIPIENTS, MAX_DEPIN_MESSAGE_SIZE,
                                                DEFAULT_DEPIN_MESSAGE_EXPIRY_HOURS, poolMB));
    }
    ~ScopedSizedPool() { pDepinMsgPool = std::move(previous); }
};

// A signed message of about 10 KB from `sender` to itself
CDepinMessage LargeMessage(const std::string& sender, const CKey& key)
{
    CECIESEncryptedMessage ecies;
    std::string error;
    BOOST_REQUIRE_MESSAGE(ECIESEncryptMessage(std::string(MAX_DEPIN_MESSAGE_SIZE - 64, 'x'), {{sender, key.GetPubKey()}}, ecies, error), error);
    CDepinMessage msg;
    msg.token = "&TEST";
    msg.senderAddress = sender;
    msg.timestamp = GetTime();
    msg.messageType = 0x02;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << ecies;
    msg.encryptedPayload.assign(ss.begin(), ss.end());
    BOOST_REQUIRE(key.Sign(msg.GetHash(), msg.signature));
    return msg;
}

const size_t MB = 1024 * 1024;
} // namespace

// One sender cannot use more than its space, and the others keep publishing.
// Without a space of its own a sender is stopped by the pool limit.
BOOST_FIXTURE_TEST_CASE(sender_space_limit_refuses_one_sender_only, DepinSignatureSetup)
{
    ScopedSizedPool pool(2);
    pDepinMsgPool->SetSpacePolicy(1, /*rolling=*/false);

    std::string alice, bob;
    CKey aliceKey = NewRevealedSender(alice);
    CKey bobKey = NewRevealedSender(bob);
    for (const std::string& holder : {alice, bob})
        BOOST_REQUIRE(passetsdb->WriteAssetAddressQuantity("&TEST", holder, 10));

    std::string error;
    size_t admitted = 0;
    while (pDepinMsgPool->AddMessage(LargeMessage(alice, aliceKey), error, false))
        BOOST_REQUIRE(++admitted < 1000);
    BOOST_CHECK_MESSAGE(error.find("Sender space limit exceeded") != std::string::npos, error);
    BOOST_CHECK(admitted > 50);
    BOOST_CHECK(pDepinMsgPool->GetSenderUsage(alice) <= 1 * MB);
    BOOST_CHECK(pDepinMsgPool->GetSenderUsage(alice) > 1 * MB - 12 * 1024);

    // Bob is not affected, and the pool is charged what its senders are
    BOOST_CHECK_MESSAGE(pDepinMsgPool->AddMessage(LargeMessage(bob, bobKey), error, false), error);
    BOOST_CHECK_EQUAL(pDepinMsgPool->DynamicMemoryUsage(), pDepinMsgPool->GetSenderUsage(alice) + pDepinMsgPool->GetSenderUsage(bob));
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetEvictedCount(), 0u);

    // With no space of her own, Alice goes on until the pool is full
    pDepinMsgPool->SetSpacePolicy(0, /*rolling=*/false);
    while (pDepinMsgPool->AddMessage(LargeMessage(alice, aliceKey), error, false))
        BOOST_REQUIRE(++admitted < 1000);
    BOOST_CHECK_MESSAGE(error.find("Pool size limit exceeded") != std::string::npos, error);
    BOOST_CHECK(pDepinMsgPool->DynamicMemoryUsage() <= 2 * MB);

    // Removing messages gives the space back
    pDepinMsgPool->Clear();
    BOOST_CHECK_EQUAL(pDepinMsgPool->DynamicMemoryUsage(), 0u);
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetSenderUsage(alice), 0u);
}

// A rolling pool never refuses for space: the oldest messages make room. A
// sender that fills its own space loses its own oldest messages, not those of
// the others; when the pool itself is full, the oldest go, whoever sent them.
BOOST_FIXTURE_TEST_CASE(rolling_pool_drops_the_oldest_messages, DepinSignatureSetup)
{
    ScopedSizedPool pool(2);
    pDepinMsgPool->SetSpacePolicy(1, /*rolling=*/true);

    std::string alice, bob, carol;
    CKey aliceKey = NewRevealedSender(alice);
    CKey bobKey = NewRevealedSender(bob);
    CKey carolKey = NewRevealedSender(carol);
    for (const std::string& holder : {alice, bob, carol})
        BOOST_REQUIRE(passetsdb->WriteAssetAddressQuantity("&TEST", holder, 10));

    std::string error;
    const CDepinMessage aliceFirst = LargeMessage(alice, aliceKey);
    const CDepinMessage bobFirst = LargeMessage(bob, bobKey);
    BOOST_REQUIRE_MESSAGE(pDepinMsgPool->AddMessage(aliceFirst, error, false), error);
    BOOST_REQUIRE_MESSAGE(pDepinMsgPool->AddMessage(bobFirst, error, false), error);

    // Alice publishes more than her space holds
    CDepinMessage aliceLast;
    for (int i = 0; i < 150; ++i) {
        aliceLast = LargeMessage(alice, aliceKey);
        BOOST_REQUIRE_MESSAGE(pDepinMsgPool->AddMessage(aliceLast, error, false), error);
    }
    CDepinMessage found;
    BOOST_CHECK(pDepinMsgPool->GetSenderUsage(alice) <= 1 * MB);
    BOOST_CHECK(!pDepinMsgPool->GetDepinMessage(aliceFirst.GetHash(), found));
    BOOST_CHECK(pDepinMsgPool->GetDepinMessage(aliceLast.GetHash(), found));
    BOOST_CHECK(pDepinMsgPool->GetDepinMessage(bobFirst.GetHash(), found));
    const uint64_t droppedForAlice = pDepinMsgPool->GetEvictedCount();
    BOOST_CHECK(droppedForAlice > 0);
    BOOST_CHECK_EQUAL(pDepinMsgPool->DynamicMemoryUsage(), pDepinMsgPool->GetSenderUsage(alice) + pDepinMsgPool->GetSenderUsage(bob));

    // Carol fills the rest of the pool and goes on: the oldest of the pool go
    pDepinMsgPool->SetSpacePolicy(0, /*rolling=*/true);
    CDepinMessage carolLast;
    for (int i = 0; i < 250; ++i) {
        carolLast = LargeMessage(carol, carolKey);
        BOOST_REQUIRE_MESSAGE(pDepinMsgPool->AddMessage(carolLast, error, false), error);
    }
    BOOST_CHECK(pDepinMsgPool->DynamicMemoryUsage() <= 2 * MB);
    BOOST_CHECK(pDepinMsgPool->DynamicMemoryUsage() > 2 * MB - 12 * 1024);
    BOOST_CHECK(!pDepinMsgPool->GetDepinMessage(bobFirst.GetHash(), found));
    BOOST_CHECK(!pDepinMsgPool->GetDepinMessage(aliceLast.GetHash(), found));
    BOOST_CHECK(pDepinMsgPool->GetDepinMessage(carolLast.GetHash(), found));
    BOOST_CHECK(pDepinMsgPool->GetEvictedCount() > droppedForAlice);
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetSenderUsage(alice), 0u);
    BOOST_CHECK_EQUAL(pDepinMsgPool->DynamicMemoryUsage(), pDepinMsgPool->GetSenderUsage(carol));
}

BOOST_AUTO_TEST_SUITE_END()
