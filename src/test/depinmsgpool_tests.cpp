// Copyright (c) 2024 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "depinmsgpool.h"
#include "depinecies.h"
#include "test/test_neurai.h"
#include "chainparams.h"
#include "key.h"
#include "pubkey.h"
#include "base58.h"
#include "streams.h"
#include "random.h"

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
static bool AddressToHash160(const std::string& address, uint160& hashOut)
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
        uint160 hash;
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
    uint160 outsiderHash;
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
    uint160 queryHash;
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

    uint160 unusedHash;
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
    uint160 mineHash;
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

    std::vector<CDepinMessage> all = {msgToMe, msgToOther, msgFromMe, msgCorrupted};
    std::vector<CDepinMessage> filtered = FilterDepinMessagesForAddress(all, mineAddress, &mineHash);

    BOOST_REQUIRE_EQUAL(filtered.size(), 2u);
    // Input order is preserved: the message addressed to me comes before the one I sent.
    BOOST_CHECK(filtered[0].GetHash() == msgToMe.GetHash());
    BOOST_CHECK(filtered[1].GetHash() == msgFromMe.GetHash());

    // A stranger with no hash160 available gets nothing at all here.
    std::vector<CDepinMessage> none = FilterDepinMessagesForAddress(all, "not-a-valid-address", nullptr);
    BOOST_CHECK(none.empty());

    // Empty input stays empty.
    BOOST_CHECK(FilterDepinMessagesForAddress({}, mineAddress, &mineHash).empty());
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

// A DEPIN token ("&...") is accepted where DEPIN assets are enabled.
BOOST_AUTO_TEST_CASE(token_depin_accepted_on_testnet)
{
    NetworkGuard g(CBaseChainParams::TESTNET);
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

// The same DEPIN-named token is rejected on mainnet -- but by the pre-existing
// network gate inside IsAssetNameValid(), not by our type check. Assert on the
// *network* wording so a future regression that swaps in the generic
// "not a DEPIN token" message gets caught.
BOOST_AUTO_TEST_CASE(token_depin_rejected_on_mainnet_by_network_gate)
{
    NetworkGuard g(CBaseChainParams::MAIN);
    std::string error;
    BOOST_CHECK(!IsValidDepinMessagingToken("&VALIDTOKEN", error));
    BOOST_CHECK(error.find("testnet and regtest") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
