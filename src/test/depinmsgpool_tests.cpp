// Copyright (c) 2024 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "depinmsgpool.h"
#include "depinecies.h"
#include "test/test_neurai.h"
#include "key.h"
#include "pubkey.h"
#include "base58.h"
#include "streams.h"
#include "random.h"

#include <boost/test/unit_test.hpp>
#include <string>
#include <vector>

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

BOOST_AUTO_TEST_SUITE_END()
