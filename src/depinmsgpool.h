// Copyright (c) 2024 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_DEPINMSGPOOL_H
#define NEURAI_DEPINMSGPOOL_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include "sync.h"
#include "uint256.h"
#include "serialize.h"
#include "amount.h"

#ifdef ENABLE_WALLET
class CWallet;
#endif

// Configuration
static const unsigned int DEFAULT_DEPIN_MSG_PORT = 19002;
static const unsigned int DEFAULT_MAX_DEPIN_RECIPIENTS = 20;
static const unsigned int MAX_DEPIN_RECIPIENTS = 50;
static const unsigned int MAX_DEPIN_MESSAGE_SIZE = 1024; // 1KB
static const int64_t DEPIN_MESSAGE_EXPIRY_TIME = 7 * 24 * 60 * 60; // 7 days in seconds

// DePIN pool persistence
static const bool DEFAULT_DEPINPOOL_PERSIST = false;
static const uint32_t DEPINPOOL_MAGIC_BYTES = 0xD0D1D2D3;
static const uint32_t DEPINPOOL_FILE_VERSION = 1;

// Per-recipient encrypted message structure
class CDepinEncryptedMessage {
public:
    std::string recipientAddress;           // Destination address
    std::vector<unsigned char> encryptedData; // ECIES-encrypted payload

    CDepinEncryptedMessage() {
        SetNull();
    }

    CDepinEncryptedMessage(const std::string& address, const std::vector<unsigned char>& data)
        : recipientAddress(address), encryptedData(data) {}

    void SetNull() {
        recipientAddress = "";
        encryptedData.clear();
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(recipientAddress);
        READWRITE(encryptedData);
    }
};

// Primary chat message structure
class CDepinMessage {
public:
    std::string token;                      // Required token
    std::string senderAddress;              // Sender address
    int64_t timestamp;                      // UNIX time
    std::vector<unsigned char> signature;   // Sender signature

    // Per-recipient encrypted payloads
    std::vector<CDepinEncryptedMessage> encryptedMessages;

    CDepinMessage() {
        SetNull();
    }

    void SetNull() {
        token = "";
        senderAddress = "";
        timestamp = 0;
        signature.clear();
        encryptedMessages.clear();
    }

    uint256 GetHash() const;
    bool IsExpired(int64_t currentTime) const;
    std::string ToString() const;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(token);
        READWRITE(senderAddress);
        READWRITE(timestamp);
        READWRITE(signature);
        READWRITE(encryptedMessages);
    }
};

// Chat message mempool
class CDepinMsgPool {
private:
    mutable CCriticalSection cs_depinmsgpool;

    std::string activeToken;                    // Token active in this pool
    std::map<uint256, CDepinMessage> mapMessages; // Hash -> Message
    std::multimap<int64_t, uint256> mapByTime;  // Timestamp -> Hash (for expiry)

    bool fEnabled;
    unsigned int nPort;
    unsigned int nMaxRecipients;

public:
    CDepinMsgPool();

    // Configuration
    bool Initialize(const std::string& token, unsigned int port, unsigned int maxRecipients);
    bool IsEnabled() const { return fEnabled; }
    std::string GetActiveToken() const { return activeToken; }
    unsigned int GetPort() const { return nPort; }
    unsigned int GetMaxRecipients() const { return nMaxRecipients; }

    // Message handling
    bool AddMessage(const CDepinMessage& message, std::string& error);
    bool GetDepinMessage(const uint256& hash, CDepinMessage& message) const;
    std::vector<CDepinMessage> GetMessagesForAddress(const std::string& address) const;
    std::vector<CDepinMessage> GetAllMessages() const;
    size_t GetMessageCount() const;

    // Cleanup
    void RemoveExpiredMessages(int64_t currentTime);
    void Clear();

    // Stats
    size_t Size() const;
    size_t DynamicMemoryUsage() const;
    int64_t GetOldestMessageTime() const;
    int64_t GetNewestMessageTime() const;

    // Persistence
    bool SaveToDisk();
    bool LoadFromDisk();
};

// Global chat mempool instance
extern std::unique_ptr<CDepinMsgPool> pDepinMsgPool;

// Helper functions
bool VerifyDepinMessageSignature(const CDepinMessage& message);
bool SignDepinMessage(CDepinMessage& message, const std::string& senderAddress);
bool CheckTokenOwnership(const std::string& address, const std::string& token, std::string& error);
std::vector<std::string> GetTokenHolders(const std::string& token, unsigned int maxHolders, std::string& error);
bool EncryptMessageForRecipient(const std::string& message, const std::string& recipientAddress,
                                 std::vector<unsigned char>& encryptedData, std::string& error);
bool DecryptMessageForAddress(const std::vector<unsigned char>& encryptedData,
                               const std::string& address, std::string& decryptedMessage,
                               std::string& error);

// Remote chat mempool helpers
#ifdef ENABLE_WALLET
bool QueryRemoteDepinMsgPool(CWallet* pwallet,
                            const std::string& ipAddress, int port,
                            const std::string& token,
                            const std::vector<std::string>& myAddresses,
                            std::vector<CDepinMessage>& messages,
                            std::string& error);

bool SignDepinChallenge(CWallet* pwallet,
                        const std::string& address,
                        const std::string& token,
                        const std::string& challenge,
                        std::string& signature,
                        std::string& error);
#endif

#endif // NEURAI_DEPINMSGPOOL_H
