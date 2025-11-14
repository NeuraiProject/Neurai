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

// Primary chat message structure with ECIES hybrid encryption
// Uses a single CECIESEncryptedMessage shared by all recipients
// The ECIES structure contains:
//   - encryptedPayload: message encrypted ONCE with AES-256-CBC
//   - recipientKeys: map of (address_hash160 -> encrypted_AES_key)
// Each recipient can decrypt the AES key with their private key,
// then decrypt the shared payload.
class CDepinMessage {
public:
    std::string token;                      // Required token
    std::string senderAddress;              // Sender address
    int64_t timestamp;                      // UNIX time
    std::vector<unsigned char> signature;   // Sender signature

    // ECIES encrypted message (serialized CECIESEncryptedMessage)
    // Shared by all recipients - each can decrypt with their private key
    std::vector<unsigned char> encryptedPayload;

    CDepinMessage() {
        SetNull();
    }

    void SetNull() {
        token = "";
        senderAddress = "";
        timestamp = 0;
        signature.clear();
        encryptedPayload.clear();
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
        READWRITE(encryptedPayload);
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
    bool AddMessage(const CDepinMessage& message, std::string& error, bool skipSignatureCheck = false);
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

// Encrypt message for ALL recipients at once (ECIES hybrid encryption)
// Creates a single CECIESEncryptedMessage with:
//   - Message encrypted once with AES
//   - AES key encrypted for each recipient
bool EncryptMessageForAllRecipients(const std::string& message,
                                     const std::vector<std::string>& recipientAddresses,
                                     std::vector<unsigned char>& encryptedData,
                                     std::string& error);

// Decrypt message for a specific address
// Extracts the recipient's encrypted AES key from CECIESEncryptedMessage,
// decrypts it with private key, then decrypts the shared payload
bool DecryptMessageForAddress(const std::vector<unsigned char>& encryptedData,
                               const std::string& address,
                               std::string& decryptedMessage,
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
                        std::string& error,
                        bool forSend = false);
#endif

#endif // NEURAI_DEPINMSGPOOL_H
