// Copyright (c) 2024 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "depinmsgpool.h"
#include "depinmsgpoolnet.h"
#include "depinecies.h"
#include "validation.h"
#include "assets/assets.h"
#include "assets/assetdb.h"
#include "txdb.h"
#include "pubkeyindex.h"
#include "hash.h"
#include "utiltime.h"
#include "key.h"
#include "pubkey.h"
#include "base58.h"
#include "util.h"
#include "utilstrencodings.h"

#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

std::unique_ptr<CDepinMsgPool> pDepinMsgPool;

// CDepinMessage implementation

uint256 CDepinMessage::GetHash() const {
    CHashWriter ss(SER_GETHASH, 0);
    ss << token << senderAddress << timestamp;
    return ss.GetHash();
}

bool CDepinMessage::IsExpired(int64_t currentTime) const {
    return (currentTime - timestamp) > DEPIN_MESSAGE_EXPIRY_TIME;
}

std::string CDepinMessage::ToString() const {
    return strprintf("CDepinMessage(token=%s, sender=%s, timestamp=%d, recipients=%d)",
                     token, senderAddress, timestamp, encryptedMessages.size());
}

// CDepinMsgPool implementation

CDepinMsgPool::CDepinMsgPool()
    : fEnabled(false), nPort(DEFAULT_DEPIN_MSG_PORT),
      nMaxRecipients(DEFAULT_MAX_DEPIN_RECIPIENTS) {
}

bool CDepinMsgPool::Initialize(const std::string& token, unsigned int port, unsigned int maxRecipients) {
    LOCK(cs_depinmsgpool);

    // Verify that -assetindex is enabled (REQUIRED)
    if (!fAssetIndex) {
        LogPrintf("ERROR: DePIN messaging requires -assetindex to be enabled. "
                  "Please restart with -assetindex and -reindex\n");
        return false;
    }

    // Verify that -pubkeyindex is enabled (REQUIRED for encryption)
    if (!fPubKeyIndex) {
        LogPrintf("ERROR: DePIN messaging requires -pubkeyindex to be enabled. "
                  "Please restart with -pubkeyindex and -reindex-chainstate\n");
        return false;
    }

    // Verify that the token is valid
    AssetType type;
    std::string error;
    if (!IsAssetNameValid(token, type, error)) {
        LogPrintf("ERROR: Invalid chat mempool token '%s': %s\n", token, error);
        return false;
    }

    // Verify that the token exists
    if (!passetsdb) {
        LogPrintf("ERROR: Asset database not available\n");
        return false;
    }

    // Token existence is not validated to allow server configuration before token creation
    // or during reindex when asset index may not be fully populated
    activeToken = token;
    nPort = port;
    nMaxRecipients = std::min(maxRecipients, MAX_DEPIN_RECIPIENTS);
    fEnabled = true;

    LogPrintf("Chat mempool initialized: token=%s, port=%d, maxRecipients=%d\n",
              activeToken, nPort, nMaxRecipients);

    return true;
}

bool CDepinMsgPool::AddMessage(const CDepinMessage& message, std::string& error) {
    LOCK(cs_depinmsgpool);

    if (!fEnabled) {
        error = "Chat mempool is not enabled";
        return false;
    }

    // Verify that the token matches
    if (message.token != activeToken) {
        error = strprintf("Message token '%s' does not match active token '%s'",
                         message.token, activeToken);
        return false;
    }

    // Verify timestamp (do not accept messages from the future)
    int64_t currentTime = GetTime();
    if (message.timestamp > currentTime + 60) { // +60s tolerance
        error = "Message timestamp is too far in the future";
        return false;
    }

    // Verify that it is not expired
    if (message.IsExpired(currentTime)) {
        error = "Message is already expired";
        return false;
    }

    // Verify message size
    size_t totalSize = 0;
    for (const auto& enc : message.encryptedMessages) {
        totalSize += enc.encryptedData.size();
    }
    if (totalSize > MAX_DEPIN_MESSAGE_SIZE * message.encryptedMessages.size()) {
        error = "Message exceeds maximum size";
        return false;
    }

    // Verify number of recipients
    if (message.encryptedMessages.size() > nMaxRecipients) {
        error = strprintf("Too many recipients (%d), maximum is %d",
                         message.encryptedMessages.size(), nMaxRecipients);
        return false;
    }

    // Verify signature
    if (!VerifyDepinMessageSignature(message)) {
        error = "Invalid message signature";
        return false;
    }

    // Verify that the sender owns the token
    if (!CheckTokenOwnership(message.senderAddress, activeToken, error)) {
        return false;
    }

    // Add message
    uint256 hash = message.GetHash();

    // Verify if it already exists
    if (mapMessages.count(hash)) {
        error = "Message already exists in mempool";
        return false;
    }

    mapMessages[hash] = message;
    mapByTime.insert(std::make_pair(message.timestamp, hash));

    LogPrint(BCLog::MEMPOOL, "Chat message added: hash=%s, sender=%s, recipients=%d\n",
             hash.ToString(), message.senderAddress, message.encryptedMessages.size());

    return true;
}

bool CDepinMsgPool::GetDepinMessage(const uint256& hash, CDepinMessage& message) const {
    LOCK(cs_depinmsgpool);
    auto it = mapMessages.find(hash);
    if (it == mapMessages.end())
        return false;
    message = it->second;
    return true;
}

std::vector<CDepinMessage> CDepinMsgPool::GetMessagesForAddress(const std::string& address) const {
    LOCK(cs_depinmsgpool);
    std::vector<CDepinMessage> result;

    for (const auto& entry : mapMessages) {
        const CDepinMessage& msg = entry.second;

        // Search if this address is a recipient
        for (const auto& enc : msg.encryptedMessages) {
            if (enc.recipientAddress == address) {
                result.push_back(msg);
                break;
            }
        }
    }

    return result;
}

std::vector<CDepinMessage> CDepinMsgPool::GetAllMessages() const {
    LOCK(cs_depinmsgpool);
    std::vector<CDepinMessage> result;
    for (const auto& entry : mapMessages) {
        result.push_back(entry.second);
    }
    return result;
}

size_t CDepinMsgPool::GetMessageCount() const {
    LOCK(cs_depinmsgpool);
    return mapMessages.size();
}

void CDepinMsgPool::RemoveExpiredMessages(int64_t currentTime) {
    LOCK(cs_depinmsgpool);

    std::vector<uint256> toRemove;

    for (const auto& entry : mapMessages) {
        if (entry.second.IsExpired(currentTime)) {
            toRemove.push_back(entry.first);
        }
    }

    for (const auto& hash : toRemove) {
        auto it = mapMessages.find(hash);
        if (it != mapMessages.end()) {
            int64_t timestamp = it->second.timestamp;
            mapMessages.erase(it);

            // Remove from mapByTime
            auto range = mapByTime.equal_range(timestamp);
            for (auto timeIt = range.first; timeIt != range.second; ) {
                if (timeIt->second == hash) {
                    timeIt = mapByTime.erase(timeIt);
                } else {
                    ++timeIt;
                }
            }
        }
    }

    if (!toRemove.empty()) {
        LogPrint(BCLog::MEMPOOL, "Removed %d expired chat messages\n", toRemove.size());
    }
}

void CDepinMsgPool::Clear() {
    LOCK(cs_depinmsgpool);
    mapMessages.clear();
    mapByTime.clear();
    LogPrint(BCLog::MEMPOOL, "Chat mempool cleared\n");
}

size_t CDepinMsgPool::Size() const {
    LOCK(cs_depinmsgpool);
    return mapMessages.size();
}

size_t CDepinMsgPool::DynamicMemoryUsage() const {
    LOCK(cs_depinmsgpool);
    size_t total = 0;
    for (const auto& entry : mapMessages) {
        const CDepinMessage& msg = entry.second;
        total += sizeof(CDepinMessage);
        total += msg.token.size();
        total += msg.senderAddress.size();
        total += msg.signature.size();
        for (const auto& enc : msg.encryptedMessages) {
            total += sizeof(CDepinEncryptedMessage);
            total += enc.recipientAddress.size();
            total += enc.encryptedData.size();
        }
    }
    return total;
}

int64_t CDepinMsgPool::GetOldestMessageTime() const {
    LOCK(cs_depinmsgpool);
    if (mapByTime.empty())
        return 0;
    return mapByTime.begin()->first;
}

int64_t CDepinMsgPool::GetNewestMessageTime() const {
    LOCK(cs_depinmsgpool);
    if (mapByTime.empty())
        return 0;
    return mapByTime.rbegin()->first;
}

// Auxiliary functions

/**
 * Check if an address has revealed its public key in the blockchain
 * Requires -pubkeyindex to be enabled
 */
bool CheckAddressHasPublicKey(const std::string& address, CPubKey& pubkey, std::string& error) {
    if (!fPubKeyIndex) {
        error = "Public key index is required but not enabled. Use -pubkeyindex";
        return false;
    }

    if (!pblocktree) {
        error = "Block tree database not available";
        return false;
    }

    // Decode address to get hash160
    CTxDestination dest = DecodeDestination(address);
    const CKeyID* keyID = boost::get<CKeyID>(&dest);
    if (!keyID) {
        error = strprintf("Invalid address format: %s", address);
        return false;
    }

    uint160 addressHash(*keyID);

    // Query pubkey index
    CPubKeyIndexValue value;
    if (!pblocktree->ReadPubKeyIndex(addressHash, value)) {
        error = strprintf("Address %s has not revealed its public key", address);
        return false;
    }

    pubkey = value.pubkey;
    if (!pubkey.IsValid()) {
        error = strprintf("Invalid public key found for address %s", address);
        return false;
    }

    return true;
}

bool VerifyDepinMessageSignature(const CDepinMessage& message) {
    if (message.signature.empty()) {
        return false;
    }

    // Get sender's public key from pubkey index
    CPubKey senderPubKey;
    std::string error;
    if (!CheckAddressHasPublicKey(message.senderAddress, senderPubKey, error)) {
        LogPrintf("VerifyDepinMessageSignature: %s\n", error);
        return false;
    }

    // Construct message hash for verification
    // Hash format: SHA256(token || senderAddress || timestamp || encryptedMessages)
    CHashWriter ss(SER_GETHASH, 0);
    ss << message.token;
    ss << message.senderAddress;
    ss << message.timestamp;
    ss << message.encryptedMessages;
    uint256 messageHash = ss.GetHash();

    // Verify signature
    if (!senderPubKey.Verify(messageHash, message.signature)) {
        LogPrintf("VerifyDepinMessageSignature: Signature verification failed\n");
        return false;
    }

    return true;
}

bool SignDepinMessage(CDepinMessage& message, const std::string& senderAddress) {
#ifdef ENABLE_WALLET
    // Get wallet
    if (vpwallets.empty()) {
        LogPrintf("SignDepinMessage: Wallet not available\n");
        return false;
    }
    CWallet* const pwallet = vpwallets[0];

    // Decode address
    CTxDestination dest = DecodeDestination(senderAddress);
    const CKeyID* keyID = boost::get<CKeyID>(&dest);
    if (!keyID) {
        LogPrintf("SignDepinMessage: Invalid sender address format\n");
        return false;
    }

    // Get private key from wallet
    CKey privKey;
    if (!pwallet->GetKey(*keyID, privKey)) {
        LogPrintf("SignDepinMessage: Private key not found in wallet for address %s\n", senderAddress);
        return false;
    }

    if (!privKey.IsValid()) {
        LogPrintf("SignDepinMessage: Invalid private key\n");
        return false;
    }

    // Construct message hash
    // Must match the format used in VerifyDepinMessageSignature
    CHashWriter ss(SER_GETHASH, 0);
    ss << message.token;
    ss << message.senderAddress;
    ss << message.timestamp;
    ss << message.encryptedMessages;
    uint256 messageHash = ss.GetHash();

    // Sign
    if (!privKey.Sign(messageHash, message.signature)) {
        LogPrintf("SignDepinMessage: Failed to sign message\n");
        return false;
    }

    return true;
#else
    LogPrintf("SignDepinMessage: Wallet support not enabled\n");
    return false;
#endif
}

bool CheckTokenOwnership(const std::string& address, const std::string& token, std::string& error) {
    if (!passetsdb) {
        error = "Asset database not available";
        return false;
    }

    CAmount quantity = 0;
    if (!passetsdb->ReadAssetAddressQuantity(token, address, quantity)) {
        error = strprintf("Address '%s' does not own token '%s'", address, token);
        return false;
    }

    if (quantity <= 0) {
        error = strprintf("Address '%s' has zero balance of token '%s'", address, token);
        return false;
    }

    return true;
}

std::vector<std::string> GetTokenHolders(const std::string& token, unsigned int maxHolders, std::string& error) {
    // REQUIRES -assetindex (already verified in Initialize)
    if (!fAssetIndex) {
        error = "Asset index is required but not enabled";
        return std::vector<std::string>();
    }

    // REQUIRES -pubkeyindex for encryption
    if (!fPubKeyIndex) {
        error = "Public key index is required but not enabled. Use -pubkeyindex";
        return std::vector<std::string>();
    }

    if (!passetsdb) {
        error = "Asset database not available";
        return std::vector<std::string>();
    }

    std::vector<std::pair<std::string, CAmount>> vecHolders;
    int nTotalEntries = 0;

    // Get holders from index (request more to have margin after filtering)
    if (!passetsdb->AssetAddressDir(vecHolders, nTotalEntries, false, token, maxHolders * 2, 0)) {
        error = "Failed to query token holders from asset index";
        return std::vector<std::string>();
    }

    // Filter addresses:
    // 1. Balance > 0
    // 2. Public key revealed in blockchain
    std::vector<std::string> addresses;
    int skippedNoPubKey = 0;

    for (const auto& holder : vecHolders) {
        if (holder.second <= 0) {
            continue;
        }

        // Check if public key is revealed
        CPubKey pubkey;
        std::string checkError;
        if (!CheckAddressHasPublicKey(holder.first, pubkey, checkError)) {
            skippedNoPubKey++;
            LogPrint(BCLog::MEMPOOL, "GetTokenHolders: Skipping %s (no public key revealed)\n",
                     holder.first);
            continue;
        }

        addresses.push_back(holder.first);

        // Check recipient limit
        if (addresses.size() >= maxHolders) {
            break;
        }
    }

    if (skippedNoPubKey > 0) {
        LogPrintf("GetTokenHolders: Filtered out %d addresses without revealed public keys\n",
                  skippedNoPubKey);
    }

    if (addresses.empty()) {
        error = strprintf("No holders of token '%s' have revealed their public keys. "
                         "Holders must spend from their address at least once to reveal their public key.",
                         token);
        return std::vector<std::string>();
    }

    LogPrintf("GetTokenHolders: Found %d eligible recipients (with revealed public keys)\n",
              addresses.size());

    return addresses;
}

bool EncryptMessageForRecipient(const std::string& message, const std::string& recipientAddress,
                                 std::vector<unsigned char>& encryptedData, std::string& error) {
    // Get recipient's public key from pubkey index
    CPubKey recipientPubKey;
    if (!CheckAddressHasPublicKey(recipientAddress, recipientPubKey, error)) {
        return false;
    }

    // Create a map with single recipient for ECIES encryption
    std::map<std::string, CPubKey> recipients;
    recipients[recipientAddress] = recipientPubKey;

    // Use ECIES hybrid encryption
    CECIESEncryptedMessage eciesMsg;
    if (!ECIESEncryptMessage(message, recipients, eciesMsg, error)) {
        return false;
    }

    // Serialize the ECIES message to encryptedData
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << eciesMsg;
    encryptedData.assign(ss.begin(), ss.end());

    return true;
}

bool DecryptMessageForAddress(const std::vector<unsigned char>& encryptedData,
                               const std::string& address, std::string& decryptedMessage,
                               std::string& error) {
#ifdef ENABLE_WALLET
    // Get wallet
    if (vpwallets.empty()) {
        error = "Wallet not available";
        return false;
    }
    CWallet* const pwallet = vpwallets[0];

    // Decode address
    CTxDestination dest = DecodeDestination(address);
    const CKeyID* keyID = boost::get<CKeyID>(&dest);
    if (!keyID) {
        error = "Invalid address format";
        return false;
    }

    // Get private key from wallet
    CKey privKey;
    if (!pwallet->GetKey(*keyID, privKey)) {
        error = strprintf("Private key not found in wallet for address %s", address);
        return false;
    }

    if (!privKey.IsValid()) {
        error = "Invalid private key";
        return false;
    }

    // Deserialize ECIES message
    CECIESEncryptedMessage eciesMsg;
    try {
        CDataStream ss(encryptedData, SER_NETWORK, PROTOCOL_VERSION);
        ss >> eciesMsg;
    } catch (const std::exception& e) {
        error = strprintf("Failed to deserialize encrypted message: %s", e.what());
        return false;
    }

    // Decrypt using ECIES
    if (!ECIESDecryptMessage(eciesMsg, privKey, address, decryptedMessage, error)) {
        return false;
    }

    return true;
#else
    error = "Wallet support not enabled";
    return false;
#endif
}

bool QueryRemoteDepinMsgPool(const std::string& ipAddress, int port,
                            const std::string& token,
                            const std::vector<std::string>& myAddresses,
                            std::vector<CDepinMessage>& messages,
                            std::string& error) {
    LogPrint(BCLog::NET, "QueryRemoteDepinMsgPool: Connecting to %s:%d for token %s\n",
             ipAddress, port, token);

    // Use the DePIN message pool client
    bool success = CDepinMsgPoolClient::QueryMessages(ipAddress, port, token,
                                                     myAddresses, messages, error);

    if (success) {
        LogPrint(BCLog::NET, "QueryRemoteDepinMsgPool: Successfully retrieved %d messages\n",
                messages.size());
    } else {
        LogPrint(BCLog::NET, "QueryRemoteDepinMsgPool: Failed: %s\n", error);
    }

    return success;
}
