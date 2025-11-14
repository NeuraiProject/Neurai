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
#include "streams.h"
#include "fs.h"

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
    return strprintf("CDepinMessage(token=%s, sender=%s, timestamp=%d, payload_size=%d)",
                     token, senderAddress, timestamp, encryptedPayload.size());
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

bool CDepinMsgPool::AddMessage(const CDepinMessage& message, std::string& error, bool skipSignatureCheck) {
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

    // Verify encryptedPayload is not empty
    if (message.encryptedPayload.empty()) {
        error = "Message has no encrypted payload";
        return false;
    }

    // Verify total message size (ECIES message includes encrypted payload + all recipient keys)
    // Maximum size is generous to accommodate multiple recipient keys
    const size_t MAX_TOTAL_SIZE = MAX_DEPIN_MESSAGE_SIZE * MAX_DEPIN_RECIPIENTS;
    if (message.encryptedPayload.size() > MAX_TOTAL_SIZE) {
        error = strprintf("Message payload too large (%d bytes), maximum is %d",
                         message.encryptedPayload.size(), MAX_TOTAL_SIZE);
        return false;
    }

    // Verify signature (skip if pre-authenticated by DePIN server)
    if (!skipSignatureCheck) {
        if (!VerifyDepinMessageSignature(message)) {
            error = "Invalid message signature";
            return false;
        }
    } else {
        LogPrintf("AddMessage: Skipping signature check for pre-authenticated message\n");
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

    LogPrint(BCLog::MEMPOOL, "DePIN message added: hash=%s, sender=%s, payload_size=%d\n",
             hash.ToString(), message.senderAddress, message.encryptedPayload.size());

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
    // With ECIES hybrid encryption, we cannot determine recipients without decrypting
    // Return all messages - caller will attempt decryption with their private key
    return GetAllMessages();
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
        total += msg.encryptedPayload.size();
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
    // Hash format: SHA256(token || senderAddress || timestamp || encryptedPayload)
    CHashWriter ss(SER_GETHASH, 0);
    ss << message.token;
    ss << message.senderAddress;
    ss << message.timestamp;
    ss << message.encryptedPayload;
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
    ss << message.encryptedPayload;
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

bool EncryptMessageForAllRecipients(const std::string& message,
                                     const std::vector<std::string>& recipientAddresses,
                                     std::vector<unsigned char>& encryptedData,
                                     std::string& error) {
    if (recipientAddresses.empty()) {
        error = "No recipients provided";
        return false;
    }

    // Build map of all recipients with their public keys
    std::map<std::string, CPubKey> recipients;
    for (const auto& address : recipientAddresses) {
        CPubKey recipientPubKey;
        if (!CheckAddressHasPublicKey(address, recipientPubKey, error)) {
            // Log warning but continue with other recipients
            LogPrintf("Warning: Skipping recipient %s: %s\n", address, error);
            continue;
        }
        recipients[address] = recipientPubKey;
    }

    if (recipients.empty()) {
        error = "No valid recipients with public keys";
        return false;
    }

    // Create single ECIES message for ALL recipients
    // This encrypts the message ONCE and creates encrypted keys for each recipient
    CECIESEncryptedMessage eciesMsg;
    if (!ECIESEncryptMessage(message, recipients, eciesMsg, error)) {
        return false;
    }

    // Serialize the ECIES message
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << eciesMsg;
    encryptedData.assign(ss.begin(), ss.end());

    LogPrintf("EncryptMessageForAllRecipients: Created shared ECIES message for %d recipients, payload size: %d bytes\n",
              recipients.size(), encryptedData.size());

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

#ifdef ENABLE_WALLET
bool QueryRemoteDepinMsgPool(CWallet* pwallet,
                            const std::string& ipAddress, int port,
                            const std::string& token,
                            const std::vector<std::string>& myAddresses,
                            std::vector<CDepinMessage>& messages,
                            std::string& error) {
    if (!pwallet) {
        error = "Wallet not available";
        return false;
    }

    if (myAddresses.empty()) {
        error = "No addresses provided for authentication";
        return false;
    }

    std::string authAddress = myAddresses.front();

    LogPrint(BCLog::NET, "QueryRemoteDepinMsgPool: Connecting to %s:%d for token %s\n",
             ipAddress, port, token);

    std::string challenge;
    int expiresIn = 0;
    if (!CDepinMsgPoolClient::RequestChallenge(ipAddress, port, token, authAddress,
                                               challenge, expiresIn, error, false)) {
        LogPrint(BCLog::NET, "QueryRemoteDepinMsgPool: Challenge failed: %s\n", error);
        return false;
    }

    std::string signature;
    if (!SignDepinChallenge(pwallet, authAddress, token, challenge, signature, error)) {
        LogPrint(BCLog::NET, "QueryRemoteDepinMsgPool: Failed to sign challenge: %s\n", error);
        return false;
    }

    bool success = CDepinMsgPoolClient::QueryMessages(ipAddress, port, token,
                                                     myAddresses, authAddress,
                                                     signature, challenge,
                                                     messages, error);

    if (success) {
        LogPrint(BCLog::NET, "QueryRemoteDepinMsgPool: Successfully retrieved %d messages\n",
                messages.size());
    } else {
        LogPrint(BCLog::NET, "QueryRemoteDepinMsgPool: Failed: %s\n", error);
    }

    return success;
}

bool SignDepinChallenge(CWallet* pwallet,
                        const std::string& address,
                        const std::string& token,
                        const std::string& challenge,
                        std::string& signature,
                        std::string& error,
                        bool forSend) {
    if (!pwallet) {
        error = "Wallet not available";
        return false;
    }

    CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest)) {
        error = "Invalid address";
        return false;
    }

    const CKeyID* keyID = boost::get<CKeyID>(&dest);
    if (!keyID) {
        error = "Address does not refer to key";
        return false;
    }

    CKey key;
    if (!pwallet->GetKey(*keyID, key)) {
        error = strprintf("Private key not found in wallet for address %s", address);
        return false;
    }

    if (!key.IsValid()) {
        error = "Invalid private key";
        return false;
    }

    CHashWriter ss(SER_GETHASH, 0);
    const char* prefix = forSend ? "DEPIN-SEND" : "DEPIN-GET";

    ss << strMessageMagic;
    ss << strprintf("%s|%s|%s|%s", prefix, token, address, challenge);

    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig)) {
        error = "Failed to sign challenge";
        return false;
    }

    signature = EncodeBase64(vchSig.data(), vchSig.size());
    return true;
}
#endif

// Persistence: Save DePIN pool to disk
bool CDepinMsgPool::SaveToDisk()
{
    LOCK(cs_depinmsgpool);

    int64_t start = GetTimeMillis();
    fs::path filepath = GetDataDir() / "depinpool.dat";
    fs::path filepathTmp = GetDataDir() / "depinpool.dat.new";

    try {
        FILE* file = fsbridge::fopen(filepathTmp, "wb");
        if (!file) {
            LogPrintf("ERROR: CDepinMsgPool::SaveToDisk(): Failed to open file %s\n",
                     filepathTmp.string());
            return false;
        }

        CAutoFile fileout(file, SER_DISK, CLIENT_VERSION);

        // Write magic bytes
        fileout << DEPINPOOL_MAGIC_BYTES;

        // Write version
        fileout << DEPINPOOL_FILE_VERSION;

        // Write current timestamp
        int64_t now = GetTime();
        fileout << now;

        // Get all messages
        std::vector<CDepinMessage> messages;
        for (const auto& entry : mapMessages) {
            messages.push_back(entry.second);
        }

        // Write message count
        uint64_t count = messages.size();
        fileout << count;

        // Write each message
        for (const auto& msg : messages) {
            fileout << msg;
        }

        FileCommit(fileout.Get());
        fileout.fclose();

        // Rename to final file
        if (!RenameOver(filepathTmp, filepath)) {
            LogPrintf("ERROR: CDepinMsgPool::SaveToDisk(): Failed to rename file\n");
            return false;
        }

        LogPrintf("DePIN Pool: Saved %d messages to disk in %dms\n",
                 count, GetTimeMillis() - start);
        return true;

    } catch (const std::exception& e) {
        LogPrintf("ERROR: CDepinMsgPool::SaveToDisk(): %s\n", e.what());
        return false;
    }
}

// Persistence: Load DePIN pool from disk
bool CDepinMsgPool::LoadFromDisk()
{
    LOCK(cs_depinmsgpool);

    int64_t start = GetTimeMillis();
    fs::path filepath = GetDataDir() / "depinpool.dat";

    // Check if file exists
    if (!fs::exists(filepath)) {
        LogPrintf("DePIN Pool: No persisted pool file found (first run)\n");
        return true;  // Not an error
    }

    try {
        FILE* file = fsbridge::fopen(filepath, "rb");
        if (!file) {
            LogPrintf("ERROR: CDepinMsgPool::LoadFromDisk(): Failed to open file %s\n",
                     filepath.string());
            return false;
        }

        CAutoFile filein(file, SER_DISK, CLIENT_VERSION);

        // Read and verify magic bytes
        uint32_t magic;
        filein >> magic;
        if (magic != DEPINPOOL_MAGIC_BYTES) {
            LogPrintf("ERROR: CDepinMsgPool::LoadFromDisk(): Invalid magic bytes (file corrupted)\n");
            filein.fclose();
            // Delete corrupted file
            fs::remove(filepath);
            return false;
        }

        // Read and verify version
        uint32_t version;
        filein >> version;
        if (version != DEPINPOOL_FILE_VERSION) {
            LogPrintf("ERROR: CDepinMsgPool::LoadFromDisk(): Incompatible version %d (expected %d)\n",
                     version, DEPINPOOL_FILE_VERSION);
            filein.fclose();
            return false;
        }

        // Read save timestamp
        int64_t saveTime;
        filein >> saveTime;

        // Read message count
        uint64_t count;
        filein >> count;

        // Read messages
        int64_t now = GetTime();
        size_t loadedCount = 0;
        size_t expiredCount = 0;

        for (uint64_t i = 0; i < count; i++) {
            CDepinMessage msg;
            filein >> msg;

            // Check if expired
            if (msg.IsExpired(now)) {
                expiredCount++;
                continue;
            }

            // Add to pool
            std::string error;
            if (AddMessage(msg, error)) {
                loadedCount++;
            } else {
                LogPrintf("WARNING: CDepinMsgPool::LoadFromDisk(): Failed to add message: %s\n", error);
            }
        }

        filein.fclose();

        LogPrintf("DePIN Pool: Loaded %d messages from disk (%d expired, skipped) in %dms\n",
                 loadedCount, expiredCount, GetTimeMillis() - start);

        // Auto-compact if more than 50% were expired
        if (expiredCount > loadedCount && loadedCount > 0) {
            LogPrintf("DePIN Pool: Auto-compacting (removed %d expired messages)\n", expiredCount);
            SaveToDisk();
        }

        return true;

    } catch (const std::exception& e) {
        LogPrintf("ERROR: CDepinMsgPool::LoadFromDisk(): %s\n", e.what());
        return false;
    }
}
