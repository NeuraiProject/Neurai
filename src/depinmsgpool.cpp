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
    ss << token << senderAddress << timestamp << messageType << encryptedPayload;
    return ss.GetHash();
}

bool CDepinMessage::IsExpired(int64_t currentTime, int64_t expiryTimeSeconds) const {
    return (currentTime - timestamp) > expiryTimeSeconds;
}

std::string CDepinMessage::ToString() const {
    return strprintf("CDepinMessage(token=%s, sender=%s, timestamp=%d, payload_size=%d)",
                     token, senderAddress, timestamp, encryptedPayload.size());
}

// CDepinMsgPool implementation

CDepinMsgPool::CDepinMsgPool()
    : fEnabled(false), nPort(DEFAULT_DEPIN_MSG_PORT),
      nMaxRecipients(DEFAULT_MAX_DEPIN_RECIPIENTS),
      nMaxMessageSize(DEFAULT_DEPIN_MESSAGE_SIZE),
      nMessageExpiryHours(DEFAULT_DEPIN_MESSAGE_EXPIRY_HOURS),
      nMaxPoolSizeMB(DEFAULT_DEPIN_POOL_SIZE_MB) {
}

bool IsValidDepinMessagingToken(const std::string& token, std::string& error)
{
    AssetType type;
    if (!IsAssetNameValid(token, type, error)) {
        return false;
    }

    if (type != AssetType::DEPIN) {
        error = strprintf(
            "Token '%s' is a valid asset name but not a DEPIN token. DePIN messaging "
            "requires a soulbound DEPIN token (name starting with '%c', e.g. '%cMYTOKEN' "
            "or a sub-token like '%cMYTOKEN/DEVICE'). DEPIN tokens are currently only "
            "available on testnet and regtest.",
            token, DEPIN_CHAR, DEPIN_CHAR, DEPIN_CHAR);
        return false;
    }

    return true;
}

bool CDepinMsgPool::Initialize(const std::string& token, unsigned int port, unsigned int maxRecipients,
                               unsigned int maxMessageSize, unsigned int messageExpiryHours, unsigned int maxPoolSizeMB) {
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

    // Verify that the token is valid AND is a DEPIN (soulbound) token.
    // DePIN messaging is scoped to DEPIN tokens only; see
    // IsValidDepinMessagingToken() for the rationale.
    std::string error;
    if (!IsValidDepinMessagingToken(token, error)) {
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

    // Apply limits
    nMaxRecipients = std::min(maxRecipients, MAX_DEPIN_RECIPIENTS);
    nMaxMessageSize = std::min(maxMessageSize, MAX_DEPIN_MESSAGE_SIZE);
    nMessageExpiryHours = std::min(messageExpiryHours, MAX_DEPIN_MESSAGE_EXPIRY_HOURS);
    nMaxPoolSizeMB = std::min(maxPoolSizeMB, MAX_DEPIN_POOL_SIZE_MB);

    fEnabled = true;

    LogPrintf("DePIN messaging initialized: token=%s, port=%d, maxRecipients=%d, maxMessageSize=%d, expiryHours=%d, maxPoolSizeMB=%d\n",
              activeToken, nPort, nMaxRecipients, nMaxMessageSize, nMessageExpiryHours, nMaxPoolSizeMB);

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

    // Verify messageType is valid
    if (message.messageType != 0x01 && message.messageType != 0x02) {
        error = strprintf("Invalid messageType: 0x%02x (must be 0x01 for private or 0x02 for group)",
                         message.messageType);
        return false;
    }

    // Verify timestamp (do not accept messages from the future)
    int64_t currentTime = GetTime();
    if (message.timestamp > currentTime + 60) { // +60s tolerance
        error = "Message timestamp is too far in the future";
        return false;
    }

    // Verify that it is not expired
    if (message.IsExpired(currentTime, GetMessageExpiryTime())) {
        error = "Message is already expired";
        return false;
    }

    // Verify encryptedPayload is not empty
    if (message.encryptedPayload.empty()) {
        error = "Message has no encrypted payload";
        return false;
    }

    // Verify message size (ECIES message includes encrypted payload + all recipient keys)
    // Maximum size is generous to accommodate multiple recipient keys
    const size_t MAX_TOTAL_SIZE = nMaxMessageSize * nMaxRecipients;
    if (message.encryptedPayload.size() > MAX_TOTAL_SIZE) {
        error = strprintf("Message payload too large (%d bytes), maximum is %d",
                         message.encryptedPayload.size(), MAX_TOTAL_SIZE);
        return false;
    }

    // Verify pool size limit
    size_t currentPoolSize = DynamicMemoryUsage();
    size_t maxPoolSizeBytes = (size_t)nMaxPoolSizeMB * 1024 * 1024;  // Convert MB to bytes
    if (currentPoolSize + message.encryptedPayload.size() > maxPoolSizeBytes) {
        error = strprintf("Pool size limit exceeded (current: %d MB, limit: %d MB). Message rejected.",
                         currentPoolSize / (1024 * 1024), nMaxPoolSizeMB);
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

bool ShouldDeliverDepinMessageToAddress(const CDepinMessage& msg, const std::string& address,
                                         const uint160* addressHash160) {
    // Sender always receives their own message, regardless of type,
    // recipientKeys contents, or payload validity.
    if (msg.senderAddress == address) {
        return true;
    }

    if (!addressHash160) {
        return false;
    }

    try {
        CECIESEncryptedMessage eciesMsg;
        CDataStream ss(msg.encryptedPayload, SER_NETWORK, PROTOCOL_VERSION);
        ss >> eciesMsg;
        return eciesMsg.recipientKeys.count(*addressHash160) > 0;
    } catch (const std::exception& e) {
        LogPrint(BCLog::NET, "ShouldDeliverDepinMessageToAddress: Failed to deserialize ECIES message: %s\n", e.what());
        return false;
    }
}

std::vector<CDepinMessage> FilterDepinMessagesForAddress(const std::vector<const CDepinMessage*>& messages,
                                                         const std::string& address,
                                                         const uint160* addressHash160) {
    std::vector<CDepinMessage> result;
    for (const CDepinMessage* msg : messages) {
        if (msg && ShouldDeliverDepinMessageToAddress(*msg, address, addressHash160)) {
            result.push_back(*msg);
        }
    }
    return result;
}

std::vector<CDepinMessage> CDepinMsgPool::GetMessagesForAddress(const std::string& address) const {
    LOCK(cs_depinmsgpool);

    // Decode the requesting address to hash160 once per call, not once per message.
    CTxDestination dest = DecodeDestination(address);
    const CKeyID* keyID = boost::get<CKeyID>(&dest);
    uint160 addressHash160;
    const uint160* hashPtr = nullptr;
    if (keyID) {
        addressHash160 = uint160(*keyID);
        hashPtr = &addressHash160;
    }

    // Collect pointers in chronological order (mapByTime, oldest first) rather
    // than hash order, then let the free function above apply the delivery
    // policy, so that policy stays unit-testable without a live pool.
    // Pointers, not copies: the pool holds up to MAX_DEPIN_POOL_SIZE_MB (1 GB)
    // of payloads and this runs under cs_depinmsgpool, so only the messages
    // actually being delivered may be copied.
    std::vector<const CDepinMessage*> ordered;
    ordered.reserve(mapByTime.size());
    for (const auto& timeEntry : mapByTime) {
        auto it = mapMessages.find(timeEntry.second);
        if (it == mapMessages.end()) {
            continue;  // Should not happen, but be defensive
        }
        ordered.push_back(&it->second);
    }

    return FilterDepinMessagesForAddress(ordered, address, hashPtr);
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
    int64_t expiryTime = GetMessageExpiryTime();

    for (const auto& entry : mapMessages) {
        if (entry.second.IsExpired(currentTime, expiryTime)) {
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

void CDepinMsgPool::RemoveMessagesOlderThan(int64_t currentTime, int64_t ageThresholdSeconds) {
    LOCK(cs_depinmsgpool);

    std::vector<uint256> toRemove;

    for (const auto& entry : mapMessages) {
        int64_t messageAge = currentTime - entry.second.timestamp;
        if (messageAge > ageThresholdSeconds) {
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
        int64_t hoursThreshold = ageThresholdSeconds / 3600;
        LogPrint(BCLog::MEMPOOL, "Removed %d messages older than %d hours\n", toRemove.size(), hoursThreshold);
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
    CDestinationIndexData addressData;
    if (!IsValidDestination(dest) || !GetDestinationIndexData(dest, addressData) ||
        (addressData.type != DEST_INDEX_KEY && addressData.type != DEST_INDEX_WITNESS_V1_AUTHSCRIPT)) {
        error = strprintf("Invalid address format: %s", address);
        return false;
    }

    // Query pubkey index
    CPubKeyIndexValue value;
    if (!pblocktree->ReadPubKeyIndex(addressData, value)) {
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
        LogPrintf("VerifyDepinMessageSignature: Signature is empty (size=%d)\n", message.signature.size());
        return false;
    }

    // Get sender's public key from pubkey index
    CPubKey senderPubKey;
    std::string error;
    if (!CheckAddressHasPublicKey(message.senderAddress, senderPubKey, error)) {
        LogPrintf("VerifyDepinMessageSignature: Public key lookup failed for %s: %s\n",
                  message.senderAddress, error);
        return false;
    }

    // Construct message hash for verification
    // Hash format (v2.1.3+): SHA256(token || senderAddress || timestamp || messageType || encryptedPayload)
    CHashWriter ss(SER_GETHASH, 0);
    ss << message.token;
    ss << message.senderAddress;
    ss << message.timestamp;
    ss << message.messageType;
    ss << message.encryptedPayload;
    uint256 messageHash = ss.GetHash();

    // Try to verify with new format (includes messageType)
    if (senderPubKey.Verify(messageHash, message.signature)) {
        return true;  // New format verified successfully
    }

    // Fallback for backward compatibility: try old format without messageType
    // This supports messages created before v2.1.3
    CHashWriter ssOld(SER_GETHASH, 0);
    ssOld << message.token;
    ssOld << message.senderAddress;
    ssOld << message.timestamp;
    ssOld << message.encryptedPayload;
    uint256 messageHashOld = ssOld.GetHash();

    if (senderPubKey.Verify(messageHashOld, message.signature)) {
        LogPrintf("VerifyDepinMessageSignature: Verified with old format (pre-v2.1.3)\n");
        return true;  // Old format verified successfully
    }

    // Both formats failed
    LogPrintf("VerifyDepinMessageSignature: Signature verification failed (tried both formats)\n");
    LogPrintf("  Sender: %s\n", message.senderAddress);
    LogPrintf("  Token: %s\n", message.token);
    LogPrintf("  Timestamp: %d\n", message.timestamp);
    LogPrintf("  MessageType: 0x%02x\n", message.messageType);
    LogPrintf("  Signature size: %d bytes\n", message.signature.size());
    LogPrintf("  Signature hex: %s\n", HexStr(message.signature));
    LogPrintf("  Message hash (new): %s\n", messageHash.ToString());
    LogPrintf("  Message hash (old): %s\n", messageHashOld.ToString());
    LogPrintf("  Sender pubkey: %s\n", HexStr(senderPubKey));
    LogPrintf("  EncryptedPayload size: %d bytes\n", message.encryptedPayload.size());
    return false;
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

// ---------------------------------------------------------------------------
// Ancestor recipients
// ---------------------------------------------------------------------------

CDepinAncestorRecipientsStats gDepinAncestorRecipientsStats;

namespace {

// assets.cpp keeps SUB_NAME_DELIMITER file-static (assets.cpp:75); this is the
// same '/' that separates the components of a sub-DEPIN name.
const char DEPIN_SECTION_DELIMITER = '/';

// The single flush point of an ancestor query, wrapped only so the tests can
// count it. See CDepinAncestorRecipientsStats for what the counter does and
// does not catch.
void DepinAncestorFlushOnce()
{
    gDepinAncestorRecipientsStats.flushCalls++;
    FlushStateToDisk();
}

// Ancestors of `token`, itself first, up to `stopAt` (inclusive) or to the
// absolute root when stopAt is empty.
//
// Strips one '/'-separated component at a time rather than calling
// GetParentName(), which would re-run IsAssetNameValid() -- regex plus a
// network check -- at every level. Each derived name is validated explicitly by
// the caller right afterwards, so nothing is skipped, only done once.
bool DeriveDepinAncestors(const std::string& token, const std::string& stopAt,
                          std::vector<std::string>& ancestors, std::string& error)
{
    ancestors.clear();

    std::string current = token;
    while (true) {
        ancestors.push_back(current);

        if (!stopAt.empty() && current == stopAt)
            return true;

        if (ancestors.size() >= MAX_DEPIN_ANCESTOR_DEPTH) {
            error = strprintf("Token '%s' has more than %u ancestor levels", token,
                              (unsigned int)MAX_DEPIN_ANCESTOR_DEPTH);
            return false;
        }

        const size_t pos = current.find_last_of(DEPIN_SECTION_DELIMITER);
        if (pos == std::string::npos)
            break;

        current = current.substr(0, pos);
    }

    // Reached the root without matching stopAt, so it was never on this branch.
    if (!stopAt.empty()) {
        error = strprintf("stop_at '%s' is neither '%s' nor one of its '/'-separated ancestors",
                          stopAt, token);
        return false;
    }

    return true;
}

// Does `pubkey`, as stored in -pubkeyindex for `address`, actually belong to it?
//
// The index is keyed by destination, but a corrupted or hostile entry could
// hand back a key that hashes elsewhere; encrypting for it would produce a
// payload the holder cannot open. Only P2PKH destinations qualify: the DePIN
// encryption layer keys recipients by uint160(CKeyID) (depinecies.cpp), so a
// script or AuthScript address can never be a recipient regardless of what the
// index holds.
bool PubKeyMatchesAddress(const std::string& address, const CPubKey& pubkey)
{
    CTxDestination dest = DecodeDestination(address);
    const CKeyID* keyID = boost::get<CKeyID>(&dest);
    if (!keyID)
        return false;

    return pubkey.GetID() == *keyID;
}

} // namespace

bool GetDepinAncestorRecipients(const std::string& token,
                                size_t maxResults,
                                CDepinAncestorRecipients& result,
                                std::string& error,
                                const std::string& stopAt)
{
    result = CDepinAncestorRecipients();
    result.token = token;
    result.stopAt = stopAt;
    result.maxResults = maxResults;

    if (maxResults == 0) {
        error = "max_results must be at least 1";
        return false;
    }
    if (maxResults > MAX_DEPIN_ANCESTOR_RECIPIENTS_HARD_CAP) {
        error = strprintf("max_results %u exceeds the hard cap of %u", (unsigned int)maxResults,
                          (unsigned int)MAX_DEPIN_ANCESTOR_RECIPIENTS_HARD_CAP);
        return false;
    }

    // The lock and the flush belong to this function, not to its callers: it is
    // public and reusable, and a caller that forgot either would get an
    // incoherent answer with no warning. cs_main is recursive, so a caller that
    // already holds it (depinsendmsg does) is unaffected.
    LOCK(cs_main);

    // Preconditions first, BEFORE the flush. Not merely to avoid paying for a
    // global flush on the way to an error: FlushStateToDisk() dereferences
    // pcoinsTip unguarded in its main path (validation.cpp:3202) and pblocktree
    // unguarded in its pruning branch (validation.cpp:3165). With either null,
    // flushing first would not produce a precondition error, it would take the
    // node down. Everything below then reads chain state under the same cs_main
    // that has already been taken, so nothing changes between check and use.
    if (!fAssetIndex) {
        error = "Asset index is required but not enabled. Restart with -assetindex and -reindex";
        return false;
    }
    if (!fPubKeyIndex) {
        error = "Public key index is required but not enabled. Restart with -pubkeyindex and -reindex-chainstate";
        return false;
    }
    if (!passetsdb) {
        error = "Asset database not available";
        return false;
    }
    if (!pblocktree) {
        error = "Block tree database not available";
        return false;
    }
    if (!pcoinsTip) {
        error = "Coins view not available";
        return false;
    }
    // Emphasised because its absence fails OPEN. CheckForDEPINRestriction() and
    // friends consult prestricteddb under `if (prestricteddb)` and return false
    // when it is null, so every address would look unrestricted: self-revoked
    // and frozen holders would be returned as recipients, silently and with the
    // appearance of a correct answer.
    if (!prestricteddb) {
        error = "Restricted asset database not available; restriction state cannot be read, "
                "and treating every address as unrestricted would return revoked and frozen holders";
        return false;
    }

    // Name validation and ancestor derivation are pure, so they run before the
    // flush too -- a malformed token should not cost a global flush.
    if (!IsValidDepinMessagingToken(token, error))
        return false;

    if (!stopAt.empty()) {
        std::string stopAtError;
        if (!IsValidDepinMessagingToken(stopAt, stopAtError)) {
            error = strprintf("Invalid stop_at '%s': %s", stopAt, stopAtError);
            return false;
        }
    }

    std::vector<std::string> ancestors;
    if (!DeriveDepinAncestors(token, stopAt, ancestors, error))
        return false;

    for (const std::string& ancestor : ancestors) {
        std::string ancestorError;
        if (!IsValidDepinMessagingToken(ancestor, ancestorError)) {
            error = strprintf("Derived ancestor '%s' of '%s' is not a valid DEPIN token: %s",
                              ancestor, token, ancestorError);
            return false;
        }
    }

    // Single flush of the query. Everything read below -- asset existence,
    // holders, restrictions -- is read from disk, so this is what makes the
    // databases authoritative for state produced by recently connected blocks.
    DepinAncestorFlushOnce();

    // Each ancestor must exist exactly. A missing intermediate level is an
    // error, never something to skip on the way to the root: silently jumping
    // over it would answer a different question than the one asked.
    for (const std::string& ancestor : ancestors) {
        CNewAsset asset;
        int assetHeight = 0;
        uint256 assetBlockHash;
        if (!passetsdb->ReadAssetData(ancestor, asset, assetHeight, assetBlockHash)) {
            if (ancestor == token) {
                error = strprintf("DEPIN token '%s' does not exist", token);
            } else {
                error = strprintf("Ancestor '%s' of token '%s' does not exist", ancestor, token);
            }
            return false;
        }
    }

    std::map<std::string, std::vector<std::pair<std::string, CAmount> > > rowsByAsset;
    bool hitRowLimit = false;
    if (!passetsdb->AssetAddressDirMulti(ancestors, rowsByAsset, MAX_DEPIN_ANCESTOR_SCAN_ROWS, hitRowLimit)) {
        error = strprintf("Failed to query holders of '%s' and its ancestors from the asset index", token);
        return false;
    }

    // Reaching the exploration bound is an error, not a truncation. truncated
    // promises "these are the first N in a deterministic order"; here the
    // working set was never collected in full, so sorting what arrived and
    // returning its head would be an arbitrary answer wearing a correct one's
    // clothes.
    if (hitRowLimit) {
        error = strprintf("Resolving '%s' exceeds the exploration limit of %u (asset, address) rows. "
                          "The branch (%u ancestors, starting at '%s') is too large to resolve in a "
                          "single call; this is an error rather than a truncated result because the "
                          "candidate set was never collected in full.",
                          token, (unsigned int)MAX_DEPIN_ANCESTOR_SCAN_ROWS,
                          (unsigned int)ancestors.size(), ancestors.back());
        return false;
    }

    // Group by address, dropping non-positive balances. std::map orders the
    // addresses lexicographically, which is what makes the result -- and
    // therefore the truncation point -- independent of LevelDB's physical
    // ordering.
    std::map<std::string, std::vector<std::string> > activeAssetsByAddress;
    for (const auto& assetRows : rowsByAsset) {
        for (const auto& row : assetRows.second) {
            if (row.second <= 0)
                continue;
            activeAssetsByAddress[row.first].push_back(assetRows.first);
        }
    }

    // Walk the addresses in that order, evaluating each one COMPLETELY before
    // moving on. Restrictions and public keys are interleaved per address, not
    // resolved in two passes: a prior full pass over restrictions would work,
    // but it would destroy the early stop -- a branch with 200,000 addresses
    // and maxResults = 10 would do 400,000 restriction seeks before looking at
    // a single public key. Interleaved, both costs are bounded by the same
    // thing (addresses examined until enough eligible ones are found), which is
    // also why skippedRestrictedComplete can follow the same rule as
    // skippedNoPubKeyComplete.
    for (const auto& entry : activeAssetsByAddress) {
        const std::string& address = entry.first;

        // (a) Two ranged seeks for this address -- not one lookup per ancestor.
        std::set<std::string> ownerFrozen;
        std::set<std::string> selfRevoked;
        gDepinAncestorRecipientsStats.restrictionQueries++;
        if (!prestricteddb->GetAddressDepinRestrictions(address, ownerFrozen, selfRevoked)) {
            error = strprintf("Failed to read restriction state for address '%s'", address);
            return false;
        }

        // (b) Membership resolved in memory. One active pair is enough: holding
        // an ancestor already grants visibility over the branch, so revoking in
        // a section does not withdraw what the root grants. Deciding this after
        // looking at ALL of the address's pairs is what keeps skippedRestricted
        // from counting addresses that are still active elsewhere.
        bool hasActivePair = false;
        for (const std::string& assetName : entry.second) {
            if (ownerFrozen.count(assetName) || selfRevoked.count(assetName))
                continue;
            hasActivePair = true;
            break;
        }
        if (!hasActivePair) {
            result.skippedRestricted++;
            continue;  // deliberately no public-key lookup for a dropped address
        }

        // (c) and (d): the public key, and only then.
        CPubKey pubkey;
        std::string pubkeyError;
        gDepinAncestorRecipientsStats.pubkeyQueries++;
        if (!CheckAddressHasPublicKey(address, pubkey, pubkeyError) ||
            !PubKeyMatchesAddress(address, pubkey)) {
            result.skippedNoPubKey++;
            continue;
        }

        // This is the (maxResults + 1)-th eligible recipient: the probe that
        // distinguishes "exactly at the limit" from "there are more". It proves
        // truncation and does not enter the response.
        if (result.recipients.size() == maxResults) {
            result.truncated = true;
            break;
        }

        CDepinRecipient recipient;
        recipient.address = address;
        recipient.pubkey = pubkey;
        result.recipients.push_back(recipient);
    }

    result.ancestors = ancestors;
    result.skippedNoPubKeyComplete = !result.truncated;
    result.skippedRestrictedComplete = !result.truncated;

    return true;
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

#ifdef ENABLE_DEPIN_GATEWAY
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

    LogPrint(BCLog::NET, "QueryRemoteDepinMsgPool: Connecting to %s:%d for token %s\n",
             ipAddress, port, token);

    // GETMESSAGES only serves the address that completed the challenge, so a
    // wallet holding the token at several addresses must authenticate once per
    // address instead of listing them all in a single request.
    // Accumulate locally and only hand the result over once every address has
    // succeeded: this call is all-or-nothing, and a caller that ignores the
    // return value must not end up reading a half-filled list.
    std::vector<CDepinMessage> mergedMessages;
    std::set<uint256> seenHashes;
    for (const std::string& addr : myAddresses) {
        std::string challenge;
        int expiresIn = 0;
        if (!CDepinMsgPoolClient::RequestChallenge(ipAddress, port, token, addr,
                                                   challenge, expiresIn, error, false)) {
            LogPrint(BCLog::NET, "QueryRemoteDepinMsgPool: Challenge failed for %s: %s\n", addr, error);
            return false;
        }

        std::string signature;
        if (!SignDepinChallenge(pwallet, addr, token, challenge, signature, error)) {
            LogPrint(BCLog::NET, "QueryRemoteDepinMsgPool: Failed to sign challenge for %s: %s\n", addr, error);
            return false;
        }

        std::vector<CDepinMessage> addrMessages;
        if (!CDepinMsgPoolClient::QueryMessages(ipAddress, port, token,
                                                {addr}, addr, signature, challenge,
                                                addrMessages, error)) {
            LogPrint(BCLog::NET, "QueryRemoteDepinMsgPool: Query failed for %s: %s\n", addr, error);
            return false;
        }

        // A group message can list several of this wallet's addresses as
        // recipients, so the same message may come back once per address.
        for (const CDepinMessage& msg : addrMessages) {
            if (seenHashes.insert(msg.GetHash()).second) {
                mergedMessages.push_back(msg);
            }
        }
    }

    messages.swap(mergedMessages);

    LogPrint(BCLog::NET, "QueryRemoteDepinMsgPool: Successfully retrieved %d messages for %d addresses\n",
            messages.size(), myAddresses.size());

    return true;
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
            if (msg.IsExpired(now, GetMessageExpiryTime())) {
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
