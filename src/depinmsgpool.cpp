// Copyright (c) 2024 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "depinmsgpool.h"
#include "depinchallenge.h"
#include "depinecies.h"
#include "validation.h"
#include "assets/assets.h"
#include "assets/assetdb.h"
#include "txdb.h"
#include "pubkeyindex.h"
#include "hash.h"
#include "random.h"
#include "dbwrapper.h"
#include <limits>
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

#include <algorithm>

std::unique_ptr<CDepinMsgPool> pDepinMsgPool;
CDepinAdmissionStats gDepinAdmissionStats;

CDepinServiceStatus GetDepinServiceStatus()
{
    LOCK(cs_main);
    CDepinServiceStatus status;
    const CBlockIndex* tip = chainActive.Tip();
    const int64_t maxAge = gArgs.GetArg("-depinmaxtipage", DEFAULT_DEPIN_MAX_TIP_AGE);
    const int64_t maxLag = gArgs.GetArg("-depinmaxheaderlag", DEFAULT_DEPIN_MAX_HEADER_LAG);
    status.height = chainActive.Height();
    status.headers = pindexBestHeader ? pindexBestHeader->nHeight : -1;
    status.tipAge = tip ? std::max<int64_t>(0, GetTime() - tip->GetBlockTime()) : 0;
    if (maxAge <= 0 || maxLag < 0) {
        status.reason = "invalid freshness configuration";
    } else if (fImporting || fReindex || !tip || !pindexBestHeader || !pcoinsTip || !passets ||
               tip->nChainWork < nMinimumChainWork) {
        status.reason = "initial block download or chainstate unavailable";
    } else if (status.tipAge > maxAge) {
        status.reason = "active tip is too old";
    } else if (int64_t(status.headers) - status.height > maxLag) {
        status.reason = "active chain is behind known headers";
    } else if (pDepinMsgPool && !pDepinMsgPool->StorageHealthy()) {
        status.reason = "durable storage unavailable; restart required";
    } else if (IsInitialBlockDownload()) {
        status.reason = "initial block download";
    } else {
        status.ready = true;
    }
    return status;
}

bool CheckDepinServiceReady(std::string& error)
{
    const CDepinServiceStatus status = GetDepinServiceStatus();
    if (!status.ready) {
        error = "DePIN service not ready: " + status.reason;
        return false;
    }
    return true;
}

bool DecodeDepinMessage(const std::vector<unsigned char>& bytes, CDepinMessage& message, std::string& error)
{
    try {
        if (bytes.size() > MAX_DEPIN_MESSAGE_WIRE_BYTES) throw std::ios_base::failure("message exceeds wire budget");
        CDataStream stream(bytes, SER_NETWORK, PROTOCOL_VERSION);
        CDepinMessage decoded;
        ReadDepinMessageBounded(stream, decoded);
        if (!stream.empty()) throw std::ios_base::failure("trailing message bytes");
        message = std::move(decoded);
        return true;
    } catch (const std::exception& e) {
        error = std::string("Invalid DePIN message: ") + e.what();
        return false;
    }
}

// CDepinMessage implementation

uint256 CDepinMessage::GetHash() const {
    CHashWriter ss(SER_GETHASH, 0);
    ss << token << senderAddress << timestamp << messageType << encryptedPayload;
    return ss.GetHash();
}

bool CDepinMessage::IsExpired(int64_t currentTime, int64_t expiryTimeSeconds) const {
    return expiryTimeSeconds < 0 || (currentTime >= timestamp &&
        uint64_t(currentTime) - uint64_t(timestamp) > uint64_t(expiryTimeSeconds));
}

std::string CDepinMessage::ToString() const {
    return strprintf("CDepinMessage(token=%s, sender=%s, timestamp=%d, payload_size=%d)",
                     token, senderAddress, timestamp, encryptedPayload.size());
}

// CDepinMsgPool implementation

CDepinMsgPool::CDepinMsgPool()
    : fEnabled(false),
      nMaxRecipients(DEFAULT_MAX_DEPIN_RECIPIENTS),
      nMaxMessageSize(DEFAULT_DEPIN_MESSAGE_SIZE),
      nMessageExpiryHours(DEFAULT_DEPIN_MESSAGE_EXPIRY_HOURS),
      nMaxPoolSizeMB(DEFAULT_DEPIN_POOL_SIZE_MB) {
    streamId = GetRandHash();
}

CDepinMsgPool::~CDepinMsgPool() = default;

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

bool CDepinMsgPool::Initialize(const std::string& token, unsigned int maxRecipients,
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

    // A pool with maxRecipients == 0 can never carry a message: the payload
    // size cap multiplies by it and the recipientKeys count check rejects
    // anything >= 1 recipient. Reject the misconfiguration at startup instead
    // of booting a pool that silently drops everything.
    if (maxMessageSize == 0 || messageExpiryHours == 0 || maxPoolSizeMB == 0) {
        LogPrintf("ERROR: DePIN size, expiry and pool limits must be positive\n");
        return false;
    }
    if (maxRecipients == 0) {
        LogPrintf("ERROR: -depinmsgmaxusers must be at least 1\n");
        return false;
    }

    // Token existence is not validated to allow server configuration before token creation
    // or during reindex when asset index may not be fully populated
    activeToken = token;

    // Apply limits
    nMaxRecipients = std::min(maxRecipients, MAX_DEPIN_RECIPIENTS);
    nMaxMessageSize = std::min(maxMessageSize, MAX_DEPIN_MESSAGE_SIZE);
    nMessageExpiryHours = std::min(messageExpiryHours, MAX_DEPIN_MESSAGE_EXPIRY_HOURS);
    nMaxPoolSizeMB = std::min(maxPoolSizeMB, MAX_DEPIN_POOL_SIZE_MB);

    fEnabled = true;

    LogPrintf("DePIN messaging initialized: token=%s, maxRecipients=%d, maxMessageSize=%d, expiryHours=%d, maxPoolSizeMB=%d\n",
              activeToken, nMaxRecipients, nMaxMessageSize, nMessageExpiryHours, nMaxPoolSizeMB);

    return true;
}

bool CDepinMsgPool::AddMessage(const CDepinMessage& message, std::string& error, bool skipSignatureCheck,
                              DepinAdmissionError* admissionError) {
    if (admissionError) *admissionError = DepinAdmissionError::NONE;
    // A block cannot connect or disconnect between authorization and insertion.
    // Never acquire cs_main for the first time under the pool lock.
    LOCK(cs_main);
    if (!CheckDepinServiceReady(error)) return false;
    return AddMessageInternal(message, error, skipSignatureCheck, /*restoring=*/false, admissionError);
}

bool CDepinMsgPool::AddMessageInternal(const CDepinMessage& message, std::string& error,
                                      bool skipSignatureCheck, bool restoring,
                                      DepinAdmissionError* admissionError, uint64_t restoreSequence) {
    if (!fEnabled) {
        error = "Chat mempool is not enabled";
        return false;
    }

    // Restoration bypasses current membership, never token syntax/type.
    if (!IsValidDepinMessagingToken(message.token, error)) return false;

    int64_t timestampFloor;
    {
        LOCK(cs_depinmsgpool);
        if (storageFault) { error = "DePIN storage unavailable"; return false; }
        timestampFloor = minimumTimestamp;
    }
    if (message.token.size() > 128 || message.senderAddress.size() > 64 || message.signature.size() > 80) {
        error = "DePIN message field exceeds size budget"; return false;
    }

    // Verify that the token is the active token or a section (sub-asset)
    // inside its subtree. The root itself always qualifies, so a pre-sections
    // client that only ever sends the configured token is unaffected.
    if (!IsDepinSectionOrRoot(message.token, activeToken)) {
        error = strprintf("Message token '%s' is not active token '%s' or a section inside it",
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
    if (message.timestamp < timestampFloor || message.timestamp < 0 ||
        (message.timestamp > currentTime && uint64_t(message.timestamp) - uint64_t(currentTime) > 60)) {
        error = "Message timestamp is invalid, below the durable retention floor, or too far in the future";
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

    // Bound ECIES wire bytes, then enforce the configured plaintext length
    // and per-recipient overhead separately during strict decoding.
    const size_t MAX_TOTAL_SIZE = DepinECIESWireLimit(nMaxMessageSize, nMaxRecipients);
    if (message.encryptedPayload.size() > MAX_TOTAL_SIZE) {
        error = strprintf("Message payload too large (%d bytes), maximum is %d",
                         message.encryptedPayload.size(), MAX_TOTAL_SIZE);
        return false;
    }

    CECIESEncryptedMessage eciesProbe;
    if (!DecodeDepinECIES(message.encryptedPayload, nMaxMessageSize, nMaxRecipients, eciesProbe, error))
        return false;
    std::vector<uint160> recipients;
    for (const auto& entry : eciesProbe.recipientKeys) recipients.push_back(entry.first);

    CDepinMessage admitted = message;
    // Restored v2 messages have already been checked against their saved key.
    if (!skipSignatureCheck) {
        if (!VerifyDepinMessageSignature(message, &admitted.verifiedSenderKey)) {
            error = "Invalid message signature";
            return false;
        }
    } else {
        LogPrintf("AddMessage: Skipping signature check for pre-authenticated message\n");
    }

    // New publications require current sender and recipient permissions.
    // Restoration preserves valid historical messages for remaining readers.
    const int64_t permissionStart = GetTimeMicros();
    if (!restoring) {
        if (!HasDepinSectionAccess(message.senderAddress, message.token, activeToken, error)) {
            return false;
        }
        for (const uint160& id : recipients) {
            const std::string address = EncodeDestination(CKeyID(id));
            std::string accessError;
            if (!HasDepinSectionAccess(address, message.token, activeToken, accessError)) {
                if (admissionError) *admissionError = DepinAdmissionError::RECIPIENT_NOT_AUTHORIZED;
                error = strprintf("Recipient not authorized: %s: %s", address, accessError);
                return false;
            }
        }
    }
    gDepinAdmissionStats.permissionMicros += GetTimeMicros() - permissionStart;

    // Permission reads and signature work run before taking the pool lock.
    // cs_main is still held by AddMessage, so no authorization can go stale.
    const int64_t poolWaitStart = GetTimeMicros();
    LOCK(cs_depinmsgpool);
    const int64_t poolStart = GetTimeMicros();
    gDepinAdmissionStats.poolWaitMicros += poolStart - poolWaitStart;
    // Cleanup may encounter an I/O failure while signature/permission work
    // runs outside the pool lock. Recheck before any admission or disk write.
    if (storageFault) { error = "DePIN storage unavailable"; return false; }
    if (message.timestamp < minimumTimestamp) { error = "Message timestamp below retention floor"; return false; }
    const size_t currentPoolSize = DynamicMemoryUsage();
    const size_t maxPoolSizeBytes = (size_t)nMaxPoolSizeMB * 1024 * 1024;
    const size_t incomingSize = sizeof(CDepinMessage) + message.token.size() + message.senderAddress.size() +
                                message.signature.size() + message.encryptedPayload.size() + 320;
    if (currentPoolSize + incomingSize > maxPoolSizeBytes) {
        error = strprintf("Pool size limit exceeded (current: %d MB, limit: %d MB). Message rejected.",
                         currentPoolSize / (1024 * 1024), nMaxPoolSizeMB);
        return false;
    }

    // Add message
    uint256 hash = message.GetHash();

    // Verify if it already exists
    if (mapMessages.count(hash)) {
        error = "Message already exists in mempool";
        return false;
    }

    auto tombstone = tombstones.find(hash);
    if (tombstone != tombstones.end() && GetTime() <= tombstone->second) {
        error = "Message was administratively deleted";
        return false;
    }
    if (!restoreSequence && highWater >= uint64_t(std::numeric_limits<int64_t>::max())) {
        error = "DePIN admission sequence exhausted"; return false;
    }
    const uint64_t sequence = restoring && restoreSequence ? restoreSequence : highWater + 1;
    // Allocate all index nodes before the durable write. The pool lock keeps
    // provisional entries invisible; every failure rolls them back together.
    const std::vector<uint256> rollback{hash};
    auto undo = [&] {
        mapBySequence.erase(sequence);
        sequenceByHash.erase(hash);
        ApplyErase(rollback);
    };
    try {
        mapMessages.emplace(hash, std::move(admitted));
        mapByTime.emplace(message.timestamp, hash);
        mapBySequence.emplace(sequence, hash);
        sequenceByHash.emplace(hash, sequence);
        if (!restoring && !CommitAdmission(mapMessages.at(hash), sequence, error)) {
            undo(); return false;
        }
    } catch (...) { undo(); throw; }
    highWater = std::max(highWater, sequence);

    LogPrint(BCLog::MEMPOOL, "DePIN message added: hash=%s, sender=%s, payload_size=%d\n",
             hash.ToString(), message.senderAddress, message.encryptedPayload.size());

    gDepinAdmissionStats.poolHoldMicros += GetTimeMicros() - poolStart;
    gDepinAdmissionStats.admitted++;
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
                                         const uint160* addressHash160,
                                         const std::string& scopeToken) {
    // Scope first: BEFORE the sender shortcut (a sender's own message from
    // another section must not appear in the wrong tab) and before the ECIES
    // deserialization below (the expensive part). Empty scope is the
    // historical behavior, untouched.
    if (!scopeToken.empty() && !IsDepinSectionOrRoot(msg.token, scopeToken)) {
        return false;
    }

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
        std::string error;
        if (!DecodeDepinECIES(msg.encryptedPayload, MAX_DEPIN_MESSAGE_SIZE, MAX_DEPIN_RECIPIENTS, eciesMsg, error))
            return false;
        return eciesMsg.recipientKeys.count(*addressHash160) > 0;
    } catch (const std::exception& e) {
        LogPrint(BCLog::NET, "ShouldDeliverDepinMessageToAddress: Failed to deserialize ECIES message: %s\n", e.what());
        return false;
    }
}

std::vector<CDepinMessage> FilterDepinMessagesForAddress(const std::vector<const CDepinMessage*>& messages,
                                                         const std::string& address,
                                                         const uint160* addressHash160,
                                                         const std::string& scopeToken) {
    std::vector<CDepinMessage> result;
    for (const CDepinMessage* msg : messages) {
        if (msg && ShouldDeliverDepinMessageToAddress(*msg, address, addressHash160, scopeToken)) {
            result.push_back(*msg);
        }
    }
    return result;
}

std::vector<CDepinMessage> CDepinMsgPool::GetMessagesForAddress(const std::string& address,
                                                                const std::string& scopeToken) const {
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
    const int64_t now = GetTime();
    const int64_t expiry = GetMessageExpiryTime();
    for (const auto& timeEntry : mapByTime) {
        auto it = mapMessages.find(timeEntry.second);
        if (it == mapMessages.end()) {
            continue;  // Should not happen, but be defensive
        }
        // Expiry applies even to the sender's own messages, before visibility
        // shortcuts and independently of periodic cleanup.
        if (it->second.IsExpired(now, expiry)) {
            continue;
        }
        ordered.push_back(&it->second);
    }

    return FilterDepinMessagesForAddress(ordered, address, hashPtr, scopeToken);
}

std::vector<CDepinMessage> CDepinMsgPool::GetAllMessages(bool includeExpired) const {
    LOCK(cs_depinmsgpool);
    const int64_t now = GetTime();
    const int64_t expiry = GetMessageExpiryTime();
    std::vector<CDepinMessage> result;
    for (const auto& entry : mapMessages) {
        if (!includeExpired && entry.second.IsExpired(now, expiry)) {
            continue;
        }
        result.push_back(entry.second);
    }
    return result;
}

size_t CDepinMsgPool::GetMessageCount() const {
    LOCK(cs_depinmsgpool);
    return mapMessages.size();
}

void CDepinMsgPool::EraseMessages(const std::vector<uint256>& hashes) {
    std::string error;
    if (!CommitErase(hashes, false, GetTime(), error)) {
        LogPrintf("DePIN cleanup failed: %s\n", error);
        return;
    }
    ApplyErase(hashes);
}

void CDepinMsgPool::ApplyErase(const std::vector<uint256>& hashes) {
    for (const auto& hash : hashes) {
        auto it = mapMessages.find(hash);
        if (it != mapMessages.end()) {
            int64_t timestamp = it->second.timestamp;
            auto sequence = sequenceByHash.find(hash);
            if (sequence != sequenceByHash.end()) {
                mapBySequence.erase(sequence->second);
                sequenceByHash.erase(sequence);
            }
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
}

void CDepinMsgPool::RemoveExpiredMessages(int64_t currentTime, const std::string& scopeToken) {
    LOCK(cs_depinmsgpool);

    std::vector<uint256> toRemove;
    int64_t expiryTime = GetMessageExpiryTime();

    for (const auto& entry : mapMessages) {
        if (!scopeToken.empty() && !IsDepinSectionOrRoot(entry.second.token, scopeToken)) {
            continue;
        }
        if (entry.second.IsExpired(currentTime, expiryTime)) {
            toRemove.push_back(entry.first);
        }
    }

    EraseMessages(toRemove);

    if (!toRemove.empty()) {
        LogPrint(BCLog::MEMPOOL, "Removed %d expired chat messages\n", toRemove.size());
    }
}

void CDepinMsgPool::RemoveMessagesOlderThan(int64_t currentTime, int64_t ageThresholdSeconds,
                                            const std::string& scopeToken) {
    LOCK(cs_depinmsgpool);

    std::vector<uint256> toRemove;

    for (const auto& entry : mapMessages) {
        if (!scopeToken.empty() && !IsDepinSectionOrRoot(entry.second.token, scopeToken)) {
            continue;
        }
        if (entry.second.IsExpired(currentTime, ageThresholdSeconds)) {
            toRemove.push_back(entry.first);
        }
    }

    EraseMessages(toRemove);

    if (!toRemove.empty()) {
        int64_t hoursThreshold = ageThresholdSeconds / 3600;
        LogPrint(BCLog::MEMPOOL, "Removed %d messages older than %d hours\n", toRemove.size(), hoursThreshold);
    }
}

void CDepinMsgPool::Clear() {
    LOCK(cs_depinmsgpool);
    mapMessages.clear();
    mapByTime.clear();
    mapBySequence.clear();
    sequenceByHash.clear();
    LogPrint(BCLog::MEMPOOL, "Chat mempool cleared\n");
}

size_t CDepinMsgPool::ClearScope(const std::string& scopeToken) {
    LOCK(cs_depinmsgpool);

    std::vector<uint256> toRemove;
    for (const auto& entry : mapMessages) {
        if (IsDepinSectionOrRoot(entry.second.token, scopeToken)) {
            toRemove.push_back(entry.first);
        }
    }

    EraseMessages(toRemove);

    if (!toRemove.empty()) {
        LogPrint(BCLog::MEMPOOL, "Removed %d chat messages in scope %s\n",
                 toRemove.size(), scopeToken);
    }
    return toRemove.size();
}

size_t CDepinMsgPool::CountMessagesInScope(const std::string& scopeToken, int64_t now) const {
    LOCK(cs_depinmsgpool);
    const int64_t expiry = GetMessageExpiryTime();
    size_t count = 0;
    for (const auto& entry : mapMessages) {
        if (!entry.second.IsExpired(now, expiry) &&
            (scopeToken.empty() || IsDepinSectionOrRoot(entry.second.token, scopeToken))) {
            count++;
        }
    }
    return count;
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
        total += sizeof(CDepinMessage) + 320; // conservative charge for four tree indexes
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

bool CDepinMsgPool::GetSections(std::vector<std::string>& sections, std::string& error) {
    LOCK(cs_main);
    if (!CheckDepinServiceReady(error)) return false;
    if (!fEnabled) {
        error = "Chat mempool is not enabled";
        return false;
    }
    if (!passetsdb) {
        error = "Asset database not available";
        return false;
    }

    // Lazy invalidation on tip change: zero work while nobody asks, reorgs
    // covered for free (any tip change invalidates), and nothing runs inside
    // the validation thread. Lock order cs_main -> cs_sectionCache.
    uint256 tip;
    {
        LOCK(cs_main);
        if (chainActive.Tip()) {
            tip = chainActive.Tip()->GetBlockHash();
        }
    }

    {
        LOCK(cs_sectionCache);
        if (!tip.IsNull() && tip == sectionSnapshotTip && !sectionSnapshot.empty()) {
            sections = sectionSnapshot;
            return true;
        }
    }

    // Build outside the section-cache lock but under cs_main. Read persisted
    // metadata without flushing and merge creations/deletions from the tip.
    //
    // The '/'-terminated wildcard prefix already excludes "&TESTING" and
    // "&TEST.FOO"; IsDepinSectionOrRoot below is a belt-and-braces recheck.
    std::vector<CDatabasedAssetData> subAssets;
    if (!passetsdb->AssetDir(subAssets, activeToken + "/*", MAX_CACHE_ASSETS_SIZE, 0, /*flush=*/false)) {
        error = strprintf("Failed to enumerate sections of '%s' from the asset database", activeToken);
        return false;
    }

    if (!passets) {
        error = "Asset chainstate cache not available";
        return false;
    }
    std::set<std::string> names;
    for (const auto& data : subAssets) {
        const std::string& name = data.asset.strName;
        if (name != activeToken && IsDepinSectionOrRoot(name, activeToken)) names.insert(name);
    }
    for (const auto& item : passets->setNewAssetsToRemove) names.erase(item.asset.strName);
    for (const auto& item : passets->setNewAssetsToAdd) {
        const std::string& name = item.asset.strName;
        if (name != activeToken && IsDepinSectionOrRoot(name, activeToken)) names.insert(name);
    }
    std::vector<std::string> built{activeToken};
    built.insert(built.end(), names.begin(), names.end());

    {
        LOCK(cs_sectionCache);
        sectionSnapshotTip = tip;
        sectionSnapshot = built;
    }

    sections = built;
    return true;
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
        (addressData.type != DEST_INDEX_KEY && addressData.type != DEST_INDEX_WITNESS_V1_AUTHSCRIPT &&
         addressData.type != DEST_INDEX_WITNESS_V2_STRICT_PQ && addressData.type != DEST_INDEX_WITNESS_V3_STRICT_ECDSA)) {
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

bool VerifyDepinMessageSignature(const CDepinMessage& message, CPubKey* verifiedKey) {
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

    // The signed hash is the message identifier itself:
    // doubleSHA256(token || senderAddress || timestamp || messageType || encryptedPayload)
    uint256 messageHash = message.GetHash();

    const auto destination = DecodeDestination(message.senderAddress);
    const CKeyID* senderId = boost::get<CKeyID>(&destination);
    if (senderId && senderPubKey.GetID() == *senderId && senderPubKey.Verify(messageHash, message.signature)) {
        if (verifiedKey) *verifiedKey = senderPubKey;
        return true;
    }

    LogPrintf("VerifyDepinMessageSignature: Signature verification failed\n");
    LogPrintf("  Sender: %s\n", message.senderAddress);
    LogPrintf("  Token: %s\n", message.token);
    LogPrintf("  Timestamp: %d\n", message.timestamp);
    LogPrintf("  MessageType: 0x%02x\n", message.messageType);
    LogPrintf("  Signature size: %d bytes\n", message.signature.size());
    LogPrintf("  Signature hex: %s\n", HexStr(message.signature));
    LogPrintf("  Message hash: %s\n", messageHash.ToString());
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

    // Sign the message identifier (GetHash). messageType is covered by the
    // hash, so it must already hold its final value when signing.
    uint256 messageHash = message.GetHash();

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

// Shared preconditions of the two authorization checks below. Each absence is a
// named error BEFORE any read: answering "no access" for a database the node
// cannot read would deny with a false reason, which misleads exactly like
// granting too much. fRequireRestrictions distinguishes the holder check (needs
// prestricteddb: reading restrictions from a null pointer fails OPEN, letting
// frozen and self-revoked holders publish) from the owner check (owner tokens
// cannot be frozen or self-revoked, so it only reads balances).
static bool CheckDepinAccessPreconditions(bool fRequireRestrictions, std::string& error)
{
    if (!fAssetIndex) {
        error = "Asset index is required but not enabled. Restart with -assetindex and -reindex";
        return false;
    }
    if (!passetsdb) {
        error = "Asset database not available";
        return false;
    }
    if (fRequireRestrictions && !prestricteddb) {
        error = "Restricted asset database not available; restriction state cannot be read, "
                "and treating every address as unrestricted would let frozen and revoked "
                "holders publish";
        return false;
    }
    if (!passets) {
        error = "Asset chainstate cache not available";
        return false;
    }
    return true;
}

bool HasDepinSectionAccess(const std::string& address, const std::string& sectionToken,
                           const std::string& root, std::string& error)
{
    LOCK(cs_main);
    if (!CheckDepinAccessPreconditions(true, error))
        return false;

    if (!IsValidDepinMessagingToken(sectionToken, error))
        return false;
    std::string rootError;
    if (!IsValidDepinMessagingToken(root, rootError)) {
        error = strprintf("Invalid pool root '%s': %s", root, rootError);
        return false;
    }

    std::vector<std::string> ancestors;
    if (!DeriveDepinAncestors(sectionToken, root, ancestors, error))
        return false;

    // Query results stay local; reading new pairs must not fill the global map
    // and indirectly trigger a full chainstate/UTXO flush.
    CAssetsCache balances;
    for (const std::string& ancestor : ancestors) {
        gDepinAdmissionStats.balanceQueries++;
        if (!GetBestAssetAddressAmount(balances, ancestor, address) ||
            balances.mapAssetsAddressAmount.at(std::make_pair(ancestor, address)) <= 0)
            continue;
        if (passets->CheckForDEPINRestriction(ancestor, address))
            continue;
        return true;
    }

    error = strprintf("Address '%s' holds no active balance of '%s' or of any of its "
                      "ancestors up to '%s'", address, sectionToken, root);
    return false;
}

bool HasDepinSectionOwnerAccess(const std::string& address, const std::string& sectionToken,
                                const std::string& root, std::string& error)
{
    LOCK(cs_main);
    if (!CheckDepinAccessPreconditions(false, error))
        return false;

    if (!IsValidDepinMessagingToken(sectionToken, error))
        return false;
    std::string rootError;
    if (!IsValidDepinMessagingToken(root, rootError)) {
        error = strprintf("Invalid pool root '%s': %s", root, rootError);
        return false;
    }

    // Derive over the BASE names and re-append OWNER_TAG per level:
    // "&TEST/GENERAL!" is not a component of anything, so deriving over the
    // owner name itself would answer a meaningless question.
    std::vector<std::string> ancestors;
    if (!DeriveDepinAncestors(sectionToken, root, ancestors, error))
        return false;

    CAssetsCache balances;
    for (const std::string& ancestor : ancestors) {
        const std::string owner = ancestor + OWNER_TAG;
        gDepinAdmissionStats.balanceQueries++;
        if (GetBestAssetAddressAmount(balances, owner, address) &&
            balances.mapAssetsAddressAmount.at(std::make_pair(owner, address)) > 0) {
            return true;
        }
    }

    error = strprintf("Address '%s' does not hold the owner token of '%s' or of any of its "
                      "ancestors up to '%s'", address, sectionToken, root);
    return false;
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

} // namespace

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

bool IsDepinSectionOrRoot(const std::string& name, const std::string& root)
{
    if (root.empty() || name.size() < root.size())
        return false;
    if (name.compare(0, root.size(), root) != 0)
        return false;
    // The character after the root prefix decides everything: end-of-string is
    // the root itself, '/' is a section, anything else ("&TESTING", "&TEST.FOO")
    // is a different asset that merely shares a prefix.
    return name.size() == root.size() || name[root.size()] == DEPIN_SECTION_DELIMITER;
}

std::string GetDepinSectionLabel(const std::string& name, const std::string& root)
{
    if (!IsDepinSectionOrRoot(name, root))
        return name;
    if (name.size() == root.size())
        return "";
    return name.substr(root.size() + 1);
}

namespace {

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

    // The public helper owns the chain lock so each caller gets a coherent
    // directory. Recursive acquisition is safe for callers already holding it.
    LOCK(cs_main);

    // Fail closed before reading any chainstate-dependent data.
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

    // Name validation and ancestor derivation are pure and precede disk reads.
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

    if (!passets || !passetsCache) {
        error = "Asset chainstate cache not available";
        return false;
    }
    // No disk flush: read and merge the connected-tip cache under cs_main.
    if (!CheckDepinServiceReady(error)) return false;

    // Each ancestor must exist exactly. A missing intermediate level is an
    // error, never something to skip on the way to the root: silently jumping
    // over it would answer a different question than the one asked.
    for (const std::string& ancestor : ancestors) {
        CNewAsset asset;
        int assetHeight = 0;
        uint256 assetBlockHash;
        if (!passets->GetAssetMetaDataIfExists(ancestor, asset, assetHeight, assetBlockHash)) {
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

    size_t rowCount = 0;
    for (const auto& rows : rowsByAsset) rowCount += rows.second.size();
    for (const std::string& ancestor : ancestors) {
        auto& rows = rowsByAsset[ancestor];
        std::map<std::string, CAmount> current(rows.begin(), rows.end());
        auto it = passets->mapAssetsAddressAmount.lower_bound(std::make_pair(ancestor, std::string()));
        for (; it != passets->mapAssetsAddressAmount.end() && it->first.first == ancestor; ++it) {
            const std::string& address = it->first.second;
            if (!current.count(address)) {
                if (it->second <= 0) continue;
                if (++rowCount > MAX_DEPIN_ANCESTOR_SCAN_ROWS) {
                    error = "Recipient working set exceeds the exploration limit";
                    return false;
                }
            }
            current[address] = it->second; // Includes zero-balance deletions.
        }
        rows.assign(current.begin(), current.end());
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

        // Membership follows the connected cache, including pending freezes,
        // unfreezes and self-revocations. One active pair is enough: holding
        // an ancestor already grants visibility over the branch, so revoking in
        // a section does not withdraw what the root grants. Deciding this after
        // looking at ALL of the address's pairs is what keeps skippedRestricted
        // from counting addresses that are still active elsewhere.
        bool hasActivePair = false;
        gDepinAncestorRecipientsStats.restrictionQueries++;
        for (const std::string& assetName : entry.second) {
            if (passets->CheckForDEPINRestriction(assetName, address))
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
        if (!DecodeDepinECIES(encryptedData, MAX_DEPIN_MESSAGE_SIZE, MAX_DEPIN_RECIPIENTS, eciesMsg, error))
            return false;
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
bool SignDepinChallenge(CWallet* pwallet,
                        const std::string& address,
                        const std::string& token,
                        const std::string& challenge,
                        std::string& signature,
                        std::string& error,
                        DepinChallengeType type) {
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

    // One preimage helper for signer and verifier: the two cannot drift apart.
    return SignDepinChallengePreimage(key, DepinChallengePreimage(type, token, address, challenge),
                                      signature, error);
}
#endif
