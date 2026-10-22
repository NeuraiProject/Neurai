// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.

#include "depinaddress.h"
#include "depinmsgpool.h"
#include "dbwrapper.h"
#include "depinecies.h"
#include "base58.h"
#include "hash.h"
#include "random.h"
#include "utiltime.h"
#include "validation.h"

#include <limits>

namespace {
const char META = 'V', MESSAGE = 'M', TOMBSTONE = 'T', QUARANTINE = 'Q';
const uint32_t STATE_VERSION = 2;
const int64_t MAX_RETENTION = int64_t(MAX_DEPIN_MESSAGE_EXPIRY_HOURS) * 3600;

struct StateMeta {
    uint32_t version = STATE_VERSION;
    std::string root;
    uint256 stream;
    uint64_t high = 0;
    uint8_t keep = 0;
    int64_t minimumTimestamp = 0;
    uint8_t legacyDone = 0;
    template <typename Stream> void Serialize(Stream& s) const {
        s << version << root << stream << high << keep << minimumTimestamp << legacyDone;
    }
    template <typename Stream> void Unserialize(Stream& s) {
        s >> version;
        root = ReadDepinString(s, 128);
        s >> stream >> high >> keep >> minimumTimestamp >> legacyDone;
        if (!s.empty()) throw std::ios_base::failure("trailing DePIN metadata");
    }
};

struct StoredMessage {
    uint64_t sequence = 0;
    std::vector<unsigned char> bytes;
    CPubKey senderKey;
    template <typename Stream> void Serialize(Stream& s) const { s << sequence << bytes << senderKey; }
    template <typename Stream> void Unserialize(Stream& s) {
        s >> sequence;
        bytes = ReadDepinBytes(s, MAX_DEPIN_MESSAGE_WIRE_BYTES);
        const auto key = ReadDepinBytes(s, 65);
        senderKey = CPubKey(key.begin(), key.end());
        if (!s.empty()) throw std::ios_base::failure("trailing DePIN record");
    }
};

StoredMessage EncodeRecord(const CDepinMessage& message, uint64_t sequence)
{
    CDataStream data(SER_DISK, CLIENT_VERSION);
    data << message;
    return {sequence, std::vector<unsigned char>(data.begin(), data.end()), message.verifiedSenderKey};
}

fs::path StatePath(const std::string& root)
{
    CHashWriter hash(SER_GETHASH, 0);
    hash << root;
    return GetDataDir() / "depinstate-v2" / hash.GetHash().ToString();
}

void Require(bool condition, const std::string& error)
{
    if (!condition) throw std::runtime_error(error);
}
}

bool CDepinMsgPool::StorageHealthy() const { LOCK(cs_depinmsgpool); return !storageFault; }
uint256 CDepinMsgPool::GetStreamId() const { LOCK(cs_depinmsgpool); return streamId; }
uint64_t CDepinMsgPool::GetHighWater() const { LOCK(cs_depinmsgpool); return highWater; }
size_t CDepinMsgPool::GetTombstoneCount() const { LOCK(cs_depinmsgpool); return tombstones.size(); }

bool CDepinMsgPool::FailStorage(const std::string& reason, std::string& error)
{
    storageFault = true;
    error = "DePIN durable storage failure: " + reason;
    LogPrintf("%s; service disabled until restart\n", error);
    return false;
}

bool CDepinMsgPool::CommitAdmission(const CDepinMessage& message, uint64_t sequence, std::string& error)
{
    if (!store || !persistMessages) return !storageFault;
    try {
        CDBBatch batch(*store);
        batch.Write(META, StateMeta{STATE_VERSION, activeToken, streamId, sequence, 1, minimumTimestamp, uint8_t(legacyImported)});
        batch.Write(std::make_pair(MESSAGE, message.GetHash()), EncodeRecord(message, sequence));
        Require(store->WriteBatch(batch, true), "admission sync failed");
        return true;
    } catch (const std::exception& e) { return FailStorage(e.what(), error); }
}

bool CDepinMsgPool::CommitErase(const std::vector<uint256>& hashes, bool moderation, int64_t now,
                               std::string& error, const std::map<uint256, int64_t>* retainedTimestamps)
{
    if (storageFault) { error = "DePIN storage unavailable"; return false; }
    if (hashes.empty() && !moderation) return true;
    // Keep moderation hashes for the longest configurable TTL, so increasing
    // -depinmsgexpire cannot revive an already acknowledged deletion.
    std::map<uint256, int64_t> marks;
    int64_t nextFloor = minimumTimestamp;
    const int64_t expiredBefore = now > MAX_RETENTION ? now - MAX_RETENTION : 0;
    if (moderation) {
        for (const auto& entry : tombstones) {
            if (now <= entry.second) marks.insert(entry);
            else nextFloor = std::max(nextFloor, expiredBefore);
        }
        for (const auto& hash : hashes) {
            const auto it = mapMessages.find(hash);
            if (it == mapMessages.end() && (!retainedTimestamps || !retainedTimestamps->count(hash))) continue;
            const int64_t timestamp = it != mapMessages.end() ? it->second.timestamp : retainedTimestamps->at(hash);
            const int64_t expiry = timestamp > std::numeric_limits<int64_t>::max() - MAX_RETENTION
                ? std::numeric_limits<int64_t>::max() : timestamp + MAX_RETENTION;
            if (now <= expiry) marks[hash] = expiry;
            else nextFloor = std::max(nextFloor, expiredBefore);
        }
        if (marks.size() > tombstoneLimit) {
            error = "DePIN tombstone capacity exceeded; nothing deleted";
            return false;
        }
    }
    try {
        if (store) {
            CDBBatch batch(*store);
            for (const auto& hash : hashes) batch.Erase(std::make_pair(MESSAGE, hash));
            if (moderation) {
                for (const auto& old : tombstones)
                    if (!marks.count(old.first)) batch.Erase(std::make_pair(TOMBSTONE, old.first));
                for (const auto& entry : marks) batch.Write(std::make_pair(TOMBSTONE, entry.first), entry.second);
            }
            batch.Write(META, StateMeta{STATE_VERSION, activeToken,
                persistMessages ? streamId : checkpointStream,
                persistMessages ? highWater : checkpointHigh,
                uint8_t(persistMessages || checkpointKeep), nextFloor, uint8_t(legacyImported)});
            Require(store->WriteBatch(batch, true), "deletion sync failed");
        }
        if (moderation) tombstones.swap(marks);
        minimumTimestamp = nextFloor;
        return true;
    } catch (const std::exception& e) { return FailStorage(e.what(), error); }
}

bool CDepinMsgPool::Purge(const std::string& scope, int64_t now, bool all, int64_t olderThan,
                         size_t& removed, std::string& error)
{
    LOCK(cs_depinmsgpool);
    removed = 0;
    std::map<uint256, int64_t> selected;
    for (const auto& entry : mapMessages) {
        const auto& message = entry.second;
        if (!scope.empty() && !IsDepinSectionOrRoot(message.token, scope)) continue;
        if (all || message.IsExpired(now, olderThan)) selected[entry.first] = message.timestamp;
    }
    // Disabling message retention does not erase the previous checkpoint.
    // Moderation must still cover it, or re-enabling retention could undo an
    // acknowledged "all"/scope/age deletion of currently invisible history.
    if (store && !persistMessages) {
        try {
            std::unique_ptr<CDBIterator> it(store->NewIterator());
            it->Seek(std::make_pair(MESSAGE, uint256()));
            while (it->Valid()) {
                char type;
                Require(it->GetKey(type), "unreadable checkpoint key");
                if (type != MESSAGE) break;
                std::pair<char, uint256> key;
                StoredMessage record;
                CDepinMessage message;
                std::string decodeError;
                Require(it->GetKeySize() == 33 && it->GetKey(key) &&
                        it->GetValueSize() <= MAX_DEPIN_MESSAGE_WIRE_BYTES + 83 && it->GetValue(record) &&
                        DecodeDepinMessage(record.bytes, message, decodeError) && message.GetHash() == key.second,
                        "cannot safely moderate damaged retained checkpoint");
                if ((scope.empty() || IsDepinSectionOrRoot(message.token, scope)) &&
                    (all || message.IsExpired(now, olderThan))) selected[key.second] = message.timestamp;
                it->Next();
            }
            it->CheckStatus();
        } catch (const std::exception& e) { return FailStorage(e.what(), error); }
    }
    std::vector<uint256> hashes;
    hashes.reserve(selected.size());
    for (const auto& entry : selected) hashes.push_back(entry.first);
    if (!CommitErase(hashes, true, now, error, &selected)) return false;
    ApplyErase(hashes);
    removed = hashes.size();
    return true;
}

bool CDepinMsgPool::GetLegacyPage(const std::string& address, const std::string& scope, int64_t from,
                                 const std::string& anchor, size_t limit, std::vector<CDepinMessage>& messages,
                                 bool& hasMore, std::string& error) const
{
    LOCK(cs_depinmsgpool);
    if (storageFault) { error = "DePIN storage unavailable"; return false; }
    DepinRecipient id;
    if (!DepinRecipient::FromAddress(address, id)) { error = "Legacy or strict ECDSA address required"; return false; }
    uint256 hash;
    if (!anchor.empty()) hash.SetHex(anchor);
    bool found = anchor.empty();
    const int64_t now = GetTime();
    size_t bytes = 2048;
    hasMore = false;
    messages.clear();
    for (const auto& entry : mapByTime) {
        const auto& message = mapMessages.at(entry.second);
        if (message.timestamp < from || message.IsExpired(now, GetMessageExpiryTime()) ||
            !ShouldDeliverDepinMessageToAddress(message, address, &id, scope)) continue;
        if (!found) { if (entry.second == hash) found = true; continue; }
        const size_t cost = 2 * (message.encryptedPayload.size() + message.signature.size()) + 1024;
        if ((limit && messages.size() >= limit) || bytes + cost > MAX_DEPIN_REPLY_PLAINTEXT) {
            hasMore = true; break;
        }
        messages.push_back(message);
        bytes += cost;
    }
    if (!found) { error = "after_hash not found in available messages"; return false; }
    return true;
}

bool CDepinMsgPool::GetSequencePage(const std::string& address, const std::string& scope,
                                   const uint256& stream, uint64_t after, size_t limit,
                                   int64_t fromTimestamp, CDepinSequencePage& page, std::string& error) const
{
    LOCK(cs_depinmsgpool);
    if (storageFault) { error = "DePIN storage unavailable"; return false; }
    if (stream != streamId) { error = "DePIN stream changed; restart pagination and deduplicate by hash"; return false; }
    if (after > highWater) { error = "DePIN cursor is ahead of this stream"; return false; }
    if (!limit || limit > 1000) { error = "limit must be 1..1000"; return false; }
    page = CDepinSequencePage();
    page.stream = streamId;
    page.after = after;
    DepinRecipient id;
    if (!DepinRecipient::FromAddress(address, id)) { error = "Legacy or strict ECDSA address required"; return false; }
    const int64_t now = GetTime();
    size_t bytes = 2048; // response metadata and chained nonce allowance
    for (auto it = mapBySequence.upper_bound(after); it != mapBySequence.end(); ++it) {
        const auto& message = mapMessages.at(it->second);
        if (message.IsExpired(now, GetMessageExpiryTime()) || message.timestamp < fromTimestamp ||
            !ShouldDeliverDepinMessageToAddress(message, address, &id, scope)) {
            page.after = it->first;
            continue;
        }
        const size_t cost = 2 * (message.encryptedPayload.size() + message.signature.size()) + 1024;
        if (page.messages.size() >= limit || bytes + cost > MAX_DEPIN_REPLY_PLAINTEXT) {
            page.hasMore = true;
            break;
        }
        page.messages.push_back({it->first, message});
        page.after = it->first;
        bytes += cost;
    }
    if (!page.hasMore) page.after = highWater;
    return true;
}

bool CDepinMsgPool::InitializeStorage(bool keepMessages, std::string& error, size_t maxTombstones)
{
    LOCK(cs_main);
    LOCK(cs_depinmsgpool);
    try {
        Require(maxTombstones && maxTombstones <= MAX_DEPIN_TOMBSTONE_LIMIT, "invalid tombstone limit");
        tombstoneLimit = maxTombstones;
        store.reset();
        const fs::path path = StatePath(activeToken);
        fs::create_directories(path.parent_path());
        store.reset(new CDBWrapper(path, 1 << 20));
        std::unique_ptr<CDBIterator> metadata(store->NewIterator());
        metadata->Seek(META);
        char metadataType = 0;
        const bool existed = metadata->Valid() && metadata->GetKey(metadataType) && metadataType == META;
        StateMeta meta;
        if (existed) {
            Require(metadata->GetKeySize() == 1 && metadata->GetValueSize() <= 256 && metadata->GetValue(meta),
                    "unreadable critical metadata");
            Require(meta.version == STATE_VERSION && meta.root == activeToken && !meta.stream.IsNull() &&
                    meta.high <= uint64_t(std::numeric_limits<int64_t>::max()) && meta.keep <= 1 && meta.minimumTimestamp >= 0 && meta.legacyDone <= 1,
                    "incompatible or corrupt DePIN metadata");
        }
        metadata->CheckStatus();
        minimumTimestamp = existed ? meta.minimumTimestamp : 0;
        legacyImported = existed && meta.legacyDone;
        storageFault = false;
        persistMessages = keepMessages;
        Clear();
        tombstones.clear();
        CDBBatch batch(*store);
        std::unique_ptr<CDBIterator> it(store->NewIterator());
        it->Seek(std::make_pair(TOMBSTONE, uint256()));
        while (it->Valid()) {
            char type;
            Require(it->GetKey(type), "unreadable state key");
            if (type != TOMBSTONE) break;
            std::pair<char, uint256> key;
            int64_t expiry = 0;
            Require(it->GetKeySize() == 33 && it->GetKey(key) && it->GetValueSize() == 8 && it->GetValue(expiry) && expiry >= 0,
                    "corrupt tombstone; deletion guarantees cannot be recovered");
            if (GetTime() <= expiry) {
                Require(tombstones.size() < tombstoneLimit, "stored tombstones exceed configured capacity");
                tombstones[key.second] = expiry;
            } else {
                batch.Erase(key);
                const int64_t now = GetTime();
                minimumTimestamp = std::max(minimumTimestamp, now > MAX_RETENTION ? now - MAX_RETENTION : 0);
            }
            Require(existed, "critical metadata missing while tombstones exist");
            it->Next();
        }
        it->CheckStatus();
        streamId = existed && keepMessages && meta.keep ? meta.stream : GetRandHash();
        highWater = 0;
        bool lostRecord = false;
        std::set<uint64_t> seenSequences;
        it.reset(store->NewIterator());
        it->Seek(std::make_pair(MESSAGE, uint256()));
        while (it->Valid()) {
            char type;
            Require(it->GetKey(type), "unreadable state key");
            if (type != MESSAGE) break;
            std::pair<char, uint256> key;
            Require(it->GetKeySize() == 33 && it->GetKey(key), "corrupt message key");
            Require(existed, "critical metadata missing while messages exist");
            if (existed && keepMessages && meta.keep) {
                StoredMessage record;
                Require(it->GetValueSize() <= MAX_DEPIN_MESSAGE_WIRE_BYTES + 83 && it->GetValue(record),
                        "corrupt message framing; preserve database for recovery");
                Require(record.sequence && record.sequence <= meta.high && seenSequences.insert(record.sequence).second,
                        "inconsistent admission counter");
                CDepinMessage message;
                std::string validationError;
                if (!DecodeDepinMessage(record.bytes, message, validationError) || message.GetHash() != key.second) {
                    lostRecord = true;
                    batch.Write(std::make_pair(QUARANTINE, key.second), record);
                    batch.Erase(key);
                } else if (message.IsExpired(GetTime(), GetMessageExpiryTime()) || message.timestamp < minimumTimestamp || tombstones.count(key.second)) {
                    batch.Erase(key);
                } else {
                    if (DepinPubKeyMatchesAddress(message.senderAddress, record.senderKey) &&
                        record.senderKey.Verify(message.GetHash(), message.signature)) {
                        message.verifiedSenderKey = record.senderKey;
                        if (!AddMessageInternal(message, validationError, true, true, nullptr, record.sequence)) {
                            lostRecord = true;
                            batch.Write(std::make_pair(QUARANTINE, key.second), record);
                            batch.Erase(key);
                            LogPrintf("DePIN: quarantined invalid complete record: %s\n", validationError);
                        }
                    } else {
                        lostRecord = true;
                        batch.Write(std::make_pair(QUARANTINE, key.second), record);
                        batch.Erase(key);
                        LogPrintf("DePIN: quarantined historical signature/key mismatch\n");
                    }
                }
            } // Disabled retention leaves the previous checkpoint untouched.
            it->Next();
        }
        it->CheckStatus();
        if (existed && keepMessages && meta.keep) highWater = meta.high;
        // First-time v1 migration is all-or-nothing. Never guess record borders
        // after truncation, and preserve the original file even on success.
        const fs::path legacy = GetDataDir() / "depinpool.dat";
        if (!legacyImported && keepMessages && fs::exists(legacy)) {
            Require(fs::file_size(legacy) <= size_t(nMaxPoolSizeMB) * 1024 * 1024 + (1 << 20), "legacy pool exceeds migration budget");
            CAutoFile file(fsbridge::fopen(legacy, "rb"), SER_DISK, CLIENT_VERSION);
            Require(!file.IsNull(), "cannot open legacy pool");
            uint32_t magic, version;
            int64_t saved;
            uint64_t count;
            file >> magic >> version >> saved >> count;
            Require(magic == DEPINPOOL_MAGIC_BYTES && version == 1 && count <= 1000000, "invalid legacy pool header");
            for (uint64_t n = 0; n < count; ++n) {
                CDepinMessage message;
                // Old releases admitted a larger payload before applying
                // semantic validation. Consume a complete old record within
                // that historical bound, then reject it without losing the
                // following record. Truncation still aborts initialization.
                ReadDepinMessageBounded(file, message, MAX_DEPIN_MESSAGE_SIZE * MAX_DEPIN_RECIPIENTS);
                std::string validationError;
                if (AddMessageInternal(message, validationError, false, true)) {
                    const uint256 hash = message.GetHash();
                    batch.Write(std::make_pair(MESSAGE, hash), EncodeRecord(mapMessages.at(hash), sequenceByHash.at(hash)));
                } else LogPrintf("DePIN v1 migration: skipped complete invalid record: %s\n", validationError);
            }
            Require(feof(file.Get()) || fgetc(file.Get()) == EOF, "trailing legacy pool data");
            file.fclose();
            const fs::path backup = legacy.string() + ".v1.bak";
            if (!fs::exists(backup)) fs::copy_file(legacy, backup);
        }
        if (keepMessages) legacyImported = true;
        if (lostRecord) streamId = GetRandHash();
        checkpointStream = keepMessages ? streamId : GetRandHash();
        checkpointHigh = keepMessages ? highWater : (existed ? meta.high : 0);
        checkpointKeep = keepMessages || (existed && meta.keep);
        if (keepMessages) batch.Write(META, StateMeta{STATE_VERSION, activeToken, streamId, highWater, 1, minimumTimestamp, uint8_t(legacyImported)});
        else {
            // Reserve a new identity for a future restored checkpoint, separate
            // from this volatile run. Never discard retained history on toggle.
            batch.Write(META, StateMeta{STATE_VERSION, activeToken, checkpointStream,
                                        checkpointHigh, uint8_t(checkpointKeep), minimumTimestamp, uint8_t(legacyImported)});
        }
        Require(store->WriteBatch(batch, true), "startup state sync failed");
        return true;
    } catch (const std::exception& e) {
        Clear();
        return FailStorage(e.what(), error);
    }
}

bool CDepinMsgPool::LoadFromDisk()
{
    std::string error;
    return InitializeStorage(true, error, tombstoneLimit);
}

bool CDepinMsgPool::SaveToDisk()
{
    LOCK(cs_depinmsgpool);
    if (storageFault) return false;
    try {
        if (!store) {
            const auto path = StatePath(activeToken);
            fs::create_directories(path.parent_path());
            store.reset(new CDBWrapper(path, 1 << 20));
        }
        CDBBatch batch(*store);
        std::unique_ptr<CDBIterator> it(store->NewIterator());
        it->Seek(std::make_pair(MESSAGE, uint256()));
        while (it->Valid()) {
            char type;
            Require(it->GetKey(type), "unreadable state key");
            if (type != MESSAGE) break;
            std::pair<char, uint256> key;
            Require(it->GetKeySize() == 33 && it->GetKey(key), "corrupt message key");
            batch.Erase(key);
            it->Next();
        }
        it->CheckStatus();
        for (const auto& entry : mapMessages)
            batch.Write(std::make_pair(MESSAGE, entry.first), EncodeRecord(entry.second, sequenceByHash.at(entry.first)));
        for (const auto& entry : tombstones) batch.Write(std::make_pair(TOMBSTONE, entry.first), entry.second);
        batch.Write(META, StateMeta{STATE_VERSION, activeToken, streamId, highWater, 1, minimumTimestamp, 1});
        Require(store->WriteBatch(batch, true), "snapshot sync failed");
        persistMessages = true;
        legacyImported = true;
        return true;
    } catch (const std::exception& e) {
        std::string error;
        return FailStorage(e.what(), error);
    }
}
