// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "silentpaymentindex.h"

#include "chain.h"
#include "chainparams.h"
#include "init.h"
#include "primitives/block.h"
#include "sync.h"
#include "txdb.h"
#include "ui_interface.h"
#include "undo.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validation.h"

#include <univalue.h>

#include <algorithm>
#include <map>

bool fSilentPaymentIndex = DEFAULT_SILENTPAYMENTINDEX;

namespace silentpayments {

size_t nIndexBatchBytes = DEFAULT_INDEX_BATCH_BYTES;

namespace {

CCriticalSection cs_index;
std::map<uint256, std::vector<unsigned char>> mapPendingRecords; // guarded by cs_index
size_t nPendingBytes = 0;                                         // guarded by cs_index
std::vector<std::pair<int, int>> vMissingRanges;                  // guarded by cs_index

/** Writes the pending records in a synchronous batch (cs_index held). */
bool WritePendingRecords()
{
    AssertLockHeld(cs_index);
    if (mapPendingRecords.empty()) return true;
    std::vector<std::pair<uint256, std::vector<unsigned char>>> records(mapPendingRecords.begin(), mapPendingRecords.end());
    if (!pblocktree->WriteSilentPaymentRecords(records, true)) return false;
    mapPendingRecords.clear();
    nPendingBytes = 0;
    return true;
}

/** Metadata: schema || start height (LE32) || context N. */
std::vector<unsigned char> EncodeMeta(int startHeight, const std::vector<unsigned char>& context)
{
    std::vector<unsigned char> meta{INDEX_SCHEMA};
    for (int i = 0; i < 4; ++i) meta.push_back(((uint32_t)startHeight >> (8 * i)) & 0xff);
    meta.insert(meta.end(), context.begin(), context.end());
    return meta;
}

/** Stored value: schema || canonical block bytes. */
std::vector<unsigned char> EncodeRecord(const IndexBlock& block)
{
    std::vector<unsigned char> value{INDEX_SCHEMA};
    SerializeIndexBlock(block, value);
    return value;
}

bool DecodeRecord(const std::vector<unsigned char>& value, IndexBlock& block, std::vector<unsigned char>& bytes)
{
    if (value.empty() || value[0] != INDEX_SCHEMA) return false;
    bytes.assign(value.begin() + 1, value.end());
    size_t pos = 0;
    std::string error;
    return DeserializeIndexBlock(bytes, pos, block, error) && pos == bytes.size();
}

/** A record is valid for an active block if it decodes strictly and its hash,
 *  height and parent are those of the block. */
bool ReadValidRecord(const CBlockIndex* pindex, std::vector<unsigned char>& bytes)
{
    IndexBlock block;
    if (!ReadIndexRecord(pindex->GetBlockHash(), block, bytes)) return false;
    const uint256 prev = pindex->pprev ? pindex->pprev->GetBlockHash() : uint256();
    return block.height == (uint32_t)pindex->nHeight && block.prev == prev;
}

/** Rebuild from the block files; false if the data is not available. */
bool RebuildRecord(const std::vector<unsigned char>& context, const CBlockIndex* pindex,
                   const Consensus::Params& consensus, std::vector<unsigned char>& value)
{
    AssertLockHeld(cs_main); // pruning deletes block files under cs_main
    if (!pindex->pprev || !(pindex->nStatus & BLOCK_HAVE_DATA) || !(pindex->nStatus & BLOCK_HAVE_UNDO)) return false;
    CBlock block;
    CBlockUndo undo;
    if (!ReadBlockFromDisk(block, pindex, consensus) ||
        !UndoReadFromDisk(undo, pindex->GetUndoPos(), pindex->pprev->GetBlockHash())) {
        LogPrintf("%s: cannot read block or undo data of %s\n", __func__, pindex->GetBlockHash().ToString());
        return false;
    }
    IndexBlock record;
    if (!BuildIndexBlock(context, block, undo, pindex, record)) {
        LogPrintf("%s: block %s does not match its undo data\n", __func__, pindex->GetBlockHash().ToString());
        return false;
    }
    value = EncodeRecord(record);
    return true;
}

void AddMissing(std::vector<std::pair<int, int>>& ranges, int height)
{
    if (!ranges.empty() && ranges.back().second + 1 == height) {
        ranges.back().second = height;
    } else {
        ranges.emplace_back(height, height);
    }
}

std::string HexBytes(const uint256& value) { return HexStr(value.begin(), value.end()); }

} // namespace

int IndexStartHeight(const Consensus::Params& consensus)
{
    return std::max(1, consensus.nStrictAuthScriptHeight);
}

bool BuildIndexBlock(const std::vector<unsigned char>& context, const CBlock& block, const CBlockUndo& undo,
                     const CBlockIndex* pindex, IndexBlock& out)
{
    if (block.vtx.empty() || undo.vtxundo.size() + 1 != block.vtx.size()) return false;
    IndexBlock result;
    result.hash = pindex->GetBlockHash();
    result.prev = pindex->pprev ? pindex->pprev->GetBlockHash() : uint256();
    result.height = pindex->nHeight;
    for (size_t i = 1; i < block.vtx.size(); ++i) {
        const CTransaction& tx = *block.vtx[i];
        const CTxUndo& txundo = undo.vtxundo[i - 1];
        if (txundo.vprevout.size() != tx.vin.size()) return false;
        std::vector<CTxOut> spent;
        spent.reserve(tx.vin.size());
        for (size_t j = 0; j < tx.vin.size(); ++j) {
            spent.push_back(txundo.vprevout[j].out);
            // Every spend of a native v3 output, whoever spends it: clients
            // learn that a payment is gone without asking for it.
            if (IsNativeV3Script(spent.back().scriptPubKey)) result.spent.push_back(tx.vin[j].prevout);
        }
        IndexEntry entry;
        if (BuildIndexEntry(context, tx, spent, entry)) result.entries.push_back(std::move(entry));
    }
    out = std::move(result);
    return true;
}

bool IndexConnectedBlock(const CBlock& block, const CBlockUndo& undo, const CBlockIndex* pindex)
{
    AssertLockHeld(cs_main);
    IndexBlock record;
    if (!BuildIndexBlock(LocalContext(), block, undo, pindex, record)) {
        return error("%s: block %s does not match its undo data", __func__, pindex->GetBlockHash().ToString());
    }
    std::vector<std::pair<uint256, std::vector<unsigned char>>> records{{record.hash, EncodeRecord(record)}};
    if (!pblocktree->WriteSilentPaymentRecords(records, false)) return false;
    LOCK(cs_index);
    std::vector<unsigned char>& pending = mapPendingRecords[records[0].first];
    nPendingBytes = nPendingBytes - pending.size() + records[0].second.size();
    pending = std::move(records[0].second);
    // Bounded memory: past the limit the records become durable now, earlier
    // than FlushIndex would make them, which keeps its guarantee.
    if (nPendingBytes > nIndexBatchBytes) return WritePendingRecords();
    return true;
}

bool FlushIndex()
{
    LOCK(cs_index);
    return WritePendingRecords();
}

void ResetIndex()
{
    LOCK(cs_index);
    mapPendingRecords.clear();
    nPendingBytes = 0;
    vMissingRanges.clear();
}

size_t PendingIndexRecords()
{
    LOCK(cs_index);
    return mapPendingRecords.size();
}

size_t PendingIndexBytes()
{
    LOCK(cs_index);
    return nPendingBytes;
}

bool InitIndex(const CChainParams& chainparams, int checkDepth, std::string& error)
{
    LOCK(cs_main);
    ResetIndex();
    const Consensus::Params& consensus = chainparams.GetConsensus();
    const int start = IndexStartHeight(consensus);
    const std::vector<unsigned char> context = LocalContext();
    std::vector<unsigned char> meta;
    const bool hasMeta = pblocktree->ReadSilentPaymentMeta(meta);

    if (!fSilentPaymentIndex) {
        if (hasMeta) {
            LogPrintf("Silent payment index disabled: erasing its records\n");
            if (!pblocktree->EraseSilentPaymentRecords() || !pblocktree->EraseSilentPaymentMeta()) {
                error = _("Failed to erase the silent payment index");
                return false;
            }
        }
        return true;
    }

    const int tipHeight = chainActive.Height();
    const std::vector<unsigned char> wanted = EncodeMeta(start, context);
    if (!hasMeta || meta != wanted) {
        // A node that already deleted block files cannot build the records
        // of the history it no longer has.
        if (fHavePruned && tipHeight >= start) {
            error = _("Enabling -silentpaymentindex on a pruned node requires -reindex");
            return false;
        }
        if (hasMeta) {
            LogPrintf("Silent payment index: schema, start height or chain changed; rebuilding\n");
            if (!pblocktree->EraseSilentPaymentRecords()) {
                error = _("Failed to erase the silent payment index");
                return false;
            }
        }
        if (!pblocktree->WriteSilentPaymentMeta(wanted)) {
            error = _("Failed to write the silent payment index");
            return false;
        }
    }

    // Verify every record of the active chain; rebuild what is absent or
    // invalid while the block files still have it.
    std::vector<std::pair<uint256, std::vector<unsigned char>>> writes;
    size_t writeBytes = 0;
    std::vector<std::pair<int, int>> missing;
    int rebuilt = 0, rewritten = 0, lastPercent = -1;
    const int total = std::max(0, tipHeight - start + 1);
    if (total > 0) LogPrintf("Verifying silent payment index from height %d to %d\n", start, tipHeight);
    for (int height = start; height <= tipHeight; ++height) {
        const int percent = (int)(100.0 * (height - start) / total);
        if (percent != lastPercent && total > 1000) {
            uiInterface.ShowProgress(_("Verifying silent payment index..."), percent, false);
            lastPercent = percent;
        }
        if (ShutdownRequested()) return true; // the next start resumes from the metadata
        const CBlockIndex* pindex = chainActive[height];
        std::vector<unsigned char> bytes, value;
        const bool valid = ReadValidRecord(pindex, bytes);
        const bool deep = height > tipHeight - checkDepth;
        if (valid && !deep) continue;
        if (!RebuildRecord(context, pindex, consensus, value)) {
            if (!valid) AddMissing(missing, height);
            continue; // a valid record of a pruned block is kept
        }
        if (valid) {
            if (std::equal(value.begin() + 1, value.end(), bytes.begin(), bytes.end())) continue;
            LogPrintf("Silent payment index: record of block %s (height %d) differs from the block; rewritten\n",
                      pindex->GetBlockHash().ToString(), height);
            ++rewritten;
        } else {
            ++rebuilt;
        }
        writeBytes += value.size();
        writes.emplace_back(pindex->GetBlockHash(), std::move(value));
        // Batches bounded by records and by bytes: blocks of large records
        // must not pile up in memory.
        if (writes.size() >= 1000 || writeBytes >= nIndexBatchBytes) {
            if (!pblocktree->WriteSilentPaymentRecords(writes, false)) {
                error = _("Failed to write the silent payment index");
                return false;
            }
            writes.clear();
            writeBytes = 0;
        }
    }
    // The last batch is synchronous and makes the earlier ones durable too.
    if (!pblocktree->WriteSilentPaymentRecords(writes, true)) {
        error = _("Failed to write the silent payment index");
        return false;
    }
    if (total > 1000) uiInterface.ShowProgress("", 100, false);
    LogPrintf("Silent payment index: %d blocks verified, %d rebuilt, %d rewritten, %u missing ranges\n",
              total, rebuilt, rewritten, (unsigned)missing.size());
    for (const auto& range : missing) {
        LogPrintf("Silent payment index: no record and no block data for heights %d-%d; the index is incomplete\n",
                  range.first, range.second);
    }
    LOCK(cs_index);
    vMissingRanges = std::move(missing);
    return true;
}

IndexStatus GetIndexStatus()
{
    LOCK2(cs_main, cs_index);
    IndexStatus status;
    status.enabled = fSilentPaymentIndex;
    status.startHeight = IndexStartHeight(GetParams().GetConsensus());
    status.tipHeight = chainActive.Height();
    if (!status.enabled) return status;
    status.missing = vMissingRanges;
    // ConnectBlock stores the record of each block before the tip moves, so
    // only the ranges found at startup can be missing.
    status.syncedHeight = status.missing.empty() ? status.tipHeight
                                                 : std::min(status.tipHeight, status.missing.front().first - 1);
    if (status.syncedHeight >= 0 && chainActive[status.syncedHeight]) {
        status.syncedHash = chainActive[status.syncedHeight]->GetBlockHash();
    }
    status.complete = status.missing.empty() && status.syncedHeight == status.tipHeight;
    return status;
}

bool ReadIndexRecord(const uint256& hash, IndexBlock& block, std::vector<unsigned char>& bytes)
{
    std::vector<unsigned char> value;
    if (!pblocktree->ReadSilentPaymentRecord(hash, value)) return false;
    return DecodeRecord(value, block, bytes) && block.hash == hash;
}

UniValue IndexBlockToJSON(const IndexBlock& block, const uint256& digest)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("height", (int64_t)block.height);
    result.pushKV("hash", block.hash.GetHex());
    result.pushKV("prev", block.prev.GetHex());
    UniValue entries(UniValue::VARR);
    for (const IndexEntry& entry : block.entries) {
        UniValue item(UniValue::VOBJ);
        item.pushKV("txid", entry.txid.GetHex());
        item.pushKV("tweak", HexStr(entry.tweak.begin(), entry.tweak.end()));
        UniValue outputs(UniValue::VARR);
        for (const IndexOutput& output : entry.outputs) {
            UniValue out(UniValue::VOBJ);
            out.pushKV("vout", (int64_t)output.vout);
            out.pushKV("commitment", HexBytes(output.commitment));
            // A string: amounts above 2^53 satoshis do not fit a JS number.
            out.pushKV("value_sat", std::to_string(output.value));
            outputs.push_back(out);
        }
        item.pushKV("outputs", outputs);
        entries.push_back(item);
    }
    result.pushKV("entries", entries);
    UniValue spent(UniValue::VARR);
    for (const COutPoint& outpoint : block.spent) {
        UniValue item(UniValue::VOBJ);
        item.pushKV("txid", outpoint.hash.GetHex());
        item.pushKV("vout", (int64_t)outpoint.n);
        spent.push_back(item);
    }
    result.pushKV("spent", spent);
    result.pushKV("digest", HexBytes(digest));
    return result;
}

RangeError QueryRange(const RangeRequest& request, RangeResult& result, std::string& error)
{
    result = RangeResult();
    if (!fSilentPaymentIndex) {
        error = "Silent payment index is disabled (start the node with -silentpaymentindex)";
        return RangeError::DISABLED;
    }
    if (request.count < 1) {
        error = "count must be at least 1";
        return RangeError::INVALID_PARAMETER;
    }
    std::vector<uint256> hashes;
    {
        LOCK(cs_main);
        if (!chainActive.Tip()) { // e.g. early in -reindex
            error = "The node has no active chain yet";
            return RangeError::INCOMPLETE;
        }
        const IndexStatus status = GetIndexStatus();
        const int tipHeight = chainActive.Height();
        IndexRangeHeader& header = result.header;
        header.snapshotHeight = tipHeight;
        header.snapshotHash = chainActive.Tip()->GetBlockHash();
        header.syncedHeight = std::max(0, status.syncedHeight);
        if (request.startHeight < status.startHeight || request.startHeight > tipHeight + 1) {
            error = strprintf("start_height must be between %d and %d", status.startHeight, tipHeight + 1);
            return RangeError::INVALID_PARAMETER;
        }
        if (request.hasAnchor) {
            BlockMap::const_iterator it = mapBlockIndex.find(request.anchor);
            if (it == mapBlockIndex.end()) {
                error = "anchor_hash not found";
                return RangeError::ANCHOR_NOT_FOUND;
            }
            if (it->second->nHeight != request.startHeight - 1) {
                error = "anchor_hash must be the block at start_height - 1";
                return RangeError::INVALID_PARAMETER;
            }
            if (!chainActive.Contains(it->second)) {
                result.reorg = true;
                result.forkHeight = chainActive.FindFork(it->second)->nHeight;
                return RangeError::NONE;
            }
        }
        header.nextHeight = request.startHeight;
        if (request.startHeight == tipHeight + 1) {
            header.status = INDEX_RANGE_TIP;
            return RangeError::NONE;
        }
        if (request.startHeight > status.syncedHeight) {
            error = "Silent payment index is incomplete from height " + std::to_string(status.syncedHeight + 1) +
                    " (see getsilentpaymentindexinfo); restart with -reindex to rebuild it";
            return RangeError::INCOMPLETE;
        }
        const int64_t wanted = std::min<int64_t>(request.count, request.maxBlocks);
        const int last = (int)std::min<int64_t>(status.syncedHeight, request.startHeight + wanted - 1);
        for (int height = request.startHeight; height <= last; ++height) {
            hashes.push_back(chainActive[height]->GetBlockHash());
        }
    }

    size_t total = 0;
    for (const uint256& hash : hashes) {
        IndexBlock block;
        std::vector<unsigned char> bytes;
        if (!ReadIndexRecord(hash, block, bytes)) {
            error = "Cannot read the silent payment index record of block " + hash.GetHex();
            return RangeError::READ_FAILED;
        }
        if (!result.bytes.empty() && total + bytes.size() > request.maxBytes) break;
        total += bytes.size();
        result.blocks.push_back(std::move(block));
        result.bytes.push_back(std::move(bytes));
    }
    IndexRangeHeader& header = result.header;
    header.nextHeight = request.startHeight + result.blocks.size();
    if (header.nextHeight > header.snapshotHeight) {
        header.status = INDEX_RANGE_TIP;
    } else if ((int)header.nextHeight <= (int)header.syncedHeight) {
        header.status = INDEX_RANGE_MORE;
    } else {
        header.status = INDEX_RANGE_INCOMPLETE;
    }
    return RangeError::NONE;
}

std::string RangeStatusName(uint8_t status)
{
    switch (status) {
    case INDEX_RANGE_MORE: return "more";
    case INDEX_RANGE_TIP: return "tip";
    case INDEX_RANGE_WAIT: return "wait";
    case INDEX_RANGE_INCOMPLETE: return "incomplete";
    }
    return "unknown";
}

UniValue IndexStatusToJSON(const IndexStatus& status)
{
    const std::vector<unsigned char> context = LocalContext();
    UniValue result(UniValue::VOBJ);
    result.pushKV("enabled", UniValue(status.enabled));
    result.pushKV("state", !status.enabled ? "disabled" : status.missing.empty() ? "ready" : "incomplete");
    result.pushKV("schema", (int)INDEX_SCHEMA);
    UniValue formats(UniValue::VARR);
    formats.push_back((int)INDEX_FORMAT);
    result.pushKV("formats", formats);
    result.pushKV("context", HexStr(context));
    result.pushKV("start_height", status.startHeight);
    if (status.enabled) {
        result.pushKV("synced_height", status.syncedHeight);
        result.pushKV("synced_hash", status.syncedHash.IsNull() ? "" : status.syncedHash.GetHex());
    }
    result.pushKV("complete", UniValue(status.complete));
    UniValue missing(UniValue::VARR);
    for (const auto& range : status.missing) {
        UniValue item(UniValue::VARR);
        item.push_back(range.first);
        item.push_back(range.second);
        missing.push_back(item);
    }
    result.pushKV("missing", missing);
    result.pushKV("pruned", UniValue(fHavePruned));
    return result;
}

UniValue IndexBlockMessageToJSON(const IndexBlock& block, const std::vector<unsigned char>& bytes)
{
    const std::vector<unsigned char> context = LocalContext();
    UniValue result(UniValue::VOBJ);
    result.pushKV("format", (int)INDEX_FORMAT);
    result.pushKV("context", HexStr(context));
    result.pushKV("block", IndexBlockToJSON(block, IndexBlockDigest(context, bytes)));
    return result;
}

static UniValue SnapshotToJSON(const IndexRangeHeader& header)
{
    UniValue snapshot(UniValue::VOBJ);
    snapshot.pushKV("height", (int64_t)header.snapshotHeight);
    snapshot.pushKV("hash", header.snapshotHash.GetHex());
    return snapshot;
}

UniValue RangeResultToJSON(const RangeResult& result)
{
    UniValue json(UniValue::VOBJ);
    if (result.reorg) {
        json.pushKV("reorg", UniValue(true));
        json.pushKV("fork_height", result.forkHeight);
        json.pushKV("snapshot", SnapshotToJSON(result.header));
        return json;
    }
    const std::vector<unsigned char> context = LocalContext();
    json.pushKV("format", (int)INDEX_FORMAT);
    json.pushKV("context", HexStr(context));
    json.pushKV("snapshot", SnapshotToJSON(result.header));
    json.pushKV("synced_height", (int64_t)result.header.syncedHeight);
    UniValue blocks(UniValue::VARR);
    for (size_t i = 0; i < result.blocks.size(); ++i) {
        blocks.push_back(IndexBlockToJSON(result.blocks[i], IndexBlockDigest(context, result.bytes[i])));
    }
    json.pushKV("blocks", blocks);
    json.pushKV("next_height", (int64_t)result.header.nextHeight);
    json.pushKV("status", RangeStatusName(result.header.status));
    return json;
}

void RangeResultToMessage(const RangeResult& result, std::vector<unsigned char>& out)
{
    SerializeIndexRangeMessage(LocalContext(), result.header, result.bytes, out);
}

} // namespace silentpayments
