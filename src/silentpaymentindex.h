// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Light client index of NIP-047 silent payments (-silentpaymentindex).
//
// One record per connected block from max(1, strict AuthScript activation):
// every eligible transaction with a native v3 output, with its public tweak
// and its native v3 outputs, and every native v3 output the block spends.
// Without view keys the node cannot tell a silent payment from any other v3
// output, so it indexes all candidates and every client downloads the same
// data. Records are keyed by block hash and never change; the active chain
// maps heights to hashes.

#ifndef NEURAI_SILENTPAYMENTINDEX_H
#define NEURAI_SILENTPAYMENTINDEX_H

#include "silentpayments.h"
#include "uint256.h"

#include <string>
#include <utility>
#include <vector>

class CBlock;
class CBlockIndex;
class CBlockUndo;
class CChainParams;
class UniValue;
namespace Consensus { struct Params; }

static const bool DEFAULT_SILENTPAYMENTINDEX = false;
static const int DEFAULT_CHECKSILENTPAYMENTINDEX = 6;

extern bool fSilentPaymentIndex;

namespace silentpayments {

/** Storage schema of the records; a change rebuilds the index. */
static constexpr uint8_t INDEX_SCHEMA = 1;
static constexpr unsigned int INDEX_RANGE_MAX_BLOCKS = 1000;
static constexpr size_t INDEX_RANGE_MAX_BYTES = 4 * 1024 * 1024;

/** Bytes of records kept in memory before they are written: the records
 *  waiting for FlushIndex, and each batch of the startup repair. */
static constexpr size_t DEFAULT_INDEX_BATCH_BYTES = 32 * 1024 * 1024;
extern size_t nIndexBatchBytes; //!< tests lower it

/** First indexed height: max(1, strict AuthScript activation). The genesis
 *  block never connects its transactions. */
int IndexStartHeight(const Consensus::Params& consensus);

/** Record of a block from the block and its undo data. The only builder: used
 *  by ConnectBlock and by the startup repair alike. */
bool BuildIndexBlock(const std::vector<unsigned char>& context, const CBlock& block, const CBlockUndo& undo,
                     const CBlockIndex* pindex, IndexBlock& out);

/** ConnectBlock (cs_main held): stores the record of a connected block. The
 *  write is not synchronous; FlushIndex makes it durable. */
bool IndexConnectedBlock(const CBlock& block, const CBlockUndo& undo, const CBlockIndex* pindex);

/** FlushStateToDisk (cs_main held): rewrites the records stored since the
 *  last flush in a synchronous batch. Called before the block index and the
 *  chainstate are flushed, so every block of a flushed chainstate has its
 *  record on disk, also when ReplayBlocks later rolls it forward without
 *  ConnectBlock. IndexConnectedBlock does the same earlier whenever the
 *  pending records exceed nIndexBatchBytes. */
bool FlushIndex();

/** Startup, after the chain is loaded and before the first prune: applies the
 *  option/metadata transitions and verifies every record of the active chain
 *  from the start height, rebuilding the absent or invalid ones from block
 *  and undo data. The last checkDepth records are also compared byte by byte
 *  with a rebuild. Blocks that cannot be rebuilt (pruned) leave the index
 *  incomplete. Returns false with `error` when the node must not start. */
bool InitIndex(const CChainParams& chainparams, int checkDepth, std::string& error);

/** Forgets the in-memory state (pending records, missing ranges). */
void ResetIndex();

/** Records stored since the last FlushIndex, and their bytes. */
size_t PendingIndexRecords();
size_t PendingIndexBytes();

struct IndexStatus {
    bool enabled = false;
    int startHeight = 0;
    int tipHeight = -1;
    int syncedHeight = -1;     //!< highest h with a valid record for every active block in [start, h]
    uint256 syncedHash;
    bool complete = false;     //!< ready and synced up to the tip
    std::vector<std::pair<int, int>> missing; //!< ranges without a record or data to rebuild it
};

/** Current status; takes cs_main. */
IndexStatus GetIndexStatus();

/** Reads and decodes the record of `hash` (schema, strict decoding and hash).
 *  `bytes` gets the canonical block bytes. */
bool ReadIndexRecord(const uint256& hash, IndexBlock& block, std::vector<unsigned char>& bytes);

/** JSON object of one block record. */
UniValue IndexBlockToJSON(const IndexBlock& block, const uint256& digest);

struct RangeRequest {
    int startHeight = 0;
    int64_t count = 0;
    bool hasAnchor = false;
    uint256 anchor;              //!< hash the client has at startHeight - 1
    unsigned int maxBlocks = INDEX_RANGE_MAX_BLOCKS;
    size_t maxBytes = INDEX_RANGE_MAX_BYTES;
};

struct RangeResult {
    bool reorg = false;          //!< the anchor left the active chain
    int forkHeight = -1;         //!< last height the anchor's branch shares with the active chain
    IndexRangeHeader header;
    std::vector<IndexBlock> blocks;
    std::vector<std::vector<unsigned char>> bytes;
};

enum class RangeError { NONE, DISABLED, INVALID_PARAMETER, ANCHOR_NOT_FOUND, INCOMPLETE, READ_FAILED };

/** Blocks from startHeight on the active chain, taken as one snapshot under
 *  cs_main and read afterwards: records never change, so the result is
 *  exactly the active chain of the snapshot even if a reorganisation happens
 *  meanwhile. Never truncates a block: always at least one, whole blocks up
 *  to maxBytes. */
RangeError QueryRange(const RangeRequest& request, RangeResult& result, std::string& error);

/** Name of an IndexRangeStatus for JSON. */
std::string RangeStatusName(uint8_t status);

// JSON shared by the RPC and REST interfaces.
UniValue IndexStatusToJSON(const IndexStatus& status);
/** {format, context, block}: immutable for a block hash. */
UniValue IndexBlockMessageToJSON(const IndexBlock& block, const std::vector<unsigned char>& bytes);
/** {format, context, snapshot, synced_height, blocks, next_height, status}, or
 *  {reorg, fork_height, snapshot} when the anchor left the active chain. */
UniValue RangeResultToJSON(const RangeResult& result);
/** Binary range message of a result without reorg. */
void RangeResultToMessage(const RangeResult& result, std::vector<unsigned char>& out);

} // namespace silentpayments

#endif // NEURAI_SILENTPAYMENTINDEX_H
