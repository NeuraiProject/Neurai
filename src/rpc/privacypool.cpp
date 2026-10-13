// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.

#include "assets/assets.h"
#include "chainparams.h"
#include "coins.h"
#include "core_io.h"
#include "hash.h"
#include "rpc/server.h"
#include "script/standard.h"
#include "sync.h"
#include "txdb.h"
#include "utilstrencodings.h"
#include "validation.h"

#include <boost/thread/thread.hpp>
#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <univalue.h>

namespace {
// These are RPC resource limits, not consensus or pool-capacity limits.
constexpr int DEFAULT_PAGE_LIMIT = 100;
constexpr int MAX_PAGE_LIMIT = 1000;
constexpr size_t MAX_PAGE_BYTES = 1024 * 1024;
constexpr size_t MAX_CURSOR_WALK = 10000;
constexpr size_t MAX_CACHED_POSITIONS = 4096;
constexpr uint32_t TERMINAL_VOUT = std::numeric_limits<uint32_t>::max();

struct ConfirmedTx {
    CTransactionRef tx;
    const CBlockIndex* block;
};

struct Pool {
    COutPoint birth;
    ConfirmedTx origin;
    std::vector<unsigned char> commitment;
    bool hasAsset = false;
    std::string asset;
    CAmount assetAmount = 0;
    uint256 id;
};

struct Position {
    COutPoint point;
    ConfirmedTx created;
    int64_t sequence = 0;
    bool Terminal() const { return point.n == TERMINAL_VOUT; }
};

// A disposable acceleration cache, not a pool registry. On a cache miss (also
// after restarting the node), prove ancestry again using the existing indexes.
// A cached position is usable only after its block and birth are checked on the
// captured active chain. Active ancestry binds all of the intervening steps.
CCriticalSection cs_positions;
std::map<std::pair<COutPoint, COutPoint>, int64_t> verifiedPositions;

void Remember(const Pool& pool, const Position& position)
{
    LOCK(cs_positions);
    if (verifiedPositions.size() >= MAX_CACHED_POSITIONS) verifiedPositions.clear();
    verifiedPositions[{pool.birth, position.point}] = position.sequence;
}

void ObjectFields(const UniValue& value, const std::set<std::string>& allowed, const char* name)
{
    if (!value.isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string(name) + " must be an object");
    std::set<std::string> seen;
    for (const auto& key : value.getKeys()) {
        if (!allowed.count(key) || !seen.insert(key).second)
            throw JSONRPCError(RPC_INVALID_PARAMETER, std::string(name) + " contains an unknown or duplicate field");
    }
}

int64_t Integer(const UniValue& value, int64_t minimum, int64_t maximum, const char* name)
{
    if (!value.isNum()) throw JSONRPCError(RPC_INVALID_PARAMETER, std::string(name) + " must be an integer");
    int64_t result;
    try { result = value.get_int64(); }
    catch (const std::exception&) { throw JSONRPCError(RPC_INVALID_PARAMETER, std::string(name) + " must be an integer"); }
    if (result < minimum || result > maximum)
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string(name) + " is out of range");
    return result;
}

COutPoint ReadPoint(const UniValue& value, bool terminal = false)
{
    ObjectFields(value, {"txid", "vout"}, "outpoint");
    const auto& index = find_value(value, "vout");
    // Only cursor positions can encode a spent thread with no matching successor.
    const auto& keys = value.getKeys();
    if (std::find(keys.begin(), keys.end(), "vout") == keys.end())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "outpoint requires vout");
    return COutPoint(ParseHashV(find_value(value, "txid"), "txid"),
        terminal && index.isNull() ? TERMINAL_VOUT : Integer(index, 0, TERMINAL_VOUT - 1, "vout"));
}

UniValue PointJSON(const COutPoint& point)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("txid", point.hash.GetHex());
    if (point.n == TERMINAL_VOUT) result.pushKV("vout", UniValue());
    else result.pushKV("vout", static_cast<int64_t>(point.n));
    return result;
}

UniValue BlockJSON(const CBlockIndex* block)
{
    UniValue result(UniValue::VOBJ);
    result.pushKV("height", block->nHeight);
    result.pushKV("hash", block->GetBlockHash().GetHex());
    return result;
}

const CBlockIndex* Snapshot(const UniValue& cursor)
{
    LOCK(cs_main);
    if (!fSpentIndex || !fTxIndex)
        throw JSONRPCError(RPC_MISC_ERROR, "Privacy-pool transport requires -spentindex and -txindex; rebuild the indexes when enabling them");
    if (!chainActive.Tip()) throw JSONRPCError(RPC_IN_WARMUP, "Active chain unavailable");
    if (cursor.isNull()) return chainActive.Tip();
    ObjectFields(cursor, {"version", "pool_id", "position", "sequence", "anchor", "snapshot", "complete"}, "cursor");
    Integer(find_value(cursor, "version"), 1, 1, "cursor version");
    const auto& complete = find_value(cursor, "complete");
    if (!complete.isBool()) throw JSONRPCError(RPC_INVALID_PARAMETER, "cursor complete must be boolean");
    const auto& snapshot = find_value(cursor, "snapshot");
    ObjectFields(snapshot, {"height", "hash"}, "cursor snapshot");
    const int height = Integer(find_value(snapshot, "height"), 0, std::numeric_limits<int>::max(), "snapshot height");
    const uint256 hash = ParseHashV(find_value(snapshot, "hash"), "snapshot hash");
    if (height > chainActive.Height() || chainActive[height]->GetBlockHash() != hash)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cursor snapshot reorganized; restart from a canonical checkpoint or birth");
    // Pages share one immutable snapshot. A completed cursor starts a new scan
    // at today's tip, retaining its already-verified position.
    return complete.get_bool() ? chainActive.Tip() : chainActive[height];
}

void CheckSnapshot(const CBlockIndex* snapshot)
{
    LOCK(cs_main);
    if (!chainActive.Contains(snapshot))
        throw JSONRPCError(RPC_MISC_ERROR, "Chain reorganized during privacy-pool query; retry");
}

ConfirmedTx ReadConfirmed(const uint256& txid, const CBlockIndex* snapshot)
{
    boost::this_thread::interruption_point();
    // GetTransaction takes cs_main. Keep this scope to one disk lookup rather
    // than holding the chain lock for the entire paginated history query.
    LOCK(cs_main);
    CTransactionRef tx;
    uint256 blockHash;
    if (!GetTransaction(txid, tx, GetParams().GetConsensus(), blockHash, false) || blockHash.IsNull())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Confirmed transaction or its historical data unavailable");
    const auto found = mapBlockIndex.find(blockHash);
    if (found == mapBlockIndex.end() || !chainActive.Contains(found->second) ||
        found->second->nHeight > snapshot->nHeight || snapshot->GetAncestor(found->second->nHeight) != found->second)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Transaction is not in the captured active-chain snapshot");
    return {tx, found->second};
}

bool Identity(const CTxOut& output, std::vector<unsigned char>& commitment, CAssetTransfer& asset, bool& hasAsset)
{
    int version;
    hasAsset = output.scriptPubKey.IsAssetScript();
    if (hasAsset) {
        std::string address;
        return GetAssetScriptWitnessProgram(output.scriptPubKey, version, commitment) && version == 1 &&
            TransferAssetFromScript(output.scriptPubKey, asset, address);
    }
    return output.scriptPubKey.IsWitnessProgram(version, commitment) && version == 1 && commitment.size() == 32;
}

Pool ReadPool(const UniValue& value, const CBlockIndex* snapshot)
{
    Pool pool;
    pool.birth = ReadPoint(value);
    pool.origin = ReadConfirmed(pool.birth.hash, snapshot);
    if (pool.birth.n >= pool.origin.tx->vout.size()) throw JSONRPCError(RPC_INVALID_PARAMETER, "Birth vout does not exist");
    CAssetTransfer asset;
    if (!Identity(pool.origin.tx->vout[pool.birth.n], pool.commitment, asset, pool.hasAsset))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Birth must be an AuthScript v1 output, optionally with an asset transfer wrapper");
    pool.asset = asset.strName;
    pool.assetAmount = asset.nAmount;
    CHashWriter identity(SER_GETHASH, 0);
    identity << std::string("Neurai/privacy-pool/transport/v1") << GetParams().GenesisBlock().GetHash() << pool.birth;
    pool.id = identity.GetHash();
    return pool;
}

bool Matches(const Pool& pool, const CTxOut& output)
{
    std::vector<unsigned char> commitment;
    CAssetTransfer asset;
    bool hasAsset;
    return Identity(output, commitment, asset, hasAsset) && commitment == pool.commitment && hasAsset == pool.hasAsset &&
        (!hasAsset || (asset.strName == pool.asset && asset.nAmount == pool.assetAmount));
}

bool Next(const Pool& pool, const Position& position, const CBlockIndex* snapshot, Position& next, unsigned int& input)
{
    if (position.Terminal()) return false;
    CSpentIndexKey key(position.point.hash, position.point.n);
    CSpentIndexValue spender;
    {
        LOCK(cs_main);
        // Deliberately bypass GetSpentIndex: it overlays mempool spends.
        if (!pblocktree->ReadSpentIndex(key, spender)) {
            const Coin& coin = pcoinsTip->AccessCoin(position.point);
            if (coin.IsSpent() || coin.out != position.created.tx->vout[position.point.n])
                throw JSONRPCError(RPC_DATABASE_ERROR, "Consumed state missing from confirmed spent index");
            return false;
        }
    }
    if (spender.blockHeight > snapshot->nHeight) return false;
    auto confirmed = ReadConfirmed(spender.txid, snapshot);
    if (spender.blockHeight != confirmed.block->nHeight || spender.inputIndex >= confirmed.tx->vin.size() ||
        confirmed.tx->vin[spender.inputIndex].prevout != position.point || confirmed.block->nHeight < position.created.block->nHeight)
        throw JSONRPCError(RPC_DATABASE_ERROR, "Spent index disagrees with confirmed state transaction");
    uint32_t successor = TERMINAL_VOUT;
    for (size_t n = 0; n < confirmed.tx->vout.size(); ++n) {
        if (!Matches(pool, confirmed.tx->vout[n])) continue;
        if (successor != TERMINAL_VOUT)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Ambiguous state successors; this pool needs a profile-specific adapter");
        successor = n;
    }
    input = spender.inputIndex;
    next = {COutPoint(spender.txid, successor), confirmed, position.sequence + 1};
    Remember(pool, next);
    return true;
}

Position Start(const Pool& pool, const UniValue& cursor, const CBlockIndex* snapshot)
{
    Position position{pool.birth, pool.origin, 0};
    Remember(pool, position);
    if (cursor.isNull()) return position;
    if (ParseHashV(find_value(cursor, "pool_id"), "cursor pool_id") != pool.id)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cursor belongs to a different pool");
    const auto point = ReadPoint(find_value(cursor, "position"), true);
    const int64_t sequence = Integer(find_value(cursor, "sequence"), 0, std::numeric_limits<int64_t>::max() - 1, "cursor sequence");
    const auto& anchor = find_value(cursor, "anchor");
    ObjectFields(anchor, {"height", "hash"}, "cursor anchor");
    const int anchorHeight = Integer(find_value(anchor, "height"), 0, snapshot->nHeight, "cursor anchor height");
    const uint256 anchorHash = ParseHashV(find_value(anchor, "hash"), "cursor anchor hash");
    auto created = ReadConfirmed(point.hash, snapshot);
    if (created.block->nHeight != anchorHeight || created.block->GetBlockHash() != anchorHash)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cursor position anchor mismatch");
    if (point.n != TERMINAL_VOUT && (point.n >= created.tx->vout.size() || !Matches(pool, created.tx->vout[point.n])))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cursor position is not a matching pool state");
    {
        LOCK(cs_positions);
        const auto found = verifiedPositions.find({pool.birth, point});
        if (found != verifiedPositions.end()) {
            if (found->second != sequence) throw JSONRPCError(RPC_INVALID_PARAMETER, "Cursor sequence mismatch");
            return {point, created, sequence};
        }
    }
    // Never accept a caller-selected state just because its commitment matches.
    // Prove it descends from this exact birth, including for unregistered pools.
    for (size_t n = 0; n < MAX_CURSOR_WALK && position.point != point; ++n) {
        Position next;
        unsigned int input;
        if (!Next(pool, position, snapshot, next, input))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Cursor is not a descendant of pool birth");
        position = next;
        if (position.sequence > sequence) break;
    }
    if (position.point != point || position.sequence != sequence)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cursor is not a descendant of pool birth with the claimed sequence, or exceeds 10000-step prototype validation limit");
    return position;
}

UniValue StateJSON(const Position& position)
{
    if (position.Terminal()) return UniValue();
    UniValue state = PointJSON(position.point);
    const auto& output = position.created.tx->vout[position.point.n];
    state.pushKV("height", position.created.block->nHeight);
    state.pushKV("blockhash", position.created.block->GetBlockHash().GetHex());
    state.pushKV("script", HexStr(output.scriptPubKey));
    state.pushKV("value_satoshis", std::to_string(output.nValue));
    return state;
}

UniValue CursorJSON(const Pool& pool, const Position& position, const CBlockIndex* snapshot, bool complete)
{
    UniValue cursor(UniValue::VOBJ);
    cursor.pushKV("version", 1);
    cursor.pushKV("pool_id", pool.id.GetHex());
    cursor.pushKV("position", PointJSON(position.point));
    cursor.pushKV("sequence", position.sequence);
    cursor.pushKV("anchor", BlockJSON(position.created.block));
    cursor.pushKV("snapshot", BlockJSON(snapshot));
    cursor.pushKV("complete", UniValue(complete));
    return cursor;
}

UniValue Query(const JSONRPCRequest& request, bool info)
{
    const int maxParams = info ? 2 : 3;
    if (request.fHelp || request.params.size() < 1 || request.params.size() > static_cast<size_t>(maxParams))
        throw std::runtime_error(info ?
            "getprivacypoolinfo pool ( limit )\n"
            "\nRead public state-thread identity and confirmed state, without registering a pool.\n"
            "Requires -spentindex and -txindex and readable historical transactions.\n"
            "pool: {\"txid\": birth_txid, \"vout\": birth_output}\n"
            "limit: maximum transitions to follow (default 100, maximum 1000).\n"
            "history_complete=false means current_state is unknown; continue with next_cursor.\n"
            "The reported profile describes the transport, not an audited privacy circuit.\n" :
            "getprivacypoolupdates pool ( cursor limit )\n"
            "\nReturn confirmed public pool transactions, including complete witnesses, in state-thread order.\n"
            "pool: {\"txid\": birth_txid, \"vout\": birth_output}; no registry or viewing key.\n"
            "cursor: null for birth, otherwise the unchanged next_cursor from a previous query.\n"
            "limit: maximum updates (default 100, maximum 1000); pages also have a 1 MiB raw-byte limit.\n"
            "Pages pin one chain snapshot; a completed cursor refreshes to the current tip.\n"
            "A reorganized snapshot or foreign/tampered cursor is rejected. Mempool spends are excluded.\n"
            "No matching successor ends this transport; it does not prove the contract is closed.\n");
    const UniValue cursor = !info && request.params.size() > 1 ? request.params[1] : UniValue();
    const size_t limitParam = info ? 1 : 2;
    const int limit = request.params.size() > limitParam && !request.params[limitParam].isNull() ?
        Integer(request.params[limitParam], 1, MAX_PAGE_LIMIT, "limit") : DEFAULT_PAGE_LIMIT;
    const CBlockIndex* snapshot = Snapshot(cursor);
    const Pool pool = ReadPool(request.params[0], snapshot);
    Position position = Start(pool, cursor, snapshot);
    UniValue updates(UniValue::VARR);
    size_t bytes = 0;
    int followed = 0;
    bool complete = false;
    for (;;) {
        Position next;
        unsigned int input;
        if (!Next(pool, position, snapshot, next, input)) { complete = true; break; }
        const size_t txBytes = GetSerializeSize(*next.created.tx, SER_NETWORK, PROTOCOL_VERSION);
        if (followed >= limit || (!info && bytes + txBytes > MAX_PAGE_BYTES)) {
            if (!followed && !info) throw JSONRPCError(RPC_MISC_ERROR, "Pool transaction exceeds the prototype page byte limit");
            break;
        }
        if (!info) {
            UniValue update(UniValue::VOBJ);
            update.pushKV("sequence", next.sequence);
            update.pushKV("txid", next.point.hash.GetHex());
            update.pushKV("wtxid", next.created.tx->GetWitnessHash().GetHex());
            update.pushKV("height", next.created.block->nHeight);
            update.pushKV("blockhash", next.created.block->GetBlockHash().GetHex());
            update.pushKV("input_index", static_cast<int64_t>(input));
            update.pushKV("spent", PointJSON(position.point));
            update.pushKV("state", StateJSON(next));
            update.pushKV("raw", EncodeHexTx(*next.created.tx));
            UniValue witnesses(UniValue::VARR);
            for (const auto& vin : next.created.tx->vin) {
                UniValue stack(UniValue::VARR);
                for (const auto& item : vin.scriptWitness.stack) stack.push_back(HexStr(item));
                witnesses.push_back(stack);
            }
            update.pushKV("witness", witnesses);
            updates.push_back(update);
        }
        bytes += txBytes;
        ++followed;
        position = next;
    }
    CheckSnapshot(snapshot);
    UniValue result(UniValue::VOBJ);
    result.pushKV("pool_id", pool.id.GetHex());
    result.pushKV("genesis", GetParams().GenesisBlock().GetHash().GetHex());
    result.pushKV("profile", "authscript-v1-state-thread");
    result.pushKV("privacy_profile", UniValue());
    result.pushKV("commitment", HexStr(pool.commitment));
    if (pool.hasAsset) result.pushKV("thread_asset", pool.asset);
    else result.pushKV("thread_asset", UniValue());
    result.pushKV("birth", StateJSON({pool.birth, pool.origin, 0}));
    result.pushKV("snapshot", BlockJSON(snapshot));
    result.pushKV("indexed_height", snapshot->nHeight);
    result.pushKV("history_complete", UniValue(complete));
    result.pushKV("has_more", UniValue(!complete));
    result.pushKV("continuation", position.Terminal() ? "not_found" : "matching_state");
    result.pushKV("current_state", complete ? StateJSON(position) : UniValue());
    result.pushKV("last_state", StateJSON(position));
    result.pushKV("transitions_followed", followed);
    result.pushKV("next_cursor", CursorJSON(pool, position, snapshot, complete));
    if (!info) result.pushKV("updates", updates);
    return result;
}
} // namespace

static UniValue getprivacypoolinfo(const JSONRPCRequest& request) { return Query(request, true); }
static UniValue getprivacypoolupdates(const JSONRPCRequest& request) { return Query(request, false); }

static const CRPCCommand commands[] = {
    { "blockchain", "getprivacypoolinfo", &getprivacypoolinfo, {"pool", "limit"} },
    { "blockchain", "getprivacypoolupdates", &getprivacypoolupdates, {"pool", "cursor", "limit"} },
};

void RegisterPrivacyPoolRPCCommands(CRPCTable& table)
{
    for (const auto& command : commands) table.appendCommand(command.name, &command);
}
