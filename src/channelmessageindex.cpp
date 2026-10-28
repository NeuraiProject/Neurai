// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "channelmessageindex.h"

#include "assets/assets.h"
#include "base58.h"
#include "chain.h"
#include "chainparams.h"
#include "core_io.h"
#include "crypto/sha256.h"
#include "dbwrapper.h"
#include "merkleblock.h"
#include "primitives/block.h"
#include "script/script.h"
#include "streams.h"
#include "undo.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validation.h"
#include "version.h"

#include <univalue.h>

#include <algorithm>
#include <map>
#include <memory>
#include <set>
#include <tuple>

bool fChannelMessageIndex = DEFAULT_CHANNELMESSAGEINDEX;

namespace channelmessages {
namespace {

const char DB_SCHEMA = 'V';
const char DB_TIP = 'T';     // last marked block, where startup resumes
const char DB_BLOCK = 'B';   // marker: block hash -> number of messages
const char DB_MESSAGE = 'M'; // (channel, txid, vout) -> ChannelMessage

const size_t INDEX_CACHE_BYTES = 8 << 20;
const size_t INDEX_BATCH_BYTES = 16 << 20;

std::unique_ptr<CDBWrapper> g_db;

using MessageKey = std::pair<char, std::pair<std::string, std::pair<uint256, uint32_t>>>;

MessageKey KeyOf(const std::string& channel, const uint256& txid, uint32_t vout)
{
    return std::make_pair(DB_MESSAGE, std::make_pair(channel, std::make_pair(txid, vout)));
}

fs::path IndexPath()
{
    return GetDataDir() / "indexes" / "channelmessages";
}

/** Data pushed by the transaction's first OP_RETURN output, if any. */
std::vector<unsigned char> OpReturnData(const CTransaction& tx)
{
    for (const CTxOut& txout : tx.vout) {
        const CScript& script = txout.scriptPubKey;
        if (script.empty() || script[0] != OP_RETURN)
            continue;
        std::vector<unsigned char> data;
        std::vector<unsigned char> push;
        opcodetype opcode;
        CScript::const_iterator pc = script.begin() + 1;
        while (pc < script.end() && script.GetOp(pc, opcode, push))
            data.insert(data.end(), push.begin(), push.end());
        return data;
    }
    return {};
}

void WriteBlock(CDBBatch& batch, const CBlockIndex* pindex, const std::vector<ChannelMessage>& messages)
{
    for (const auto& message : messages)
        batch.Write(KeyOf(message.channel, message.txid, message.vout), message);
    batch.Write(std::make_pair(DB_BLOCK, pindex->GetBlockHash()), static_cast<uint32_t>(messages.size()));
    batch.Write(DB_TIP, pindex->GetBlockHash());
}

} // namespace

int IndexStartHeight(const CChainParams& chainparams)
{
    return std::max(1, chainparams.GetAssetActivationHeight());
}

void BuildBlockMessages(const CBlock& block, const CBlockUndo& undo, const CBlockIndex* pindex,
                        std::vector<ChannelMessage>& out)
{
    out.clear();
    for (size_t i = 1; i < block.vtx.size() && i - 1 < undo.vtxundo.size(); ++i) {
        const CTransaction& tx = *block.vtx[i];

        // As in CheckTxAssets: the first input of each asset names its sender
        std::map<std::string, std::string> senders;
        for (const Coin& coin : undo.vtxundo[i - 1].vprevout) {
            CAssetOutputEntry data;
            if (GetAssetData(coin.out.scriptPubKey, data))
                senders.insert(std::make_pair(data.assetName, EncodeDestination(data.destination)));
        }

        bool fOpReturnRead = false;
        std::vector<unsigned char> opReturn;
        for (uint32_t n = 0; n < tx.vout.size(); ++n) {
            CAssetOutputEntry data;
            if (!GetAssetData(tx.vout[n].scriptPubKey, data) || data.type != TX_TRANSFER_ASSET || data.message.empty())
                continue;
            if (!IsAssetNameAnOwner(data.assetName) && !IsAssetNameAnMsgChannel(data.assetName))
                continue;
            const std::string address = EncodeDestination(data.destination);
            const auto sender = senders.find(data.assetName);
            if (sender == senders.end() || sender->second != address)
                continue;
            if (!fOpReturnRead) {
                opReturn = OpReturnData(tx);
                fOpReturnRead = true;
            }

            ChannelMessage message;
            message.channel = data.assetName;
            message.txid = tx.GetHash();
            message.vout = n;
            message.txIndex = i;
            message.height = pindex->nHeight;
            message.blockHash = pindex->GetBlockHash();
            message.blockTime = pindex->GetBlockTime();
            message.expireTime = data.expireTime;
            message.message = data.message;
            message.address = address;
            message.opReturn = opReturn;
            out.push_back(message);
        }
    }
}

bool IndexConnectedBlock(const CBlock& block, const CBlockUndo& undo, const CBlockIndex* pindex)
{
    // Not open yet: the startup catch-up will index the block
    if (!g_db)
        return true;
    std::vector<ChannelMessage> messages;
    BuildBlockMessages(block, undo, pindex, messages);
    CDBBatch batch(*g_db);
    WriteBlock(batch, pindex, messages);
    return g_db->WriteBatch(batch);
}

bool InitIndex(const CChainParams& chainparams, std::string& error)
{
    LOCK(cs_main);
    g_db.reset();
    if (!fChannelMessageIndex)
        return true;

    g_db.reset(new CDBWrapper(IndexPath(), INDEX_CACHE_BYTES));
    uint8_t schema = 0;
    if (!g_db->Read(DB_SCHEMA, schema) || schema != INDEX_SCHEMA) {
        LogPrintf("Channel message index: new or schema changed, building it from the blocks\n");
        g_db.reset();
        g_db.reset(new CDBWrapper(IndexPath(), INDEX_CACHE_BYTES, false, true));
        if (!g_db->Write(DB_SCHEMA, INDEX_SCHEMA, true)) {
            error = _("Failed to write the channel message index");
            return false;
        }
    }

    // Every ancestor of the last marked block is marked, so resume after the
    // point where its branch meets the active chain
    const int start = IndexStartHeight(chainparams);
    int resume = start;
    uint256 tip;
    if (g_db->Read(DB_TIP, tip)) {
        const auto it = mapBlockIndex.find(tip);
        if (it != mapBlockIndex.end()) {
            const CBlockIndex* fork = chainActive.FindFork(it->second);
            if (fork)
                resume = std::max(start, fork->nHeight + 1);
        }
    }

    CDBBatch batch(*g_db);
    int indexed = 0;
    for (int height = resume; height <= chainActive.Height(); ++height) {
        const CBlockIndex* pindex = chainActive[height];
        if (g_db->Exists(std::make_pair(DB_BLOCK, pindex->GetBlockHash())))
            continue;
        if (!(pindex->nStatus & BLOCK_HAVE_DATA) || !(pindex->nStatus & BLOCK_HAVE_UNDO)) {
            error = strprintf(_("-channelmessageindex needs block %d, which is not on disk"), height);
            return false;
        }
        CBlock block;
        CBlockUndo undo;
        if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus()) ||
            !UndoReadFromDisk(undo, pindex->GetUndoPos(), pindex->pprev->GetBlockHash())) {
            error = strprintf(_("Failed to read block %d for -channelmessageindex"), height);
            return false;
        }
        std::vector<ChannelMessage> messages;
        BuildBlockMessages(block, undo, pindex, messages);
        WriteBlock(batch, pindex, messages);
        ++indexed;
        if (batch.SizeEstimate() > INDEX_BATCH_BYTES) {
            if (!g_db->WriteBatch(batch)) {
                error = _("Failed to write the channel message index");
                return false;
            }
            batch.Clear();
            LogPrintf("Channel message index: indexed up to height %d\n", height);
        }
    }
    if (!g_db->WriteBatch(batch, true)) {
        error = _("Failed to write the channel message index");
        return false;
    }
    LogPrintf("Channel message index: %d blocks indexed at startup, synced to height %d\n", indexed, chainActive.Height());
    return true;
}

void ShutdownIndex()
{
    g_db.reset();
}

bool QueryChannel(const std::string& channel, int fromHeight, int toHeight,
                  std::vector<ChannelMessage>& out, std::string& error)
{
    AssertLockHeld(cs_main);
    out.clear();
    if (!g_db) {
        error = "The channel message index is disabled; start the node with -channelmessageindex";
        return false;
    }

    std::unique_ptr<CDBIterator> cursor(g_db->NewIterator());
    cursor->Seek(KeyOf(channel, uint256(), 0));
    while (cursor->Valid()) {
        MessageKey key;
        if (!cursor->GetKey(key) || key.first != DB_MESSAGE || key.second.first != channel)
            break;
        ChannelMessage message;
        if (!cursor->GetValue(message)) {
            error = "Failed to read the channel message index";
            return false;
        }
        // Records of blocks that left the active chain are ignored, not deleted
        if (message.height >= fromHeight && message.height <= toHeight) {
            const CBlockIndex* pindex = chainActive[message.height];
            if (pindex && pindex->GetBlockHash() == message.blockHash)
                out.push_back(message);
        }
        cursor->Next();
    }

    std::sort(out.begin(), out.end(), [](const ChannelMessage& a, const ChannelMessage& b) {
        return std::make_tuple(a.height, a.txIndex, a.vout) < std::make_tuple(b.height, b.txIndex, b.vout);
    });
    return true;
}

bool QueryChannelJSON(const QueryOptions& options, UniValue& result, std::string& error)
{
    AssertLockHeld(cs_main);
    if (!IsAssetNameAnOwner(options.channel) && !IsAssetNameAnMsgChannel(options.channel)) {
        error = "A channel is an owner token (NAME!) or a message channel (NAME~CHANNEL)";
        return false;
    }

    const int toHeight = options.toHeight < 0 ? chainActive.Height() : options.toHeight;
    std::vector<ChannelMessage> messages;
    if (!QueryChannel(options.channel, options.fromHeight, toHeight, messages, error))
        return false;

    // Expiry is decided here, against a time every node agrees on
    const int64_t referenceTime = options.referenceTime >= 0 ? options.referenceTime
                                                             : chainActive.Tip()->GetMedianTimePast();
    UniValue list(UniValue::VARR);
    UniValue nextFromHeight(UniValue::VNULL);
    size_t nReturned = 0;
    int lastHeight = -1;
    CBlock block;
    int blockHeight = -1;
    for (const auto& message : messages) {
        const bool fExpired = message.expireTime != 0 && message.expireTime <= referenceTime;
        if (fExpired && !options.fIncludeExpired)
            continue;
        const std::string encoded = EncodeAssetData(message.message);
        if (!options.messageFilter.empty() && encoded != options.messageFilter)
            continue;
        // A page ends between blocks, so from_height = next_from_height
        // resumes it without repeating or skipping a message
        if (nReturned >= options.limit && message.height != lastHeight) {
            nextFromHeight = message.height;
            break;
        }

        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("channel", message.channel));
        entry.push_back(Pair("authority", IsAssetNameAnOwner(message.channel) ? "owner" : "channel"));
        entry.push_back(Pair("txid", message.txid.GetHex()));
        entry.push_back(Pair("vout", static_cast<int64_t>(message.vout)));
        entry.push_back(Pair("height", message.height));
        entry.push_back(Pair("block_hash", message.blockHash.GetHex()));
        entry.push_back(Pair("block_time", message.blockTime));
        entry.push_back(Pair("expire_time", message.expireTime));
        entry.push_back(Pair("expired", fExpired));
        entry.push_back(Pair("message", encoded));
        entry.push_back(Pair("address", message.address));
        if (!message.opReturn.empty()) {
            entry.push_back(Pair("op_return", HexStr(message.opReturn)));
            // Inline content that authenticates itself: the message is its SHA-256
            uint256 digest;
            CSHA256().Write(message.opReturn.data(), message.opReturn.size()).Finalize(digest.begin());
            entry.push_back(Pair("op_return_matches", message.message == std::string(digest.begin(), digest.end())));
        }

        if (options.fIncludeTx || options.fIncludeProof) {
            // Messages come in chain order: one read per block
            if (blockHeight != message.height) {
                if (!ReadBlockFromDisk(block, chainActive[message.height], GetParams().GetConsensus())) {
                    error = strprintf("Failed to read block %d", message.height);
                    return false;
                }
                blockHeight = message.height;
            }
            if (message.txIndex >= block.vtx.size()) {
                error = strprintf("Failed to read block %d", message.height);
                return false;
            }
            if (options.fIncludeTx)
                entry.push_back(Pair("tx", EncodeHexTx(*block.vtx[message.txIndex])));
            if (options.fIncludeProof) {
                // The same proof as gettxoutproof: checked against a header
                CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                ss << CMerkleBlock(block, std::set<uint256>{message.txid});
                entry.push_back(Pair("proof", HexStr(ss.begin(), ss.end())));
            }
        }
        list.push_back(entry);
        ++nReturned;
        lastHeight = message.height;
    }

    result = UniValue(UniValue::VOBJ);
    result.push_back(Pair("channel", options.channel));
    result.push_back(Pair("synced_height", chainActive.Height()));
    result.push_back(Pair("reference_time", referenceTime));
    result.push_back(Pair("messages", list));
    result.push_back(Pair("next_from_height", nextFromHeight));
    return true;
}

} // namespace channelmessages
