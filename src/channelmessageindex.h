// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Chain-wide index of asset channel messages (-channelmessageindex, NIP-048
// delivery C).
//
// A channel message is a message carried by an owner token ("NAME!") or a
// message channel token ("NAME~CHANNEL") sent back to the address it came
// from, as legacy messaging defines it. The legacy inbox only keeps the
// channels of the local wallet and drops expired messages using the local
// clock; this index keeps every message of every channel, independent of any
// wallet, and leaves expiry to the query, so nodes synced at different times
// answer alike.
//
// Records are keyed by (channel, txid, vout) and carry the block they were
// mined in. They are never deleted: a query keeps the records whose block is
// in the active chain, so a reorganisation needs no undo. Every indexed block
// gets a marker, and startup indexes the active-chain blocks without one.

#ifndef NEURAI_CHANNELMESSAGEINDEX_H
#define NEURAI_CHANNELMESSAGEINDEX_H

#include "serialize.h"
#include "uint256.h"

#include <string>
#include <vector>

class CBlock;
class CBlockIndex;
class CBlockUndo;
class CChainParams;
class UniValue;

static const bool DEFAULT_CHANNELMESSAGEINDEX = false;

extern bool fChannelMessageIndex;

namespace channelmessages {

/** Storage schema of the records; a change rebuilds the index. */
static constexpr uint8_t INDEX_SCHEMA = 1;

struct ChannelMessage {
    std::string channel;                 //!< "NAME!" or "NAME~CHANNEL"
    uint256 txid;
    uint32_t vout = 0;
    uint32_t txIndex = 0;                //!< position of the transaction in its block
    int32_t height = 0;
    uint256 blockHash;
    int64_t blockTime = 0;
    int64_t expireTime = 0;              //!< 0: never expires
    std::string message;                 //!< raw bytes: 32-byte hash or 34-byte IPFS hash
    std::string address;                 //!< the address that sent the message to itself
    std::vector<unsigned char> opReturn; //!< data pushed by the transaction's OP_RETURN output, if any

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(channel);
        READWRITE(txid);
        READWRITE(vout);
        READWRITE(txIndex);
        READWRITE(height);
        READWRITE(blockHash);
        READWRITE(blockTime);
        READWRITE(expireTime);
        READWRITE(message);
        READWRITE(address);
        READWRITE(opReturn);
    }
};

/** First indexed height: no asset message exists before asset activation. */
int IndexStartHeight(const CChainParams& chainparams);

/** Messages of a connected block, from the block and its undo data. */
void BuildBlockMessages(const CBlock& block, const CBlockUndo& undo, const CBlockIndex* pindex,
                        std::vector<ChannelMessage>& out);

/** ConnectBlock (cs_main held): stores the messages of a connected block and
 *  marks it indexed. Not synchronous: a lost write leaves the block without a
 *  marker, and the next startup indexes it again. */
bool IndexConnectedBlock(const CBlock& block, const CBlockUndo& undo, const CBlockIndex* pindex);

/** Startup, after the chain is loaded (takes cs_main): opens the index, rebuilds
 *  it if its schema changed, and indexes the active-chain blocks it lacks.
 *  Returns false with `error` when the node must not start. */
bool InitIndex(const CChainParams& chainparams, std::string& error);

/** Closes the index. */
void ShutdownIndex();

/** Messages of a channel whose block is in the active chain and whose height
 *  is in [fromHeight, toHeight], in chain order (cs_main held). */
bool QueryChannel(const std::string& channel, int fromHeight, int toHeight,
                  std::vector<ChannelMessage>& out, std::string& error);

/** Messages returned by one query: a block is never split, so the last block
 *  of a page may go past the limit. */
static const size_t DEFAULT_CHANNEL_MESSAGES_LIMIT = 1000;
static const size_t MAX_CHANNEL_MESSAGES_LIMIT = 10000;

struct QueryOptions {
    std::string channel;
    size_t limit = DEFAULT_CHANNEL_MESSAGES_LIMIT;
    int fromHeight = 0;
    int toHeight = -1;            //!< -1: the tip
    bool fIncludeExpired = false;
    int64_t referenceTime = -1;   //!< expiry reference; -1: median time past of the tip
    std::string messageFilter;    //!< only messages with this encoded payload
    bool fIncludeTx = false;
    bool fIncludeProof = false;
};

/** JSON shared by getchannelmessages and REST (cs_main held). When the limit
 *  stops the query, next_from_height is where the next page starts. */
bool QueryChannelJSON(const QueryOptions& options, UniValue& result, std::string& error);

} // namespace channelmessages

#endif // NEURAI_CHANNELMESSAGEINDEX_H
