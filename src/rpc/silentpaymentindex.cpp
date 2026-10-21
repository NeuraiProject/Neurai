// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// RPC interface of the NIP-047 light client index (silentpaymentindex.h).
// Public chain data only: no wallet and no keys.

#include "chain.h"
#include "chainparams.h"
#include "rpc/server.h"
#include "silentpaymentindex.h"
#include "sync.h"
#include "utilstrencodings.h"
#include "validation.h"

#include <univalue.h>

static void RequireIndex()
{
    if (!fSilentPaymentIndex)
        throw JSONRPCError(RPC_MISC_ERROR, "Silent payment index is disabled (start the node with -silentpaymentindex)");
}

static bool ParseEncoding(const UniValue& value)
{
    const std::string encoding = value.isNull() ? "json" : value.get_str();
    if (encoding != "json" && encoding != "hex")
        throw JSONRPCError(RPC_INVALID_PARAMETER, "encoding must be \"json\" or \"hex\"");
    return encoding == "hex";
}

UniValue getsilentpaymentindexinfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getsilentpaymentindexinfo\n"
            "\nState of the NIP-047 silent payment index (-silentpaymentindex).\n"
            "\nResult:\n"
            "{\n"
            "  \"enabled\" : true|false,      (boolean) whether the node maintains the index\n"
            "  \"state\" : \"str\",             (string) disabled, ready or incomplete (records missing and their blocks pruned)\n"
            "  \"schema\" : n,                (numeric) storage schema of the records\n"
            "  \"formats\" : [n,...],         (array) public formats served\n"
            "  \"context\" : \"hex\",           (string) NIP-047 context N: network id, genesis, profile and family\n"
            "  \"start_height\" : n,          (numeric) first indexed height: max(1, strict AuthScript activation)\n"
            "  \"synced_height\" : n,         (numeric) every active block from start_height to this height has a record\n"
            "  \"synced_hash\" : \"hash\",      (string) hash of the block at synced_height\n"
            "  \"complete\" : true|false,     (boolean) ready and synced up to the tip\n"
            "  \"missing\" : [[n,n],...],     (array) height ranges without a record or block data to rebuild it\n"
            "  \"pruned\" : true|false        (boolean) whether the node has deleted block files\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getsilentpaymentindexinfo", "")
            + HelpExampleRpc("getsilentpaymentindexinfo", "")
        );

    return silentpayments::IndexStatusToJSON(silentpayments::GetIndexStatus());
}

UniValue getsilentpaymenttweaks(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "getsilentpaymenttweaks \"blockhash\" ( \"encoding\" )\n"
            "\nNIP-047 light client data of one block: every eligible transaction with a native v3 output,\n"
            "its public tweak T = h*A and all its native v3 outputs, plus every native v3 output the block spends.\n"
            "A receiver computes b_scan*T for each entry; the node learns nothing about it.\n"
            "Requires -silentpaymentindex.\n"
            "\nArguments:\n"
            "1. \"blockhash\"     (string, required) the block hash\n"
            "2. \"encoding\"      (string, optional, default=json) json, or hex for the binary message of type 1\n"
            "\nResult (json):\n"
            "{\n"
            "  \"format\" : 1,\n"
            "  \"context\" : \"hex\",          (string) NIP-047 context N\n"
            "  \"block\" : {                  (object) immutable for this block hash\n"
            "    \"height\" : n,\n"
            "    \"hash\" : \"hash\",\n"
            "    \"prev\" : \"hash\",\n"
            "    \"entries\" : [\n"
            "      {\n"
            "        \"txid\" : \"hex\",\n"
            "        \"tweak\" : \"hex\",          (string) 33-byte compressed point T\n"
            "        \"outputs\" : [{ \"vout\" : n, \"commitment\" : \"hex\", \"value_sat\" : \"n\" },...]\n"
            "      },...\n"
            "    ],\n"
            "    \"spent\" : [{ \"txid\" : \"hex\", \"vout\" : n },...],\n"
            "    \"digest\" : \"hex\"            (string) tagged hash of the canonical block bytes\n"
            "  },\n"
            "  \"in_active_chain\" : true|false\n"
            "}\n"
            "\nResult (hex):\n"
            "\"hex\"                         (string) binary message of type 1\n"
            "\nExamples:\n"
            + HelpExampleCli("getsilentpaymenttweaks", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
            + HelpExampleRpc("getsilentpaymenttweaks", "\"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
        );

    RequireIndex();
    const uint256 hash = ParseHashV(request.params[0], "blockhash");
    const bool hex = ParseEncoding(request.params[1]);
    bool inActiveChain;
    int height;
    {
        LOCK(cs_main);
        BlockMap::const_iterator it = mapBlockIndex.find(hash);
        if (it == mapBlockIndex.end())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");
        height = it->second->nHeight;
        if (height < silentpayments::IndexStartHeight(GetParams().GetConsensus()))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Block is below the start height of the silent payment index");
        inActiveChain = chainActive.Contains(it->second);
    }
    silentpayments::IndexBlock block;
    std::vector<unsigned char> bytes;
    if (!silentpayments::ReadIndexRecord(hash, block, bytes) || block.height != (uint32_t)height)
        throw JSONRPCError(RPC_MISC_ERROR, "No silent payment index record for this block (see getsilentpaymentindexinfo)");

    if (hex) {
        std::vector<unsigned char> message;
        silentpayments::SerializeIndexBlockMessage(silentpayments::LocalContext(), bytes, message);
        return HexStr(message);
    }
    UniValue result = silentpayments::IndexBlockMessageToJSON(block, bytes);
    result.pushKV("in_active_chain", UniValue(inActiveChain));
    return result;
}

UniValue getsilentpaymenttweaksrange(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 4)
        throw std::runtime_error(
            "getsilentpaymenttweaksrange start_height count ( \"anchor_hash\" \"encoding\" )\n"
            "\nNIP-047 light client data of consecutive blocks of the active chain, as getsilentpaymenttweaks.\n"
            "The blocks come from one snapshot of the active chain. Whole blocks only: at least one, up to\n"
            "1000 blocks and 4 MB. Requires -silentpaymentindex.\n"
            "\nArguments:\n"
            "1. start_height      (numeric, required) first height, from start_height of getsilentpaymentindexinfo\n"
            "                     up to the tip + 1 (an empty answer with status \"tip\")\n"
            "2. count             (numeric, required) number of blocks wanted\n"
            "3. \"anchor_hash\"     (string, optional) hash the client has at start_height - 1. If it left the active\n"
            "                     chain the answer is {\"reorg\": true, \"fork_height\": n}: continue from fork_height + 1\n"
            "4. \"encoding\"        (string, optional, default=json) json, or hex for the binary message of type 2\n"
            "\nResult (json):\n"
            "{\n"
            "  \"format\" : 1,\n"
            "  \"context\" : \"hex\",\n"
            "  \"snapshot\" : { \"height\" : n, \"hash\" : \"hash\" },  (object) tip when the request was served\n"
            "  \"synced_height\" : n,\n"
            "  \"blocks\" : [ {...},... ],     (array) as \"block\" in getsilentpaymenttweaks\n"
            "  \"next_height\" : n,            (numeric) height after the last block returned\n"
            "  \"status\" : \"str\"             (string) more: ask again now; tip: wait for a new block;\n"
            "                                incomplete: the index lacks data from next_height\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getsilentpaymenttweaksrange", "1000 100")
            + HelpExampleRpc("getsilentpaymenttweaksrange", "1000, 100, \"00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09\"")
        );

    silentpayments::RangeRequest range;
    range.startHeight = request.params[0].get_int();
    range.count = request.params[1].get_int64();
    if (!request.params[2].isNull() && !request.params[2].get_str().empty()) {
        range.hasAnchor = true;
        range.anchor = ParseHashV(request.params[2], "anchor_hash");
    }
    const bool hex = ParseEncoding(request.params[3]);

    silentpayments::RangeResult result;
    std::string error;
    switch (silentpayments::QueryRange(range, result, error)) {
    case silentpayments::RangeError::NONE: break;
    case silentpayments::RangeError::DISABLED: throw JSONRPCError(RPC_MISC_ERROR, error);
    case silentpayments::RangeError::INVALID_PARAMETER: throw JSONRPCError(RPC_INVALID_PARAMETER, error);
    case silentpayments::RangeError::ANCHOR_NOT_FOUND: throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);
    case silentpayments::RangeError::INCOMPLETE: throw JSONRPCError(RPC_MISC_ERROR, error);
    case silentpayments::RangeError::READ_FAILED: throw JSONRPCError(RPC_DATABASE_ERROR, error);
    }
    if (hex && !result.reorg) {
        std::vector<unsigned char> message;
        silentpayments::RangeResultToMessage(result, message);
        return HexStr(message);
    }
    return silentpayments::RangeResultToJSON(result);
}

static const CRPCCommand commands[] =
{ //  category              name                            actor (function)               argNames
  //  --------------------- ------------------------------  -----------------------------  ----------
    { "blockchain",         "getsilentpaymentindexinfo",    &getsilentpaymentindexinfo,    {} },
    { "blockchain",         "getsilentpaymenttweaks",       &getsilentpaymenttweaks,       {"blockhash", "encoding"} },
    { "blockchain",         "getsilentpaymenttweaksrange",  &getsilentpaymenttweaksrange,  {"start_height", "count", "anchor_hash", "encoding"} },
};

void RegisterSilentPaymentIndexRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
