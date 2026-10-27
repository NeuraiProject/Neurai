// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain.h"
#include "chainparams.h"
#include "core_io.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "validation.h"
#include "httpserver.h"
#include "rpc/blockchain.h"
#include "rpc/server.h"
#include "channelmessageindex.h"
#include "silentpaymentindex.h"
#include "streams.h"
#include "sync.h"
#include "txmempool.h"
#include "utilstrencodings.h"
#include "version.h"

#include <boost/algorithm/string.hpp>

#include <univalue.h>

static const size_t MAX_GETUTXOS_OUTPOINTS = 15; //allow a max of 15 outpoints to be queried at once

enum RetFormat {
    RF_UNDEF,
    RF_BINARY,
    RF_HEX,
    RF_JSON,
};

static const struct {
    enum RetFormat rf;
    const char* name;
} rf_names[] = {
      {RF_UNDEF, ""},
      {RF_BINARY, "bin"},
      {RF_HEX, "hex"},
      {RF_JSON, "json"},
};

struct CCoin {
    uint32_t nHeight;
    CTxOut out;

    ADD_SERIALIZE_METHODS;

    CCoin() : nHeight(0) {}
    explicit CCoin(Coin&& in) : nHeight(in.nHeight), out(std::move(in.out)) {}

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        uint32_t nTxVerDummy = 0;
        READWRITE(nTxVerDummy);
        READWRITE(nHeight);
        READWRITE(out);
    }
};

static bool RESTERR(HTTPRequest* req, enum HTTPStatusCode status, std::string message)
{
    req->WriteHeader("Content-Type", "text/plain");
    req->WriteReply(status, message + "\r\n");
    return false;
}

static enum RetFormat ParseDataFormat(std::string& param, const std::string& strReq)
{
    const std::string::size_type pos = strReq.rfind('.');
    if (pos == std::string::npos)
    {
        param = strReq;
        return rf_names[0].rf;
    }

    param = strReq.substr(0, pos);
    const std::string suff(strReq, pos + 1);

    for (unsigned int i = 0; i < ARRAYLEN(rf_names); i++)
        if (suff == rf_names[i].name)
            return rf_names[i].rf;

    /* If no suffix is found, return original string.  */
    param = strReq;
    return rf_names[0].rf;
}

static std::string AvailableDataFormatsString()
{
    std::string formats = "";
    for (unsigned int i = 0; i < ARRAYLEN(rf_names); i++)
        if (strlen(rf_names[i].name) > 0) {
            formats.append(".");
            formats.append(rf_names[i].name);
            formats.append(", ");
        }

    if (formats.length() > 0)
        return formats.substr(0, formats.length() - 2);

    return formats;
}

static bool ParseHashStr(const std::string& strReq, uint256& v)
{
    if (!IsHex(strReq) || (strReq.size() != 64))
        return false;

    v.SetHex(strReq);
    return true;
}

static bool CheckWarmup(HTTPRequest* req)
{
    std::string statusmessage;
    if (RPCIsInWarmup(&statusmessage))
         return RESTERR(req, HTTP_SERVICE_UNAVAILABLE, "Service temporarily unavailable: " + statusmessage);
    return true;
}

static bool rest_headers(HTTPRequest* req,
                         const std::string& strURIPart)
{
    if (!CheckWarmup(req))
        return false;
    std::string param;
    const RetFormat rf = ParseDataFormat(param, strURIPart);
    std::vector<std::string> path;
    boost::split(path, param, boost::is_any_of("/"));

    if (path.size() != 2)
        return RESTERR(req, HTTP_BAD_REQUEST, "No header count specified. Use /rest/headers/<count>/<hash>.<ext>.");

    long count = strtol(path[0].c_str(), nullptr, 10);
    if (count < 1 || count > 2000)
        return RESTERR(req, HTTP_BAD_REQUEST, "Header count out of range: " + path[0]);

    std::string hashStr = path[1];
    uint256 hash;
    if (!ParseHashStr(hashStr, hash))
        return RESTERR(req, HTTP_BAD_REQUEST, "Invalid hash: " + hashStr);

    std::vector<const CBlockIndex *> headers;
    headers.reserve(count);
    {
        LOCK(cs_main);
        BlockMap::const_iterator it = mapBlockIndex.find(hash);
        const CBlockIndex *pindex = (it != mapBlockIndex.end()) ? it->second : nullptr;
        while (pindex != nullptr && chainActive.Contains(pindex)) {
            headers.push_back(pindex);
            if (headers.size() == (unsigned long)count)
                break;
            pindex = chainActive.Next(pindex);
        }
    }

    CDataStream ssHeader(SER_NETWORK, PROTOCOL_VERSION);
    for (const CBlockIndex *pindex : headers) {
        ssHeader << pindex->GetBlockHeader();
    }

    switch (rf) {
    case RF_BINARY: {
        std::string binaryHeader = ssHeader.str();
        req->WriteHeader("Content-Type", "application/octet-stream");
        req->WriteReply(HTTP_OK, binaryHeader);
        return true;
    }

    case RF_HEX: {
        std::string strHex = HexStr(ssHeader.begin(), ssHeader.end()) + "\n";
        req->WriteHeader("Content-Type", "text/plain");
        req->WriteReply(HTTP_OK, strHex);
        return true;
    }
    case RF_JSON: {
        UniValue jsonHeaders(UniValue::VARR);
        for (const CBlockIndex *pindex : headers) {
            jsonHeaders.push_back(blockheaderToJSON(pindex));
        }
        std::string strJSON = jsonHeaders.write() + "\n";
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, strJSON);
        return true;
    }
    default: {
        return RESTERR(req, HTTP_NOT_FOUND, "output format not found (available: .bin, .hex)");
    }
    }
}

static bool rest_block(HTTPRequest* req,
                       const std::string& strURIPart,
                       bool showTxDetails)
{
    if (!CheckWarmup(req))
        return false;
    std::string hashStr;
    const RetFormat rf = ParseDataFormat(hashStr, strURIPart);

    uint256 hash;
    if (!ParseHashStr(hashStr, hash))
        return RESTERR(req, HTTP_BAD_REQUEST, "Invalid hash: " + hashStr);

    CBlock block;
    CBlockIndex* pblockindex = nullptr;
    {
        LOCK(cs_main);
        if (mapBlockIndex.count(hash) == 0)
            return RESTERR(req, HTTP_NOT_FOUND, hashStr + " not found");

        pblockindex = mapBlockIndex[hash];
        if (fHavePruned && !(pblockindex->nStatus & BLOCK_HAVE_DATA) && pblockindex->nTx > 0)
            return RESTERR(req, HTTP_NOT_FOUND, hashStr + " not available (pruned data)");

        if (!ReadBlockFromDisk(block, pblockindex, GetParams().GetConsensus()))
            return RESTERR(req, HTTP_NOT_FOUND, hashStr + " not found");
    }

    CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION | RPCSerializationFlags());
    ssBlock << block;

    switch (rf) {
    case RF_BINARY: {
        std::string binaryBlock = ssBlock.str();
        req->WriteHeader("Content-Type", "application/octet-stream");
        req->WriteReply(HTTP_OK, binaryBlock);
        return true;
    }

    case RF_HEX: {
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end()) + "\n";
        req->WriteHeader("Content-Type", "text/plain");
        req->WriteReply(HTTP_OK, strHex);
        return true;
    }

    case RF_JSON: {
        UniValue objBlock = blockToJSON(block, pblockindex, showTxDetails);
        std::string strJSON = objBlock.write() + "\n";
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, strJSON);
        return true;
    }

    default: {
        return RESTERR(req, HTTP_NOT_FOUND, "output format not found (available: " + AvailableDataFormatsString() + ")");
    }
    }
}

static bool rest_block_extended(HTTPRequest* req, const std::string& strURIPart)
{
    return rest_block(req, strURIPart, true);
}

static bool rest_block_notxdetails(HTTPRequest* req, const std::string& strURIPart)
{
    return rest_block(req, strURIPart, false);
}

// A bit of a hack - dependency on a function defined in rpc/blockchain.cpp
UniValue getblockchaininfo(const JSONRPCRequest& request);

static bool rest_chaininfo(HTTPRequest* req, const std::string& strURIPart)
{
    if (!CheckWarmup(req))
        return false;
    std::string param;
    const RetFormat rf = ParseDataFormat(param, strURIPart);

    switch (rf) {
    case RF_JSON: {
        JSONRPCRequest jsonRequest;
        jsonRequest.params = UniValue(UniValue::VARR);
        UniValue chainInfoObject = getblockchaininfo(jsonRequest);
        std::string strJSON = chainInfoObject.write() + "\n";
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, strJSON);
        return true;
    }
    default: {
        return RESTERR(req, HTTP_NOT_FOUND, "output format not found (available: json)");
    }
    }
}

static bool rest_mempool_info(HTTPRequest* req, const std::string& strURIPart)
{
    if (!CheckWarmup(req))
        return false;
    std::string param;
    const RetFormat rf = ParseDataFormat(param, strURIPart);

    switch (rf) {
    case RF_JSON: {
        UniValue mempoolInfoObject = mempoolInfoToJSON();

        std::string strJSON = mempoolInfoObject.write() + "\n";
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, strJSON);
        return true;
    }
    default: {
        return RESTERR(req, HTTP_NOT_FOUND, "output format not found (available: json)");
    }
    }
}

static bool rest_mempool_contents(HTTPRequest* req, const std::string& strURIPart)
{
    if (!CheckWarmup(req))
        return false;
    std::string param;
    const RetFormat rf = ParseDataFormat(param, strURIPart);

    switch (rf) {
    case RF_JSON: {
        UniValue mempoolObject = mempoolToJSON(true);

        std::string strJSON = mempoolObject.write() + "\n";
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, strJSON);
        return true;
    }
    default: {
        return RESTERR(req, HTTP_NOT_FOUND, "output format not found (available: json)");
    }
    }
}

static bool rest_tx(HTTPRequest* req, const std::string& strURIPart)
{
    if (!CheckWarmup(req))
        return false;
    std::string hashStr;
    const RetFormat rf = ParseDataFormat(hashStr, strURIPart);

    uint256 hash;
    if (!ParseHashStr(hashStr, hash))
        return RESTERR(req, HTTP_BAD_REQUEST, "Invalid hash: " + hashStr);

    CTransactionRef tx;
    uint256 hashBlock = uint256();
    if (!GetTransaction(hash, tx, GetParams().GetConsensus(), hashBlock, true))
        return RESTERR(req, HTTP_NOT_FOUND, hashStr + " not found");

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION | RPCSerializationFlags());
    ssTx << tx;

    switch (rf) {
    case RF_BINARY: {
        std::string binaryTx = ssTx.str();
        req->WriteHeader("Content-Type", "application/octet-stream");
        req->WriteReply(HTTP_OK, binaryTx);
        return true;
    }

    case RF_HEX: {
        std::string strHex = HexStr(ssTx.begin(), ssTx.end()) + "\n";
        req->WriteHeader("Content-Type", "text/plain");
        req->WriteReply(HTTP_OK, strHex);
        return true;
    }

    case RF_JSON: {
        UniValue objTx(UniValue::VOBJ);
        TxToUniv(*tx, hashBlock, objTx);
        std::string strJSON = objTx.write() + "\n";
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, strJSON);
        return true;
    }

    default: {
        return RESTERR(req, HTTP_NOT_FOUND, "output format not found (available: " + AvailableDataFormatsString() + ")");
    }
    }
}

static bool rest_getutxos(HTTPRequest* req, const std::string& strURIPart)
{
    if (!CheckWarmup(req))
        return false;
    std::string param;
    const RetFormat rf = ParseDataFormat(param, strURIPart);

    std::vector<std::string> uriParts;
    if (param.length() > 1)
    {
        std::string strUriParams = param.substr(1);
        boost::split(uriParts, strUriParams, boost::is_any_of("/"));
    }

    // throw exception in case of an empty request
    std::string strRequestMutable = req->ReadBody();
    if (strRequestMutable.length() == 0 && uriParts.size() == 0)
        return RESTERR(req, HTTP_BAD_REQUEST, "Error: empty request");

    bool fInputParsed = false;
    bool fCheckMemPool = false;
    std::vector<COutPoint> vOutPoints;

    // parse/deserialize input
    // input-format = output-format, rest/getutxos/bin requires binary input, gives binary output, ...

    if (uriParts.size() > 0)
    {
        //inputs is sent over URI scheme (/rest/getutxos/checkmempool/txid1-n/txid2-n/...)
        if (uriParts[0] == "checkmempool") fCheckMemPool = true;

        for (size_t i = (fCheckMemPool) ? 1 : 0; i < uriParts.size(); i++)
        {
            uint256 txid;
            int32_t nOutput;
            std::string strTxid = uriParts[i].substr(0, uriParts[i].find("-"));
            std::string strOutput = uriParts[i].substr(uriParts[i].find("-")+1);

            if (!ParseInt32(strOutput, &nOutput) || !IsHex(strTxid))
                return RESTERR(req, HTTP_BAD_REQUEST, "Parse error");

            txid.SetHex(strTxid);
            vOutPoints.push_back(COutPoint(txid, (uint32_t)nOutput));
        }

        if (vOutPoints.size() > 0)
            fInputParsed = true;
        else
            return RESTERR(req, HTTP_BAD_REQUEST, "Error: empty request");
    }

    switch (rf) {
    case RF_HEX: {
        // convert hex to bin, continue then with bin part
        std::vector<unsigned char> strRequestV = ParseHex(strRequestMutable);
        strRequestMutable.assign(strRequestV.begin(), strRequestV.end());
    }

    case RF_BINARY: {
        try {
            //deserialize only if user sent a request
            if (strRequestMutable.size() > 0)
            {
                if (fInputParsed) //don't allow sending input over URI and HTTP RAW DATA
                    return RESTERR(req, HTTP_BAD_REQUEST, "Combination of URI scheme inputs and raw post data is not allowed");

                CDataStream oss(SER_NETWORK, PROTOCOL_VERSION);
                oss << strRequestMutable;
                oss >> fCheckMemPool;
                oss >> vOutPoints;
            }
        } catch (const std::ios_base::failure& e) {
            // abort in case of unreadable binary data
            return RESTERR(req, HTTP_BAD_REQUEST, "Parse error");
        }
        break;
    }

    case RF_JSON: {
        if (!fInputParsed)
            return RESTERR(req, HTTP_BAD_REQUEST, "Error: empty request");
        break;
    }
    default: {
        return RESTERR(req, HTTP_NOT_FOUND, "output format not found (available: " + AvailableDataFormatsString() + ")");
    }
    }

    // limit max outpoints
    if (vOutPoints.size() > MAX_GETUTXOS_OUTPOINTS)
        return RESTERR(req, HTTP_BAD_REQUEST, strprintf("Error: max outpoints exceeded (max: %d, tried: %d)", MAX_GETUTXOS_OUTPOINTS, vOutPoints.size()));

    // check spentness and form a bitmap (as well as a JSON capable human-readable string representation)
    std::vector<unsigned char> bitmap;
    std::vector<CCoin> outs;
    std::string bitmapStringRepresentation;
    std::vector<bool> hits;
    bitmap.resize((vOutPoints.size() + 7) / 8);
    {
        LOCK2(cs_main, mempool.cs);

        CCoinsView viewDummy;
        CCoinsViewCache view(&viewDummy);

        CCoinsViewCache& viewChain = *pcoinsTip;
        CCoinsViewMemPool viewMempool(&viewChain, mempool);

        if (fCheckMemPool)
            view.SetBackend(viewMempool); // switch cache backend to db+mempool in case user likes to query mempool

        for (size_t i = 0; i < vOutPoints.size(); i++) {
            bool hit = false;
            Coin coin;
            if (view.GetCoin(vOutPoints[i], coin) && !mempool.isSpent(vOutPoints[i])) {
                hit = true;
                outs.emplace_back(std::move(coin));
            }

            hits.push_back(hit);
            bitmapStringRepresentation.append(hit ? "1" : "0"); // form a binary string representation (human-readable for json output)
            bitmap[i / 8] |= ((uint8_t)hit) << (i % 8);
        }
    }

    switch (rf) {
    case RF_BINARY: {
        // serialize data
        // use exact same output as mentioned in Bip64
        CDataStream ssGetUTXOResponse(SER_NETWORK, PROTOCOL_VERSION);
        ssGetUTXOResponse << chainActive.Height() << chainActive.Tip()->GetBlockHash() << bitmap << outs;
        std::string ssGetUTXOResponseString = ssGetUTXOResponse.str();

        req->WriteHeader("Content-Type", "application/octet-stream");
        req->WriteReply(HTTP_OK, ssGetUTXOResponseString);
        return true;
    }

    case RF_HEX: {
        CDataStream ssGetUTXOResponse(SER_NETWORK, PROTOCOL_VERSION);
        ssGetUTXOResponse << chainActive.Height() << chainActive.Tip()->GetBlockHash() << bitmap << outs;
        std::string strHex = HexStr(ssGetUTXOResponse.begin(), ssGetUTXOResponse.end()) + "\n";

        req->WriteHeader("Content-Type", "text/plain");
        req->WriteReply(HTTP_OK, strHex);
        return true;
    }

    case RF_JSON: {
        UniValue objGetUTXOResponse(UniValue::VOBJ);

        // pack in some essentials
        // use more or less the same output as mentioned in Bip64
        objGetUTXOResponse.push_back(Pair("chainHeight", chainActive.Height()));
        objGetUTXOResponse.push_back(Pair("chaintipHash", chainActive.Tip()->GetBlockHash().GetHex()));
        objGetUTXOResponse.push_back(Pair("bitmap", bitmapStringRepresentation));

        UniValue utxos(UniValue::VARR);
        for (const CCoin& coin : outs) {
            UniValue utxo(UniValue::VOBJ);
            utxo.push_back(Pair("height", (int32_t)coin.nHeight));
            utxo.push_back(Pair("value", ValueFromAmount(coin.out.nValue)));

            // include the script in a json output
            UniValue o(UniValue::VOBJ);
            ScriptPubKeyToUniv(coin.out.scriptPubKey, o, true);
            utxo.push_back(Pair("scriptPubKey", o));
            utxos.push_back(utxo);
        }
        objGetUTXOResponse.push_back(Pair("utxos", utxos));

        // return json string
        std::string strJSON = objGetUTXOResponse.write() + "\n";
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, strJSON);
        return true;
    }
    default: {
        return RESTERR(req, HTTP_NOT_FOUND, "output format not found (available: " + AvailableDataFormatsString() + ")");
    }
    }
}

// NIP-047 light client index (silentpaymentindex.h). The format version is
// part of the path, so caches never mix formats.

/** Removes "?query" from `path` and returns the query. */
static std::string StripQuery(std::string& path)
{
    const std::string::size_type pos = path.find('?');
    if (pos == std::string::npos) return "";
    const std::string query = path.substr(pos + 1);
    path = path.substr(0, pos);
    return query;
}

static std::string QueryValue(const std::string& query, const std::string& name)
{
    std::vector<std::string> params;
    boost::split(params, query, boost::is_any_of("&"));
    for (const std::string& param : params) {
        if (param.compare(0, name.size() + 1, name + "=") == 0) return param.substr(name.size() + 1);
    }
    return "";
}

static bool WriteIndexReply(HTTPRequest* req, RetFormat rf, const std::vector<unsigned char>& message,
                            const UniValue& json, const std::string& cacheControl)
{
    req->WriteHeader("Cache-Control", cacheControl);
    switch (rf) {
    case RF_BINARY:
        req->WriteHeader("Content-Type", "application/octet-stream");
        req->WriteReply(HTTP_OK, std::string(message.begin(), message.end()));
        return true;
    case RF_HEX:
        req->WriteHeader("Content-Type", "text/plain");
        req->WriteReply(HTTP_OK, HexStr(message) + "\n");
        return true;
    case RF_JSON:
        req->WriteHeader("Content-Type", "application/json");
        req->WriteReply(HTTP_OK, json.write() + "\n");
        return true;
    default:
        return RESTERR(req, HTTP_NOT_FOUND, "output format not found (available: " + AvailableDataFormatsString() + ")");
    }
}

static bool rest_sp_tweaks(HTTPRequest* req, const std::string& strURIPart)
{
    if (!CheckWarmup(req))
        return false;
    if (!fSilentPaymentIndex)
        return RESTERR(req, HTTP_SERVICE_UNAVAILABLE, "Silent payment index is disabled");
    std::string path = strURIPart;
    StripQuery(path);
    std::string hashStr;
    const RetFormat rf = ParseDataFormat(hashStr, path);
    uint256 hash;
    if (!ParseHashStr(hashStr, hash))
        return RESTERR(req, HTTP_BAD_REQUEST, "Invalid hash: " + hashStr);
    int height;
    {
        LOCK(cs_main);
        BlockMap::const_iterator it = mapBlockIndex.find(hash);
        if (it == mapBlockIndex.end())
            return RESTERR(req, HTTP_NOT_FOUND, hashStr + " not found");
        height = it->second->nHeight;
    }
    silentpayments::IndexBlock block;
    std::vector<unsigned char> bytes;
    if (height < silentpayments::IndexStartHeight(GetParams().GetConsensus()) ||
        !silentpayments::ReadIndexRecord(hash, block, bytes) || block.height != (uint32_t)height)
        return RESTERR(req, HTTP_NOT_FOUND, hashStr + " has no silent payment index record");
    std::vector<unsigned char> message;
    if (rf == RF_BINARY || rf == RF_HEX)
        silentpayments::SerializeIndexBlockMessage(silentpayments::LocalContext(), bytes, message);
    // The record of a block hash never changes.
    return WriteIndexReply(req, rf, message, rf == RF_JSON ? silentpayments::IndexBlockMessageToJSON(block, bytes) : UniValue(),
                           "public, max-age=31536000, immutable");
}

static bool rest_sp_tweaks_range(HTTPRequest* req, const std::string& strURIPart)
{
    if (!CheckWarmup(req))
        return false;
    std::string path = strURIPart;
    const std::string anchor = QueryValue(StripQuery(path), "anchor");
    std::string param;
    const RetFormat rf = ParseDataFormat(param, path);
    std::vector<std::string> parts;
    boost::split(parts, param, boost::is_any_of("/"));
    int32_t startHeight;
    int64_t count;
    if (parts.size() != 2 || !ParseInt32(parts[0], &startHeight) || !ParseInt64(parts[1], &count))
        return RESTERR(req, HTTP_BAD_REQUEST, "Use /rest/sptweaksrange/v1/<height>/<count>.<ext>?anchor=<hash>");
    silentpayments::RangeRequest range;
    range.startHeight = startHeight;
    range.count = count;
    if (!anchor.empty()) {
        if (!ParseHashStr(anchor, range.anchor))
            return RESTERR(req, HTTP_BAD_REQUEST, "Invalid anchor: " + anchor);
        range.hasAnchor = true;
    }
    if (rf == RF_UNDEF)
        return RESTERR(req, HTTP_NOT_FOUND, "output format not found (available: " + AvailableDataFormatsString() + ")");

    silentpayments::RangeResult result;
    std::string error;
    switch (silentpayments::QueryRange(range, result, error)) {
    case silentpayments::RangeError::NONE: break;
    case silentpayments::RangeError::DISABLED: return RESTERR(req, HTTP_SERVICE_UNAVAILABLE, error);
    case silentpayments::RangeError::INVALID_PARAMETER: return RESTERR(req, HTTP_BAD_REQUEST, error);
    case silentpayments::RangeError::ANCHOR_NOT_FOUND: return RESTERR(req, HTTP_NOT_FOUND, error);
    case silentpayments::RangeError::INCOMPLETE: return RESTERR(req, HTTP_NOT_FOUND, error);
    case silentpayments::RangeError::READ_FAILED: return RESTERR(req, HTTP_INTERNAL_SERVER_ERROR, error);
    }
    if (result.reorg) {
        // Conflict: the anchor left the active chain. JSON for every format.
        req->WriteHeader("Content-Type", "application/json");
        req->WriteHeader("Cache-Control", "no-store");
        req->WriteReply(409, silentpayments::RangeResultToJSON(result).write() + "\n");
        return true;
    }
    std::vector<unsigned char> message;
    if (rf == RF_BINARY || rf == RF_HEX) silentpayments::RangeResultToMessage(result, message);
    // Heights depend on the active chain: cache briefly only.
    return WriteIndexReply(req, rf, message, rf == RF_JSON ? silentpayments::RangeResultToJSON(result) : UniValue(),
                           "public, max-age=5");
}

static bool rest_sp_index_info(HTTPRequest* req, const std::string& strURIPart)
{
    if (!CheckWarmup(req))
        return false;
    std::string param;
    if (ParseDataFormat(param, strURIPart) != RF_JSON || !param.empty())
        return RESTERR(req, HTTP_NOT_FOUND, "output format not found (available: json)");
    req->WriteHeader("Content-Type", "application/json");
    req->WriteHeader("Cache-Control", "no-store");
    req->WriteReply(HTTP_OK, silentpayments::IndexStatusToJSON(silentpayments::GetIndexStatus()).write() + "\n");
    return true;
}

// NIP-048 C: messages of an asset channel, from -channelmessageindex. The
// channel goes last because sub-asset names contain '/'.
static bool rest_channel_messages(HTTPRequest* req, const std::string& strURIPart)
{
    if (!CheckWarmup(req))
        return false;
    std::string param;
    if (ParseDataFormat(param, strURIPart) != RF_JSON)
        return RESTERR(req, HTTP_NOT_FOUND, "output format not found (available: json)");
    const std::string::size_type slash = param.find('/');
    int fromHeight = 0;
    if (slash == std::string::npos || !ParseInt32(param.substr(0, slash), &fromHeight) || fromHeight < 0)
        return RESTERR(req, HTTP_BAD_REQUEST, "Use /rest/channelmessages/<from_height>/<channel>.json");

    channelmessages::QueryOptions options;
    options.channel = param.substr(slash + 1);
    options.fromHeight = fromHeight;
    UniValue result;
    std::string error;
    {
        LOCK(cs_main);
        if (!channelmessages::QueryChannelJSON(options, result, error))
            return RESTERR(req, fChannelMessageIndex ? HTTP_BAD_REQUEST : HTTP_SERVICE_UNAVAILABLE, error);
    }
    req->WriteHeader("Content-Type", "application/json");
    req->WriteReply(HTTP_OK, result.write() + "\n");
    return true;
}

static const struct {
    const char* prefix;
    bool (*handler)(HTTPRequest* req, const std::string& strReq);
} uri_prefixes[] = {
      {"/rest/tx/", rest_tx},
      {"/rest/block/notxdetails/", rest_block_notxdetails},
      {"/rest/block/", rest_block_extended},
      {"/rest/chaininfo", rest_chaininfo},
      {"/rest/mempool/info", rest_mempool_info},
      {"/rest/mempool/contents", rest_mempool_contents},
      {"/rest/headers/", rest_headers},
      {"/rest/getutxos", rest_getutxos},
      {"/rest/sptweaks/v1/", rest_sp_tweaks},
      {"/rest/sptweaksrange/v1/", rest_sp_tweaks_range},
      {"/rest/spindexinfo", rest_sp_index_info},
      {"/rest/channelmessages/", rest_channel_messages},
};

bool StartREST()
{
    for (unsigned int i = 0; i < ARRAYLEN(uri_prefixes); i++)
        RegisterHTTPHandler(uri_prefixes[i].prefix, false, uri_prefixes[i].handler);
    return true;
}

void InterruptREST()
{
}

void StopREST()
{
    for (unsigned int i = 0; i < ARRAYLEN(uri_prefixes); i++)
        UnregisterHTTPHandler(uri_prefixes[i].prefix, false);
}
