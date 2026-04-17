// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core_io.h"

#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "serialize.h"
#include "streams.h"
#include <univalue.h>
#include "util.h"
#include "utilstrencodings.h"
#include "version.h"

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/split.hpp>

CScript ParseScript(const std::string& s)
{
    CScript result;

    static std::map<std::string, opcodetype> mapOpNames;

    if (mapOpNames.empty())
    {
        for (unsigned int op = 0; op <= MAX_OPCODE; op++)
        {
            // Allow OP_RESERVED to get into mapOpNames
            if (op < OP_NOP && op != OP_RESERVED)
                continue;

            const char* name = GetOpName((opcodetype)op);
            if (strcmp(name, "OP_UNKNOWN") == 0)
                continue;
            std::string strName(name);
            mapOpNames[strName] = (opcodetype)op;
            // Convenience: OP_ADD and just ADD are both recognized:
            boost::algorithm::replace_first(strName, "OP_", "");
            mapOpNames[strName] = (opcodetype)op;
        }
        // Legacy NOP aliases: several former OP_NOP* slots were upgraded to
        // real opcodes (OP_NOP7→OP_TXFIELD, OP_NOP8→OP_SPLIT, OP_NOP9→OP_TXLOCKTIME).
        // Keep the old names parseable so script_tests.json fixtures that
        // predate the upgrade still round-trip correctly. The opcode byte is
        // identical; only the canonical name changed.
        // OP_NOP2, OP_NOP3, OP_NOP4, OP_NOP5, OP_NOP6 are all aliases whose
        // canonical name (CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY,
        // CHECKTEMPLATEVERIFY, CHECKSIGFROMSTACK, TXHASH) is what
        // GetOpName returns, so the original NOP-labeled fixture lines stop
        // parsing once these upgrades landed. Register the legacy names
        // explicitly.
        mapOpNames["OP_NOP4"]  = OP_NOP4;
        mapOpNames["NOP4"]     = OP_NOP4;
        mapOpNames["OP_NOP5"]  = OP_NOP5;
        mapOpNames["NOP5"]     = OP_NOP5;
        mapOpNames["OP_NOP6"]  = OP_NOP6;
        mapOpNames["NOP6"]     = OP_NOP6;
        mapOpNames["OP_NOP7"]  = OP_NOP7;
        mapOpNames["NOP7"]     = OP_NOP7;
        mapOpNames["OP_NOP8"]  = OP_NOP8;
        mapOpNames["NOP8"]     = OP_NOP8;
        mapOpNames["OP_NOP9"]  = OP_NOP9;
        mapOpNames["NOP9"]     = OP_NOP9;
        mapOpNames["OP_NOP10"] = OP_NOP10;
        mapOpNames["NOP10"]    = OP_NOP10;
    }

    std::vector<std::string> words;
    boost::algorithm::split(words, s, boost::algorithm::is_any_of(" \t\n"), boost::algorithm::token_compress_on);

    for (std::vector<std::string>::const_iterator w = words.begin(); w != words.end(); ++w)
    {
        if (w->empty())
        {
            // Empty string, ignore. (boost::split given '' will return one word)
        }
        else if (all(*w, boost::algorithm::is_digit()) ||
            (boost::algorithm::starts_with(*w, "-") && all(std::string(w->begin()+1, w->end()), boost::algorithm::is_digit())))
        {
            // Number
            int64_t n = atoi64(*w);
            result << n;
        }
        else if (boost::algorithm::starts_with(*w, "0x") && (w->begin()+2 != w->end()) && IsHex(std::string(w->begin()+2, w->end())))
        {
            // Raw hex data, inserted NOT pushed onto stack:
            std::vector<unsigned char> raw = ParseHex(std::string(w->begin()+2, w->end()));
            result.insert(result.end(), raw.begin(), raw.end());
        }
        else if (w->size() >= 2 && boost::algorithm::starts_with(*w, "'") && boost::algorithm::ends_with(*w, "'"))
        {
            // Single-quoted string, pushed as data. NOTE: this is poor-man's
            // parsing, spaces/tabs/newlines in single-quoted strings won't work.
            std::vector<unsigned char> value(w->begin()+1, w->end()-1);
            result << value;
        }
        else if (mapOpNames.count(*w))
        {
            // opcode, e.g. OP_ADD or ADD:
            result << mapOpNames[*w];
        }
        else
        {
            throw std::runtime_error("script parse error: word=[" + *w + "]");
        }
    }

    return result;
}

// Check that all of the input and output scripts of a transaction contains valid opcodes
bool CheckTxScriptsSanity(const CMutableTransaction& tx)
{
    // Check input scripts for non-coinbase txs
    if (!CTransaction(tx).IsCoinBase()) {
        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            if (!tx.vin[i].scriptSig.HasValidOps() || tx.vin[i].scriptSig.size() > MAX_SCRIPT_SIZE) {
                return false;
            }
        }
    }
    // Check output scripts
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        if (!tx.vout[i].scriptPubKey.HasValidOps() || tx.vout[i].scriptPubKey.size() > MAX_SCRIPT_SIZE) {
            return false;
        }
    }
    
    return true;
}

bool DecodeHexTx(CMutableTransaction& tx, const std::string& strHexTx, bool fTryNoWitness)
{
    if (!IsHex(strHexTx)) {
        return false;
    }

    std::vector<unsigned char> txData(ParseHex(strHexTx));

    if (fTryNoWitness) {
        CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS);
        try {
            ssData >> tx;
            if (ssData.eof() && CheckTxScriptsSanity(tx)) {
                return true;
            }
        }
        catch (const std::exception&) {
            // Fall through.
        }
    }

    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ssData >> tx;
        if (!ssData.empty()) {
            return false;
        }
    }
    catch (const std::exception&) {
        return false;
    }

    return true;
}

bool DecodeHexBlk(CBlock& block, const std::string& strHexBlk)
{
    if (!IsHex(strHexBlk))
        return false;

    std::vector<unsigned char> blockData(ParseHex(strHexBlk));
    CDataStream ssBlock(blockData, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ssBlock >> block;
    }
    catch (const std::exception&) {
        return false;
    }

    return true;
}

uint256 ParseHashUV(const UniValue& v, const std::string& strName)
{
    std::string strHex;
    if (v.isStr())
        strHex = v.getValStr();
    return ParseHashStr(strHex, strName);  // Note: ParseHashStr("") throws a runtime_error
}

uint256 ParseHashStr(const std::string& strHex, const std::string& strName)
{
    if (!IsHex(strHex)) // Note: IsHex("") is false
        throw std::runtime_error(strName + " must be hexadecimal string (not '" + strHex + "')");

    uint256 result;
    result.SetHex(strHex);
    return result;
}

std::vector<unsigned char> ParseHexUV(const UniValue& v, const std::string& strName)
{
    std::string strHex;
    if (v.isStr())
        strHex = v.getValStr();
    if (!IsHex(strHex))
        throw std::runtime_error(strName + " must be hexadecimal string (not '" + strHex + "')");
    return ParseHex(strHex);
}
