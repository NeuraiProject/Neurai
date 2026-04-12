// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h>
#include <assets/assets.h>
#include <hash.h>
#include <validation.h>
#include "script/standard.h"
#include "chainparams.h"

#include "pubkey.h"
#include "script/script.h"
#include "util.h"
#include "utilstrencodings.h"

typedef std::vector<unsigned char> valtype;

bool fAcceptDatacarrier = DEFAULT_ACCEPT_DATACARRIER;
unsigned nMaxDatacarrierBytes = MAX_OP_RETURN_RELAY;

unsigned int GetMaxOPReturnRelay()
{
    // Use larger OP_RETURN size in testnet for testing purposes
    if (GetParams().NetworkIDString() == "test") {
        return MAX_OP_RETURN_RELAY_TESTNET;
    }
    return MAX_OP_RETURN_RELAY;
}

CScriptID::CScriptID(const CScript& in) : uint160(Hash160(in.begin(), in.end())) {}

const char* GetTxnOutputType(txnouttype t)
{
    switch (t)
    {
    case TX_NONSTANDARD: return "nonstandard";
    case TX_PUBKEY: return "pubkey";
    case TX_PUBKEYHASH: return "pubkeyhash";
    case TX_SCRIPTHASH: return "scripthash";
    case TX_MULTISIG: return "multisig";
    case TX_NULL_DATA: return "nulldata";
    case TX_RESTRICTED_ASSET_DATA: return "nullassetdata";
    case TX_WITNESS_V0_KEYHASH: return "witness_v0_keyhash";
    case TX_WITNESS_V0_SCRIPTHASH: return "witness_v0_scripthash";
    case TX_WITNESS_V1_AUTHSCRIPT: return "witness_v1_authscript";

    /** XNA START */
    case TX_NEW_ASSET: return ASSET_NEW_STRING;
    case TX_TRANSFER_ASSET: return ASSET_TRANSFER_STRING;
    case TX_REISSUE_ASSET: return ASSET_REISSUE_STRING;
    /** XNA END */
    }
    return nullptr;
}

namespace {
bool ExtractAssetDestinationData(const CScript& scriptPubKey, CTxDestination* destinationRet, std::vector<unsigned char>* hashBytesRet, int* prefixSizeRet, int* witnessversionRet, std::vector<unsigned char>* witnessprogramRet)
{
    if (witnessversionRet) {
        *witnessversionRet = 0;
    }
    if (witnessprogramRet) {
        witnessprogramRet->clear();
    }

    if (scriptPubKey.size() >= 25 &&
        scriptPubKey[0] == OP_DUP &&
        scriptPubKey[1] == OP_HASH160 &&
        scriptPubKey[2] == 0x14 &&
        scriptPubKey[23] == OP_EQUALVERIFY &&
        scriptPubKey[24] == OP_CHECKSIG) {
        std::vector<unsigned char> hashBytes(scriptPubKey.begin() + 3, scriptPubKey.begin() + 23);
        if (destinationRet) {
            *destinationRet = CKeyID(uint160(hashBytes));
        }
        if (hashBytesRet) {
            *hashBytesRet = hashBytes;
        }
        if (prefixSizeRet) {
            *prefixSizeRet = 25;
        }
        return true;
    }

    if (scriptPubKey.size() >= 34) {
        CScript prefix(scriptPubKey.begin(), scriptPubKey.begin() + 34);
        int witnessversion = 0;
        std::vector<unsigned char> witnessprogram;
        if (prefix.IsWitnessProgram(witnessversion, witnessprogram) && witnessversion == 1 && witnessprogram.size() == 32) {
            if (destinationRet) {
                *destinationRet = WitnessV1AuthScript(uint256(witnessprogram));
            }
            if (hashBytesRet) {
                *hashBytesRet = witnessprogram;
            }
            if (prefixSizeRet) {
                *prefixSizeRet = 34;
            }
            if (witnessversionRet) {
                *witnessversionRet = witnessversion;
            }
            if (witnessprogramRet) {
                *witnessprogramRet = witnessprogram;
            }
            return true;
        }
    }

    return false;
}
} // namespace

bool Solver(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<std::vector<unsigned char> >& vSolutionsRet)
{
    // Templates
    static std::multimap<txnouttype, CScript> mTemplates;
    if (mTemplates.empty())
    {
        // Standard tx, sender provides pubkey, receiver adds signature
        mTemplates.insert(std::make_pair(TX_PUBKEY, CScript() << OP_PUBKEY << OP_CHECKSIG));

        // Neurai address tx, sender provides hash of pubkey, receiver provides signature and pubkey
        mTemplates.insert(std::make_pair(TX_PUBKEYHASH, CScript() << OP_DUP << OP_HASH160 << OP_PUBKEYHASH << OP_EQUALVERIFY << OP_CHECKSIG));

        // Sender provides N pubkeys, receivers provides M signatures
        mTemplates.insert(std::make_pair(TX_MULTISIG, CScript() << OP_SMALLINTEGER << OP_PUBKEYS << OP_SMALLINTEGER << OP_CHECKMULTISIG));
    }

    vSolutionsRet.clear();

    // Shortcut for pay-to-script-hash, which are more constrained than the other types:
    // it is always OP_HASH160 20 [20 byte hash] OP_EQUAL
    if (scriptPubKey.IsPayToScriptHash())
    {
        typeRet = TX_SCRIPTHASH;
        std::vector<unsigned char> hashBytes(scriptPubKey.begin()+2, scriptPubKey.begin()+22);
        vSolutionsRet.push_back(hashBytes);
        return true;
    }
    /** XNA START */
    int nType = 0;
    bool fIsOwner = false;
    if (scriptPubKey.IsAssetScript(nType, fIsOwner)) {
        typeRet = (txnouttype)nType;
        std::vector<unsigned char> hashBytes;
        if (!ExtractAssetDestinationData(scriptPubKey, nullptr, &hashBytes, nullptr, nullptr, nullptr)) {
            return false;
        }
        vSolutionsRet.push_back(hashBytes);
        return true;
    }
    /** XNA END */

    int witnessversion;
    std::vector<unsigned char> witnessprogram;
    if (scriptPubKey.IsWitnessProgram(witnessversion, witnessprogram)) {
        if (witnessversion == 0 && witnessprogram.size() == 20) {
            typeRet = TX_WITNESS_V0_KEYHASH;
            vSolutionsRet.push_back(witnessprogram);
            return true;
        }
        if (witnessversion == 0 && witnessprogram.size() == 32) {
            typeRet = TX_WITNESS_V0_SCRIPTHASH;
            vSolutionsRet.push_back(witnessprogram);
            return true;
        }
        if (witnessversion == 1 && witnessprogram.size() == 32) {
            typeRet = TX_WITNESS_V1_AUTHSCRIPT;
            vSolutionsRet.push_back(witnessprogram);
            return true;
        }
        return false;
    }

    // Provably prunable, data-carrying output
    //
    // So long as script passes the IsUnspendable() test and all but the first
    // byte passes the IsPushOnly() test we don't care what exactly is in the
    // script.
    if (scriptPubKey.size() >= 1 && scriptPubKey[0] == OP_RETURN && scriptPubKey.IsPushOnly(scriptPubKey.begin()+1)) {
        typeRet = TX_NULL_DATA;
        return true;
    }

    // Provably prunable, asset data-carrying output
    //
    // So long as script passes the IsUnspendable() test and all but the first three
    // byte passes the IsPushOnly()
    if (scriptPubKey.size() >= 1 && scriptPubKey[0] == OP_XNA_ASSET && scriptPubKey.IsPushOnly(scriptPubKey.begin()+1)) {
        typeRet = TX_RESTRICTED_ASSET_DATA;

        if (scriptPubKey[1] == 0x14 && scriptPubKey.size() >= 23) {
            // Legacy: hash at bytes [2..22)
            std::vector<unsigned char> hashBytes(scriptPubKey.begin() + 2, scriptPubKey.begin() + 22);
            vSolutionsRet.push_back(hashBytes);
            vSolutionsRet.push_back({0x00}); // version 0 = legacy
        } else if (scriptPubKey[1] == OP_1 && scriptPubKey.size() >= 36 && scriptPubKey[2] == 0x20) {
            // AuthScript: commitment at bytes [3..35)
            std::vector<unsigned char> hashBytes(scriptPubKey.begin() + 3, scriptPubKey.begin() + 35);
            vSolutionsRet.push_back(hashBytes);
            vSolutionsRet.push_back({0x01}); // version 1 = AuthScript
        }
        return true;
    }

    // Scan templates
    const CScript& script1 = scriptPubKey;
    for (const std::pair<txnouttype, CScript>& tplate : mTemplates)
    {
        const CScript& script2 = tplate.second;
        vSolutionsRet.clear();

        opcodetype opcode1, opcode2;
        std::vector<unsigned char> vch1, vch2;

        // Compare
        CScript::const_iterator pc1 = script1.begin();
        CScript::const_iterator pc2 = script2.begin();
        while (true)
        {
            if (pc1 == script1.end() && pc2 == script2.end())
            {
                // Found a match
                typeRet = tplate.first;
                if (typeRet == TX_MULTISIG)
                {
                    // Additional checks for TX_MULTISIG:
                    unsigned char m = vSolutionsRet.front()[0];
                    unsigned char n = vSolutionsRet.back()[0];
                    if (m < 1 || n < 1 || m > n || vSolutionsRet.size()-2 != n)
                        return false;
                }
                return true;
            }
            if (!script1.GetOp(pc1, opcode1, vch1))
                break;
            if (!script2.GetOp(pc2, opcode2, vch2))
                break;

            // Template matching opcodes:
            if (opcode2 == OP_PUBKEYS)
            {
                while (vch1.size() >= 33 && vch1.size() <= 65)
                {
                    vSolutionsRet.push_back(vch1);
                    if (!script1.GetOp(pc1, opcode1, vch1))
                        break;
                }
                if (!script2.GetOp(pc2, opcode2, vch2))
                    break;
                // Normal situation is to fall through
                // to other if/else statements
            }

            if (opcode2 == OP_PUBKEY)
            {
                if (vch1.size() < 33 || vch1.size() > 65)
                    break;
                vSolutionsRet.push_back(vch1);
            }
            else if (opcode2 == OP_PUBKEYHASH)
            {
                if (vch1.size() != sizeof(uint160))
                    break;
                vSolutionsRet.push_back(vch1);
            }
            else if (opcode2 == OP_SMALLINTEGER)
            {   // Single-byte small integer pushed onto vSolutions
                if (opcode1 == OP_0 ||
                    (opcode1 >= OP_1 && opcode1 <= OP_16))
                {
                    char n = (char)CScript::DecodeOP_N(opcode1);
                    vSolutionsRet.push_back(valtype(1, n));
                }
                else
                    break;
            }
            else if (opcode1 != opcode2 || vch1 != vch2)
            {
                // Others must match exactly
                break;
            }
        }
    }

    vSolutionsRet.clear();
    typeRet = TX_NONSTANDARD;
    return false;
}

bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet)
{
    std::vector<valtype> vSolutions;
    txnouttype whichType;
    if (!Solver(scriptPubKey, whichType, vSolutions)) {
        return false;
    }

    if (whichType == TX_PUBKEY)
    {
        CPubKey pubKey(vSolutions[0]);
        if (!pubKey.IsValid())
            return false;

        addressRet = pubKey.GetID();
        return true;
    }
    else if (whichType == TX_PUBKEYHASH)
    {
        addressRet = CKeyID(uint160(vSolutions[0]));
        return true;
    }
    else if (whichType == TX_SCRIPTHASH)
    {
        addressRet = CScriptID(uint160(vSolutions[0]));
        return true;
    /** XNA START */
    } else if (whichType == TX_NEW_ASSET || whichType == TX_REISSUE_ASSET || whichType == TX_TRANSFER_ASSET) {
        return ExtractAssetDestination(scriptPubKey, addressRet);
    } else if (whichType == TX_RESTRICTED_ASSET_DATA) {
        if (vSolutions.size() >= 2) {
            if (vSolutions[1].size() == 1 && vSolutions[1][0] == 0x01) {
                addressRet = WitnessV1AuthScript(uint256(vSolutions[0]));
            } else {
                addressRet = CKeyID(uint160(vSolutions[0]));
            }
            return true;
        } else if (vSolutions.size() == 1) {
            addressRet = CKeyID(uint160(vSolutions[0]));
            return true;
        }
    }
     /** XNA END */
    else if (whichType == TX_WITNESS_V1_AUTHSCRIPT) {
        addressRet = WitnessV1AuthScript(uint256(vSolutions[0]));
        return true;
    }
    // Multisig txns have more than one address...
    return false;
}

bool ExtractAssetDestination(const CScript& scriptPubKey, CTxDestination& addressRet)
{
    return ExtractAssetDestinationData(scriptPubKey, &addressRet, nullptr, nullptr, nullptr, nullptr);
}

bool GetAssetScriptWitnessProgram(const CScript& scriptPubKey, int& witnessversion, std::vector<unsigned char>& witnessprogram, std::vector<unsigned char>* assetData)
{
    int nType = 0;
    bool fIsOwner = false;
    if (!scriptPubKey.IsAssetScript(nType, fIsOwner)) {
        return false;
    }

    int prefixSize = 0;
    if (!ExtractAssetDestinationData(scriptPubKey, nullptr, nullptr, &prefixSize, &witnessversion, &witnessprogram)) {
        return false;
    }

    if (witnessversion != 1 || witnessprogram.size() != 32) {
        return false;
    }

    if (assetData) {
        assetData->assign(scriptPubKey.begin() + prefixSize, scriptPubKey.end());
    }

    return true;
}

bool GetAuthScriptDescriptor(uint8_t authType, const CPubKey* pubkey, std::vector<unsigned char>& authDescriptor)
{
    authDescriptor.clear();
    switch (authType) {
    case 0x00:
        authDescriptor.push_back(0x00);
        return true;
    case 0x01:
    case 0x02: {
        if (pubkey == nullptr || !pubkey->IsValid()) {
            return false;
        }
        authDescriptor.push_back(authType);
        const uint160 keyHash = Hash160(pubkey->begin(), pubkey->end());
        authDescriptor.insert(authDescriptor.end(), keyHash.begin(), keyHash.end());
        return true;
    }
    default:
        return false;
    }
}

uint256 GetAuthScriptCommitment(uint8_t authType, const CPubKey* pubkey, const CScript& witnessScript)
{
    std::vector<unsigned char> authDescriptor;
    if (!GetAuthScriptDescriptor(authType, pubkey, authDescriptor)) {
        return uint256();
    }

    uint256 witnessScriptHash;
    if (!witnessScript.empty()) {
        CSHA256().Write(witnessScript.data(), witnessScript.size()).Finalize(witnessScriptHash.begin());
    } else {
        CSHA256().Finalize(witnessScriptHash.begin());
    }

    std::vector<unsigned char> preimage;
    preimage.reserve(1 + authDescriptor.size() + witnessScriptHash.size());
    preimage.push_back(0x01);
    preimage.insert(preimage.end(), authDescriptor.begin(), authDescriptor.end());
    preimage.insert(preimage.end(), witnessScriptHash.begin(), witnessScriptHash.end());
    return TaggedHash("NeuraiAuthScript", preimage);
}

bool GetDestinationIndexKey(const CTxDestination& dest, uint160& hashBytes, int& type)
{
    if (const CKeyID* keyID = boost::get<CKeyID>(&dest)) {
        hashBytes = *keyID;
        type = DEST_INDEX_KEY;
        return true;
    }
    if (const CScriptID* scriptID = boost::get<CScriptID>(&dest)) {
        hashBytes = *scriptID;
        type = DEST_INDEX_SCRIPT;
        return true;
    }
    if (const WitnessV1AuthScript* authScript = boost::get<WitnessV1AuthScript>(&dest)) {
        hashBytes = Hash160(authScript->begin(), authScript->end());
        type = DEST_INDEX_WITNESS_V1_AUTHSCRIPT;
        return true;
    }

    hashBytes.SetNull();
    type = DEST_INDEX_NONE;
    return false;
}

bool GetScriptDestinationIndexKey(const CScript& scriptPubKey, uint160& hashBytes, int& type)
{
    std::vector<valtype> vSolutions;
    txnouttype whichType;
    if (!Solver(scriptPubKey, whichType, vSolutions)) {
        hashBytes.SetNull();
        type = DEST_INDEX_NONE;
        return false;
    }

    CTxDestination destination;
    switch (whichType) {
    case TX_PUBKEY: {
        CPubKey pubKey(vSolutions[0]);
        if (!pubKey.IsValid()) {
            hashBytes.SetNull();
            type = DEST_INDEX_NONE;
            return false;
        }
        destination = pubKey.GetID();
        break;
    }
    case TX_PUBKEYHASH:
        destination = CKeyID(uint160(vSolutions[0]));
        break;
    case TX_SCRIPTHASH:
        destination = CScriptID(uint160(vSolutions[0]));
        break;
    case TX_WITNESS_V1_AUTHSCRIPT:
        destination = WitnessV1AuthScript(uint256(vSolutions[0]));
        break;
    case TX_NEW_ASSET:
    case TX_REISSUE_ASSET:
    case TX_TRANSFER_ASSET:
        if (!ExtractAssetDestination(scriptPubKey, destination)) {
            hashBytes.SetNull();
            type = DEST_INDEX_NONE;
            return false;
        }
        break;
    default:
        hashBytes.SetNull();
        type = DEST_INDEX_NONE;
        return false;
    }

    return GetDestinationIndexKey(destination, hashBytes, type);
}

bool ExtractDestinations(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<CTxDestination>& addressRet, int& nRequiredRet)
{
    addressRet.clear();
    typeRet = TX_NONSTANDARD;
    std::vector<valtype> vSolutions;
    if (!Solver(scriptPubKey, typeRet, vSolutions))
        return false;
    if (typeRet == TX_NULL_DATA) {
        // This is data, not addresses
        return false;
    }

    if (typeRet == TX_MULTISIG)
    {
        nRequiredRet = vSolutions.front()[0];
        for (unsigned int i = 1; i < vSolutions.size()-1; i++)
        {
            CPubKey pubKey(vSolutions[i]);
            if (!pubKey.IsValid())
                continue;

            CTxDestination address = pubKey.GetID();
            addressRet.push_back(address);
        }

        if (addressRet.empty())
            return false;
    }
    else
    {
        nRequiredRet = 1;
        CTxDestination address;
        if (!ExtractDestination(scriptPubKey, address))
           return false;
        addressRet.push_back(address);
    }

    return true;
}

namespace
{
class CScriptVisitor : public boost::static_visitor<bool>
{
private:
    CScript *script;
public:
    explicit CScriptVisitor(CScript *scriptin) { script = scriptin; }

    bool operator()(const CNoDestination &dest) const {
        script->clear();
        return false;
    }

    bool operator()(const CKeyID &keyID) const {
        script->clear();
        *script << OP_DUP << OP_HASH160 << ToByteVector(keyID) << OP_EQUALVERIFY << OP_CHECKSIG;
        return true;
    }

    bool operator()(const CScriptID &scriptID) const {
        script->clear();
        *script << OP_HASH160 << ToByteVector(scriptID) << OP_EQUAL;
        return true;
    }

    bool operator()(const WitnessV1AuthScript &id) const {
        script->clear();
        *script << OP_1 << ToByteVector(id);
        return true;
    }
};
} // namespace

namespace
{
    class CNullAssetScriptVisitor : public boost::static_visitor<bool>
    {
    private:
        CScript *script;
    public:
        explicit CNullAssetScriptVisitor(CScript *scriptin) { script = scriptin; }

        bool operator()(const CNoDestination &dest) const {
            script->clear();
            return false;
        }

        bool operator()(const CKeyID &keyID) const {
            script->clear();
            *script << OP_XNA_ASSET << ToByteVector(keyID);
            return true;
        }

        bool operator()(const CScriptID &scriptID) const {
            script->clear();
            *script << OP_XNA_ASSET << ToByteVector(scriptID);
            return true;
        }

        bool operator()(const WitnessV1AuthScript &id) const {
            script->clear();
            *script << OP_XNA_ASSET << OP_1 << ToByteVector(id);
            return true;
        }
    };
} // namespace

CScript GetScriptForDestination(const CTxDestination& dest)
{
    CScript script;

    boost::apply_visitor(CScriptVisitor(&script), dest);
    return script;
}

CScript GetScriptForNullAssetDataDestination(const CTxDestination &dest)
{
    CScript script;

    boost::apply_visitor(CNullAssetScriptVisitor(&script), dest);
    return script;
}

CScript GetScriptForRawPubKey(const CPubKey& pubKey)
{
    return CScript() << std::vector<unsigned char>(pubKey.begin(), pubKey.end()) << OP_CHECKSIG;
}

CScript GetScriptForMultisig(int nRequired, const std::vector<CPubKey>& keys)
{
    CScript script;

    script << CScript::EncodeOP_N(nRequired);
    for (const CPubKey& key : keys)
        script << ToByteVector(key);
    script << CScript::EncodeOP_N(keys.size()) << OP_CHECKMULTISIG;
    return script;
}

CScript GetScriptForWitness(const CScript& redeemscript)
{
    CScript ret;

    txnouttype typ;
    std::vector<std::vector<unsigned char> > vSolutions;
    if (Solver(redeemscript, typ, vSolutions)) {
        if (typ == TX_PUBKEY) {
            unsigned char h160[20];
            CHash160().Write(&vSolutions[0][0], vSolutions[0].size()).Finalize(h160);
            ret << OP_0 << std::vector<unsigned char>(&h160[0], &h160[20]);
            return ret;
        } else if (typ == TX_PUBKEYHASH) {
           ret << OP_0 << vSolutions[0];
           return ret;
        }
    }
    uint256 hash;
    CSHA256().Write(&redeemscript[0], redeemscript.size()).Finalize(hash.begin());
    ret << OP_0 << ToByteVector(hash);
    return ret;
}

bool IsValidDestination(const CTxDestination& dest) {
    return dest.which() != 0;
}
