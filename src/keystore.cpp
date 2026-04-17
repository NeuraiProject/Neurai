// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "keystore.h"

#include "key.h"
#include "pubkey.h"
#include "util.h"

bool CKeyStore::AddKey(const CKey &key) {
    return AddKeyPubKey(key, key.GetPubKey());
}

bool CBasicKeyStore::GetPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const
{
    CKey key;
    if (!GetKey(address, key)) {
        LOCK(cs_KeyStore);
        WatchKeyMap::const_iterator it = mapWatchKeys.find(address);
        if (it != mapWatchKeys.end()) {
            vchPubKeyOut = it->second;
            return true;
        }
        return false;
    }
    vchPubKeyOut = key.GetPubKey();
    return true;
}

bool CBasicKeyStore::AddKeyPubKey(const CKey& key, const CPubKey &pubkey)
{
    LOCK(cs_KeyStore);
    mapKeys[pubkey.GetID()] = key;
    return true;
}

bool CBasicKeyStore::AddCScript(const CScript& redeemScript)
{
    // NIP-019: cap raised to MAX_PQ_SCRIPT_ELEMENT_SIZE so PQ-sized
    // P2WSH witnessScripts (via signrawtransactionwithkey) and PQ-sized
    // P2SH redeemScripts (watch-only via importaddress/importmulti) can
    // be stored. Consensus-level P2SH spendability remains bounded by
    // MAX_SCRIPT_ELEMENT_SIZE in EvalScript.
    if (redeemScript.size() > MAX_PQ_SCRIPT_ELEMENT_SIZE)
        return error("CBasicKeyStore::AddCScript(): redeemScripts > %i bytes are invalid", MAX_PQ_SCRIPT_ELEMENT_SIZE);

    LOCK(cs_KeyStore);
    mapScripts[CScriptID(redeemScript)] = redeemScript;
    return true;
}

bool CBasicKeyStore::HaveCScript(const CScriptID& hash) const
{
    LOCK(cs_KeyStore);
    return mapScripts.count(hash) > 0;
}

bool CBasicKeyStore::GetCScript(const CScriptID &hash, CScript& redeemScriptOut) const
{
    LOCK(cs_KeyStore);
    ScriptMap::const_iterator mi = mapScripts.find(hash);
    if (mi != mapScripts.end())
    {
        redeemScriptOut = (*mi).second;
        return true;
    }
    return false;
}

static bool ExtractPubKey(const CScript &dest, CPubKey& pubKeyOut)
{
    //TODO: Use Solver to extract this?
    CScript::const_iterator pc = dest.begin();
    opcodetype opcode;
    std::vector<unsigned char> vch;
    if (!dest.GetOp(pc, opcode, vch) || vch.empty())
        return false;
    pubKeyOut = CPubKey(vch);
    if (!pubKeyOut.IsFullyValid())
        return false;
    if (!dest.GetOp(pc, opcode, vch) || opcode != OP_CHECKSIG || dest.GetOp(pc, opcode, vch))
        return false;
    return true;
}

bool CBasicKeyStore::AddWatchOnly(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.insert(dest);
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey))
        mapWatchKeys[pubKey.GetID()] = pubKey;
    return true;
}

bool CBasicKeyStore::RemoveWatchOnly(const CScript &dest)
{
    LOCK(cs_KeyStore);
    setWatchOnly.erase(dest);
    CPubKey pubKey;
    if (ExtractPubKey(dest, pubKey))
        mapWatchKeys.erase(pubKey.GetID());
    return true;
}

bool CBasicKeyStore::HaveWatchOnly(const CScript &dest) const
{
    LOCK(cs_KeyStore);
    return setWatchOnly.count(dest) > 0;
}

bool CBasicKeyStore::HaveWatchOnly() const
{
    LOCK(cs_KeyStore);
    return (!setWatchOnly.empty());
}

bool CBasicKeyStore::AddAuthScriptSpendData(const uint256& commitment, const AuthScriptSpendData& spendData)
{
    LOCK(cs_KeyStore);
    mapAuthScriptSpendData[commitment] = spendData;
    return true;
}

bool CBasicKeyStore::GetAuthScriptSpendData(const uint256& commitment, AuthScriptSpendData& spendData) const
{
    LOCK(cs_KeyStore);
    AuthScriptSpendDataMap::const_iterator it = mapAuthScriptSpendData.find(commitment);
    if (it == mapAuthScriptSpendData.end()) {
        return false;
    }
    spendData = it->second;
    return true;
}

bool CBasicKeyStore::HaveAuthScriptSpendData(const uint256& commitment) const
{
    LOCK(cs_KeyStore);
    return mapAuthScriptSpendData.count(commitment) > 0;
}


bool CBasicKeyStore::AddWords(const uint256& p_hash, const std::vector<unsigned char>& p_vchWords)
{
    LOCK(cs_KeyStore);
    nWordHash = p_hash;
    vchWords = p_vchWords;
    return true;
}

bool CBasicKeyStore::AddPassphrase(const std::vector<unsigned char>& p_vchPassphrase)
{
    LOCK(cs_KeyStore);
    vchPassphrase = p_vchPassphrase;
    return true;
}

void CBasicKeyStore::GetBip39Data(uint256& p_hash, std::vector<unsigned char>& p_vchWords, std::vector<unsigned char>& p_vchPassphrase, std::vector<unsigned char>& p_vchSeed)
{
    LOCK(cs_KeyStore);
    p_hash = nWordHash;
    p_vchWords = vchWords;
    p_vchPassphrase = vchPassphrase;
    p_vchSeed = g_vchSeed;
}

bool CBasicKeyStore::AddVchSeed(const std::vector<unsigned char>& p_vchSeed)
{
    LOCK(cs_KeyStore);
    g_vchSeed = p_vchSeed;
    return true;
}
