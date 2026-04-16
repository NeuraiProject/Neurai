// Copyright (c) 2017-2021 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Script-parsing helpers for asset types.
// Extracted from assets/assets.cpp so that LIBNEURAI_COMMON (and neurai-tx)
// can link against them without pulling in the full server stack.

#include "assets.h"
#include "base58.h"
#include "script/standard.h"
#include "streams.h"
#include "util.h"
#include "version.h"

bool TransferAssetFromScript(const CScript& scriptPubKey, CAssetTransfer& assetTransfer, std::string& strAddress)
{
    int nStartingIndex = 0;
    if (!IsScriptTransferAsset(scriptPubKey, nStartingIndex))
        return false;

    CTxDestination destination;
    ExtractDestination(scriptPubKey, destination);
    strAddress = EncodeDestination(destination);

    // nStartingIndex is always computed dynamically (kawpow has been active
    // since launch; the old hardcoded-31 fallback is intentionally omitted).
    std::vector<unsigned char> vchTransferAsset;
    vchTransferAsset.insert(vchTransferAsset.end(), scriptPubKey.begin() + nStartingIndex, scriptPubKey.end());
    CDataStream ssAsset(vchTransferAsset, SER_NETWORK, PROTOCOL_VERSION);

    try {
        ssAsset >> assetTransfer;
    } catch(std::exception& e) {
        error("Failed to get the transfer asset from the stream: %s", e.what());
        return false;
    }

    return true;
}

bool AssetFromScript(const CScript& scriptPubKey, CNewAsset& assetNew, std::string& strAddress)
{
    int nStartingIndex = 0;
    if (!IsScriptNewAsset(scriptPubKey, nStartingIndex))
        return false;

    CTxDestination destination;
    ExtractDestination(scriptPubKey, destination);
    strAddress = EncodeDestination(destination);

    std::vector<unsigned char> vchNewAsset;
    vchNewAsset.insert(vchNewAsset.end(), scriptPubKey.begin() + nStartingIndex, scriptPubKey.end());
    CDataStream ssAsset(vchNewAsset, SER_NETWORK, PROTOCOL_VERSION);

    try {
        ssAsset >> assetNew;
    } catch(std::exception& e) {
        error("Failed to get the asset from the stream: %s", e.what());
        return false;
    }

    return true;
}

bool MsgChannelAssetFromScript(const CScript& scriptPubKey, CNewAsset& assetNew, std::string& strAddress)
{
    int nStartingIndex = 0;
    if (!IsScriptNewMsgChannelAsset(scriptPubKey, nStartingIndex))
        return false;

    CTxDestination destination;
    ExtractDestination(scriptPubKey, destination);
    strAddress = EncodeDestination(destination);

    std::vector<unsigned char> vchNewAsset;
    vchNewAsset.insert(vchNewAsset.end(), scriptPubKey.begin() + nStartingIndex, scriptPubKey.end());
    CDataStream ssAsset(vchNewAsset, SER_NETWORK, PROTOCOL_VERSION);

    try {
        ssAsset >> assetNew;
    } catch(std::exception& e) {
        error("Failed to get the msg channel asset from the stream: %s", e.what());
        return false;
    }

    return true;
}

bool QualifierAssetFromScript(const CScript& scriptPubKey, CNewAsset& assetNew, std::string& strAddress)
{
    int nStartingIndex = 0;
    if (!IsScriptNewQualifierAsset(scriptPubKey, nStartingIndex))
        return false;

    CTxDestination destination;
    ExtractDestination(scriptPubKey, destination);
    strAddress = EncodeDestination(destination);

    std::vector<unsigned char> vchNewAsset;
    vchNewAsset.insert(vchNewAsset.end(), scriptPubKey.begin() + nStartingIndex, scriptPubKey.end());
    CDataStream ssAsset(vchNewAsset, SER_NETWORK, PROTOCOL_VERSION);

    try {
        ssAsset >> assetNew;
    } catch(std::exception& e) {
        error("Failed to get the qualifier asset from the stream: %s", e.what());
        return false;
    }

    return true;
}

bool RestrictedAssetFromScript(const CScript& scriptPubKey, CNewAsset& assetNew, std::string& strAddress)
{
    int nStartingIndex = 0;
    if (!IsScriptNewRestrictedAsset(scriptPubKey, nStartingIndex))
        return false;

    CTxDestination destination;
    ExtractDestination(scriptPubKey, destination);
    strAddress = EncodeDestination(destination);

    std::vector<unsigned char> vchNewAsset;
    vchNewAsset.insert(vchNewAsset.end(), scriptPubKey.begin() + nStartingIndex, scriptPubKey.end());
    CDataStream ssAsset(vchNewAsset, SER_NETWORK, PROTOCOL_VERSION);

    try {
        ssAsset >> assetNew;
    } catch(std::exception& e) {
        error("Failed to get the restricted asset from the stream: %s", e.what());
        return false;
    }

    return true;
}

bool OwnerAssetFromScript(const CScript& scriptPubKey, std::string& assetName, std::string& strAddress)
{
    int nStartingIndex = 0;
    if (!IsScriptOwnerAsset(scriptPubKey, nStartingIndex))
        return false;

    CTxDestination destination;
    ExtractDestination(scriptPubKey, destination);
    strAddress = EncodeDestination(destination);

    std::vector<unsigned char> vchOwnerAsset;
    vchOwnerAsset.insert(vchOwnerAsset.end(), scriptPubKey.begin() + nStartingIndex, scriptPubKey.end());
    CDataStream ssOwner(vchOwnerAsset, SER_NETWORK, PROTOCOL_VERSION);

    try {
        ssOwner >> assetName;
    } catch(std::exception& e) {
        error("Failed to get the owner asset from the stream: %s", e.what());
        return false;
    }

    return true;
}

bool ReissueAssetFromScript(const CScript& scriptPubKey, CReissueAsset& reissue, std::string& strAddress)
{
    int nStartingIndex = 0;
    if (!IsScriptReissueAsset(scriptPubKey, nStartingIndex))
        return false;

    CTxDestination destination;
    ExtractDestination(scriptPubKey, destination);
    strAddress = EncodeDestination(destination);

    std::vector<unsigned char> vchReissueAsset;
    vchReissueAsset.insert(vchReissueAsset.end(), scriptPubKey.begin() + nStartingIndex, scriptPubKey.end());
    CDataStream ssReissue(vchReissueAsset, SER_NETWORK, PROTOCOL_VERSION);

    try {
        ssReissue >> reissue;
    } catch(std::exception& e) {
        error("Failed to get the reissue asset from the stream: %s", e.what());
        return false;
    }

    return true;
}
