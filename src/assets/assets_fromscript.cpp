// Copyright (c) 2017-2021 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Pure script-parsing and name-validation functions for asset types.
// Extracted from assets/assets.cpp into LIBNEURAI_COMMON so that
// neurai-tx can link without pulling in the full server stack
// (validation.h, wallet.h, net.h, etc.).

#include <regex>
#include <vector>
#include <string>

#include "assets.h"
#include "assettypes.h"
#include "base58.h"
#include "chainparams.h"
#include "chainparamsbase.h"
#include "script/standard.h"
#include "streams.h"
#include "util.h"
#include "utilstrencodings.h"
#include "version.h"

#include <boost/algorithm/string.hpp>

// ---------------------------------------------------------------------------
// Local constants (static — internal linkage, safe to duplicate across TUs)
// ---------------------------------------------------------------------------

static const auto MAX_NAME_LENGTH          = 31;
static const auto MAX_NAME_LENGTH_TESTNET  = 121;
static const auto MAX_CHANNEL_NAME_LENGTH  = 12;

static bool AreDEPINAssetsEnabledOnCurrentNetwork()
{
    const std::string& network = GetParams().NetworkIDString();
    return network == CBaseChainParams::TESTNET || network == CBaseChainParams::REGTEST;
}

int GetMaxAssetNameLength()
{
    if (GetParams().NetworkIDString() == "test")
        return MAX_NAME_LENGTH_TESTNET;
    return MAX_NAME_LENGTH;
}

// ---------------------------------------------------------------------------
// Regex patterns
// ---------------------------------------------------------------------------

static const std::regex ROOT_NAME_CHARACTERS("^[A-Z0-9._]{3,}$");
static const std::regex SUB_NAME_CHARACTERS("^[A-Z0-9._]+$");
static const std::regex UNIQUE_TAG_CHARACTERS("^[-A-Za-z0-9@$%&*()[\\]{}_.?:]+$");
static const std::regex MSG_CHANNEL_TAG_CHARACTERS("^[A-Za-z0-9_]+$");
static const std::regex VOTE_TAG_CHARACTERS("^[A-Z0-9._]+$");
static const std::regex QUALIFIER_NAME_CHARACTERS("#[A-Z0-9._]{3,}$");
static const std::regex SUB_QUALIFIER_NAME_CHARACTERS("#[A-Z0-9._]+$");
static const std::regex RESTRICTED_NAME_CHARACTERS("\\$[A-Z0-9._]{3,}$");
static const std::regex DEPIN_NAME_CHARACTERS("&[A-Z0-9._]{3,}$");
static const std::regex SUB_DEPIN_NAME_CHARACTERS("&[A-Z0-9._/]+$");
static const std::regex DOUBLE_PUNCTUATION("^.*[._]{2,}.*$");
static const std::regex LEADING_PUNCTUATION("^[._].*$");
static const std::regex TRAILING_PUNCTUATION("^.*[._]$");
static const std::regex QUALIFIER_LEADING_PUNCTUATION("^[#\\$][._].*$");
static const std::string SUB_NAME_DELIMITER = "/";
static const std::string UNIQUE_TAG_DELIMITER = "#";
static const std::string MSG_CHANNEL_TAG_DELIMITER = "~";
static const std::string VOTE_TAG_DELIMITER = "^";
static const std::string RESTRICTED_TAG_DELIMITER = "$";
static const std::regex UNIQUE_INDICATOR(R"(^[^^~#!]+#[^~#!\/]+$)");
static const std::regex MSG_CHANNEL_INDICATOR(R"(^[^^~#!]+~[^~#!\/]+$)");
static const std::regex OWNER_INDICATOR(R"(^[^^~#!]+!$)");
static const std::regex VOTE_INDICATOR(R"(^[^^~#!]+\^[^~#!\/]+$)");
static const std::regex QUALIFIER_INDICATOR("^[#][A-Z0-9._]{3,}$");
static const std::regex SUB_QUALIFIER_INDICATOR("^#[A-Z0-9._]+\\/#[A-Z0-9._]+$");
static const std::regex RESTRICTED_INDICATOR("^[\\$][A-Z0-9._]{3,}$");
static const std::regex DEPIN_INDICATOR("^[&][A-Z0-9._]{3,}$");
static const std::regex SUB_DEPIN_INDICATOR("^&[A-Z0-9._]+\\/[A-Z0-9._/]+$");
static const std::regex NEURAI_NAMES("^XNA$|^NEURAI$|^NEURAICOIN$|^#XNA$|^#NEURAI$|^#NEURAICOIN$");

// ---------------------------------------------------------------------------
// Name character validators
// ---------------------------------------------------------------------------

static bool IsRootNameValid(const std::string& name)
{
    return std::regex_match(name, ROOT_NAME_CHARACTERS)
        && !std::regex_match(name, DOUBLE_PUNCTUATION)
        && !std::regex_match(name, LEADING_PUNCTUATION)
        && !std::regex_match(name, TRAILING_PUNCTUATION)
        && !std::regex_match(name, NEURAI_NAMES);
}

static bool IsQualifierNameValid(const std::string& name)
{
    return std::regex_match(name, QUALIFIER_NAME_CHARACTERS)
        && !std::regex_match(name, DOUBLE_PUNCTUATION)
        && !std::regex_match(name, QUALIFIER_LEADING_PUNCTUATION)
        && !std::regex_match(name, TRAILING_PUNCTUATION)
        && !std::regex_match(name, NEURAI_NAMES);
}

static bool IsRestrictedNameValid(const std::string& name)
{
    return std::regex_match(name, RESTRICTED_NAME_CHARACTERS)
        && !std::regex_match(name, DOUBLE_PUNCTUATION)
        && !std::regex_match(name, LEADING_PUNCTUATION)
        && !std::regex_match(name, TRAILING_PUNCTUATION)
        && !std::regex_match(name, NEURAI_NAMES);
}

static bool IsSubQualifierNameValid(const std::string& name)
{
    return std::regex_match(name, SUB_QUALIFIER_NAME_CHARACTERS)
        && !std::regex_match(name, DOUBLE_PUNCTUATION)
        && !std::regex_match(name, LEADING_PUNCTUATION)
        && !std::regex_match(name, TRAILING_PUNCTUATION);
}

static bool IsSubNameValid(const std::string& name)
{
    return std::regex_match(name, SUB_NAME_CHARACTERS)
        && !std::regex_match(name, DOUBLE_PUNCTUATION)
        && !std::regex_match(name, LEADING_PUNCTUATION)
        && !std::regex_match(name, TRAILING_PUNCTUATION);
}

bool IsUniqueTagValid(const std::string& tag)
{
    return std::regex_match(tag, UNIQUE_TAG_CHARACTERS);
}

static bool IsVoteTagValid(const std::string& tag)
{
    return std::regex_match(tag, VOTE_TAG_CHARACTERS);
}

static bool IsMsgChannelTagValid(const std::string& tag)
{
    return std::regex_match(tag, MSG_CHANNEL_TAG_CHARACTERS)
        && !std::regex_match(tag, DOUBLE_PUNCTUATION)
        && !std::regex_match(tag, LEADING_PUNCTUATION)
        && !std::regex_match(tag, TRAILING_PUNCTUATION);
}

static bool IsNameValidBeforeTag(const std::string& name)
{
    std::vector<std::string> parts;
    boost::split(parts, name, boost::is_any_of(SUB_NAME_DELIMITER));
    if (!IsRootNameValid(parts.front())) return false;
    if (parts.size() > 1) {
        for (unsigned long i = 1; i < parts.size(); i++) {
            if (!IsSubNameValid(parts[i])) return false;
        }
    }
    return true;
}

static bool IsQualifierNameValidBeforeTag(const std::string& name)
{
    std::vector<std::string> parts;
    boost::split(parts, name, boost::is_any_of(SUB_NAME_DELIMITER));
    if (!IsQualifierNameValid(parts.front())) return false;
    if (parts.size() > 2) return false;
    if (parts.size() > 1) {
        for (unsigned long i = 1; i < parts.size(); i++) {
            if (!IsSubQualifierNameValid(parts[i])) return false;
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Public name helpers
// ---------------------------------------------------------------------------

bool IsAssetNameASubasset(const std::string& name)
{
    std::vector<std::string> parts;
    boost::split(parts, name, boost::is_any_of(SUB_NAME_DELIMITER));
    if (!IsRootNameValid(parts.front())) return false;
    return parts.size() > 1;
}

bool IsAssetNameASubQualifier(const std::string& name)
{
    std::vector<std::string> parts;
    boost::split(parts, name, boost::is_any_of(SUB_NAME_DELIMITER));
    if (!IsQualifierNameValid(parts.front())) return false;
    return parts.size() > 1;
}

bool IsAssetNameADEPIN(const std::string& name)
{
    return IsAssetNameValid(name)
        && (std::regex_match(name, DEPIN_INDICATOR) || std::regex_match(name, SUB_DEPIN_INDICATOR));
}

bool IsAssetNameASubDEPIN(const std::string& name)
{
    return IsAssetNameValid(name) && std::regex_match(name, SUB_DEPIN_INDICATOR);
}

bool IsTypeCheckNameValid(const AssetType type, const std::string& name, std::string& error)
{
    int maxLength = GetMaxAssetNameLength();

    if (type == AssetType::UNIQUE) {
        if (name.size() > (size_t)maxLength) { error = "Name is greater than max length of " + std::to_string(maxLength); return false; }
        std::vector<std::string> parts;
        boost::split(parts, name, boost::is_any_of(UNIQUE_TAG_DELIMITER));
        bool valid = IsNameValidBeforeTag(parts.front()) && IsUniqueTagValid(parts.back());
        if (!valid) { error = "Unique name contains invalid characters (Valid characters are: A-Z a-z 0-9 @ $ % & * ( ) [ ] { } _ . ? : -)"; return false; }
        return true;
    } else if (type == AssetType::MSGCHANNEL) {
        if (name.size() > (size_t)maxLength) { error = "Name is greater than max length of " + std::to_string(maxLength); return false; }
        std::vector<std::string> parts;
        boost::split(parts, name, boost::is_any_of(MSG_CHANNEL_TAG_DELIMITER));
        bool valid = IsNameValidBeforeTag(parts.front()) && IsMsgChannelTagValid(parts.back());
        if (parts.back().size() > (size_t)MAX_CHANNEL_NAME_LENGTH) { error = "Channel name is greater than max length of " + std::to_string(MAX_CHANNEL_NAME_LENGTH); return false; }
        if (!valid) { error = "Message Channel name contains invalid characters (Valid characters are: A-Z 0-9 _ .) (special characters can't be the first or last characters)"; return false; }
        return true;
    } else if (type == AssetType::OWNER) {
        if (name.size() > (size_t)maxLength) { error = "Name is greater than max length of " + std::to_string(maxLength); return false; }
        const std::string ownerBaseName = name.substr(0, name.size() - 1);
        bool valid = IsNameValidBeforeTag(ownerBaseName) || IsAssetNameADEPIN(ownerBaseName);
        if (!valid) { error = "Owner name contains invalid characters (Valid characters are: A-Z 0-9 _ .) (special characters can't be the first or last characters)"; return false; }
        return true;
    } else if (type == AssetType::VOTE) {
        if (name.size() > (size_t)maxLength) { error = "Name is greater than max length of " + std::to_string(maxLength); return false; }
        std::vector<std::string> parts;
        boost::split(parts, name, boost::is_any_of(VOTE_TAG_DELIMITER));
        bool valid = IsNameValidBeforeTag(parts.front()) && IsVoteTagValid(parts.back());
        if (!valid) { error = "Vote name contains invalid characters (Valid characters are: A-Z 0-9 _ .) (special characters can't be the first or last characters)"; return false; }
        return true;
    } else if (type == AssetType::QUALIFIER || type == AssetType::SUB_QUALIFIER) {
        if (name.size() > (size_t)maxLength) { error = "Name is greater than max length of " + std::to_string(maxLength); return false; }
        bool valid = IsQualifierNameValidBeforeTag(name);
        if (!valid) { error = "Qualifier name contains invalid characters (Valid characters are: A-Z 0-9 _ .) (# must be the first character, _ . special characters can't be the first or last characters)"; return false; }
        return true;
    } else if (type == AssetType::RESTRICTED) {
        if (name.size() > (size_t)maxLength) { error = "Name is greater than max length of " + std::to_string(maxLength); return false; }
        bool valid = IsRestrictedNameValid(name);
        if (!valid) { error = "Restricted name contains invalid characters (Valid characters are: A-Z 0-9 _ .) ($ must be the first character, _ . special characters can't be the first or last characters)"; return false; }
        return true;
    } else if (type == AssetType::DEPIN) {
        if (name.size() > (size_t)maxLength) { error = "Name is greater than max length of " + std::to_string(maxLength); return false; }
        if (name.find('/') != std::string::npos) {
            std::vector<std::string> parts;
            boost::split(parts, name, boost::is_any_of("/"));
            if (parts[0][0] != DEPIN_CHAR) { error = "DEPIN name must start with &"; return false; }
            for (const auto& part : parts) {
                if (part.size() < MIN_ASSET_LENGTH) {
                    error = "Each DEPIN sub-part must be at least " + std::to_string(MIN_ASSET_LENGTH) + " characters";
                    return false;
                }
            }
        } else {
            if (name[0] != DEPIN_CHAR) { error = "DEPIN name must start with &"; return false; }
            if (name.size() < (size_t)(MIN_ASSET_LENGTH + 1)) {
                error = "DEPIN name must be at least " + std::to_string(MIN_ASSET_LENGTH) + " characters (excluding &)";
                return false;
            }
        }
        return true;
    } else {
        if (name.size() > (size_t)(maxLength - 1)) { error = "Name is greater than max length of " + std::to_string(maxLength - 1); return false; }
        if (!IsAssetNameASubasset(name) && name.size() < MIN_ASSET_LENGTH) { error = "Name must be contain " + std::to_string(MIN_ASSET_LENGTH) + " characters"; return false; }
        bool valid = IsNameValidBeforeTag(name);
        if (!valid && IsAssetNameASubasset(name) && name.size() < 3) { error = "Name must have at least 3 characters (Valid characters are: A-Z 0-9 _ .)"; return false; }
        if (!valid) { error = "Name contains invalid characters (Valid characters are: A-Z 0-9 _ .) (special characters can't be the first or last characters)"; return false; }
        return true;
    }
}

bool IsAssetNameValid(const std::string& name, AssetType& assetType, std::string& error)
{
    if (name.length() > static_cast<size_t>(GetMaxAssetNameLength())) {
        error = "Name is greater than max length of " + std::to_string(GetMaxAssetNameLength());
        return false;
    }
    assetType = AssetType::INVALID;
    if (std::regex_match(name, UNIQUE_INDICATOR)) {
        bool ret = IsTypeCheckNameValid(AssetType::UNIQUE, name, error);
        if (ret) assetType = AssetType::UNIQUE;
        return ret;
    } else if (std::regex_match(name, MSG_CHANNEL_INDICATOR)) {
        bool ret = IsTypeCheckNameValid(AssetType::MSGCHANNEL, name, error);
        if (ret) assetType = AssetType::MSGCHANNEL;
        return ret;
    } else if (std::regex_match(name, OWNER_INDICATOR)) {
        bool ret = IsTypeCheckNameValid(AssetType::OWNER, name, error);
        if (ret) assetType = AssetType::OWNER;
        return ret;
    } else if (std::regex_match(name, VOTE_INDICATOR)) {
        bool ret = IsTypeCheckNameValid(AssetType::VOTE, name, error);
        if (ret) assetType = AssetType::VOTE;
        return ret;
    } else if (std::regex_match(name, QUALIFIER_INDICATOR)) {
        bool ret = IsTypeCheckNameValid(AssetType::QUALIFIER, name, error);
        if (ret) {
            if (IsAssetNameASubQualifier(name)) assetType = AssetType::SUB_QUALIFIER;
            else assetType = AssetType::QUALIFIER;
        }
        return ret;
    } else if (std::regex_match(name, SUB_QUALIFIER_INDICATOR)) {
        bool ret = IsTypeCheckNameValid(AssetType::SUB_QUALIFIER, name, error);
        if (ret) { if (IsAssetNameASubQualifier(name)) assetType = AssetType::SUB_QUALIFIER; }
        return ret;
    } else if (std::regex_match(name, RESTRICTED_INDICATOR)) {
        bool ret = IsTypeCheckNameValid(AssetType::RESTRICTED, name, error);
        if (ret) assetType = AssetType::RESTRICTED;
        return ret;
    } else if (std::regex_match(name, DEPIN_INDICATOR) || std::regex_match(name, SUB_DEPIN_INDICATOR)) {
        if (!AreDEPINAssetsEnabledOnCurrentNetwork()) {
            error = "DEPIN assets are only available in testnet and regtest";
            return false;
        }
        bool ret = IsTypeCheckNameValid(AssetType::DEPIN, name, error);
        if (ret) assetType = AssetType::DEPIN;
        return ret;
    } else {
        auto type = IsAssetNameASubasset(name) ? AssetType::SUB : AssetType::ROOT;
        bool ret = IsTypeCheckNameValid(type, name, error);
        if (ret) assetType = type;
        return ret;
    }
}

bool IsAssetNameValid(const std::string& name)
{
    AssetType _assetType;
    std::string _error;
    return IsAssetNameValid(name, _assetType, _error);
}

bool IsAssetNameValid(const std::string& name, AssetType& assetType)
{
    std::string _error;
    return IsAssetNameValid(name, assetType, _error);
}

bool IsAssetNameARoot(const std::string& name)
{
    AssetType type;
    return IsAssetNameValid(name, type) && type == AssetType::ROOT;
}

bool IsAssetNameAnOwner(const std::string& name)
{
    return IsAssetNameValid(name) && std::regex_match(name, OWNER_INDICATOR);
}

bool IsAssetNameAnRestricted(const std::string& name)
{
    return IsAssetNameValid(name) && std::regex_match(name, RESTRICTED_INDICATOR);
}

bool IsAssetNameAQualifier(const std::string& name, bool fOnlyQualifiers)
{
    if (fOnlyQualifiers)
        return IsAssetNameValid(name) && std::regex_match(name, QUALIFIER_INDICATOR);
    return IsAssetNameValid(name)
        && (std::regex_match(name, QUALIFIER_INDICATOR) || std::regex_match(name, SUB_QUALIFIER_INDICATOR));
}

bool IsAssetNameAnMsgChannel(const std::string& name)
{
    return IsAssetNameValid(name) && std::regex_match(name, MSG_CHANNEL_INDICATOR);
}

// ---------------------------------------------------------------------------
// *FromScript functions
// ---------------------------------------------------------------------------

bool TransferAssetFromScript(const CScript& scriptPubKey, CAssetTransfer& assetTransfer, std::string& strAddress)
{
    int nStartingIndex = 0;
    if (!IsScriptTransferAsset(scriptPubKey, nStartingIndex))
        return false;

    CTxDestination destination;
    ExtractDestination(scriptPubKey, destination);
    strAddress = EncodeDestination(destination);

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

// ---------------------------------------------------------------------------
// IsScript* functions
// ---------------------------------------------------------------------------

bool IsScriptNewAsset(const CScript& scriptPubKey)
{
    int index = 0;
    return IsScriptNewAsset(scriptPubKey, index);
}

bool IsScriptNewAsset(const CScript& scriptPubKey, int& nStartingIndex)
{
    int nType = 0;
    bool fIsOwner = false;
    if (scriptPubKey.IsAssetScript(nType, fIsOwner, nStartingIndex))
        return nType == TX_NEW_ASSET && !fIsOwner;
    return false;
}

bool IsScriptNewUniqueAsset(const CScript& scriptPubKey)
{
    int index = 0;
    return IsScriptNewUniqueAsset(scriptPubKey, index);
}

bool IsScriptNewUniqueAsset(const CScript& scriptPubKey, int& nStartingIndex)
{
    int nType = 0;
    bool fIsOwner = false;
    if (!scriptPubKey.IsAssetScript(nType, fIsOwner, nStartingIndex))
        return false;
    CNewAsset asset;
    std::string address;
    if (!AssetFromScript(scriptPubKey, asset, address))
        return false;
    AssetType assetType;
    if (!IsAssetNameValid(asset.strName, assetType))
        return false;
    return AssetType::UNIQUE == assetType;
}

bool IsScriptNewMsgChannelAsset(const CScript& scriptPubKey)
{
    int index = 0;
    return IsScriptNewMsgChannelAsset(scriptPubKey, index);
}

bool IsScriptNewMsgChannelAsset(const CScript& scriptPubKey, int& nStartingIndex)
{
    int nType = 0;
    bool fIsOwner = false;
    if (!scriptPubKey.IsAssetScript(nType, fIsOwner, nStartingIndex))
        return false;
    CNewAsset asset;
    std::string address;
    if (!AssetFromScript(scriptPubKey, asset, address))
        return false;
    AssetType assetType;
    if (!IsAssetNameValid(asset.strName, assetType))
        return false;
    return AssetType::MSGCHANNEL == assetType;
}

bool IsScriptOwnerAsset(const CScript& scriptPubKey)
{
    int index = 0;
    return IsScriptOwnerAsset(scriptPubKey, index);
}

bool IsScriptOwnerAsset(const CScript& scriptPubKey, int& nStartingIndex)
{
    int nType = 0;
    bool fIsOwner = false;
    if (scriptPubKey.IsAssetScript(nType, fIsOwner, nStartingIndex))
        return nType == TX_NEW_ASSET && fIsOwner;
    return false;
}

bool IsScriptReissueAsset(const CScript& scriptPubKey)
{
    int index = 0;
    return IsScriptReissueAsset(scriptPubKey, index);
}

bool IsScriptReissueAsset(const CScript& scriptPubKey, int& nStartingIndex)
{
    int nType = 0;
    bool fIsOwner = false;
    if (scriptPubKey.IsAssetScript(nType, fIsOwner, nStartingIndex))
        return nType == TX_REISSUE_ASSET;
    return false;
}

bool IsScriptTransferAsset(const CScript& scriptPubKey)
{
    int index = 0;
    return IsScriptTransferAsset(scriptPubKey, index);
}

bool IsScriptTransferAsset(const CScript& scriptPubKey, int& nStartingIndex)
{
    int nType = 0;
    bool fIsOwner = false;
    if (scriptPubKey.IsAssetScript(nType, fIsOwner, nStartingIndex))
        return nType == TX_TRANSFER_ASSET;
    return false;
}

bool IsScriptNewQualifierAsset(const CScript& scriptPubKey)
{
    int index = 0;
    return IsScriptNewQualifierAsset(scriptPubKey, index);
}

bool IsScriptNewQualifierAsset(const CScript& scriptPubKey, int& nStartingIndex)
{
    int nType = 0;
    bool fIsOwner = false;
    if (!scriptPubKey.IsAssetScript(nType, fIsOwner, nStartingIndex))
        return false;
    CNewAsset asset;
    std::string address;
    if (!AssetFromScript(scriptPubKey, asset, address))
        return false;
    AssetType assetType;
    if (!IsAssetNameValid(asset.strName, assetType))
        return false;
    return AssetType::QUALIFIER == assetType || AssetType::SUB_QUALIFIER == assetType;
}

bool IsScriptNewRestrictedAsset(const CScript& scriptPubKey)
{
    int index = 0;
    return IsScriptNewRestrictedAsset(scriptPubKey, index);
}

bool IsScriptNewRestrictedAsset(const CScript& scriptPubKey, int& nStartingIndex)
{
    int nType = 0;
    bool fIsOwner = false;
    if (!scriptPubKey.IsAssetScript(nType, fIsOwner, nStartingIndex))
        return false;
    CNewAsset asset;
    std::string address;
    if (!AssetFromScript(scriptPubKey, asset, address))
        return false;
    AssetType assetType;
    if (!IsAssetNameValid(asset.strName, assetType))
        return false;
    return AssetType::RESTRICTED == assetType;
}

// ---------------------------------------------------------------------------
// Null / verifier data from script
// ---------------------------------------------------------------------------

#define OFFSET_THREE 3
#define OFFSET_FOUR  4

bool AssetNullDataFromScript(const CScript& scriptPubKey, CNullAssetTxData& assetData, std::string& strAddress)
{
    if (!scriptPubKey.IsNullAssetTxDataScript())
        return false;

    CTxDestination destination;
    ExtractDestination(scriptPubKey, destination);
    strAddress = EncodeDestination(destination);

    int dataOffset = -1;
    if (scriptPubKey.size() > 23 && scriptPubKey[0] == OP_XNA_ASSET && scriptPubKey[1] == 0x14) {
        dataOffset = 23;
    } else if (scriptPubKey.size() > 36 && scriptPubKey[0] == OP_XNA_ASSET && scriptPubKey[1] == OP_1 && scriptPubKey[2] == 0x20) {
        dataOffset = 36;
    } else {
        return false;
    }

    std::vector<unsigned char> vchAssetData;
    vchAssetData.insert(vchAssetData.end(), scriptPubKey.begin() + dataOffset, scriptPubKey.end());
    CDataStream ssData(vchAssetData, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ssData >> assetData;
    } catch (std::exception& e) {
        error("Failed to get the null asset tx data from the stream: %s", e.what());
        return false;
    }
    return true;
}

bool GlobalAssetNullDataFromScript(const CScript& scriptPubKey, CNullAssetTxData& assetData)
{
    if (!scriptPubKey.IsNullGlobalRestrictionAssetTxDataScript())
        return false;

    std::vector<unsigned char> vchAssetData;
    vchAssetData.insert(vchAssetData.end(), scriptPubKey.begin() + OFFSET_FOUR, scriptPubKey.end());
    CDataStream ssData(vchAssetData, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ssData >> assetData;
    } catch (std::exception& e) {
        error("Failed to get the global restriction asset tx data from the stream: %s", e.what());
        return false;
    }
    return true;
}

bool AssetNullVerifierDataFromScript(const CScript& scriptPubKey, CNullAssetTxVerifierString& verifierData)
{
    if (!scriptPubKey.IsNullAssetVerifierTxDataScript())
        return false;

    std::vector<unsigned char> vchAssetData;
    vchAssetData.insert(vchAssetData.end(), scriptPubKey.begin() + OFFSET_THREE, scriptPubKey.end());
    CDataStream ssData(vchAssetData, SER_NETWORK, PROTOCOL_VERSION);
    try {
        ssData >> verifierData;
    } catch (std::exception& e) {
        error("Failed to get the verifier string from the stream: %s", e.what());
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// GetAssetData / EncodeAssetData / EncodeIPFS / DecodeIPFS
// ---------------------------------------------------------------------------

bool GetAssetData(const CScript& script, CAssetOutputEntry& data)
{
    std::string address = "";
    std::string assetName = "";

    int nType = 0;
    bool fIsOwner = false;
    if (!script.IsAssetScript(nType, fIsOwner))
        return false;

    txnouttype type = txnouttype(nType);

    if (type == TX_NEW_ASSET && !fIsOwner) {
        CNewAsset asset;
        if (AssetFromScript(script, asset, address)) {
            data.type = TX_NEW_ASSET;
            data.nAmount = asset.nAmount;
            data.destination = DecodeDestination(address);
            data.assetName = asset.strName;
            return true;
        } else if (MsgChannelAssetFromScript(script, asset, address)) {
            data.type = TX_NEW_ASSET;
            data.nAmount = asset.nAmount;
            data.destination = DecodeDestination(address);
            data.assetName = asset.strName;
        } else if (QualifierAssetFromScript(script, asset, address)) {
            data.type = TX_NEW_ASSET;
            data.nAmount = asset.nAmount;
            data.destination = DecodeDestination(address);
            data.assetName = asset.strName;
        } else if (RestrictedAssetFromScript(script, asset, address)) {
            data.type = TX_NEW_ASSET;
            data.nAmount = asset.nAmount;
            data.destination = DecodeDestination(address);
            data.assetName = asset.strName;
        }
    } else if (type == TX_TRANSFER_ASSET) {
        CAssetTransfer transfer;
        if (TransferAssetFromScript(script, transfer, address)) {
            data.type = TX_TRANSFER_ASSET;
            data.nAmount = transfer.nAmount;
            data.destination = DecodeDestination(address);
            data.assetName = transfer.strName;
            data.message = transfer.message;
            data.expireTime = transfer.nExpireTime;
            return true;
        } else {
            LogPrintf("Failed to get transfer from script\n");
        }
    } else if (type == TX_NEW_ASSET && fIsOwner) {
        if (OwnerAssetFromScript(script, assetName, address)) {
            data.type = TX_NEW_ASSET;
            data.nAmount = OWNER_ASSET_AMOUNT;
            data.destination = DecodeDestination(address);
            data.assetName = assetName;
            return true;
        }
    } else if (type == TX_REISSUE_ASSET) {
        CReissueAsset reissue;
        if (ReissueAssetFromScript(script, reissue, address)) {
            data.type = TX_REISSUE_ASSET;
            data.nAmount = reissue.nAmount;
            data.destination = DecodeDestination(address);
            data.assetName = reissue.strName;
            return true;
        }
    }

    return false;
}

std::string EncodeIPFS(std::string decoded)
{
    std::vector<char> charData(decoded.begin(), decoded.end());
    std::vector<unsigned char> unsignedCharData;
    for (char c : charData)
        unsignedCharData.push_back(static_cast<unsigned char>(c));
    return EncodeBase58(unsignedCharData);
}

std::string DecodeIPFS(std::string encoded)
{
    std::vector<unsigned char> b;
    DecodeBase58(encoded, b);
    return std::string(b.begin(), b.end());
}

std::string EncodeAssetData(std::string decoded)
{
    if (decoded.size() == 34)
        return EncodeIPFS(decoded);
    else if (decoded.size() == 32)
        return HexStr(decoded);
    return "";
}

// ---------------------------------------------------------------------------
// Weak stubs — COMMON placeholders that neurai-tx links against.
// The real SERVER definitions override these when neuraid / neurai-qt link.
// ---------------------------------------------------------------------------

// messages.cpp (SERVER) → real definition
__attribute__((weak)) void AddAddressSeen(const std::string& /*address*/) {}

// validation.cpp (SERVER) → real definition
__attribute__((weak)) bool AreAssetsDeployed() { return false; }

// consensus/consensus.cpp (SERVER) → real definition
__attribute__((weak)) unsigned int GetMaxBlockWeight() { return 8000000u; }

// assets/assets.cpp (SERVER) → real definition
__attribute__((weak)) bool CAssetsCache::TrySpendCoin(const COutPoint& /*out*/, const CTxOut& /*coin*/) { return true; }
