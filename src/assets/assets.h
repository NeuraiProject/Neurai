// Copyright (c) 2017-2021 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef NEURAICOIN_ASSET_PROTOCOL_H
#define NEURAICOIN_ASSET_PROTOCOL_H

#include "amount.h"
#include "tinyformat.h"
#include "assettypes.h"

#include <string>
#include <set>
#include <map>
#include <unordered_map>
#include <list>

#define XNA_R 114
#define XNA_V 118
#define XNA_N 110
#define XNA_Q 113
#define XNA_T 116
#define XNA_O 111

#define DEFAULT_UNITS 0
#define DEFAULT_REISSUABLE 1
#define DEFAULT_HAS_IPFS 0
#define DEFAULT_IPFS ""
#define MIN_ASSET_LENGTH 3
#define MAX_ASSET_LENGTH 32
#define MAX_ASSET_LENGTH_TESTNET 121  // 120 visible root/sub characters + 1 for owner tag
#define OWNER_TAG "!"
#define OWNER_LENGTH 1
#define OWNER_UNITS 0
#define OWNER_ASSET_AMOUNT 1 * COIN
#define UNIQUE_ASSET_AMOUNT 1 * COIN
#define UNIQUE_ASSET_UNITS 0
#define UNIQUE_ASSETS_REISSUABLE 0

/**
 * Get maximum asset name length based on network
 * Returns the total asset-name limit used by validation.
 * ROOT/SUB names reserve one extra character for the OWNER_TAG ('!').
 */
int GetMaxAssetNameLength();

#define RESTRICTED_CHAR '$'
#define QUALIFIER_CHAR '#'
#define DEPIN_CHAR '&'  // Soulbound assets (testnet and regtest only)

#define QUALIFIER_ASSET_MIN_AMOUNT 1 * COIN
#define QUALIFIER_ASSET_MAX_AMOUNT 10 * COIN
#define QUALIFIER_ASSET_UNITS 0

#define DEPIN_ASSET_UNITS 0

#define ASSET_TRANSFER_STRING "transfer_asset"
#define ASSET_NEW_STRING "new_asset"
#define ASSET_REISSUE_STRING "reissue_asset"

#define MINIMUM_REWARDS_PAYOUT_HEIGHT 60

class CScript;
class CDataStream;
class CTransaction;
class CTxOut;
class Coin;
class CCoinsViewCache;
class CWallet;
class CReserveKey;
class CWalletTx;
// CAssetOutputEntry is defined in assettypes.h (included above)
class CCoinControl;
struct CBlockAssetUndo;
class COutput;

// 2500 * 82 Bytes == 205 KB (kilobytes) of memory
#define MAX_CACHE_ASSETS_SIZE 2500

// Create map that store that state of current reissued transaction that the mempool as accepted.
// If an asset name is in this map, any other reissue transactions wont be accepted into the mempool
extern std::map<uint256, std::string> mapReissuedTx;
extern std::map<std::string, uint256> mapReissuedAssets;

class CAssets {
public:
    std::map<std::pair<std::string, std::string>, CAmount> mapAssetsAddressAmount; // pair < Asset Name , Address > -> Quantity of tokens in the address

    // Dirty, Gets wiped once flushed to database
    std::map<std::string, CNewAsset> mapReissuedAssetData; // Asset Name -> New Asset Data

    CAssets(const CAssets& assets) {
        this->mapAssetsAddressAmount = assets.mapAssetsAddressAmount;
        this->mapReissuedAssetData = assets.mapReissuedAssetData;
    }

    CAssets& operator=(const CAssets& other) {
        mapAssetsAddressAmount = other.mapAssetsAddressAmount;
        mapReissuedAssetData = other.mapReissuedAssetData;
        return *this;
    }

    CAssets() {
        SetNull();
    }

    void SetNull() {
        mapAssetsAddressAmount.clear();
        mapReissuedAssetData.clear();
    }
};

struct ErrorReport {

    enum ErrorType {
        NotSetError = 0,
        InvalidQualifierName = 1,
        EmptyString = 2,
        LengthToLarge = 3,
        InvalidSubExpressionFormula = 4,
        InvalidSyntax = 5,
        AssetDoesntExist = 6,
        FailedToVerifyAgainstAddress = 7,
        EmptySubExpression = 8,
        UnknownOperator = 9,
        ParenthesisParity = 10,
        VariableNotFound = 11
    };

    ErrorType type = ErrorType::NotSetError;
    std::string strDevData;
    std::vector<std::string> vecUserData;
};

std::string GetUserErrorString(const ErrorReport& report);

class CAssetsCache : public CAssets
{
private:
    bool AddBackSpentAsset(const Coin& coin, const std::string& assetName, const std::string& address, const CAmount& nAmount, const COutPoint& out);
    void AddToAssetBalance(const std::string& strName, const std::string& address, const CAmount& nAmount);
    bool UndoTransfer(const CAssetTransfer& transfer, const std::string& address, const COutPoint& outToRemove);
public :
    //! These are memory only containers that show dirty entries that will be databased when flushed
    std::vector<CAssetCacheUndoAssetAmount> vUndoAssetAmount;
    std::vector<CAssetCacheSpendAsset> vSpentAssets;

    //! New Assets Caches
    std::set<CAssetCacheNewAsset> setNewAssetsToRemove;
    std::set<CAssetCacheNewAsset> setNewAssetsToAdd;

    //! New Reissue Caches
    std::set<CAssetCacheReissueAsset> setNewReissueToRemove;
    std::set<CAssetCacheReissueAsset> setNewReissueToAdd;

    //! Ownership Assets Caches
    std::set<CAssetCacheNewOwner> setNewOwnerAssetsToAdd;
    std::set<CAssetCacheNewOwner> setNewOwnerAssetsToRemove;

    //! Transfer Assets Caches
    std::set<CAssetCacheNewTransfer> setNewTransferAssetsToAdd;
    std::set<CAssetCacheNewTransfer> setNewTransferAssetsToRemove;

    //! Qualfier Address Asset Caches
    std::set<CAssetCacheQualifierAddress> setNewQualifierAddressToAdd;
    std::set<CAssetCacheQualifierAddress> setNewQualifierAddressToRemove;

    //! Restricted Address Asset Caches
    std::set<CAssetCacheRestrictedAddress> setNewRestrictedAddressToAdd;
    std::set<CAssetCacheRestrictedAddress> setNewRestrictedAddressToRemove;

    //! Restricted Global Asset Caches
    std::set<CAssetCacheRestrictedGlobal> setNewRestrictedGlobalToAdd;
    std::set<CAssetCacheRestrictedGlobal> setNewRestrictedGlobalToRemove;

    //! Restricted Assets Verifier Caches
    std::set<CAssetCacheRestrictedVerifiers> setNewRestrictedVerifierToAdd;
    std::set<CAssetCacheRestrictedVerifiers> setNewRestrictedVerifierToRemove;

    //! DEPIN Self-Restriction Caches
    std::set<CAssetCacheSelfRestriction> setNewSelfRestrictionToAdd;
    std::set<CAssetCacheSelfRestriction> setNewSelfRestrictionToRemove;

    //! Root Qualifier Address Map
    std::map<CAssetCacheRootQualifierChecker, std::set<std::string> > mapRootQualifierAddressesAdd;
    std::map<CAssetCacheRootQualifierChecker, std::set<std::string> > mapRootQualifierAddressesRemove;

    CAssetsCache() : CAssets()
    {
        SetNull();
        ClearDirtyCache();
    }

    CAssetsCache(const CAssetsCache& cache) : CAssets(cache)
    {
        //! Copy dirty cache also
        this->vSpentAssets = cache.vSpentAssets;
        this->vUndoAssetAmount = cache.vUndoAssetAmount;

        //! Transfer Caches
        this->setNewTransferAssetsToAdd = cache.setNewTransferAssetsToAdd;
        this->setNewTransferAssetsToRemove = cache.setNewTransferAssetsToRemove;

        //! Issue Caches
        this->setNewAssetsToRemove = cache.setNewAssetsToRemove;
        this->setNewAssetsToAdd = cache.setNewAssetsToAdd;

        //! Reissue Caches
        this->setNewReissueToRemove = cache.setNewReissueToRemove;
        this->setNewReissueToAdd = cache.setNewReissueToAdd;

        //! Owner Caches
        this->setNewOwnerAssetsToAdd = cache.setNewOwnerAssetsToAdd;
        this->setNewOwnerAssetsToRemove = cache.setNewOwnerAssetsToRemove;

        //! Qualifier Caches
        this->setNewQualifierAddressToAdd = cache.setNewQualifierAddressToAdd;
        this->setNewQualifierAddressToRemove = cache.setNewQualifierAddressToRemove;

        //! Restricted Address Caches
        this->setNewRestrictedAddressToAdd = cache.setNewRestrictedAddressToAdd;
        this->setNewRestrictedAddressToRemove = cache.setNewRestrictedAddressToRemove;

        //! Restricted Global Caches
        this->setNewRestrictedGlobalToAdd = cache.setNewRestrictedGlobalToAdd;
        this->setNewRestrictedGlobalToRemove = cache.setNewRestrictedGlobalToRemove;

        //! Restricted Verifier Caches
        this->setNewRestrictedVerifierToAdd = cache.setNewRestrictedVerifierToAdd;
        this->setNewRestrictedVerifierToRemove = cache.setNewRestrictedVerifierToRemove;

        //! DEPIN Self-Restriction Caches
        this->setNewSelfRestrictionToAdd = cache.setNewSelfRestrictionToAdd;
        this->setNewSelfRestrictionToRemove = cache.setNewSelfRestrictionToRemove;

        //! Root Qualifier Address Map
        this->mapRootQualifierAddressesAdd = cache.mapRootQualifierAddressesAdd;
        this->mapRootQualifierAddressesRemove = cache.mapRootQualifierAddressesRemove;
    }

    CAssetsCache& operator=(const CAssetsCache& cache)
    {
        this->mapAssetsAddressAmount = cache.mapAssetsAddressAmount;
        this->mapReissuedAssetData = cache.mapReissuedAssetData;

        //! Copy dirty cache also
        this->vSpentAssets = cache.vSpentAssets;
        this->vUndoAssetAmount = cache.vUndoAssetAmount;

        //! Transfer Caches
        this->setNewTransferAssetsToAdd = cache.setNewTransferAssetsToAdd;
        this->setNewTransferAssetsToRemove = cache.setNewTransferAssetsToRemove;

        //! Issue Caches
        this->setNewAssetsToRemove = cache.setNewAssetsToRemove;
        this->setNewAssetsToAdd = cache.setNewAssetsToAdd;

        //! Reissue Caches
        this->setNewReissueToRemove = cache.setNewReissueToRemove;
        this->setNewReissueToAdd = cache.setNewReissueToAdd;

        //! Owner Caches
        this->setNewOwnerAssetsToAdd = cache.setNewOwnerAssetsToAdd;
        this->setNewOwnerAssetsToRemove = cache.setNewOwnerAssetsToRemove;

        //! Qualifier Caches
        this->setNewQualifierAddressToAdd = cache.setNewQualifierAddressToAdd;
        this->setNewQualifierAddressToRemove = cache.setNewQualifierAddressToRemove;

        //! Restricted Address Caches
        this->setNewRestrictedAddressToAdd = cache.setNewRestrictedAddressToAdd;
        this->setNewRestrictedAddressToRemove = cache.setNewRestrictedAddressToRemove;

        //! Restricted Global Caches
        this->setNewRestrictedGlobalToAdd = cache.setNewRestrictedGlobalToAdd;
        this->setNewRestrictedGlobalToRemove = cache.setNewRestrictedGlobalToRemove;

        //! Restricted Verifier Caches
        this->setNewRestrictedVerifierToAdd = cache.setNewRestrictedVerifierToAdd;
        this->setNewRestrictedVerifierToRemove = cache.setNewRestrictedVerifierToRemove;

        //! DEPIN Self-Restriction Caches
        this->setNewSelfRestrictionToAdd = cache.setNewSelfRestrictionToAdd;
        this->setNewSelfRestrictionToRemove = cache.setNewSelfRestrictionToRemove;

        //! Root Qualifier Address Map
        this->mapRootQualifierAddressesAdd = cache.mapRootQualifierAddressesAdd;
        this->mapRootQualifierAddressesRemove = cache.mapRootQualifierAddressesRemove;

        return *this;
    }

    //! Cache only undo functions
    bool RemoveNewAsset(const CNewAsset& asset, const std::string address);
    bool RemoveTransfer(const CAssetTransfer& transfer, const std::string& address, const COutPoint& out);
    bool RemoveOwnerAsset(const std::string& assetsName, const std::string address);
    bool RemoveReissueAsset(const CReissueAsset& reissue, const std::string address, const COutPoint& out, const std::vector<std::pair<std::string, CBlockAssetUndo> >& vUndoIPFS);
    bool UndoAssetCoin(const Coin& coin, const COutPoint& out);
    bool RemoveQualifierAddress(const std::string& assetName, const std::string& address, const QualifierType type);
    bool RemoveRestrictedAddress(const std::string& assetName, const std::string& address, const RestrictedType type);
    bool RemoveGlobalRestricted(const std::string& assetName, const RestrictedType type);
    bool RemoveSelfRestriction(const std::string& assetName, const std::string& address, bool isSelfRevoke);
    bool RemoveRestrictedVerifier(const std::string& assetName, const std::string& verifier, const bool fUndoingReissue = false);

    //! Cache only add asset functions
    bool AddNewAsset(const CNewAsset& asset, const std::string address, const int& nHeight, const uint256& blockHash);
    bool AddTransferAsset(const CAssetTransfer& transferAsset, const std::string& address, const COutPoint& out, const CTxOut& txOut);
    bool AddOwnerAsset(const std::string& assetsName, const std::string address);
    bool AddReissueAsset(const CReissueAsset& reissue, const std::string address, const COutPoint& out);
    bool AddQualifierAddress(const std::string& assetName, const std::string& address, const QualifierType type);
    bool AddRestrictedAddress(const std::string& assetName, const std::string& address, const RestrictedType type);
    bool AddGlobalRestricted(const std::string& assetName, const RestrictedType type);
    bool AddSelfRestriction(const std::string& assetName, const std::string& address, bool isSelfRevoke);
    bool AddRestrictedVerifier(const std::string& assetName, const std::string& verifier);

    //! Cache only validation functions
    bool TrySpendCoin(const COutPoint& out, const CTxOut& coin);

    //! Help functions
    bool ContainsAsset(const CNewAsset& asset);
    bool ContainsAsset(const std::string& assetName);

    //! Returns true if an asset with this name already exists
    bool CheckIfAssetExists(const std::string& name, bool fForceDuplicateCheck = true);

    //! Returns true if an asset with the name exists, and it was able to get the asset metadata from database
    bool GetAssetMetaDataIfExists(const std::string &name, CNewAsset &asset);
    bool GetAssetMetaDataIfExists(const std::string &name, CNewAsset &asset, int& nHeight, uint256& blockHash);

    //! Returns true if the Asset Verifier String was found for an asset_name, if fSkipTempCache is true, it will only search passets pointer and databases
    bool GetAssetVerifierStringIfExists(const std::string &name, CNullAssetTxVerifierString& verifier, bool fSkipTempCache = false);

    //! Return true if the address has the given qualifier assigned to it
    bool CheckForAddressQualifier(const std::string &qualifier_name, const std::string& address, bool fSkipTempCache = false);

    //! Return true if the address is marked as frozen
    bool CheckForAddressRestriction(const std::string &restricted_name, const std::string& address, bool fSkipTempCache = false);

    //! Return true if the restricted asset is globally freezing trading
    bool CheckForGlobalRestriction(const std::string &restricted_name, bool fSkipTempCache = false);

    //! Return true if the DEPIN asset is blocked (owner freeze OR self-revoke)
    bool CheckForDEPINRestriction(const std::string &assetName, const std::string& address, bool fSkipTempCache = false);
    bool CheckForDEPINSelfRestriction(const std::string &assetName, const std::string& address, bool fSkipTempCache = false);

    //! Calculate the size of the CAssets (in bytes)
    size_t DynamicMemoryUsage() const;

    //! Get the size of the none databased cache
    size_t GetCacheSize() const;
    size_t GetCacheSizeV2() const;

    //! Flush all new cache entries into the passets global cache
    bool Flush();

    //! Write asset cache data to database
    bool DumpCacheToDatabase();

    //! Clear all dirty cache sets, vetors, and maps
    void ClearDirtyCache() {

        vUndoAssetAmount.clear();
        vSpentAssets.clear();

        setNewAssetsToRemove.clear();
        setNewAssetsToAdd.clear();

        setNewReissueToAdd.clear();
        setNewReissueToRemove.clear();

        setNewTransferAssetsToAdd.clear();
        setNewTransferAssetsToRemove.clear();

        setNewOwnerAssetsToAdd.clear();
        setNewOwnerAssetsToRemove.clear();

        mapReissuedAssetData.clear();
        mapAssetsAddressAmount.clear();

        setNewQualifierAddressToAdd.clear();
        setNewQualifierAddressToRemove.clear();

        setNewRestrictedAddressToAdd.clear();
        setNewRestrictedAddressToRemove.clear();

        setNewRestrictedGlobalToAdd.clear();
        setNewRestrictedGlobalToRemove.clear();

        setNewRestrictedVerifierToAdd.clear();
        setNewRestrictedVerifierToRemove.clear();

        setNewSelfRestrictionToAdd.clear();
        setNewSelfRestrictionToRemove.clear();

        mapRootQualifierAddressesAdd.clear();
        mapRootQualifierAddressesRemove.clear();
    }

   std::string CacheToString() const {

       return strprintf(
               "vNewAssetsToRemove size : %d, vNewAssetsToAdd size : %d, vNewTransfer size : %d, vSpentAssets : %d\n"
               "setNewQualifierAddressToAdd size : %d, setNewQualifierAddressToRemove size : %d, setNewRestrictedAddressToAdd size : %d\n"
               "setNewRestrictedAddressToRemove size : %d, setNewRestrictedGlobalToAdd size : %d, setNewRestrictedGlobalToRemove : %d",
               setNewAssetsToRemove.size(), setNewAssetsToAdd.size(), setNewTransferAssetsToAdd.size(),
               vSpentAssets.size(), setNewQualifierAddressToAdd.size(), setNewQualifierAddressToRemove.size(), setNewRestrictedAddressToAdd.size(),
               setNewRestrictedAddressToRemove.size(), setNewRestrictedGlobalToAdd.size(), setNewRestrictedGlobalToRemove.size());
   }
};

//! Functions to be used to get access to the current burn amount required for specific asset issuance transactions
CAmount GetIssueAssetBurnAmount();
CAmount GetReissueAssetBurnAmount();
CAmount GetIssueSubAssetBurnAmount();
CAmount GetIssueUniqueAssetBurnAmount();
CAmount GetIssueMsgChannelAssetBurnAmount();
CAmount GetIssueQualifierAssetBurnAmount();
CAmount GetIssueSubQualifierAssetBurnAmount();
CAmount GetIssueRestrictedAssetBurnAmount();
CAmount GetAddNullQualifierTagBurnAmount();
CAmount GetBurnAmount(const AssetType type);
CAmount GetBurnAmount(const int nType);

//! Functions to be used to get access to the burn address for a given asset type issuance
std::string GetBurnAddress(const AssetType type);
std::string GetBurnAddress(const int nType);

void GetTxOutAssetTypes(const std::vector<CTxOut>& vout, int& issues, int& reissues, int& transfers, int& owners);

//! Check is an asset name is valid, and being able to return the asset type if needed
bool IsAssetNameValid(const std::string& name);
bool IsAssetNameValid(const std::string& name, AssetType& assetType);
bool IsAssetNameValid(const std::string& name, AssetType& assetType, std::string& error);

//! Check if an unique tagname is valid
bool IsUniqueTagValid(const std::string& tag);

//! Check if an asset is an owner
bool IsAssetNameAnOwner(const std::string& name);

//! Check if an asset is a restricted asset
bool IsAssetNameAnRestricted(const std::string& name);

//! Check if an asset is a qualifier asset or sub qualifier
bool IsAssetNameAQualifier(const std::string& name, bool fOnlyQualifiers = false);

//! Check if an asset is a sub qualifier
bool IsAssetNameASubQualifier(const std::string& name);

//! Check if an asset is a message channel
bool IsAssetNameAnMsgChannel(const std::string& name);

//! Check if an asset is a DEPIN (soulbound) asset (testnet and regtest only)
bool IsAssetNameADEPIN(const std::string& name);

//! Check if an asset is a sub-DEPIN asset
bool IsAssetNameASubDEPIN(const std::string& name);

bool IsAssetNameARoot(const std::string& name);

//! Get the root name of an asset
std::string GetParentName(const std::string& name); // Gets the parent name of a subasset TEST/TESTSUB would return TEST

//! Get the owner token name belonging to a restricted asset
std::string RestrictedNameToOwnerName(const std::string& name);

//! Build a unique asset buy giving the root name, and the tag name (ROOT, TAG) => ROOT#TAG
std::string GetUniqueAssetName(const std::string& parent, const std::string& tag);

//! Given a type, and an asset name, return if that name is valid based on the type
bool IsTypeCheckNameValid(const AssetType type, const std::string& name, std::string& error);

//! These types of asset tx, have specific metadata at certain indexes in the transaction.
//! These functions pull data from the scripts at those indexes
bool AssetFromTransaction(const CTransaction& tx, CNewAsset& asset, std::string& strAddress);
bool OwnerFromTransaction(const CTransaction& tx, std::string& ownerName, std::string& strAddress);
bool ReissueAssetFromTransaction(const CTransaction& tx, CReissueAsset& reissue, std::string& strAddress);
bool UniqueAssetFromTransaction(const CTransaction& tx, CNewAsset& asset, std::string& strAddress);
bool MsgChannelAssetFromTransaction(const CTransaction& tx, CNewAsset& asset, std::string& strAddress);
bool QualifierAssetFromTransaction(const CTransaction& tx, CNewAsset& asset, std::string& strAddress);
bool RestrictedAssetFromTransaction(const CTransaction& tx, CNewAsset& asset, std::string& strAddress);

//! Get specific asset type metadata from the given scripts
bool TransferAssetFromScript(const CScript& scriptPubKey, CAssetTransfer& assetTransfer, std::string& strAddress);
bool AssetFromScript(const CScript& scriptPubKey, CNewAsset& asset, std::string& strAddress);
bool OwnerAssetFromScript(const CScript& scriptPubKey, std::string& assetName, std::string& strAddress);
bool ReissueAssetFromScript(const CScript& scriptPubKey, CReissueAsset& reissue, std::string& strAddress);
bool MsgChannelAssetFromScript(const CScript& scriptPubKey, CNewAsset& asset, std::string& strAddress);
bool QualifierAssetFromScript(const CScript& scriptPubKey, CNewAsset& asset, std::string& strAddress);
bool RestrictedAssetFromScript(const CScript& scriptPubKey, CNewAsset& asset, std::string& strAddress);
bool AssetNullDataFromScript(const CScript& scriptPubKey, CNullAssetTxData& assetData, std::string& strAddress);
bool AssetNullVerifierDataFromScript(const CScript& scriptPubKey, CNullAssetTxVerifierString& verifierData);
bool GlobalAssetNullDataFromScript(const CScript& scriptPubKey, CNullAssetTxData& assetData);

//! Check to make sure the script contains the burn transaction
bool CheckIssueBurnTx(const CTxOut& txOut, const AssetType& type, const int numberIssued);
bool CheckIssueBurnTx(const CTxOut& txOut, const AssetType& type);

// TODO, maybe remove this function and input that check into the CheckIssueBurnTx.
//! Check to make sure the script contains the reissue burn data
bool CheckReissueBurnTx(const CTxOut& txOut);

//! issue asset scripts to make sure script meets the standards
bool CheckIssueDataTx(const CTxOut& txOut); // OP_NEURAI_ASSET XNAQ (That is a Q as in Que not an O)
bool CheckOwnerDataTx(const CTxOut& txOut);// OP_NEURAI_ASSET XNAO
bool CheckReissueDataTx(const CTxOut& txOut);// OP_NEURAI_ASSET XNAR
bool CheckTransferOwnerTx(const CTxOut& txOut);// OP_NEURAI_ASSET XNAT

//! Check the Encoded hash and make sure it is either an IPFS hash or a OIP hash
bool CheckEncoded(const std::string& hash, std::string& strError);

//! Checks the amount and units, and makes sure that the amount uses the correct decimals
bool CheckAmountWithUnits(const CAmount& nAmount, const int8_t nUnits);

//! Check script and see if it matches the asset issuance template
bool IsScriptNewAsset(const CScript& scriptPubKey);
bool IsScriptNewAsset(const CScript& scriptPubKey, int& nStartingIndex);

//! Check script and see if it matches the unquie issuance template
bool IsScriptNewUniqueAsset(const CScript& scriptPubKey);
bool IsScriptNewUniqueAsset(const CScript &scriptPubKey, int &nStartingIndex);

//! Check script and see if it matches the owner issuance template
bool IsScriptOwnerAsset(const CScript& scriptPubKey);
bool IsScriptOwnerAsset(const CScript& scriptPubKey, int& nStartingIndex);

//! Check script and see if it matches the reissue template
bool IsScriptReissueAsset(const CScript& scriptPubKey);
bool IsScriptReissueAsset(const CScript& scriptPubKey, int& nStartingIndex);

//! Check script and see if it matches the transfer asset template
bool IsScriptTransferAsset(const CScript& scriptPubKey);
bool IsScriptTransferAsset(const CScript& scriptPubKey, int& nStartingIndex);

//! Check script and see if it matches the message channel issuance template
bool IsScriptNewMsgChannelAsset(const CScript& scriptPubKey);
bool IsScriptNewMsgChannelAsset(const CScript& scriptPubKey, int& nStartingIndex);

//! Check script and see if it matches the qualifier issuance template
bool IsScriptNewQualifierAsset(const CScript& scriptPubKey);
bool IsScriptNewQualifierAsset(const CScript &scriptPubKey, int &nStartingIndex);

//! Check script and see if it matches the restricted issueance template
bool IsScriptNewRestrictedAsset(const CScript& scriptPubKey);
bool IsScriptNewRestrictedAsset(const CScript &scriptPubKey, int &nStartingIndex);

bool IsNewOwnerTxValid(const CTransaction& tx, const std::string& assetName, const std::string& address, std::string& errorMsg);

void GetAllAdministrativeAssets(CWallet *pwallet, std::vector<std::string> &names, int nMinConf = 1);
void GetAllMyAssets(CWallet* pwallet, std::vector<std::string>& names, int nMinConf = 1, bool fIncludeAdministrator = false, bool fOnlyAdministrator = false);

bool GetAssetInfoFromCoin(const Coin& coin, std::string& strName, CAmount& nAmount);
bool GetAssetInfoFromScript(const CScript& scriptPubKey, std::string& strName, CAmount& nAmount);

bool GetAssetData(const CScript& script, CAssetOutputEntry& data);

bool GetBestAssetAddressAmount(CAssetsCache& cache, const std::string& assetName, const std::string& address);
bool AddressHasAssetToken(CAssetsCache& cache, const std::string& assetName, const std::string& address);
bool AddressHasDEPINOwnerToken(CAssetsCache& cache, const std::string& assetName, const std::string& address);
bool TxContainsAssetTransfer(const CTransaction& tx, const std::string& assetName);
bool TxContainsAssetTransferToAddress(const CTransaction& tx, const std::string& assetName, const std::string& address);
bool TxContainsDEPINOwnerTokenTransfer(const CTransaction& tx, const std::string& assetName);

/**
 * Did `address` hold the owner token of `assetName` before this transaction?
 *
 * Answered structurally, from the inputs, rather than by asking an address ->
 * asset index. That matters because `fAssetIndex` is a local option that
 * defaults to off: a consensus rule that consults it gives different verdicts on
 * different nodes.
 *
 * The answer is exact, not an approximation, and it rests on three facts:
 *   1. This is only asked when the transaction transfers the owner token
 *      (the dispatch in ContextualCheckNullAssetTxOut).
 *   2. Transferring an asset requires spending it, for the same total
 *      (consensus/tx_verify.cpp, the inputs/outputs balance check).
 *   3. An owner token is indivisible (OWNER_UNITS = 0) and issued once, so
 *      exactly one UTXO of it exists at any time.
 * Therefore the transaction must be spending that one UTXO, and looking at
 * whose it was answers the question completely.
 *
 * Takes the coins view by reference on purpose: an optional pointer would let a
 * caller omit it and accept a transaction without having checked anything.
 */
bool TxSpendsDEPINOwnerTokenFromAddress(const CTransaction& tx, const CCoinsViewCache& inputs,
                                        const std::string& assetName, const std::string& address);

/**
 * Is this transaction a valid DEPIN self-revocation of `assetName`?
 *
 * The pattern -- the only exception to the soulbound rule -- is a
 * self-relocation: every input of the asset comes from one address A, every
 * output of the asset pays that same A, and the transaction carries exactly one
 * self-revocation null data (flag 1) for (assetName, A). Spending the asset's
 * own UTXOs is the authorisation: it proves key control of A and tenure of the
 * token in a single act, with no address->asset index involved.
 *
 * Aggregated over the WHOLE transaction, never per output: judging a single
 * output "looks fine" is exactly the slip that would let a second output smuggle
 * the token elsewhere, and evaluating inside the caller's vout loop would make
 * the verdict depend on output ordering. Amount conservation is NOT re-checked
 * here -- the existing inputs/outputs balance rule already enforces it for every
 * asset, and duplicating a consensus rule is how two copies drift apart.
 *
 * Fails closed: any asset input or output that cannot be parsed denies the
 * exception, because "all at one address" cannot be claimed over a set that was
 * not read in full. Owner-token involvement (either direction) also denies it:
 * that form is the owner's, not the holder's.
 */
bool IsDepinSelfRevocationTransaction(const CTransaction& tx, const CCoinsViewCache& inputs,
                                      const std::string& assetName, std::string& strError);


//! Decode and Encode IPFS hashes, or OIP hashes
std::string DecodeAssetData(std::string encoded);
std::string EncodeAssetData(std::string decoded);
std::string DecodeIPFS(std::string encoded);
std::string EncodeIPFS(std::string decoded);

#ifdef ENABLE_WALLET

bool GetAllMyAssetBalances(std::map<std::string, std::vector<COutput> >& outputs, std::map<std::string, CAmount>& amounts, const int confirmations = 0, const std::string& prefix = "");
bool GetMyAssetBalance(const std::string& name, CAmount& balance, const int& confirmations);

/**
 * Wallet-only answers to "who holds what", built on AvailableAssets so they do
 * not need -assetindex. They see only what this wallet controls, so they are
 * good for an early warning or for picking one of your own addresses, and are
 * not a substitute for a consensus rule.
 *
 * Locking: AvailableCoinsAll takes LOCK2(cs_main, cs_wallet) internally and
 * both are recursive, so holding them beforehand is harmless and omitting them
 * is not a crash. A caller that ACTS on the answer should still hold cs_wallet
 * across the call and the decision, or the wallet may change in between -- the
 * RPC callers do (LOCK2(cs_main, pwallet->cs_wallet) at the top). The GUI
 * validation slot does not, and does not need to: its answer is only a warning.
 */
bool GetWalletOwnerTokenAddress(CWallet* pwallet, const std::string& ownerTokenName, std::string& ownerAddress);

//! First wallet address holding a positive balance of `assetName`, skipping any
//! address that also holds its owner token (those cannot self-revoke).
bool GetWalletAssetHolderAddress(CWallet* pwallet, const std::string& assetName,
                                 std::string& holderAddress, bool& fFoundOwnerControlledHolding);

//! One concrete UTXO of `assetName` at such an address, with its exact amount.
//! The self-revocation self-transfer must spend a specific outpoint and return
//! exactly its amount; the aggregate balance would let coin selection recruit
//! inputs from other addresses and break the consensus pattern intermittently.
bool GetWalletAssetHolderOutpoint(CWallet* pwallet, const std::string& assetName,
                                  std::string& holderAddress, COutPoint& outpointRet,
                                  CAmount& amountRet, bool& fFoundOwnerControlledHolding);

//! Creates new asset issuance transaction
bool CreateAssetTransaction(CWallet* pwallet, CCoinControl& coinControl, const CNewAsset& asset, const std::string& address, std::pair<int, std::string>& error, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRequired, std::string* verifier_string = nullptr);
bool CreateAssetTransaction(CWallet* pwallet, CCoinControl& coinControl, const std::vector<CNewAsset> assets, const std::string& address, std::pair<int, std::string>& error, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRequired, std::string* verifier_string = nullptr);

//! Create a reissue asset transaction
bool CreateReissueAssetTransaction(CWallet* pwallet, CCoinControl& coinControl, const CReissueAsset& asset, const std::string& address, std::pair<int, std::string>& error, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRequired, std::string* verifier_string = nullptr);


//! Create a transfer asset transaction
bool CreateTransferAssetTransaction(CWallet* pwallet, const CCoinControl& coinControl, const std::vector< std::pair<CAssetTransfer, std::string> >vTransfers, const std::string& changeAddress, std::pair<int, std::string>& error, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRequired, std::vector<std::pair<CNullAssetTxData, std::string> >* nullAssetTxData = nullptr, std::vector<CNullAssetTxData>* nullGlobalRestrictionData = nullptr);

//! Send any type of asset transaction to the network
bool SendAssetTransaction(CWallet* pwallet, CWalletTx& transaction, CReserveKey& reserveKey, std::pair<int, std::string>& error, std::string& txid);

/** Verifies that this wallet owns the give asset */
bool VerifyWalletHasAsset(const std::string& asset_name, std::pair<int, std::string>& pairError);
#endif

/** Helper method for extracting address bytes, asset name and amount from an asset script */
bool ParseAssetScript(CScript scriptPubKey, uint160 &hashBytes, std::string &assetName, CAmount &assetAmount);

/** Helper method for extracting #TAGS from a verifier string */
void ExtractVerifierStringQualifiers(const std::string& verifier, std::set<std::string>& qualifiers);
bool CheckVerifierString(const std::string& verifier, std::set<std::string>& setFoundQualifiers, std::string& strError, ErrorReport* errorReport = nullptr);
std::string GetStrippedVerifierString(const std::string& verifier);

/** Helper methods that validate changes to null asset data transaction databases */
bool VerifyNullAssetDataFlag(const int& flag, std::string& strError);
bool VerifyQualifierChange(CAssetsCache& cache, const CNullAssetTxData& data, const std::string& address, std::string& strError);
bool VerifyRestrictedAddressChange(CAssetsCache& cache, const CNullAssetTxData& data, const std::string& address, std::string& strError);
bool VerifyDEPINOwnerChange(CAssetsCache& cache, const CNullAssetTxData& data, const std::string& address, std::string& strError);
bool VerifySelfRestrictionChange(CAssetsCache& cache, const CNullAssetTxData& data, const std::string& address, std::string& strError);
bool VerifyGlobalRestrictedChange(CAssetsCache& cache, const CNullAssetTxData& data, std::string& strError);

//// Non Contextual Check functions
bool CheckVerifierAssetTxOut(const CTxOut& txout, std::string& strError);
bool CheckNewAsset(const CNewAsset& asset, std::string& strError);
bool CheckReissueAsset(const CReissueAsset& asset, std::string& strError);

//// Contextual Check functions
/**
 * `inputs` is a mandatory reference, not an optional pointer: the DEPIN owner
 * branch decides authorisation from the transaction's inputs, and a caller that
 * could omit them would accept the transaction without having checked.
 */
bool ContextualCheckNullAssetTxOut(const CTxOut& txout, const CTransaction* tx, const CCoinsViewCache& inputs, CAssetsCache* assetCache, std::string& strError, std::vector<std::pair<std::string, CNullAssetTxData>>* myNullAssetData = nullptr);
bool ContextualCheckGlobalAssetTxOut(const CTxOut& txout, CAssetsCache* assetCache, std::string& strError);
bool ContextualCheckVerifierAssetTxOut(const CTxOut& txout, CAssetsCache* assetCache, std::string& strError);
bool ContextualCheckVerifierString(CAssetsCache* cache, const std::string& verifier, const std::string& check_address, std::string& strError, ErrorReport* errorReport = nullptr);
bool ContextualCheckNewAsset(CAssetsCache* assetCache, const CNewAsset& asset, std::string& strError, bool fCheckMempool = false);
bool ContextualCheckTransferAsset(CAssetsCache* assetCache, const CAssetTransfer& transfer, const std::string& address, std::string& strError);
bool ContextualCheckReissueAsset(CAssetsCache* assetCache, const CReissueAsset& reissue_asset, std::string& strError, const CTransaction& tx);
bool ContextualCheckReissueAsset(CAssetsCache* assetCache, const CReissueAsset& reissue_asset, std::string& strError);
bool ContextualCheckUniqueAssetTx(CAssetsCache* assetCache, std::string& strError, const CTransaction& tx);
bool ContextualCheckUniqueAsset(CAssetsCache* assetCache, const CNewAsset& unique_asset, std::string& strError);

#endif //NEURAICOIN_ASSET_PROTOCOL_H
