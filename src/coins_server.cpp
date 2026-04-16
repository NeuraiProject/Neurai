// Copyright (c) 2012-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// AddCoins — split from coins.cpp into LIBNEURAI_SERVER because it depends on
// the asset cache, wallet, and messaging subsystems unavailable in LIBNEURAI_COMMON.

#include "coins.h"
#include "consensus/consensus.h"
#include "memusage.h"
#include "random.h"
#include "util.h"
#include "validation.h"
#include "tinyformat.h"
#include "base58.h"

#include <assert.h>
#include <tuple>
#include <assets/assets.h>
#include <wallet/wallet.h>

void AddCoins(CCoinsViewCache& cache, const CTransaction &tx, int nHeight, uint256 blockHash, bool check, CAssetsCache* assetsCache, std::pair<std::string, CBlockAssetUndo>* undoAssetData) {
    bool fCoinbase = tx.IsCoinBase();
    const uint256& txid = tx.GetHash();

    /** XNA START */
        if (AreAssetsDeployed()) {
            if (assetsCache) {
                if (tx.IsNewAsset()) { // This works are all new root assets, sub asset, and restricted assets
                    CNewAsset asset;
                    std::string strAddress;
                    if (!AssetFromTransaction(tx, asset, strAddress)) {
                        error("%s : Failed to get new asset from transaction while connecting block. TXID : %s",
                              __func__, tx.GetHash().GetHex());
                    }

                    std::string ownerName;
                    std::string ownerAddress;
                    if (!OwnerFromTransaction(tx, ownerName, ownerAddress)) {
                        error("%s : Failed to get owner asset from transaction while connecting block. TXID : %s",
                              __func__, tx.GetHash().GetHex());
                    }

                    // Add the new asset to cache
                    if (!assetsCache->AddNewAsset(asset, strAddress, nHeight, blockHash))
                        error("%s : Failed at adding a new asset to our cache. asset: %s", __func__,
                              asset.strName);

                // Add the owner asset to cache
                if (!assetsCache->AddOwnerAsset(ownerName, ownerAddress))
                    error("%s : Failed at adding a new asset to our cache. asset: %s", __func__,
                          asset.strName);

            } else if (tx.IsReissueAsset()) {
                CReissueAsset reissue;
                std::string strAddress;
                if (!ReissueAssetFromTransaction(tx, reissue, strAddress)) {
                    error("%s : Failed to get reissue asset from transaction while connecting block. TXID : %s",
                          __func__, tx.GetHash().GetHex());
                }

                int reissueIndex = tx.vout.size() - 1;

                // Get the asset before we change it
                CNewAsset asset;
                if (!assetsCache->GetAssetMetaDataIfExists(reissue.strName, asset))
                    error("%s: Failed to get the original asset that is getting reissued. Asset Name : %s",
                          __func__, reissue.strName);

                if (!assetsCache->AddReissueAsset(reissue, strAddress, COutPoint(txid, reissueIndex)))
                    error("%s: Failed to reissue an asset. Asset Name : %s", __func__, reissue.strName);

                // Check to see if we are reissuing a restricted asset
                bool fFoundRestrictedAsset = false;
                AssetType type;
                IsAssetNameValid(asset.strName, type);
                if (type == AssetType::RESTRICTED) {
                    fFoundRestrictedAsset = true;
                }

                // Set the old IPFSHash for the blockundo
                bool fIPFSChanged = !reissue.strIPFSHash.empty();
                bool fUnitsChanged = reissue.nUnits != -1;
                bool fVerifierChanged = false;
                std::string strOldVerifier = "";

                // If we are reissuing a restricted asset, we need to check to see if the verifier string is being reissued
                if (fFoundRestrictedAsset) {
                    CNullAssetTxVerifierString verifier;
                    // Search through all outputs until you find a restricted verifier change.
                    for (auto index: tx.vout) {
                        if (index.scriptPubKey.IsNullAssetVerifierTxDataScript()) {
                            if (!AssetNullVerifierDataFromScript(index.scriptPubKey, verifier)) {
                                error("%s: Failed to get asset null verifier data and add it to the coins CTxOut: %s", __func__,
                                      index.ToString());
                                break;
                            }

                            fVerifierChanged = true;
                            break;
                        }
                    }

                    CNullAssetTxVerifierString oldVerifer{strOldVerifier};
                    if (fVerifierChanged && !assetsCache->GetAssetVerifierStringIfExists(asset.strName, oldVerifer))
                        error("%s : Failed to get asset original verifier string that is getting reissued, Asset Name: %s", __func__, asset.strName);

                    if (fVerifierChanged) {
                        strOldVerifier = oldVerifer.verifier_string;
                    }

                    // Add the verifier to the cache if there was one found
                    if (fVerifierChanged && !assetsCache->AddRestrictedVerifier(asset.strName, verifier.verifier_string))
                        error("%s : Failed at adding a restricted verifier to our cache: asset: %s, verifier : %s",
                              asset.strName, verifier.verifier_string);
                }

                // If any of the following items were changed by reissuing, we need to database the old values so it can be undone correctly
                if (fIPFSChanged || fUnitsChanged || fVerifierChanged) {
                    undoAssetData->first = reissue.strName; // Asset Name
                    undoAssetData->second = CBlockAssetUndo {fIPFSChanged, fUnitsChanged, asset.strIPFSHash, asset.units, ASSET_UNDO_INCLUDES_VERIFIER_STRING, fVerifierChanged, strOldVerifier}; // ipfschanged, unitchanged, Old Assets IPFSHash, old units
                }
            } else if (tx.IsNewUniqueAsset()) {
                for (int n = 0; n < (int)tx.vout.size(); n++) {
                    auto out = tx.vout[n];

                    CNewAsset asset;
                    std::string strAddress;

                    if (IsScriptNewUniqueAsset(out.scriptPubKey)) {
                        AssetFromScript(out.scriptPubKey, asset, strAddress);

                        // Add the new asset to cache
                        if (!assetsCache->AddNewAsset(asset, strAddress, nHeight, blockHash))
                            error("%s : Failed at adding a new asset to our cache. asset: %s", __func__,
                                  asset.strName);
                    }
                }
            } else if (tx.IsNewMsgChannelAsset()) {
                CNewAsset asset;
                std::string strAddress;
                MsgChannelAssetFromTransaction(tx, asset, strAddress);

                // Add the new asset to cache
                if (!assetsCache->AddNewAsset(asset, strAddress, nHeight, blockHash))
                    error("%s : Failed at adding a new asset to our cache. asset: %s", __func__,
                          asset.strName);
            } else if (tx.IsNewQualifierAsset()) {
                CNewAsset asset;
                std::string strAddress;
                QualifierAssetFromTransaction(tx, asset, strAddress);

                // Add the new asset to cache
                if (!assetsCache->AddNewAsset(asset, strAddress, nHeight, blockHash))
                    error("%s : Failed at adding a new qualifier asset to our cache. asset: %s", __func__,
                          asset.strName);
            }  else if (tx.IsNewRestrictedAsset()) {
                CNewAsset asset;
                std::string strAddress;
                RestrictedAssetFromTransaction(tx, asset, strAddress);

                // Add the new asset to cache
                if (!assetsCache->AddNewAsset(asset, strAddress, nHeight, blockHash))
                    error("%s : Failed at adding a new restricted asset to our cache. asset: %s", __func__,
                          asset.strName);

                // Find the restricted verifier string and cache it
                CNullAssetTxVerifierString verifier;
                // Search through all outputs until you find a restricted verifier change.
                for (auto index: tx.vout) {
                    if (index.scriptPubKey.IsNullAssetVerifierTxDataScript()) {
                        CNullAssetTxVerifierString verifier;
                        if (!AssetNullVerifierDataFromScript(index.scriptPubKey, verifier))
                            error("%s: Failed to get asset null data and add it to the coins CTxOut: %s", __func__,
                                  index.ToString());

                        // Add the verifier to the cache
                        if (!assetsCache->AddRestrictedVerifier(asset.strName, verifier.verifier_string))
                            error("%s : Failed at adding a restricted verifier to our cache: asset: %s, verifier : %s",
                                  asset.strName, verifier.verifier_string);

                        break;
                    }
                }
            }
        }
    }
    /** XNA END */

    for (size_t i = 0; i < tx.vout.size(); ++i) {
        bool overwrite = check ? cache.HaveCoin(COutPoint(txid, i)) : fCoinbase;
        // Always set the possible_overwrite flag to AddCoin for coinbase txn, in order to correctly
        // deal with the pre-BIP30 occurrences of duplicate coinbase transactions.
        cache.AddCoin(COutPoint(txid, i), Coin(tx.vout[i], nHeight, fCoinbase), overwrite);

        /** XNA START */
        if (AreAssetsDeployed()) {
            if (assetsCache) {
                CAssetOutputEntry assetData;
                if (GetAssetData(tx.vout[i].scriptPubKey, assetData)) {

                    // If this is a transfer asset, and the amount is greater than zero
                    // We want to make sure it is added to the asset addresses database if (fAssetIndex == true)
                    if (assetData.type == TX_TRANSFER_ASSET && assetData.nAmount > 0) {
                        // Create the objects needed from the assetData
                        CAssetTransfer assetTransfer(assetData.assetName, assetData.nAmount, assetData.message, assetData.expireTime);
                        std::string address = EncodeDestination(assetData.destination);

                        // Add the transfer asset data to the asset cache
                        if (!assetsCache->AddTransferAsset(assetTransfer, address, COutPoint(txid, i), tx.vout[i]))
                            LogPrintf("%s : ERROR - Failed to add transfer asset CTxOut: %s\n", __func__,
                                      tx.vout[i].ToString());

                        /** Subscribe to new message channels if they are sent to a new address, or they are the owner token or message channel */
#ifdef ENABLE_WALLET
                        if (fMessaging && pMessageSubscribedChannelsCache) {
                            LOCK(cs_messaging);
                            if (vpwallets.size() && vpwallets[0]->IsMine(tx.vout[i]) == ISMINE_SPENDABLE) {
                                AssetType aType;
                                IsAssetNameValid(assetTransfer.strName, aType);

                                if (aType == AssetType::ROOT || aType == AssetType::SUB) {
                                    if (!IsChannelSubscribed(GetParentName(assetTransfer.strName) + OWNER_TAG)) {
                                        if (!IsAddressSeen(address)) {
                                            AddChannel(GetParentName(assetTransfer.strName) + OWNER_TAG);
                                            AddAddressSeen(address);
                                        }
                                    }
                                } else if (aType == AssetType::OWNER || aType == AssetType::MSGCHANNEL) {
                                    AddChannel(assetTransfer.strName);
                                    AddAddressSeen(address);
                                }
                            }
                        }
#endif
                    } else if (assetData.type == TX_NEW_ASSET) {
                        /** Subscribe to new message channels if they are assets you created, or are new msgchannels of channels already being watched */
#ifdef ENABLE_WALLET
                        if (fMessaging && pMessageSubscribedChannelsCache) {
                            LOCK(cs_messaging);
                            if (vpwallets.size()) {
                                AssetType aType;
                                IsAssetNameValid(assetData.assetName, aType);
                                if (vpwallets[0]->IsMine(tx.vout[i]) == ISMINE_SPENDABLE) {
                                    if (aType == AssetType::ROOT || aType == AssetType::SUB) {
                                        AddChannel(assetData.assetName + OWNER_TAG);
                                        AddAddressSeen(EncodeDestination(assetData.destination));
                                    } else if (aType == AssetType::OWNER || aType == AssetType::MSGCHANNEL) {
                                        AddChannel(assetData.assetName);
                                        AddAddressSeen(EncodeDestination(assetData.destination));
                                    }
                                } else {
                                    if (aType == AssetType::MSGCHANNEL) {
                                        if (IsChannelSubscribed(GetParentName(assetData.assetName) + OWNER_TAG)) {
                                            AddChannel(assetData.assetName);
                                        }
                                    }
                                }
                            }
                        }
#endif
                    }
                }

                CScript script = tx.vout[i].scriptPubKey;
                if (script.IsNullAsset()) {
                    if (script.IsNullAssetTxDataScript()) {
                        CNullAssetTxData data;
                        std::string address;
                        AssetNullDataFromScript(script, data, address);

                        AssetType type;
                        IsAssetNameValid(data.asset_name, type);

                        if (type == AssetType::RESTRICTED) {
                            assetsCache->AddRestrictedAddress(data.asset_name, address, data.flag ? RestrictedType::FREEZE_ADDRESS : RestrictedType::UNFREEZE_ADDRESS);
                        } else if (type == AssetType::QUALIFIER || type == AssetType::SUB_QUALIFIER) {
                            assetsCache->AddQualifierAddress(data.asset_name, address, data.flag ? QualifierType::ADD_QUALIFIER : QualifierType::REMOVE_QUALIFIER);
                        } else if (type == AssetType::DEPIN) {
                            if (TxContainsDEPINOwnerTokenTransfer(tx, data.asset_name)) {
                                assetsCache->AddRestrictedAddress(data.asset_name, address, data.flag ? RestrictedType::FREEZE_ADDRESS : RestrictedType::UNFREEZE_ADDRESS);
                                if (!data.flag) {
                                    assetsCache->AddSelfRestriction(data.asset_name, address, false);
                                }
                            } else {
                                assetsCache->AddSelfRestriction(data.asset_name, address, true);
                            }
                        }
                    } else if (script.IsNullGlobalRestrictionAssetTxDataScript()) {
                        CNullAssetTxData data;
                        GlobalAssetNullDataFromScript(script, data);

                        assetsCache->AddGlobalRestricted(data.asset_name, data.flag ? RestrictedType::GLOBAL_FREEZE : RestrictedType::GLOBAL_UNFREEZE);
                    }
                }
            }
        }
        /** XNA END */
    }
}

