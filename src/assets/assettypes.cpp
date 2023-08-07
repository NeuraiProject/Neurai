// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assettypes.h"
#include "hash.h"

int IntFromAssetType(AssetType type) {
    return (int)type;
}

AssetType AssetTypeFromInt(int nType) {
    return (AssetType)nType;
}

uint256 CAssetCacheQualifierAddress::GetHash() {
    return Hash(assetName.begin(), assetName.end(), address.begin(), address.end());
}

uint256 CAssetCacheRestrictedAddress::GetHash() {
    return Hash(assetName.begin(), assetName.end(), address.begin(), address.end());
}

uint256 CAssetCacheRootQualifierChecker::GetHash() {
    return Hash(rootAssetName.begin(), rootAssetName.end(), address.begin(), address.end());
}
