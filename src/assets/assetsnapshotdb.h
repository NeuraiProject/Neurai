// Copyright (c) 2019 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ASSETSNAPSHOTDB_H
#define ASSETSNAPSHOTDB_H

#include <set>

#include <dbwrapper.h>
#include "amount.h"
#include "assets/rewards.h"
#include "uint256.h"

#include <map>

class CAssetSnapshotDBEntry
{
public:
    int height;
    std::string assetName;
    std::set<std::pair<std::string, CAmount>> ownersAndAmounts;

    //  Used as the DB key for the snapshot
    std::string heightAndName;

    // NIP-048 B1: the block the snapshot was captured on and a hash of its
    // content. Not part of the legacy serialization; null for a snapshot
    // captured before B1.
    uint256 blockHash;
    uint256 snapshotHash;

    // NIP-048 D3: restriction and tag state at the snapshot height. Holders
    // without any state are absent from `states`.
    bool fHasState;
    bool fGlobalFrozen;
    std::map<std::string, SnapshotHolderState> states;

    CAssetSnapshotDBEntry();
    CAssetSnapshotDBEntry(
        const std::string & p_assetName, const int p_snapshotHeight,
        const std::set<std::pair<std::string, CAmount>> & p_ownersAndAmounts
    );

    void SetNull()
    {
        height = 0;
        assetName = "";
        ownersAndAmounts.clear();

        heightAndName = "";
        blockHash.SetNull();
        snapshotHash.SetNull();
        fHasState = false;
        fGlobalFrozen = false;
        states.clear();
    }

    bool IsLegacy() const { return blockHash.IsNull(); }

    bool operator<(const CAssetSnapshotDBEntry &rhs) const
    {
        return heightAndName < rhs.heightAndName;
    }

    // Serialization methods
    ADD_SERIALIZE_METHODS;

    template<typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(height);
        READWRITE(assetName);
        READWRITE(ownersAndAmounts);
        READWRITE(heightAndName);
    }
};

class CAssetSnapshotDB  : public CDBWrapper {
public:
    explicit CAssetSnapshotDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    CAssetSnapshotDB(const CAssetSnapshotDB&) = delete;
    CAssetSnapshotDB& operator=(const CAssetSnapshotDB&) = delete;

    //  Capture the owners of an asset at the block just connected
    bool AddAssetOwnershipSnapshot(
        const std::string & p_assetName, int p_height, const uint256 & p_blockHash);

    //  Read the snapshot of an asset at a height, block-bound or legacy
    bool RetrieveOwnershipSnapshot(
        const std::string & p_assetName, int p_height,
        CAssetSnapshotDBEntry & p_snapshotEntry);

    //  Remove the asset snapshot at the specified height, both formats
    bool RemoveOwnershipSnapshot(
        const std::string & p_assetName, int p_height);
};


#endif //ASSETSNAPSHOTDB_H
