// Copyright (c) 2019 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assetsnapshotdb.h"
#include "assets/rewards.h"
#include "validation.h"
#include "base58.h"

#include <boost/algorithm/string.hpp>
#include <boost/thread.hpp>

static const char SNAPSHOTCHECK_FLAG = 'C'; // Snapshot Check (legacy, before NIP-048 B1)
static const char SNAPSHOTBLOCK_FLAG = 'B'; // Snapshot bound to its block (NIP-048 B1)

// 1: B1 (block hash); 2: D3 (holder state)
static const uint8_t SNAPSHOT_RECORD_VERSION = 2;

namespace {

/** NIP-048 B1: a snapshot plus the block it was captured on and its content
 *  hash, keyed by (asset, height) so that no two keys can collide. */
class CAssetSnapshotRecord
{
public:
    uint8_t nVersion = SNAPSHOT_RECORD_VERSION;
    CAssetSnapshotDBEntry entry;
    uint256 blockHash;
    uint256 snapshotHash;
    bool fGlobalFrozen = false;
    std::map<std::string, SnapshotHolderState> states;

    ADD_SERIALIZE_METHODS;

    template<typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(nVersion);
        READWRITE(entry);
        READWRITE(blockHash);
        READWRITE(snapshotHash);
        if (nVersion >= 2) {
            READWRITE(fGlobalFrozen);
            READWRITE(states);
        }
    }
};

std::pair<char, std::pair<std::string, int>> RecordKey(const std::string& assetName, int height)
{
    return std::make_pair(SNAPSHOTBLOCK_FLAG, std::make_pair(assetName, height));
}

} // namespace

CAssetSnapshotDBEntry::CAssetSnapshotDBEntry()
{
    SetNull();
}

CAssetSnapshotDBEntry::CAssetSnapshotDBEntry(
    const std::string & p_assetName, int p_snapshotHeight,
    const std::set<std::pair<std::string, CAmount>> & p_ownersAndAmounts
)
{
    SetNull();

    height = p_snapshotHeight;
    assetName = p_assetName;
    for (auto const & currPair : p_ownersAndAmounts) {
        ownersAndAmounts.insert(currPair);
    }

    heightAndName = std::to_string(height) + assetName;
}

CAssetSnapshotDB::CAssetSnapshotDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "rewards" / "assetsnapshot", nCacheSize, fMemory, fWipe) {
}

bool CAssetSnapshotDB::AddAssetOwnershipSnapshot(
    const std::string & p_assetName, int p_height, const uint256 & p_blockHash)
{
    LogPrint(BCLog::REWARDS, "AddAssetOwnershipSnapshot: Adding snapshot for '%s' at height %d\n",
        p_assetName.c_str(), p_height);

    //  Retrieve ownership interest for the asset at this height
    if (passetsdb == nullptr) {
        LogPrint(BCLog::REWARDS, "AddAssetOwnershipSnapshot: Invalid assets DB!\n");
        return false;
    }

    std::set<std::pair<std::string, CAmount>> ownersAndAmounts;
    std::vector<std::pair<std::string, CAmount>> tempOwnersAndAmounts;
    int totalEntryCount;

    if (!passetsdb->AssetAddressDir(tempOwnersAndAmounts, totalEntryCount, true, p_assetName, INT_MAX, 0)) {
        LogPrint(BCLog::REWARDS, "AddAssetOwnershipSnapshot: Failed to retrieve assets directory for '%s'\n", p_assetName.c_str());
        return false;
    }

    //  Retrieve all of the addresses/amounts in batches
    const int MAX_RETRIEVAL_COUNT = 100;
    bool errorsOccurred = false;

    for (int retrievalOffset = 0; retrievalOffset < totalEntryCount; retrievalOffset += MAX_RETRIEVAL_COUNT) {
        //  Retrieve the specified segment of addresses
        if (!passetsdb->AssetAddressDir(tempOwnersAndAmounts, totalEntryCount, false, p_assetName, MAX_RETRIEVAL_COUNT, retrievalOffset)) {
            LogPrint(BCLog::REWARDS, "AddAssetOwnershipSnapshot: Failed to retrieve assets directory for '%s'\n", p_assetName.c_str());
            errorsOccurred = true;
            break;
        }

        //  Verify that some addresses were returned
        if (tempOwnersAndAmounts.size() == 0) {
            LogPrint(BCLog::REWARDS, "AddAssetOwnershipSnapshot: No addresses were retrieved.\n");
            continue;
        }

        //  Move these into the main set
        for (auto const & currPair : tempOwnersAndAmounts) {
            //  Verify that the address is valid
            CTxDestination dest = DecodeDestination(currPair.first);
            if (IsValidDestination(dest)) {
                ownersAndAmounts.insert(currPair);
            }
            else {
                LogPrint(BCLog::REWARDS, "AddAssetOwnershipSnapshot: Address '%s' is invalid.\n", currPair.first.c_str());
            }
        }

        tempOwnersAndAmounts.clear();
    }

    if (errorsOccurred) {
        LogPrint(BCLog::REWARDS, "AddAssetOwnershipSnapshot: Errors occurred while acquiring ownership info for asset '%s'.\n", p_assetName.c_str());
        return false;
    }
    if (ownersAndAmounts.size() == 0) {
        LogPrint(BCLog::REWARDS, "AddAssetOwnershipSnapshot: No owners exist for asset '%s'.\n", p_assetName.c_str());
        return false;
    }

    //  Write the snapshot to the database. A reconnected height overwrites the
    //  record with the snapshot of the new block.
    CAssetSnapshotRecord record;
    record.entry = CAssetSnapshotDBEntry(p_assetName, p_height, ownersAndAmounts);
    record.blockHash = p_blockHash;

    // NIP-048 D3: restriction and tag state of every holder at this block. The
    // address directory read above flushed the state, so the restricted
    // database is current.
    if (passets) {
        record.fGlobalFrozen = passets->CheckForGlobalRestriction(p_assetName, true);
        for (const auto& owner : ownersAndAmounts) {
            SnapshotHolderState state;
            state.fFrozen = passets->CheckForAddressRestriction(p_assetName, owner.first, true);
            state.fSelfRevoked = passets->CheckForDEPINSelfRestriction(p_assetName, owner.first, true);
            if (prestricteddb) {
                std::string address = owner.first;
                prestricteddb->GetAddressQualifiers(address, state.tags);
                std::sort(state.tags.begin(), state.tags.end());
            }
            if (state.fFrozen || state.fSelfRevoked || !state.tags.empty())
                record.states[owner.first] = state;
        }
    }
    record.snapshotHash = ComputeSnapshotHashV2(p_assetName, p_height, p_blockHash, record.fGlobalFrozen,
                                                CanonicalHoldings(ownersAndAmounts, record.states));

    if (Write(RecordKey(p_assetName, p_height), record)) {
        LogPrint(BCLog::REWARDS, "AddAssetOwnershipSnapshot: Successfully added snapshot for '%s' at height %d (ownerCount = %d, block %s).\n",
            p_assetName.c_str(), p_height, ownersAndAmounts.size(), p_blockHash.GetHex());
        return true;
    }
    return false;
}

bool CAssetSnapshotDB::RetrieveOwnershipSnapshot(
    const std::string & p_assetName, int p_height,
    CAssetSnapshotDBEntry & p_snapshotEntry)
{
    CAssetSnapshotRecord record;
    if (Read(RecordKey(p_assetName, p_height), record)) {
        p_snapshotEntry = record.entry;
        p_snapshotEntry.blockHash = record.blockHash;
        p_snapshotEntry.snapshotHash = record.snapshotHash;
        p_snapshotEntry.fHasState = record.nVersion >= 2;
        p_snapshotEntry.fGlobalFrozen = record.fGlobalFrozen;
        p_snapshotEntry.states = record.states;
        return true;
    }

    //  Fall back to a snapshot captured before NIP-048 B1
    std::string heightAndName = std::to_string(p_height) + p_assetName;

    LogPrint(BCLog::REWARDS, "%s : Attempting to retrieve snapshot: heightAndName='%s'\n",
        __func__,
        heightAndName.c_str());

    bool succeeded = Read(std::make_pair(SNAPSHOTCHECK_FLAG, heightAndName), p_snapshotEntry);

    LogPrint(BCLog::REWARDS, "%s : Retrieval of snapshot for '%s' %s!\n",
        __func__,
        heightAndName.c_str(),
        succeeded ? "succeeded" : "failed");

    return succeeded;
}

bool CAssetSnapshotDB::RemoveOwnershipSnapshot(
    const std::string & p_assetName, int p_height)
{
    //  Load up the snapshot entries at this height
    std::string heightAndName = std::to_string(p_height) + p_assetName;

    LogPrint(BCLog::REWARDS, "%s : Attempting to remove snapshot: heightAndName='%s'\n",
        __func__,
        heightAndName.c_str());

    bool succeeded = Erase(RecordKey(p_assetName, p_height), true) &&
                     Erase(std::make_pair(SNAPSHOTCHECK_FLAG, heightAndName), true);

    LogPrint(BCLog::REWARDS, "%s : Removal of snapshot for '%s' %s!\n",
        __func__,
        heightAndName.c_str(),
        succeeded ? "succeeded" : "failed");

    return succeeded;
}
