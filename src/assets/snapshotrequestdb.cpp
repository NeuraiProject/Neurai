// Copyright (c) 2019 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <set>
#include <boost/thread.hpp>

#include "snapshotrequestdb.h"

// Before NIP-048 requests were keyed by the string height + name, which made
// two requests collide (height 12 of "3ABC" and height 123 of "ABC") and could
// only be found by walking every request ever made. They are moved to the
// height-keyed records when the database is opened.
static const char SNAPSHOTREQUEST_FLAG = 'S';
// (height, asset name) -> request: the requests of one height are contiguous
static const char SNAPSHOTREQUEST_HEIGHT_FLAG = 'H';

static const char DISTRIBUTEREQUEST_FLAG = 'D';

static std::pair<char, std::pair<int, std::string>> RequestKey(const std::string& assetName, int height)
{
    return std::make_pair(SNAPSHOTREQUEST_HEIGHT_FLAG, std::make_pair(height, assetName));
}

CSnapshotRequestDBEntry::CSnapshotRequestDBEntry()
{
    SetNull();
}

CSnapshotRequestDBEntry::CSnapshotRequestDBEntry(
    const std::string & p_assetName, int p_heightForSnapshot
)
{
    SetNull();

    assetName = p_assetName;
    heightForSnapshot = p_heightForSnapshot;

    heightAndName = std::to_string(heightForSnapshot) + assetName;
}

CSnapshotRequestDB::CSnapshotRequestDB(
    size_t nCacheSize, bool fMemory, bool fWipe)
    : CDBWrapper(GetDataDir() / "rewards" / "snapshotrequest", nCacheSize, fMemory, fWipe) {
    MigrateLegacyRequests();
}

void CSnapshotRequestDB::MigrateLegacyRequests()
{
    std::unique_ptr<CDBIterator> pcursor(NewIterator());
    pcursor->Seek(std::make_pair(SNAPSHOTREQUEST_FLAG, std::string()));
    CDBBatch batch(*this);
    size_t nMoved = 0;
    for (; pcursor->Valid(); pcursor->Next()) {
        std::pair<char, std::string> key;
        if (!pcursor->GetKey(key) || key.first != SNAPSHOTREQUEST_FLAG)
            break;
        CSnapshotRequestDBEntry entry;
        if (pcursor->GetValue(entry))
            batch.Write(RequestKey(entry.assetName, entry.heightForSnapshot),
                        CSnapshotRequestDBEntry(entry.assetName, entry.heightForSnapshot));
        batch.Erase(key);
        ++nMoved;
    }
    if (nMoved > 0) {
        WriteBatch(batch, true);
        LogPrintf("Snapshot requests: %u moved to the height-keyed format\n", nMoved);
    }
}

bool CSnapshotRequestDB::ScheduleSnapshot(
    const std::string & p_assetName, int p_heightForSnapshot
)
{
    LogPrint(BCLog::REWARDS, "%s : Requesting snapshot: assetName='%s', height=%d\n",
        __func__,
        p_assetName.c_str(), p_heightForSnapshot);

    CSnapshotRequestDBEntry snapshotRequest(p_assetName, p_heightForSnapshot);

    //  Add the entry to the database
    bool succeeded = Write(RequestKey(p_assetName, p_heightForSnapshot), snapshotRequest);

    LogPrint(BCLog::REWARDS, "%s : Snapshot request for '%s' at height %d %s!\n",
        __func__,
        p_assetName.c_str(), p_heightForSnapshot,
        succeeded ? "succeeded" : "failed");

    return succeeded;
}

bool CSnapshotRequestDB::RetrieveSnapshotRequest(
    const std::string & p_assetName, int p_heightForSnapshot,
    CSnapshotRequestDBEntry & p_snapshotRequest
)
{
    LogPrint(BCLog::REWARDS, "%s : Looking for snapshot request '%s' at height %d\n",
        __func__, p_assetName.c_str(), p_heightForSnapshot);

    bool succeeded = Read(RequestKey(p_assetName, p_heightForSnapshot), p_snapshotRequest);

    LogPrint(BCLog::REWARDS, "%s : Retrieval of snapshot request for '%s' at height %d %s!\n",
        __func__,
        p_assetName.c_str(), p_heightForSnapshot,
        succeeded ? "succeeded" : "failed");

    return succeeded;
}

bool CSnapshotRequestDB::ContainsSnapshotRequest(const std::string & p_assetName, int p_heightForSnapshot)
{
    return Exists(RequestKey(p_assetName, p_heightForSnapshot));
}

bool CSnapshotRequestDB::RemoveSnapshotRequest(
    const std::string & p_assetName, int p_heightForSnapshot
)
{
    LogPrint(BCLog::REWARDS, "%s : Attempting to remove snapshot request '%s' at height %d\n",
        __func__,
        p_assetName.c_str(), p_heightForSnapshot);

    bool succeeded = Erase(RequestKey(p_assetName, p_heightForSnapshot), true);

    LogPrint(BCLog::REWARDS, "%s : Removal of snapshot request for '%s' at height %d %s!\n",
        __func__,
        p_assetName.c_str(), p_heightForSnapshot,
        succeeded ? "succeeded" : "failed");

    return succeeded;
}

bool CSnapshotRequestDB::RetrieveSnapshotRequestsForHeight(
    const std::string & p_assetName, int p_blockHeight,
    std::set<CSnapshotRequestDBEntry> & p_assetsToSnapshot)
{
    bool assetNameProvided = p_assetName.length() > 0;
    if (assetNameProvided) {
        LogPrint(BCLog::REWARDS, "%s : Looking for snapshot requests for asset '%s' at height %d!\n",
            __func__,
            p_assetName.c_str(), p_blockHeight);
    }
    else {
        LogPrint(BCLog::REWARDS, "%s : Looking for all snapshot requests at height %d!\n",
            __func__,
            p_blockHeight);
    }

    p_assetsToSnapshot.clear();

    std::unique_ptr<CDBIterator> pcursor(NewIterator());

    // A height is read from its first request on (a block connection only
    // reads its own height); height zero reads every request
    if (p_blockHeight != 0)
        pcursor->Seek(std::make_pair(SNAPSHOTREQUEST_HEIGHT_FLAG, p_blockHeight));
    else
        pcursor->Seek(SNAPSHOTREQUEST_HEIGHT_FLAG);

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char, std::pair<int, std::string>> key;
        if (!pcursor->GetKey(key) || key.first != SNAPSHOTREQUEST_HEIGHT_FLAG)
            break;
        if (p_blockHeight != 0 && key.second.first != p_blockHeight)
            break;

        CSnapshotRequestDBEntry reqDbEntry;
        if (pcursor->GetValue(reqDbEntry)) {
            //  If an asset was specified, only add entries for it.
            //  Otherwise, retrieve all entries.
            if (!assetNameProvided || p_assetName == reqDbEntry.assetName) {
                p_assetsToSnapshot.insert(reqDbEntry);
            }
        } else {
            LogPrint(BCLog::REWARDS, "%s: Failed to read snapshot request\n", __func__);
        }

        pcursor->Next();
    }

    return true;
}

CDistributeSnapshotRequestDB::CDistributeSnapshotRequestDB(
        size_t nCacheSize, bool fMemory, bool fWipe)
        : CDBWrapper(GetDataDir() / "rewards" / "distributerequests", nCacheSize, fMemory, fWipe) {
}

//  Find a distribute snapshot request
bool CDistributeSnapshotRequestDB::RetrieveDistributeSnapshotRequest(const uint256& hash, CRewardSnapshot& p_rewardSnapshot)
{
    return Read(std::make_pair(DISTRIBUTEREQUEST_FLAG, hash), p_rewardSnapshot);
}

// Remove a distribute snapshot request
bool CDistributeSnapshotRequestDB::RemoveDistributeSnapshotRequest(const uint256& hash)
{
    return Erase(std::make_pair(DISTRIBUTEREQUEST_FLAG, hash));
}
