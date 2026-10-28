// Copyright (c) 2019-2020 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assets/assets.h"
#include "assets/assetdb.h"
#include "assets/messages.h"
#include <map>
#include "tinyformat.h"

#include <boost/algorithm/string.hpp>

#include "amount.h"
#include "base58.h"
#include "chain.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "httpserver.h"
#include "validation.h"
#include "net.h"
#include "policy/feerate.h"
#include "policy/fees.h"
#include "policy/policy.h"
#include "txmempool.h"
#include "rpc/mining.h"
#include "rpc/safemode.h"
#include "rpc/server.h"
#include "script/sign.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "wallet/coincontrol.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "assets/snapshotrequestdb.h"
#include "assets/assetsnapshotdb.h"
#include "assets/rewards.h"
#include "undo.h"
#include "depinaddress.h"
#include "depinmsgpool.h"

#include <boost/thread.hpp>

#include <list>
#include <memory>

#ifdef ENABLE_WALLET

////  Collect information about transactions that are pending commit
//struct PendingTransaction
//{
//    std::string id;
//    std::shared_ptr<CWalletTx> ptr;
//    std::shared_ptr<CReserveKey> reserveKey;
//    std::shared_ptr<UniValue> result;
//    CAmount fee;
//    CAmount totalAmt;
//    std::vector<OwnerAndAmount> payments;
//
//    PendingTransaction(
//        const std::string & p_txnID,
//        std::shared_ptr<CWalletTx> p_txnPtr,
//        std::shared_ptr<CReserveKey> p_reserveKey,
//        std::shared_ptr<UniValue> p_result,
//        CAmount p_txnFee,
//        CAmount p_txnAmount,
//        std::vector<OwnerAndAmount> & p_payments
//    )
//    {
//        id = p_txnID;
//        ptr = p_txnPtr;
//        reserveKey = p_reserveKey;
//        result = p_result;
//        fee = p_txnFee;
//        totalAmt = p_txnAmount;
//        payments = std::move(p_payments);
//    }
//};

UniValue requestsnapshot(const JSONRPCRequest& request) {
    if (request.fHelp || request.params.size() < 2)
        throw std::runtime_error(
                "requestsnapshot \"asset_name\" block_height\n"
                "\nSchedules a snapshot of the specified asset at the specified block height. The node captures it while it\n"
                "connects that block, so at most -maxsnapshotrequests different assets are accepted at one height.\n"

                "\nArguments:\n"
                "1. \"asset_name\"              (string, required) The asset name for which the snapshot will be taken\n"
                "2. \"block_height\"            (number, required) The block height at which the snapshot will be take\n"

                "\nResult:\n"
                "{\n"
                "  request_status: \"Added\",\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleCli("requestsnapshot", "\"TRONCO\" 12345")
                + HelpExampleRpc("requestsnapshot", "\"PHATSTACKS\" 34987")
        );

    if (!fAssetIndex) {
        return "_This rpc call is not functional unless -assetindex is enabled. To enable, please run the wallet with -assetindex, this will require a reindex to occur";
    }

    //  Extract parameters
    std::string asset_name = request.params[0].get_str();
    int block_height = request.params[1].get_int();

    AssetType ownershipAssetType;

    if (!IsAssetNameValid(asset_name, ownershipAssetType))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid asset_name: Please use a valid asset name"));

    if (ownershipAssetType == AssetType::UNIQUE || ownershipAssetType == AssetType::OWNER || ownershipAssetType == AssetType::MSGCHANNEL)
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid asset_name: OWNER, UNQIUE, MSGCHANNEL assets are not allowed for this call"));

    auto currentActiveAssetCache = GetCurrentAssetCache();
    if (!currentActiveAssetCache)
        return "_Couldn't get current asset cache.";
    CNewAsset asset;
    if (!currentActiveAssetCache->GetAssetMetaDataIfExists(asset_name, asset))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid asset_name: asset does not exist."));

    LOCK(cs_main);
    if (block_height <= chainActive.Height()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid block_height: block height should be greater than current active chain height"));
    }

    if (!pSnapshotRequestDb)
        throw JSONRPCError(RPC_DATABASE_ERROR, REWARDS_INACTIVE_ERROR);

    // A repeated request is the same record; a new one counts towards the
    // requests captured at that height
    const int64_t nMaxRequests = gArgs.GetArg("-maxsnapshotrequests", DEFAULT_MAX_SNAPSHOT_REQUESTS);
    if (nMaxRequests > 0 && !pSnapshotRequestDb->ContainsSnapshotRequest(asset_name, block_height)) {
        std::set<CSnapshotRequestDBEntry> atHeight;
        if (pSnapshotRequestDb->RetrieveSnapshotRequestsForHeight("", block_height, atHeight) &&
            static_cast<int64_t>(atHeight.size()) >= nMaxRequests)
            throw JSONRPCError(RPC_INVALID_REQUEST, strprintf(
                    "There are already %d snapshot requests at height %d (see -maxsnapshotrequests)",
                    atHeight.size(), block_height));
    }

    //  Build our snapshot request record for scheduling
    if (pSnapshotRequestDb->ScheduleSnapshot(asset_name, block_height)) {
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("request_status", "Added"));

        return obj;
    }

    throw JSONRPCError(RPC_MISC_ERROR, std::string("Failed to add requested snapshot to database"));
}

UniValue getsnapshotrequest(const JSONRPCRequest& request) {
    if (request.fHelp || request.params.size() < 2)
        throw std::runtime_error(
                "getsnapshotrequest \"asset_name\" block_height\n"
                "\nRetrieves the specified snapshot request details.\n"

                "\nArguments:\n"
                "1. \"asset_name\"              (string, required) The asset name for which the snapshot will be taken\n"
                "2. \"block_height\"            (number, required) The block height at which the snapshot will be take\n"

                "\nResult:\n"
                "{\n"
                "  asset_name: (string),\n"
                "  block_height: (number),\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleCli("getsnapshotrequest", "\"TRONCO\" 12345")
                + HelpExampleRpc("getsnapshotrequest", "\"PHATSTACKS\" 34987")
        );

    if (!fAssetIndex) {
        return "_This rpc call is not functional unless -assetindex is enabled. To enable, please run the wallet with -assetindex, this will require a reindex to occur";
    }

    //  Extract parameters
    std::string asset_name = request.params[0].get_str();
    int block_height = request.params[1].get_int();

    if (!pSnapshotRequestDb)
        throw JSONRPCError(RPC_DATABASE_ERROR, REWARDS_INACTIVE_ERROR);

    //  Retrieve the specified snapshot request
    CSnapshotRequestDBEntry snapshotRequest;

    if (pSnapshotRequestDb->RetrieveSnapshotRequest(asset_name, block_height, snapshotRequest)) {
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("asset_name", snapshotRequest.assetName));
        obj.push_back(Pair("block_height", snapshotRequest.heightForSnapshot));

        return obj;
    }
    else {
       LogPrint(BCLog::REWARDS, "Failed to retrieve specified snapshot request for asset '%s' at height %d!\n",
            asset_name.c_str(), block_height);
    }

    throw JSONRPCError(RPC_MISC_ERROR, std::string("Failed to retrieve specified snapshot request"));
}

UniValue listsnapshotrequests(const JSONRPCRequest& request) {
    if (request.fHelp || request.params.size() > 2)
        throw std::runtime_error(
                "listsnapshotrequests [\"asset_name\" [block_height]]\n"
                "\nList snapshot request details.\n"

                "\nArguments:\n"
                "asset_name: (string, optional) List only requests for a specific asset (default is \"\" for ALL)\n"
                "block_height: (number, optional) List only requests for a particular block height (default is 0 for ALL)\n"

                "\nResult:\n"
                "[\n"
                "  {\n"
                "    asset_name: (string),\n"
                "    block_height: (number)\n"
                "  }\n"
                "]\n"

                "\nExamples:\n"
                + HelpExampleCli("listsnapshotrequests", "")
                + HelpExampleRpc("listsnapshotrequests", "\"TRONCO\" 345333")
        );

    if (!fAssetIndex)
        return "_This rpc call is not functional unless -assetindex is enabled. To enable, please run the wallet with -assetindex, this will require a reindex to occur";

    //  Extract parameters
    std::string asset_name = "";
    int block_height = 0;
    if (request.params.size() > 0)
        asset_name = request.params[0].get_str();
    if (request.params.size() > 1)
        block_height = request.params[1].get_int();

    if (!pSnapshotRequestDb)
        throw JSONRPCError(RPC_DATABASE_ERROR, REWARDS_INACTIVE_ERROR);

    UniValue result(UniValue::VARR);
    std::set<CSnapshotRequestDBEntry> entries;
    if (pSnapshotRequestDb->RetrieveSnapshotRequestsForHeight(asset_name, block_height, entries)) {
        for (auto const &entry : entries) {
            UniValue item(UniValue::VOBJ);
            item.push_back(Pair("asset_name", entry.assetName));
            item.push_back(Pair("block_height", entry.heightForSnapshot));
            result.push_back(item);
        }
        return result;
    }
    else {
        LogPrint(BCLog::REWARDS, "Failed to cancel specified snapshot request for asset '%s' at height %d!\n",
                 asset_name.c_str(), block_height);
    }

    return NullUniValue;
}

UniValue cancelsnapshotrequest(const JSONRPCRequest& request) {
    if (request.fHelp || request.params.size() < 2)
        throw std::runtime_error(
                "cancelsnapshotrequest \"asset_name\" block_height\n"
                "\nCancels the specified snapshot request.\n"

                "\nArguments:\n"
                "1. \"asset_name\"              (string, required) The asset name for which the snapshot will be taken\n"
                "2. \"block_height\"            (number, required) The block height at which the snapshot will be take\n"

                "\nResult:\n"
                "{\n"
                "  request_status: (string),\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleCli("cancelsnapshotrequest", "\"TRONCO\" 12345")
                + HelpExampleRpc("cancelsnapshotrequest", "\"PHATSTACKS\" 34987")
        );

    if (!fAssetIndex) {
        return "_This rpc call is not functional unless -assetindex is enabled. To enable, please run the wallet with -assetindex, this will require a reindex to occur";
    }

    //  Extract parameters
    std::string asset_name = request.params[0].get_str();
    int block_height = request.params[1].get_int();

    if (!pSnapshotRequestDb)
        throw JSONRPCError(RPC_DATABASE_ERROR, REWARDS_INACTIVE_ERROR);

    //  Retrieve the specified reward
    if (pSnapshotRequestDb->RemoveSnapshotRequest(asset_name, block_height)) {
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("request_status", "Removed"));

        return obj;
    }
    else {
        LogPrint(BCLog::REWARDS, "Failed to cancel specified snapshot request for asset '%s' at height %d!\n",
            asset_name.c_str(), block_height);
    }

    throw JSONRPCError(RPC_MISC_ERROR, std::string("Failed to remove specified snapshot request"));
}

UniValue distributereward(const JSONRPCRequest& request) {
    if (request.fHelp || request.params.size() < 4)
        throw std::runtime_error(
                "distributereward \"asset_name\" snapshot_height \"distribution_asset_name\" gross_distribution_amount ( \"exception_addresses\" ) ( \"change_address\" )\n"
                "\nRetired (NIP-048): the node no longer sends reward payments.\n"
                "Use getdistributionplan to compute the payments, then send them from your wallet.\n"
        );

    throw JSONRPCError(RPC_METHOD_DEPRECATED, "distributereward no longer sends payments (NIP-048). Use getdistributionplan to compute them and pay from your wallet");
}

UniValue getdistributestatus(const JSONRPCRequest& request) {
    if (request.fHelp || request.params.size() < 4)
        throw std::runtime_error(
                "getdistributestatus \"asset_name\" snapshot_height \"distribution_asset_name\" gross_distribution_amount ( \"exception_addresses\" )\n"
                "\nGive information about the status of the distribution\n"

                "\nArguments:\n"
                "1. \"asset_name\"                 (string, required) The reward will be distributed all owners of this asset\n"
                "2. \"snapshot_height\"            (number, required) The block height of the ownership snapshot\n"
                "3. \"distribution_asset_name\"    (string, required) The name of the asset that will be distributed, or XNA\n"
                "4. \"gross_distribution_amount\"  (number, required) The amount of the distribution asset that will be split amongst all owners\n"
                "5. \"exception_addresses\"        (string, optional) Ownership addresses that should be excluded\n"

                "\nExamples:\n"
                + HelpExampleCli("getdistributestatus", "\"TRONCO\" 12345 \"XNA\" 1000")
                + HelpExampleCli("getdistributestatus", "\"PHATSTACKS\" 12345 \"DIVIDENDS\" 1000 \"mwN7xC3yomYdvJuVXkVC7ymY9wNBjWNduD,n4Rf18edydDaRBh7t6gHUbuByLbWEoWUTg\"")
                + HelpExampleRpc("getdistributestatus", "\"TRONCO\" 34987 \"DIVIDENDS\" 100000")
                + HelpExampleRpc("getdistributestatus", "\"PHATSTACKS\" 34987 \"XNA\" 100000 \"mwN7xC3yomYdvJuVXkVC7ymY9wNBjWNduD,n4Rf18edydDaRBh7t6gHUbuByLbWEoWUTg\"")
        );

    if (!fAssetIndex) {
        return "_This rpc call is not functional unless -assetindex is enabled. To enable, please run the wallet with -assetindex, this will require a reindex to occur";
    }

    ObserveSafeMode();

    //  Extract parameters
    std::string asset_name(request.params[0].get_str());
    int snapshot_height = request.params[1].get_int();
    std::string distribution_asset_name(request.params[2].get_str());
    CAmount distribution_amount = AmountFromValue(request.params[3], (distribution_asset_name == "XNA"));
    std::string exception_addresses;
    if (request.params.size() > 4) {
        exception_addresses = request.params[4].get_str();

        //LogPrint(BCLog::REWARDS, "Excluding \"%s\"\n", exception_addresses.c_str());
    }

    if (!pDistributeSnapshotDb)
        throw JSONRPCError(RPC_DATABASE_ERROR, REWARDS_INACTIVE_ERROR);

    CRewardSnapshot distribRewardSnapshotData(asset_name, distribution_asset_name, exception_addresses, distribution_amount, snapshot_height);
    auto hash = distribRewardSnapshotData.GetHash();

    CRewardSnapshot temp;
    if (!pDistributeSnapshotDb->RetrieveDistributeSnapshotRequest(hash, temp)) {
        return "Distribution not found";
    }

    UniValue responseObj(UniValue::VOBJ);

    responseObj.push_back(std::make_pair("Asset Name", temp.strOwnershipAsset));
    responseObj.push_back(std::make_pair("Height", std::to_string(temp.nHeight)));
    responseObj.push_back(std::make_pair("Distribution Name", temp.strDistributionAsset));
    responseObj.push_back(std::make_pair("Distribution Amount", ValueFromAmount(temp.nDistributionAmount)));
    responseObj.push_back(std::make_pair("Status", temp.nStatus));

    return responseObj;
}
#endif

/** Smallest transferable amount of an asset with the given units, in satoshis. */
static CAmount AssetUnitSize(int8_t units)
{
    CAmount unit = 1;
    for (int i = units; i < 8; ++i)
        unit *= 10;
    return unit;
}

static void CheckRewardAssetName(const std::string& name, const std::string& param)
{
    AssetType type;
    if (!IsAssetNameValid(name, type))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid %s: Please use a valid asset name", param));
    if (type == AssetType::UNIQUE || type == AssetType::OWNER || type == AssetType::MSGCHANNEL)
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid %s: OWNER, UNIQUE, MSGCHANNEL assets are not allowed for this call", param));
}

static void EnsurePlansAvailable()
{
    if (!fAssetIndex)
        throw JSONRPCError(RPC_MISC_ERROR, "Distribution plans require -assetindex");
    if (!pAssetSnapshotDb)
        throw JSONRPCError(RPC_DATABASE_ERROR, REWARDS_INACTIVE_ERROR);
}

/** The inputs of a plan (NIP-048 B2). */
struct PlanRequest {
    std::string assetName;
    int height = 0;
    std::string distributionAsset;
    CAmount amount = 0;
    std::set<std::string> exceptions;
    RemainderPolicy policy = RemainderPolicy::PAYER;
    bool fAllowLegacy = false;
    uint256 announcementTxid;      //!< B5: the transaction that announced the height
    uint256 announcementBlockHint; //!< where it was mined, for nodes without -txindex
    std::string qualifier;         //!< D3: only holders with this tag
    std::map<std::string, int64_t> weights; //!< D3: report weights; empty: holdings
    uint256 reportTxid;            //!< D3: the transaction that anchored the report hash
    uint256 reportBlockHint;
    DistributionAllocation allocation = DistributionAllocation::HOLDINGS;
    CAmount minHeld = 0;           //!< only holders with at least this much of the asset
};

/** A computed plan with everything the plan RPCs report. */
struct PlanResult {
    DistributionPlanHeader header;
    std::vector<DistributionLeaf> leaves;
    std::vector<DistributionHolding> zeroAmount;
    std::vector<std::pair<DistributionHolding, std::string>> excluded;
    int8_t ownershipUnits = 0;
    int8_t distributionUnits = 8;
    CAmount totalHeld = 0;
    bool fLegacy = false;
    int confirmations = 0;
    int announcementHeight = -1;
    int minNotice = DEFAULT_MIN_SNAPSHOT_NOTICE;
    bool fHasState = false;        //!< D3 snapshot with holder state
    bool fGlobalFrozen = false;
    int reportHeight = -1;         //!< where the report hash was anchored, when given
    uint256 reportTxid;
    std::map<CScript, CAmount> heldByScript; //!< actual holdings, when the leaves carry weights
    uint256 merkleRoot;
    uint256 planHash;
};

/** The active-chain block holding txid: from a block hint, the transaction
 *  index, or an unspent output of the transaction. Null if not found. */
static const CBlockIndex* LocateTransaction(const uint256& txid, const uint256& blockHint, CTransactionRef& tx)
{
    AssertLockHeld(cs_main);
    if (!blockHint.IsNull()) {
        const auto it = mapBlockIndex.find(blockHint);
        CBlock block;
        if (it != mapBlockIndex.end() && chainActive.Contains(it->second) &&
            ReadBlockFromDisk(block, it->second, GetParams().GetConsensus())) {
            for (const auto& blockTx : block.vtx) {
                if (blockTx->GetHash() == txid) {
                    tx = blockTx;
                    return it->second;
                }
            }
        }
    }
    uint256 hashBlock;
    if (GetTransaction(txid, tx, GetParams().GetConsensus(), hashBlock, true) && !hashBlock.IsNull()) {
        const auto it = mapBlockIndex.find(hashBlock);
        if (it != mapBlockIndex.end() && chainActive.Contains(it->second))
            return it->second;
    }
    return nullptr;
}

static std::set<std::string> ParseExceptions(const UniValue& value)
{
    std::set<std::string> exceptions;
    std::vector<std::string> parts;
    boost::split(parts, value.get_str(), boost::is_any_of(ADDRESS_COMMA_DELIMITER));
    for (std::string part : parts) {
        boost::trim(part);
        if (!part.empty())
            exceptions.insert(part);
    }
    return exceptions;
}

/** Reads the plan options (remainder, eligibility and allocation rules,
 *  announcement and report) from an options or plan object. */
static void ParsePlanOptions(const UniValue& obj, PlanRequest& req)
{
    const UniValue& remainder = find_value(obj, "remainder");
    if (!remainder.isNull()) {
        if (remainder.get_str() == "largest")
            req.policy = RemainderPolicy::LARGEST;
        else if (remainder.get_str() != "payer")
            throw JSONRPCError(RPC_INVALID_PARAMETER, "remainder must be \"payer\" or \"largest\"");
    }
    const UniValue& allowLegacy = find_value(obj, "allow_legacy_snapshot");
    if (!allowLegacy.isNull())
        req.fAllowLegacy = allowLegacy.get_bool();
    const UniValue& qualifier = find_value(obj, "qualifier");
    if (!qualifier.isNull()) {
        req.qualifier = qualifier.get_str();
        if (!IsAssetNameAQualifier(req.qualifier))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "qualifier must be a qualifier tag (#TAG or #TAG/#SUB)");
    }
    const UniValue& weights = find_value(obj, "weights");
    if (!weights.isNull()) {
        for (const std::string& address : weights.get_obj().getKeys()) {
            const int64_t weight = find_value(weights, address).get_int64();
            if (weight <= 0)
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Report weights must be positive integers");
            req.weights[address] = weight;
        }
        if (req.weights.empty())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "weights must not be empty");
    }
    const UniValue& allocation = find_value(obj, "allocation");
    if (!allocation.isNull()) {
        if (allocation.get_str() == "equal")
            req.allocation = DistributionAllocation::EQUAL;
        else if (allocation.get_str() != "holdings")
            throw JSONRPCError(RPC_INVALID_PARAMETER, "allocation must be \"holdings\" or \"equal\"");
        if (req.allocation == DistributionAllocation::EQUAL && !req.weights.empty())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "allocation \"equal\" cannot be combined with report weights");
    }
    const UniValue& minHeld = find_value(obj, "min_held");
    if (!minHeld.isNull()) {
        req.minHeld = AmountFromValue(minHeld, false);
        if (req.minHeld < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "min_held must not be negative");
    }
    const UniValue& report = find_value(obj, "report");
    if (!report.isNull()) {
        RPCTypeCheckObj(report, {
                {"txid", UniValueType(UniValue::VSTR)},
                {"block_hash", UniValueType(UniValue::VSTR)},
            }, true, true);
        req.reportTxid = ParseHashO(report, "txid");
        if (!find_value(report, "block_hash").isNull())
            req.reportBlockHint = ParseHashO(report, "block_hash");
    }
    const UniValue& announcement = find_value(obj, "announcement");
    if (!announcement.isNull()) {
        RPCTypeCheckObj(announcement, {
                {"txid", UniValueType(UniValue::VSTR)},
                {"block_hash", UniValueType(UniValue::VSTR)},
            }, true, true);
        req.announcementTxid = ParseHashO(announcement, "txid");
        if (!find_value(announcement, "block_hash").isNull())
            req.announcementBlockHint = ParseHashO(announcement, "block_hash");
    }
}

/** getdistributionplan's positional arguments. */
static PlanRequest PlanRequestFromParams(const UniValue& params)
{
    PlanRequest req;
    req.assetName = params[0].get_str();
    req.height = params[1].get_int();
    req.distributionAsset = params[2].get_str();
    req.amount = AmountFromValue(params[3], req.distributionAsset == "XNA");
    if (params.size() > 4 && !params[4].isNull())
        req.exceptions = ParseExceptions(params[4]);
    if (params.size() > 5 && !params[5].isNull()) {
        const UniValue& options = params[5].get_obj();
        RPCTypeCheckObj(options, {
                {"remainder", UniValueType(UniValue::VSTR)},
                {"allow_legacy_snapshot", UniValueType(UniValue::VBOOL)},
                {"announcement", UniValueType(UniValue::VOBJ)},
                {"qualifier", UniValueType(UniValue::VSTR)},
                {"weights", UniValueType(UniValue::VOBJ)},
                {"report", UniValueType(UniValue::VOBJ)},
                {"allocation", UniValueType(UniValue::VSTR)},
                {"min_held", UniValueType()},
            }, true, true);
        ParsePlanOptions(options, req);
    }
    return req;
}

/** The plan object taken by the proof, batch and verification RPCs. */
static PlanRequest PlanRequestFromObject(const UniValue& plan)
{
    RPCTypeCheckObj(plan, {
            {"asset_name", UniValueType(UniValue::VSTR)},
            {"snapshot_height", UniValueType(UniValue::VNUM)},
            {"distribution_asset_name", UniValueType(UniValue::VSTR)},
            {"amount", UniValueType()},
            {"exception_addresses", UniValueType(UniValue::VSTR)},
            {"remainder", UniValueType(UniValue::VSTR)},
            {"allow_legacy_snapshot", UniValueType(UniValue::VBOOL)},
            {"announcement", UniValueType(UniValue::VOBJ)},
            {"qualifier", UniValueType(UniValue::VSTR)},
            {"weights", UniValueType(UniValue::VOBJ)},
            {"report", UniValueType(UniValue::VOBJ)},
            {"allocation", UniValueType(UniValue::VSTR)},
            {"min_held", UniValueType()},
        }, true, true);
    for (const char* key : {"asset_name", "snapshot_height", "distribution_asset_name", "amount"}) {
        if (find_value(plan, key).isNull())
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Missing plan field %s", key));
    }

    PlanRequest req;
    req.assetName = find_value(plan, "asset_name").get_str();
    req.height = find_value(plan, "snapshot_height").get_int();
    req.distributionAsset = find_value(plan, "distribution_asset_name").get_str();
    req.amount = AmountFromValue(find_value(plan, "amount"), req.distributionAsset == "XNA");
    if (!find_value(plan, "exception_addresses").isNull())
        req.exceptions = ParseExceptions(find_value(plan, "exception_addresses"));
    ParsePlanOptions(plan, req);
    return req;
}

/** Height of the active-chain transaction that sends the owner token of
 *  `asset` with `expected` as its message. Throws when it is absent. */
static int VerifyOwnerAnchor(const std::string& asset, const uint256& txid, const uint256& blockHint,
                             const uint256& expected, const std::string& what)
{
    CTransactionRef tx;
    const CBlockIndex* pindex = LocateTransaction(txid, blockHint, tx);
    if (!pindex)
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s not found in the active chain: pass its block_hash or enable -txindex", what));
    const std::string message(expected.begin(), expected.end());
    for (const CTxOut& txout : tx->vout) {
        CAssetOutputEntry data;
        if (GetAssetData(txout.scriptPubKey, data) && data.type == TX_TRANSFER_ASSET &&
            data.assetName == asset + OWNER_TAG && data.message == message)
            return pindex->nHeight;
    }
    throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("The %s transaction does not carry the expected message on the owner token", what));
}

/** Computes a plan from its snapshot. Requires cs_main; throws on invalid input. */
static PlanResult ComputePlan(const PlanRequest& req)
{
    AssertLockHeld(cs_main);

    CheckRewardAssetName(req.assetName, "asset_name");
    const bool fDistributeXNA = req.distributionAsset == "XNA";
    if (!fDistributeXNA)
        CheckRewardAssetName(req.distributionAsset, "distribution_asset_name");

    if (!passets)
        throw JSONRPCError(RPC_DATABASE_ERROR, "Asset cache not setup. Please restart wallet to try again");

    PlanResult plan;
    CNewAsset ownershipAsset;
    if (!passets->GetAssetMetaDataIfExists(req.assetName, ownershipAsset))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid asset_name: asset does not exist");
    plan.ownershipUnits = ownershipAsset.units;
    if (req.minHeld % AssetUnitSize(plan.ownershipUnits) != 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "min_held must be a multiple of the asset's smallest unit");

    if (!fDistributeXNA) {
        CNewAsset distributionAsset;
        if (!passets->GetAssetMetaDataIfExists(req.distributionAsset, distributionAsset))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid distribution_asset_name: asset does not exist");
        plan.distributionUnits = distributionAsset.units;
    }

    if (req.height < 0 || req.height > chainActive.Height())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid snapshot_height: block height should be less than or equal to the current active chain height");
    const int64_t nMinConfirmations = gArgs.GetArg("-minrewardheight", MINIMUM_REWARDS_PAYOUT_HEIGHT);
    if (chainActive.Height() - req.height < nMinConfirmations)
        throw JSONRPCError(RPC_INVALID_REQUEST, strprintf(
                "The chain must be %d blocks ahead of the snapshot height before planning a distribution (see -minrewardheight)",
                nMinConfirmations));

    CAssetSnapshotDBEntry snapshot;
    if (!pAssetSnapshotDb->RetrieveOwnershipSnapshot(req.assetName, req.height, snapshot))
        throw JSONRPCError(RPC_INVALID_REQUEST, "Snapshot not found: request it with requestsnapshot before the chain reaches that height");

    plan.fHasState = snapshot.fHasState;
    plan.fGlobalFrozen = snapshot.fGlobalFrozen;
    const std::vector<DistributionHolding> holdings = CanonicalHoldings(snapshot.ownersAndAmounts, snapshot.states);
    const uint256 snapshotHash = plan.fHasState
            ? ComputeSnapshotHashV2(req.assetName, req.height, snapshot.blockHash, snapshot.fGlobalFrozen, holdings)
            : ComputeSnapshotHash(req.assetName, req.height, snapshot.blockHash, holdings);
    if (!req.qualifier.empty() && !plan.fHasState)
        throw JSONRPCError(RPC_INVALID_REQUEST, "This snapshot has no tag state: a qualifier filter needs a snapshot captured after NIP-048 D3");
    plan.fLegacy = snapshot.IsLegacy();
    if (plan.fLegacy) {
        if (!req.fAllowLegacy)
            throw JSONRPCError(RPC_INVALID_REQUEST, "This snapshot was captured before NIP-048 and has no block identity; set allow_legacy_snapshot to use it");
    } else {
        if (chainActive[req.height]->GetBlockHash() != snapshot.blockHash)
            throw JSONRPCError(RPC_DATABASE_ERROR, "The snapshot does not belong to the active chain");
        if (snapshotHash != snapshot.snapshotHash)
            throw JSONRPCError(RPC_DATABASE_ERROR, "The snapshot store is inconsistent: its content no longer matches its hash");
    }

    // B5: the owner token announced this height in advance
    if (!req.announcementTxid.IsNull()) {
        plan.announcementHeight = VerifyOwnerAnchor(req.assetName, req.announcementTxid, req.announcementBlockHint,
                SnapshotAnnouncementHash(GetParams().NetworkIDString(), req.assetName, req.height), "announcement");
        plan.minNotice = gArgs.GetArg("-minsnapshotnotice", DEFAULT_MIN_SNAPSHOT_NOTICE);
    }

    // D3: the weights of a report anchored on the owner token, if any
    const uint256 reportHash = req.weights.empty() ? uint256() : DistributionReportHash(req.weights);
    if (!req.reportTxid.IsNull()) {
        if (req.weights.empty())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "report needs the report weights");
        plan.reportHeight = VerifyOwnerAnchor(req.assetName, req.reportTxid, req.reportBlockHint, reportHash, "report");
        plan.reportTxid = req.reportTxid;
    }

    // Eligibility, in this order: exceptions, burn addresses, then the holder
    // state of a D3 snapshot (global freeze, freeze, self-revocation), the
    // qualifier filter, the minimum holding and, with a report, a weight
    std::vector<DistributionHolding> eligible;
    for (const auto& holding : holdings) {
        std::string reason;
        if (req.exceptions.count(holding.address))
            reason = "exception";
        else if (GetParams().IsBurnAddress(holding.address))
            reason = "burn";
        else if (plan.fGlobalFrozen)
            reason = "globally_frozen";
        else if (holding.flags & HOLDER_FROZEN)
            reason = "frozen";
        else if (holding.flags & HOLDER_SELF_REVOKED)
            reason = "self_revoked";
        else if (!req.qualifier.empty() && !std::binary_search(holding.tags.begin(), holding.tags.end(), req.qualifier))
            reason = "missing_qualifier";
        else if (holding.held < req.minHeld)
            reason = "below_minimum";
        else if (!req.weights.empty() && !req.weights.count(holding.address))
            reason = "no_weight";
        if (reason.empty())
            eligible.push_back(holding);
        else
            plan.excluded.emplace_back(holding, reason);
    }

    for (const auto& holding : eligible)
        plan.totalHeld += holding.held;

    // The report weights, or one per holder for equal shares, replace the
    // holdings in the allocation
    std::vector<DistributionHolding> weighted = eligible;
    if (!req.weights.empty() || req.allocation == DistributionAllocation::EQUAL) {
        for (auto& holding : weighted) {
            plan.heldByScript[holding.script] = holding.held;
            holding.held = req.weights.empty() ? 1 : req.weights.at(holding.address);
        }
    }

    CAmount remainder = 0;
    std::string strError;
    if (!AllocateDistribution(weighted, req.amount, AssetUnitSize(plan.distributionUnits), req.policy,
                              plan.leaves, plan.zeroAmount, remainder, strError))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strError);

    DistributionPlanHeader& header = plan.header;
    header.network = GetParams().NetworkIDString();
    header.ownershipAsset = req.assetName;
    header.height = req.height;
    header.blockHash = snapshot.blockHash;
    header.snapshotHash = snapshotHash;
    header.announcementTxid = req.announcementTxid;
    header.qualifier = req.qualifier;
    header.reportHash = reportHash;
    header.allocation = req.allocation;
    header.minHeld = req.minHeld;
    header.distributionAsset = req.distributionAsset;
    header.amount = req.amount;
    header.policy = req.policy;
    header.exclusions.assign(req.exceptions.begin(), req.exceptions.end());
    header.distributed = req.amount - remainder;
    header.remainder = remainder;
    header.leafCount = plan.leaves.size();
    plan.merkleRoot = DistributionMerkleRoot(plan.leaves);
    plan.planHash = ComputePlanHash(header, plan.merkleRoot);
    plan.confirmations = chainActive.Height() - req.height + 1;
    return plan;
}

/** Plans computed at the current tip. Every recipient asking for its proof, and
 *  the batches of a plan, then cost one computation per block instead of one
 *  per call; a new tip drops them, since anchors and confirmations follow it. */
static const size_t PLAN_CACHE_SIZE = 4;

struct CachedPlan {
    std::string key;
    uint256 tip;
    std::shared_ptr<const PlanResult> plan;
};

static std::list<CachedPlan> g_planCache GUARDED_BY(cs_main);

static std::string PlanCacheKey(const PlanRequest& req)
{
    CDataStream ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << req.assetName << req.height << req.distributionAsset << req.amount << req.exceptions
       << static_cast<uint8_t>(req.policy) << req.fAllowLegacy << req.announcementTxid << req.announcementBlockHint
       << req.qualifier << req.weights << req.reportTxid << req.reportBlockHint
       << static_cast<uint8_t>(req.allocation) << req.minHeld;
    return ss.str();
}

/** The plan of a request at the current tip, from the cache or computed. */
static std::shared_ptr<const PlanResult> GetPlan(const PlanRequest& req)
{
    AssertLockHeld(cs_main);
    const uint256 tip = chainActive.Tip()->GetBlockHash();
    g_planCache.remove_if([&tip](const CachedPlan& entry) { return entry.tip != tip; });

    const std::string key = PlanCacheKey(req);
    for (auto it = g_planCache.begin(); it != g_planCache.end(); ++it) {
        if (it->key == key) {
            g_planCache.splice(g_planCache.begin(), g_planCache, it);
            return g_planCache.front().plan;
        }
    }

    auto plan = std::make_shared<const PlanResult>(ComputePlan(req));
    g_planCache.push_front({key, tip, plan});
    if (g_planCache.size() > PLAN_CACHE_SIZE)
        g_planCache.pop_back();
    return plan;
}

static std::string HashHex(const uint256& hash)
{
    return HexStr(hash.begin(), hash.end());
}

static UniValue PlanToJSON(const PlanResult& plan)
{
    const DistributionPlanHeader& header = plan.header;

    UniValue snapshotObj(UniValue::VOBJ);
    snapshotObj.push_back(Pair("asset_name", header.ownershipAsset));
    snapshotObj.push_back(Pair("height", header.height));
    snapshotObj.push_back(Pair("block_hash", plan.fLegacy ? "" : header.blockHash.GetHex()));
    snapshotObj.push_back(Pair("snapshot_hash", HashHex(header.snapshotHash)));
    snapshotObj.push_back(Pair("legacy", plan.fLegacy));
    snapshotObj.push_back(Pair("format", plan.fLegacy ? 0 : plan.fHasState ? 2 : 1));
    if (plan.fHasState)
        snapshotObj.push_back(Pair("global_frozen", plan.fGlobalFrozen));
    snapshotObj.push_back(Pair("confirmations", plan.confirmations));

    // With a report or equal shares, leaves carry the weight; the holding is kept apart
    const bool fReport = !header.reportHash.IsNull();
    const bool fWeighted = fReport || header.allocation == DistributionAllocation::EQUAL;
    auto held = [&plan, fWeighted](const CScript& script, CAmount value) {
        return fWeighted ? plan.heldByScript.at(script) : value;
    };

    UniValue exceptionsArr(UniValue::VARR);
    for (const auto& address : header.exclusions)
        exceptionsArr.push_back(address);

    UniValue recipients(UniValue::VARR);
    for (const auto& leaf : plan.leaves) {
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("address", leaf.address));
        entry.push_back(Pair("script", HexStr(leaf.script.begin(), leaf.script.end())));
        entry.push_back(Pair("held", ValueFromAmount(held(leaf.script, leaf.held), plan.ownershipUnits)));
        if (fReport)
            entry.push_back(Pair("weight", leaf.held));
        entry.push_back(Pair("amount", ValueFromAmount(leaf.amount, plan.distributionUnits)));
        recipients.push_back(entry);
    }

    UniValue zeroArr(UniValue::VARR);
    for (const auto& holding : plan.zeroAmount) {
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("address", holding.address));
        entry.push_back(Pair("held", ValueFromAmount(held(holding.script, holding.held), plan.ownershipUnits)));
        if (fReport)
            entry.push_back(Pair("weight", holding.held));
        zeroArr.push_back(entry);
    }

    UniValue excludedArr(UniValue::VARR);
    for (const auto& item : plan.excluded) {
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("address", item.first.address));
        entry.push_back(Pair("held", ValueFromAmount(item.first.held, plan.ownershipUnits)));
        entry.push_back(Pair("reason", item.second));
        excludedArr.push_back(entry);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("plan_hash", HashHex(plan.planHash)));
    result.push_back(Pair("merkle_root", HashHex(plan.merkleRoot)));
    result.push_back(Pair("version", static_cast<int>(DistributionPlanVersion(header))));
    result.push_back(Pair("network", header.network));
    result.push_back(Pair("snapshot", snapshotObj));
    result.push_back(Pair("distribution_asset_name", header.distributionAsset));
    result.push_back(Pair("amount", ValueFromAmount(header.amount, plan.distributionUnits)));
    result.push_back(Pair("remainder_policy", header.policy == RemainderPolicy::LARGEST ? "largest" : "payer"));
    result.push_back(Pair("allocation", header.allocation == DistributionAllocation::EQUAL ? "equal" : "holdings"));
    result.push_back(Pair("min_held", ValueFromAmount(header.minHeld, plan.ownershipUnits)));
    result.push_back(Pair("exception_addresses", exceptionsArr));
    result.push_back(Pair("total_held", ValueFromAmount(plan.totalHeld, plan.ownershipUnits)));
    result.push_back(Pair("distributed", ValueFromAmount(header.distributed, plan.distributionUnits)));
    result.push_back(Pair("remainder", ValueFromAmount(header.remainder, plan.distributionUnits)));
    result.push_back(Pair("recipients", recipients));
    result.push_back(Pair("zero_amount", zeroArr));
    result.push_back(Pair("excluded", excludedArr));

    // B5: how independently the snapshot can be checked
    std::string verifiability = "unannounced";
    UniValue announcement(UniValue::VNULL);
    if (!header.announcementTxid.IsNull()) {
        const int notice = header.height - plan.announcementHeight;
        verifiability = notice >= plan.minNotice ? "announced" : "late_announcement";
        announcement.setObject();
        announcement.push_back(Pair("txid", header.announcementTxid.GetHex()));
        announcement.push_back(Pair("height", plan.announcementHeight));
        announcement.push_back(Pair("notice", notice));
        announcement.push_back(Pair("minimum_notice", plan.minNotice));
    }
    result.push_back(Pair("announcement", announcement));
    result.push_back(Pair("verifiability", verifiability));

    // D3 rules the plan hash commits to
    result.push_back(Pair("qualifier", header.qualifier.empty() ? UniValue(UniValue::VNULL) : UniValue(header.qualifier)));
    UniValue report(UniValue::VNULL);
    if (fReport) {
        report.setObject();
        report.push_back(Pair("hash", HashHex(header.reportHash)));
        if (plan.reportHeight >= 0) {
            report.push_back(Pair("txid", plan.reportTxid.GetHex()));
            report.push_back(Pair("height", plan.reportHeight));
        }
    }
    result.push_back(Pair("report", report));
    return result;
}

/** Batch size from an options object, within [1, MAX_DISTRIBUTION_BATCH_OUTPUTS]. */
static uint32_t ParseMaxOutputs(const UniValue& options)
{
    const UniValue& value = find_value(options, "max_outputs");
    if (value.isNull())
        return DEFAULT_DISTRIBUTION_BATCH_OUTPUTS;
    const int n = value.get_int();
    if (n < 1 || n > static_cast<int>(MAX_DISTRIBUTION_BATCH_OUTPUTS))
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("max_outputs must be between 1 and %u", MAX_DISTRIBUTION_BATCH_OUTPUTS));
    return n;
}

static size_t BatchCount(const PlanResult& plan, uint32_t nMaxOutputs)
{
    return (plan.leaves.size() + nMaxOutputs - 1) / nMaxOutputs;
}

/** Leaves [first, last) of batch nIndex. */
static std::pair<size_t, size_t> BatchRange(const PlanResult& plan, uint32_t nMaxOutputs, size_t nIndex)
{
    const size_t first = nIndex * nMaxOutputs;
    return {first, std::min(plan.leaves.size(), first + nMaxOutputs)};
}

static const std::string PLAN_OBJECT_HELP =
        "   {\n"
        "     \"asset_name\": \"name\",              (string, required) as in getdistributionplan\n"
        "     \"snapshot_height\": n,              (number, required)\n"
        "     \"distribution_asset_name\": \"name\", (string, required)\n"
        "     \"amount\": x.xxx,                   (numeric, required) gross_distribution_amount\n"
        "     \"exception_addresses\": \"a,b\",      (string, optional)\n"
        "     \"remainder\": \"payer\"|\"largest\",    (string, optional, default \"payer\")\n"
        "     \"allow_legacy_snapshot\": bool,     (boolean, optional, default false)\n"
        "     \"announcement\": {\"txid\": \"hex\", \"block_hash\": \"hex\"} (object, optional) as in getdistributionplan\n"
        "     \"qualifier\": \"#TAG\",           (string, optional) as in getdistributionplan\n"
        "     \"weights\": {\"address\": n, ...}, (object, optional) as in getdistributionplan\n"
        "     \"report\": {\"txid\": \"hex\", \"block_hash\": \"hex\"} (object, optional) as in getdistributionplan\n"
        "     \"allocation\": \"holdings\"|\"equal\", (string, optional, default \"holdings\") as in getdistributionplan\n"
        "     \"min_held\": x.xxx,               (numeric, optional) as in getdistributionplan\n"
        "   }\n";

UniValue getdistributionplan(const JSONRPCRequest& request) {
    if (request.fHelp || request.params.size() < 4 || request.params.size() > 6)
        throw std::runtime_error(
                "getdistributionplan \"asset_name\" snapshot_height \"distribution_asset_name\" gross_distribution_amount ( \"exception_addresses\" {options} )\n"
                "\nComputes, without spending anything, how gross_distribution_amount of the distribution asset is split among the\n"
                "holders of asset_name in its snapshot at snapshot_height (NIP-048). Each holder gets floor(amount * held / total)\n"
                "in whole units of the distribution asset, or floor(amount / holders) with equal allocation. The plan hash commits\n"
                "to the snapshot, the parameters and every payment;\n"
                "pay the recipients from any wallet, for instance with getdistributionbatches and createdistributionbatch.\n"

                "\nArguments:\n"
                "1. \"asset_name\"                 (string, required) The asset whose holders receive the distribution\n"
                "2. \"snapshot_height\"            (number, required) The height of a snapshot taken with requestsnapshot\n"
                "3. \"distribution_asset_name\"    (string, required) The asset to distribute, or XNA\n"
                "4. \"gross_distribution_amount\"  (number, required) The amount to split, a multiple of the distribution asset's smallest unit\n"
                "5. \"exception_addresses\"        (string, optional) Comma-separated holder addresses to exclude\n"
                "6. options                      (object, optional)\n"
                "   {\n"
                "     \"remainder\": \"payer\"|\"largest\", (string, default \"payer\") Where the undivided remainder goes: it stays with the\n"
                "                                       payer, or one unit each to the largest fractional parts (ties by script)\n"
                "     \"allow_legacy_snapshot\": bool,   (boolean, default false) Accept a snapshot captured before NIP-048, which has no block identity\n"
                "     \"announcement\": {                (object, optional) The transaction that announced snapshot_height in advance\n"
                "       \"txid\": \"hex\",                 (see getsnapshotannouncement); the plan then commits to it (format version 2)\n"
                "       \"block_hash\": \"hex\"            (optional) Its block, for nodes without -txindex\n"
                "     },\n"
                "     \"qualifier\": \"#TAG\",           (string, optional) Only holders tagged with this qualifier at the height\n"
                "     \"weights\": {\"address\": n, ...}, (object, optional) Weights of a work report, positive integers; they replace\n"
                "                                       the holdings, and holders without a weight are excluded\n"
                "     \"report\": {\"txid\": \"hex\", \"block_hash\": \"hex\"} (object, optional) The owner token transfer that anchored\n"
                "                                       the report hash (SHA-256 of 0x07 || weights)\n"
                "     \"allocation\": \"holdings\"|\"equal\", (string, default \"holdings\") Split in proportion to the holdings (or the\n"
                "                                       report weights), or in equal shares among the eligible holders, whatever\n"
                "                                       they hold; equal cannot be combined with weights\n"
                "     \"min_held\": x.xxx,               (numeric, optional) Only holders with at least this amount of asset_name\n"
                "   }\n"
                "\nA snapshot taken since NIP-048 D3 records, per holder, freezes, DEPIN self-revocations and qualifier tags; such\n"
                "holders are excluded. With a qualifier, report weights or both, the plan hash commits to them (format version 3);\n"
                "with equal allocation or a minimum holding, it commits to those too (format version 4).\n"

                "\nResult:\n"
                "{\n"
                "  \"plan_hash\": \"hex\",               (string) SHA-256 commitment to the header and the Merkle root\n"
                "  \"merkle_root\": \"hex\",             (string) RFC 6962 root over the recipients, in order\n"
                "  \"version\": n,                     (number) plan format version\n"
                "  \"network\": \"name\",                (string) network the plan belongs to\n"
                "  \"snapshot\": {\n"
                "    \"asset_name\": \"name\",\n"
                "    \"height\": n,\n"
                "    \"block_hash\": \"hash\",           (string) block the snapshot was captured on; empty for a legacy snapshot\n"
                "    \"snapshot_hash\": \"hex\",         (string) commitment to the snapshot content\n"
                "    \"legacy\": true|false,\n"
                "    \"confirmations\": n\n"
                "  },\n"
                "  \"distribution_asset_name\": \"name\",\n"
                "  \"amount\": x.xxx,                  (numeric) gross_distribution_amount\n"
                "  \"remainder_policy\": \"payer\"|\"largest\",\n"
                "  \"allocation\": \"holdings\"|\"equal\",\n"
                "  \"min_held\": x.xxx,                (numeric) minimum holding to be eligible, 0 if none\n"
                "  \"exception_addresses\": [ \"address\", ... ], (array) sorted, as committed in the plan hash\n"
                "  \"total_held\": x.xxx,              (numeric) holdings of the eligible holders\n"
                "  \"distributed\": x.xxx,             (numeric) sum of the payments: the funds the payer needs, before fees\n"
                "  \"remainder\": x.xxx,               (numeric) amount left undistributed\n"
                "  \"recipients\": [                  (array) payments, ordered by output script\n"
                "    { \"address\": \"address\", \"script\": \"hex\", \"held\": x.xxx, \"amount\": x.xxx }, ...\n"
                "  ],\n"
                "  \"zero_amount\": [ { \"address\": \"address\", \"held\": x.xxx }, ... ], (array) holders whose share rounds to zero\n"
                "  \"excluded\": [ { \"address\": \"address\", \"held\": x.xxx, \"reason\": \"...\" }, ... ], (array) reason: exception, burn,\n"
                "                                   globally_frozen, frozen, self_revoked, missing_qualifier, below_minimum or no_weight\n"
                "  \"announcement\": {                (object or null) The announcement, when given\n"
                "    \"txid\": \"hex\", \"height\": n, \"notice\": n, \"minimum_notice\": n   (notice: blocks between announcement and snapshot)\n"
                "  },\n"
                "  \"verifiability\": \"announced\"|\"late_announcement\"|\"unannounced\"  (string) Whether other nodes could capture the\n"
                "                                   same snapshot: without an announcement made with the minimum notice (-minsnapshotnotice),\n"
                "                                   recipients rely on the issuer's snapshot or on replaysnapshot\n"
                "  \"qualifier\": \"#TAG\"|null,\n"
                "  \"report\": {\"hash\": \"hex\", \"txid\": \"hex\", \"height\": n}|null  (recipients then also show their \"weight\")\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleCli("getdistributionplan", "\"TRONCO\" 12345 \"XNA\" 1000")
                + HelpExampleCli("getdistributionplan", "\"PHATSTACKS\" 12345 \"DIVIDENDS\" 1000 \"\" '{\"remainder\":\"largest\"}'")
                + HelpExampleCli("getdistributionplan", "\"&GRID\" 12345 \"XNA\" 1000 \"\" '{\"allocation\":\"equal\",\"min_held\":1}'")
                + HelpExampleRpc("getdistributionplan", "\"TRONCO\", 34987, \"DIVIDENDS\", 100000")
        );

    EnsurePlansAvailable();
    const PlanRequest req = PlanRequestFromParams(request.params);

    // The plan is immutable: the JSON of a large one is built outside cs_main
    std::shared_ptr<const PlanResult> plan;
    {
        LOCK(cs_main);
        plan = GetPlan(req);
    }
    return PlanToJSON(*plan);
}

UniValue getdistributionproof(const JSONRPCRequest& request) {
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
                "getdistributionproof {plan} \"address\"\n"
                "\nReturns the RFC 6962 inclusion proof of one recipient of a distribution plan (NIP-048). With the plan's\n"
                "merkle_root it shows that the payment is part of the plan; it does not show that the amount is right or that\n"
                "no recipient is missing (recompute the plan for that).\n"

                "\nArguments:\n"
                "1. plan                         (object, required) The plan parameters\n"
                + PLAN_OBJECT_HELP +
                "2. \"address\"                    (string, required) A recipient of the plan\n"

                "\nResult:\n"
                "{\n"
                "  \"plan_hash\": \"hex\",\n"
                "  \"merkle_root\": \"hex\",\n"
                "  \"leaf_count\": n,\n"
                "  \"index\": n,                       (number) position of the recipient in the plan\n"
                "  \"address\": \"address\",\n"
                "  \"script\": \"hex\",\n"
                "  \"amount\": x.xxx,\n"
                "  \"leaf_hash\": \"hex\",               (string) SHA-256 of 0x00 || script || amount\n"
                "  \"path\": [ \"hex\", ... ]            (array) sibling hashes, deepest first\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleCli("getdistributionproof", "'{\"asset_name\":\"TRONCO\",\"snapshot_height\":12345,\"distribution_asset_name\":\"XNA\",\"amount\":1000}' \"address\"")
        );

    EnsurePlansAvailable();
    const PlanRequest req = PlanRequestFromObject(request.params[0].get_obj());
    const std::string address = request.params[1].get_str();

    std::shared_ptr<const PlanResult> cached;
    {
        LOCK(cs_main);
        cached = GetPlan(req);
    }
    const PlanResult& plan = *cached;

    size_t index = plan.leaves.size();
    for (size_t i = 0; i < plan.leaves.size(); ++i) {
        if (plan.leaves[i].address == address) {
            index = i;
            break;
        }
    }
    if (index == plan.leaves.size())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "The address is not a recipient of this plan");

    const DistributionLeaf& leaf = plan.leaves[index];
    UniValue path(UniValue::VARR);
    for (const uint256& hash : DistributionMerkleProof(plan.leaves, index))
        path.push_back(HashHex(hash));

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("plan_hash", HashHex(plan.planHash)));
    result.push_back(Pair("merkle_root", HashHex(plan.merkleRoot)));
    result.push_back(Pair("leaf_count", static_cast<int64_t>(plan.leaves.size())));
    result.push_back(Pair("index", static_cast<int64_t>(index)));
    result.push_back(Pair("address", leaf.address));
    result.push_back(Pair("script", HexStr(leaf.script.begin(), leaf.script.end())));
    result.push_back(Pair("amount", ValueFromAmount(leaf.amount, plan.distributionUnits)));
    result.push_back(Pair("leaf_hash", HashHex(DistributionLeafHash(leaf))));
    result.push_back(Pair("path", path));
    return result;
}

UniValue getdistributionbatches(const JSONRPCRequest& request) {
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
                "getdistributionbatches {plan} ( {options} )\n"
                "\nSplits the payments of a distribution plan into batches of at most max_outputs recipients, in plan order\n"
                "(NIP-048). Each batch pays all its recipients in one transaction. Nothing is spent or locked.\n"

                "\nArguments:\n"
                "1. plan                         (object, required) The plan parameters\n"
                + PLAN_OBJECT_HELP +
                "2. options                      (object, optional)\n"
                "   {\n"
                "     \"max_outputs\": n             (number, default " + std::to_string(DEFAULT_DISTRIBUTION_BATCH_OUTPUTS) + ", max " + std::to_string(MAX_DISTRIBUTION_BATCH_OUTPUTS) + ") recipients per batch\n"
                "   }\n"

                "\nResult:\n"
                "{\n"
                "  \"plan_hash\": \"hex\",\n"
                "  \"max_outputs\": n,\n"
                "  \"batches\": [\n"
                "    {\n"
                "      \"index\": n,\n"
                "      \"batch_id\": \"hex\",          (string) SHA-256 of 0x04 || plan hash || max_outputs || index\n"
                "      \"first_recipient\": n,\n"
                "      \"recipient_count\": n,\n"
                "      \"amount\": x.xxx,            (numeric) total paid by the batch\n"
                "      \"outputs\": { ... }          (object) the payments in createrawtransaction format\n"
                "    }, ...\n"
                "  ]\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleCli("getdistributionbatches", "'{\"asset_name\":\"TRONCO\",\"snapshot_height\":12345,\"distribution_asset_name\":\"XNA\",\"amount\":1000}'")
        );

    EnsurePlansAvailable();
    const PlanRequest req = PlanRequestFromObject(request.params[0].get_obj());
    const uint32_t nMaxOutputs = request.params.size() > 1 ? ParseMaxOutputs(request.params[1].get_obj()) : DEFAULT_DISTRIBUTION_BATCH_OUTPUTS;

    std::shared_ptr<const PlanResult> cached;
    {
        LOCK(cs_main);
        cached = GetPlan(req);
    }
    const PlanResult& plan = *cached;
    const bool fDistributeXNA = plan.header.distributionAsset == "XNA";

    UniValue batches(UniValue::VARR);
    for (size_t i = 0; i < BatchCount(plan, nMaxOutputs); ++i) {
        const auto range = BatchRange(plan, nMaxOutputs, i);
        UniValue outputs(UniValue::VOBJ);
        CAmount total = 0;
        for (size_t j = range.first; j < range.second; ++j) {
            const DistributionLeaf& leaf = plan.leaves[j];
            total += leaf.amount;
            if (fDistributeXNA) {
                outputs.push_back(Pair(leaf.address, ValueFromAmount(leaf.amount)));
            } else {
                UniValue amount(UniValue::VOBJ);
                amount.push_back(Pair(plan.header.distributionAsset, ValueFromAmount(leaf.amount, plan.distributionUnits)));
                UniValue transfer(UniValue::VOBJ);
                transfer.push_back(Pair("transfer", amount));
                outputs.push_back(Pair(leaf.address, transfer));
            }
        }
        UniValue batch(UniValue::VOBJ);
        batch.push_back(Pair("index", static_cast<int64_t>(i)));
        batch.push_back(Pair("batch_id", HashHex(DistributionBatchId(plan.planHash, nMaxOutputs, i))));
        batch.push_back(Pair("first_recipient", static_cast<int64_t>(range.first)));
        batch.push_back(Pair("recipient_count", static_cast<int64_t>(range.second - range.first)));
        batch.push_back(Pair("amount", ValueFromAmount(total, plan.distributionUnits)));
        batch.push_back(Pair("outputs", outputs));
        batches.push_back(batch);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("plan_hash", HashHex(plan.planHash)));
    result.push_back(Pair("max_outputs", static_cast<int64_t>(nMaxOutputs)));
    result.push_back(Pair("batches", batches));
    return result;
}

/** What one output pays to a plan leaf: (script, amount) of the distribution asset, if any. */
static bool PaidByOutput(const CTxOut& txout, const std::string& distributionAsset, std::pair<CScript, CAmount>& paid)
{
    if (distributionAsset == "XNA") {
        if (txout.scriptPubKey.IsAssetScript())
            return false;
        paid = {txout.scriptPubKey, txout.nValue};
        return true;
    }
    CAssetOutputEntry data;
    if (!GetAssetData(txout.scriptPubKey, data) || data.type != TX_TRANSFER_ASSET || data.assetName != distributionAsset)
        return false;
    paid = {GetScriptForDestination(data.destination), data.nAmount};
    return true;
}

/** True when the transaction pays every leaf of the batch exactly. */
static bool PaysBatch(const CTransaction& tx, const PlanResult& plan, const std::pair<size_t, size_t>& range)
{
    std::multiset<std::pair<CScript, CAmount>> payments;
    for (const CTxOut& txout : tx.vout) {
        std::pair<CScript, CAmount> paid;
        if (PaidByOutput(txout, plan.header.distributionAsset, paid))
            payments.insert(paid);
    }
    for (size_t i = range.first; i < range.second; ++i) {
        const auto it = payments.find({plan.leaves[i].script, plan.leaves[i].amount});
        if (it == payments.end())
            return false;
        payments.erase(it);
    }
    return true;
}

UniValue verifydistribution(const JSONRPCRequest& request) {
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
        throw std::runtime_error(
                "verifydistribution {plan} [batches] ( {options} )\n"
                "\nClassifies the batches of a distribution plan from the operator's batch records (NIP-048): every signed\n"
                "version of each batch. Nothing is broadcast, rebuilt or spent.\n"
                "  confirmed   a version that pays the batch has the required confirmations\n"
                "  confirming  a version is in the active chain with fewer confirmations; its recipients stay reserved\n"
                "  pending     a version is in the mempool, or is signed and all its inputs are unspent; rebroadcast it\n"
                "  conflicting every version has an input spent by another transaction (needs -txindex to tell apart\n"
                "              from a confirmed version whose outputs were all spent)\n"
                "  unknown     no recorded version, or the node cannot tell; review before building anything\n"

                "\nArguments:\n"
                "1. plan                         (object, required) The plan parameters\n"
                + PLAN_OBJECT_HELP +
                "2. batches                      (array, required) The operator's batch records\n"
                "   [\n"
                "     {\n"
                "       \"index\": n,                (number, required) batch index\n"
                "       \"versions\": [              (array, required) every signed version, as hex or as\n"
                "         \"hex\" | { \"hex\": \"hex\", \"block_hash\": \"hash\" }, ...   an object with the block it was seen in\n"
                "       ]\n"
                "     }, ...\n"
                "   ]\n"
                "3. options                      (object, optional)\n"
                "   {\n"
                "     \"max_outputs\": n,            (number, default " + std::to_string(DEFAULT_DISTRIBUTION_BATCH_OUTPUTS) + ") batch size used to build the batches\n"
                "     \"confirmations\": n           (number, default 6) confirmations a batch needs to count as paid\n"
                "   }\n"

                "\nResult:\n"
                "{\n"
                "  \"plan_hash\": \"hex\",\n"
                "  \"complete\": true|false,         (boolean) every batch is confirmed\n"
                "  \"paid\": x.xxx,                  (numeric) amount in confirmed batches\n"
                "  \"reserved\": x.xxx,              (numeric) amount in confirming and pending batches\n"
                "  \"unpaid\": x.xxx,                (numeric) amount in conflicting and unknown batches\n"
                "  \"batches\": [\n"
                "    {\n"
                "      \"index\": n,\n"
                "      \"batch_id\": \"hex\",\n"
                "      \"state\": \"confirmed\"|\"confirming\"|\"pending\"|\"conflicting\"|\"unknown\",\n"
                "      \"txid\": \"hex\",              (string, optional) the version that decides the state\n"
                "      \"confirmations\": n,         (number, optional)\n"
                "      \"amount\": x.xxx,\n"
                "      \"issues\": [ \"text\", ... ]\n"
                "    }, ...\n"
                "  ]\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleCli("verifydistribution", "'{\"asset_name\":\"TRONCO\",\"snapshot_height\":12345,\"distribution_asset_name\":\"XNA\",\"amount\":1000}' '[{\"index\":0,\"versions\":[\"0200...\"]}]'")
        );

    EnsurePlansAvailable();
    const PlanRequest req = PlanRequestFromObject(request.params[0].get_obj());
    const UniValue& records = request.params[1].get_array();
    uint32_t nMaxOutputs = DEFAULT_DISTRIBUTION_BATCH_OUTPUTS;
    int nRequired = 6;
    if (request.params.size() > 2) {
        const UniValue& options = request.params[2].get_obj();
        RPCTypeCheckObj(options, {
                {"max_outputs", UniValueType(UniValue::VNUM)},
                {"confirmations", UniValueType(UniValue::VNUM)},
            }, true, true);
        nMaxOutputs = ParseMaxOutputs(options);
        if (!find_value(options, "confirmations").isNull())
            nRequired = find_value(options, "confirmations").get_int();
        if (nRequired < 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "confirmations must be at least 1");
    }

    LOCK2(cs_main, mempool.cs);
    const std::shared_ptr<const PlanResult> cached = GetPlan(req);
    const PlanResult& plan = *cached;
    const size_t nBatches = BatchCount(plan, nMaxOutputs);

    // Recorded versions per batch, with the block each was seen in when given
    std::map<size_t, std::vector<std::pair<CTransactionRef, uint256>>> versions;
    for (size_t i = 0; i < records.size(); ++i) {
        const UniValue& record = records[i].get_obj();
        const int index = find_value(record, "index").get_int();
        if (index < 0 || static_cast<size_t>(index) >= nBatches)
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Batch index %d out of range", index));
        const UniValue& list = find_value(record, "versions").get_array();
        for (size_t j = 0; j < list.size(); ++j) {
            const UniValue& entry = list[j];
            const std::string hex = entry.isStr() ? entry.get_str() : find_value(entry, "hex").get_str();
            uint256 blockHash;
            if (entry.isObject() && !find_value(entry, "block_hash").isNull())
                blockHash = ParseHashV(find_value(entry, "block_hash"), "block_hash");
            CMutableTransaction mtx;
            if (!DecodeHexTx(mtx, hex))
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Batch %d: version %u does not decode", index, j));
            versions[index].emplace_back(MakeTransactionRef(std::move(mtx)), blockHash);
        }
    }

    CAmount paid = 0, reserved = 0, unpaid = 0;
    bool fComplete = true;
    UniValue batches(UniValue::VARR);
    for (size_t i = 0; i < nBatches; ++i) {
        const auto range = BatchRange(plan, nMaxOutputs, i);
        CAmount amount = 0;
        for (size_t j = range.first; j < range.second; ++j)
            amount += plan.leaves[j].amount;

        UniValue issues(UniValue::VARR);
        std::string state = "unknown";
        uint256 decidingTxid;
        int decidingDepth = -1;
        int rank = 0; // 4 confirmed, 3 confirming, 2 pending, 1 conflicting

        const auto& batchVersions = versions[i];
        if (batchVersions.empty())
            issues.push_back("No recorded version");

        bool fAllConflicted = !batchVersions.empty();
        std::vector<const CTransaction*> live; // versions that can still confirm or did
        for (const auto& version : batchVersions) {
            const CTransaction& tx = *version.first;
            const uint256 txid = tx.GetHash();
            if (!PaysBatch(tx, plan, range)) {
                issues.push_back(strprintf("Version %s does not pay this batch", txid.GetHex()));
                fAllConflicted = false;
                continue;
            }

            // Where is this version: a given block, the transaction index, or the mempool
            int depth = 0;
            CTransactionRef located;
            const CBlockIndex* pindex = LocateTransaction(txid, version.second, located);
            if (pindex)
                depth = chainActive.Height() - pindex->nHeight + 1;

            int versionRank = 0;
            if (depth >= nRequired) {
                versionRank = 4;
            } else if (depth > 0) {
                versionRank = 3;
            } else if (mempool.exists(txid)) {
                versionRank = 2;
            } else {
                bool fInputsUnspent = true;
                for (const CTxIn& txin : tx.vin) {
                    if (!pcoinsTip->HaveCoin(txin.prevout) || mempool.isSpent(txin.prevout)) {
                        fInputsUnspent = false;
                        break;
                    }
                }
                versionRank = fInputsUnspent ? 2 : 1;
            }
            if (versionRank != 1) {
                fAllConflicted = false;
                live.push_back(&tx);
            }
            if (versionRank > rank) {
                rank = versionRank;
                decidingTxid = txid;
                decidingDepth = depth;
            }
        }

        // Live versions must spend a common input, the anchor, so only one can confirm
        if (live.size() > 1) {
            std::set<COutPoint> common;
            for (const CTxIn& txin : live[0]->vin)
                common.insert(txin.prevout);
            for (size_t v = 1; v < live.size(); ++v) {
                std::set<COutPoint> shared;
                for (const CTxIn& txin : live[v]->vin)
                    if (common.count(txin.prevout))
                        shared.insert(txin.prevout);
                common.swap(shared);
            }
            if (common.empty())
                issues.push_back("Versions that can still confirm share no input: more than one could confirm");
        }

        if (rank == 4) {
            state = "confirmed";
        } else if (rank == 3) {
            state = "confirming";
        } else if (rank == 2) {
            state = "pending";
        } else if (fAllConflicted) {
            if (fTxIndex) {
                state = "conflicting";
            } else {
                issues.push_back("Every version has a spent input and none was found: pass block_hash or enable -txindex to tell a confirmed version from a conflict");
            }
        }

        if (state == "confirmed")
            paid += amount;
        else if (state == "confirming" || state == "pending")
            reserved += amount;
        else
            unpaid += amount;
        if (state != "confirmed")
            fComplete = false;

        UniValue batch(UniValue::VOBJ);
        batch.push_back(Pair("index", static_cast<int64_t>(i)));
        batch.push_back(Pair("batch_id", HashHex(DistributionBatchId(plan.planHash, nMaxOutputs, i))));
        batch.push_back(Pair("state", state));
        if (!decidingTxid.IsNull()) {
            batch.push_back(Pair("txid", decidingTxid.GetHex()));
            batch.push_back(Pair("confirmations", decidingDepth));
        }
        batch.push_back(Pair("amount", ValueFromAmount(amount, plan.distributionUnits)));
        batch.push_back(Pair("issues", issues));
        batches.push_back(batch);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("plan_hash", HashHex(plan.planHash)));
    result.push_back(Pair("complete", fComplete));
    result.push_back(Pair("paid", ValueFromAmount(paid, plan.distributionUnits)));
    result.push_back(Pair("reserved", ValueFromAmount(reserved, plan.distributionUnits)));
    result.push_back(Pair("unpaid", ValueFromAmount(unpaid, plan.distributionUnits)));
    result.push_back(Pair("batches", batches));
    return result;
}

UniValue getsnapshotannouncement(const JSONRPCRequest& request) {
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
                "getsnapshotannouncement \"asset_name\" snapshot_height\n"
                "\nReturns the message that announces a snapshot height before the chain reaches it (NIP-048). The holder of the\n"
                "owner token sends it to itself with that message, for instance:\n"
                "  transfer \"ASSET!\" 1 \"owner_token_address\" \"message\"\n"
                "Other nodes that see the announcement request the same snapshot and can check the plan independently.\n"
                "A plan names the announcement with its \"announcement\" option.\n"

                "\nArguments:\n"
                "1. \"asset_name\"                 (string, required) The asset whose holders will be snapshotted\n"
                "2. snapshot_height              (number, required) The future snapshot height\n"

                "\nResult:\n"
                "{\n"
                "  \"asset_name\": \"name\",\n"
                "  \"snapshot_height\": n,\n"
                "  \"owner_token\": \"name\",          (string) the token that must carry the message\n"
                "  \"message\": \"hex\",               (string) SHA-256 of 0x05 || network || asset || height\n"
                "  \"minimum_notice\": n,            (number) blocks the announcement must precede the height (-minsnapshotnotice)\n"
                "  \"notice_if_mined_next\": n       (number) the notice if the announcement is mined in the next block\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleCli("getsnapshotannouncement", "\"TRONCO\" 12345")
        );

    const std::string asset_name = request.params[0].get_str();
    const int height = request.params[1].get_int();
    CheckRewardAssetName(asset_name, "asset_name");

    LOCK(cs_main);
    CNewAsset asset;
    if (!passets || !passets->GetAssetMetaDataIfExists(asset_name, asset))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid asset_name: asset does not exist");

    const uint256 message = SnapshotAnnouncementHash(GetParams().NetworkIDString(), asset_name, height);
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("asset_name", asset_name));
    result.push_back(Pair("snapshot_height", height));
    result.push_back(Pair("owner_token", asset_name + OWNER_TAG));
    result.push_back(Pair("message", HashHex(message)));
    result.push_back(Pair("minimum_notice", gArgs.GetArg("-minsnapshotnotice", DEFAULT_MIN_SNAPSHOT_NOTICE)));
    result.push_back(Pair("notice_if_mined_next", height - (chainActive.Height() + 1)));
    return result;
}

UniValue replaysnapshot(const JSONRPCRequest& request) {
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
        throw std::runtime_error(
                "replaysnapshot \"asset_name\" snapshot_height ( \"expected_snapshot_hash\" )\n"
                "\nRebuilds the holders of an asset at a height from the blocks and their undo data, without using any snapshot,\n"
                "and returns the snapshot hash they give (NIP-048). A node that did not capture the snapshot can so check a\n"
                "plan's snapshot_hash. It reads every block from asset activation to the height: it is slow, and a pruned node\n"
                "cannot do it.\n"

                "\nArguments:\n"
                "1. \"asset_name\"                 (string, required) The asset\n"
                "2. snapshot_height              (number, required) The height to rebuild\n"
                "3. \"expected_snapshot_hash\"     (string, optional) A snapshot_hash to compare with, for instance from a plan\n"

                "\nResult:\n"
                "{\n"
                "  \"asset_name\": \"name\",\n"
                "  \"height\": n,\n"
                "  \"block_hash\": \"hash\",\n"
                "  \"snapshot_hash\": \"hex\",         (string) as in getsnapshot and getdistributionplan\n"
                "  \"holders\": n,\n"
                "  \"scanned_blocks\": n,\n"
                "  \"matches_stored\": true|false|null,   (null: this node holds no snapshot at that height)\n"
                "  \"matches_expected\": true|false|null  (null: no expected hash given)\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleCli("replaysnapshot", "\"TRONCO\" 12345")
        );

    const std::string asset_name = request.params[0].get_str();
    const int height = request.params[1].get_int();
    std::string expected;
    if (request.params.size() > 2 && !request.params[2].isNull())
        expected = request.params[2].get_str();
    CheckRewardAssetName(asset_name, "asset_name");
    if (fPruneMode || fHavePruned)
        throw JSONRPCError(RPC_MISC_ERROR, "Replaying a snapshot needs every block and its undo data, and this node prunes");

    std::vector<const CBlockIndex*> blocks;
    uint256 blockHash;
    CAssetSnapshotDBEntry stored;
    bool fStored = false;
    {
        LOCK(cs_main);
        CNewAsset asset;
        if (!passets || !passets->GetAssetMetaDataIfExists(asset_name, asset))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid asset_name: asset does not exist");
        if (height < 0 || height > chainActive.Height())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid snapshot_height: block height should be less than or equal to the current active chain height");
        // The metadata height moves with reissues, so start where assets begin
        for (int h = std::max(1, GetParams().GetAssetActivationHeight()); h <= height; ++h)
            blocks.push_back(chainActive[h]);
        blockHash = chainActive[height]->GetBlockHash();
        fStored = pAssetSnapshotDb && pAssetSnapshotDb->RetrieveOwnershipSnapshot(asset_name, height, stored);
    }

    // Blocks below the tip never move on an unpruned node, so read them without
    // cs_main. Holder state follows the rules AddCoins applies to null asset data.
    std::map<std::string, CAmount> balances;
    std::map<std::string, bool> frozen;
    std::map<std::string, bool> selfRevoked;
    std::map<std::string, std::set<std::string>> tags;
    bool fGlobalFrozen = false;
    const bool fDepin = IsAssetNameADEPIN(asset_name);
    for (const CBlockIndex* pindex : blocks) {
        boost::this_thread::interruption_point();
        CBlock block;
        CBlockUndo undo;
        if (!ReadBlockFromDisk(block, pindex, GetParams().GetConsensus()) ||
            !UndoReadFromDisk(undo, pindex->GetUndoPos(), pindex->pprev->GetBlockHash()))
            throw JSONRPCError(RPC_MISC_ERROR, strprintf("Cannot read block or undo data at height %d", pindex->nHeight));
        for (size_t i = 0; i < block.vtx.size(); ++i) {
            const CTransaction& tx = *block.vtx[i];
            if (!tx.IsCoinBase()) {
                const CTxUndo& txUndo = undo.vtxundo[i - 1];
                for (size_t j = 0; j < txUndo.vprevout.size(); ++j) {
                    CAssetOutputEntry data;
                    if (GetAssetData(txUndo.vprevout[j].out.scriptPubKey, data) && data.assetName == asset_name)
                        balances[EncodeDestination(data.destination)] -= data.nAmount;
                }
            }
            for (const CTxOut& txout : tx.vout) {
                CAssetOutputEntry data;
                if (GetAssetData(txout.scriptPubKey, data) && data.assetName == asset_name)
                    balances[EncodeDestination(data.destination)] += data.nAmount;

                const CScript& script = txout.scriptPubKey;
                if (!script.IsNullAsset())
                    continue;
                CNullAssetTxData nullData;
                if (script.IsNullAssetTxDataScript()) {
                    std::string address;
                    if (!AssetNullDataFromScript(script, nullData, address))
                        continue;
                    AssetType type;
                    IsAssetNameValid(nullData.asset_name, type);
                    if (type == AssetType::QUALIFIER || type == AssetType::SUB_QUALIFIER) {
                        if (nullData.flag)
                            tags[address].insert(nullData.asset_name);
                        else
                            tags[address].erase(nullData.asset_name);
                    } else if (nullData.asset_name == asset_name && type == AssetType::RESTRICTED) {
                        frozen[address] = nullData.flag;
                    } else if (nullData.asset_name == asset_name && type == AssetType::DEPIN) {
                        if (TxContainsDEPINOwnerTokenTransfer(tx, asset_name)) {
                            frozen[address] = nullData.flag;
                            if (!nullData.flag)
                                selfRevoked[address] = false;
                        } else {
                            selfRevoked[address] = true;
                        }
                    }
                } else if (script.IsNullGlobalRestrictionAssetTxDataScript()) {
                    if (GlobalAssetNullDataFromScript(script, nullData) && nullData.asset_name == asset_name && !fDepin)
                        fGlobalFrozen = nullData.flag;
                }
            }
        }
    }

    // The asset index keeps only addresses with a positive balance
    std::set<std::pair<std::string, CAmount>> owners;
    for (const auto& balance : balances) {
        if (balance.second > 0)
            owners.insert(balance);
    }
    std::map<std::string, SnapshotHolderState> states;
    for (const auto& owner : owners) {
        SnapshotHolderState state;
        state.fFrozen = frozen.count(owner.first) && frozen.at(owner.first);
        state.fSelfRevoked = selfRevoked.count(owner.first) && selfRevoked.at(owner.first);
        if (tags.count(owner.first))
            state.tags.assign(tags.at(owner.first).begin(), tags.at(owner.first).end());
        if (state.fFrozen || state.fSelfRevoked || !state.tags.empty())
            states[owner.first] = state;
    }
    // Hash in the stored snapshot's format; with no stored snapshot, the D3 one
    const bool fWithState = !fStored || stored.fHasState;
    const uint256 snapshotHash = fWithState
            ? ComputeSnapshotHashV2(asset_name, height, blockHash, fGlobalFrozen, CanonicalHoldings(owners, states))
            : ComputeSnapshotHash(asset_name, height, blockHash, CanonicalHoldings(owners));
    const std::string hashHex = HashHex(snapshotHash);

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("asset_name", asset_name));
    result.push_back(Pair("height", height));
    result.push_back(Pair("block_hash", blockHash.GetHex()));
    result.push_back(Pair("snapshot_hash", hashHex));
    result.push_back(Pair("format", fWithState ? 2 : 1));
    result.push_back(Pair("holders", static_cast<int64_t>(CanonicalHoldings(owners).size())));
    result.push_back(Pair("scanned_blocks", static_cast<int64_t>(blocks.size())));
    if (fStored && !stored.IsLegacy())
        result.push_back(Pair("matches_stored", stored.snapshotHash == snapshotHash));
    else
        result.push_back(Pair("matches_stored", NullUniValue));
    if (!expected.empty())
        result.push_back(Pair("matches_expected", expected == hashHex));
    else
        result.push_back(Pair("matches_expected", NullUniValue));
    return result;
}

UniValue getsnapshotrecipients(const JSONRPCRequest& request) {
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
                "getsnapshotrecipients \"asset_name\" snapshot_height\n"
                "\nThe holders in a snapshot with what an encrypted bulletin to them needs (NIP-048 D5). Encryption follows DePIN\n"
                "messaging: a holder is ready when its address is P2PKH or strict ECDSA and its public key is in -pubkeyindex.\n"
                "The others are listed too, so no holder is skipped silently. Needs -pubkeyindex.\n"

                "\nArguments:\n"
                "1. \"asset_name\"                 (string, required) The asset of the snapshot\n"
                "2. snapshot_height              (number, required) The snapshot height\n"

                "\nResult:\n"
                "{\n"
                "  \"asset_name\": \"name\",\n"
                "  \"height\": n,\n"
                "  \"block_hash\": \"hash\",\n"
                "  \"snapshot_hash\": \"hex\",\n"
                "  \"ready\": n, \"key_not_revealed\": n, \"unsupported_type\": n,\n"
                "  \"holders\": [\n"
                "    {\n"
                "      \"address\": \"address\",\n"
                "      \"held\": x.xxx,\n"
                "      \"state\": \"ready\"|\"key_not_revealed\"|\"unsupported_type\",\n"
                "      \"pubkey\": \"hex\",            (string, when ready)\n"
                "      \"frozen\": bool, \"self_revoked\": bool   (snapshots with holder state)\n"
                "    }, ...\n"
                "  ]\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleCli("getsnapshotrecipients", "\"&TOKEN\" 12345")
        );

    if (!fPubKeyIndex)
        throw JSONRPCError(RPC_MISC_ERROR, "getsnapshotrecipients needs -pubkeyindex");
    if (!pAssetSnapshotDb)
        throw JSONRPCError(RPC_DATABASE_ERROR, REWARDS_INACTIVE_ERROR);
    const std::string asset_name = request.params[0].get_str();
    const int height = request.params[1].get_int();

    LOCK(cs_main);
    CNewAsset asset;
    if (!passets || !passets->GetAssetMetaDataIfExists(asset_name, asset))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid asset_name: asset does not exist");
    CAssetSnapshotDBEntry snapshot;
    if (!pAssetSnapshotDb->RetrieveOwnershipSnapshot(asset_name, height, snapshot))
        throw JSONRPCError(RPC_INVALID_REQUEST, "Snapshot not found: request it with requestsnapshot before the chain reaches that height");

    int ready = 0, notRevealed = 0, unsupported = 0;
    UniValue holders(UniValue::VARR);
    for (const auto& holding : CanonicalHoldings(snapshot.ownersAndAmounts, snapshot.states)) {
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("address", holding.address));
        entry.push_back(Pair("held", ValueFromAmount(holding.held, asset.units)));
        DepinRecipient recipient;
        CPubKey pubkey;
        std::string error;
        if (!DepinRecipient::FromAddress(holding.address, recipient)) {
            entry.push_back(Pair("state", "unsupported_type"));
            ++unsupported;
        } else if (!CheckAddressHasPublicKey(holding.address, pubkey, error)) {
            entry.push_back(Pair("state", "key_not_revealed"));
            ++notRevealed;
        } else {
            entry.push_back(Pair("state", "ready"));
            entry.push_back(Pair("pubkey", HexStr(pubkey.begin(), pubkey.end())));
            ++ready;
        }
        if (snapshot.fHasState) {
            entry.push_back(Pair("frozen", (holding.flags & HOLDER_FROZEN) != 0));
            entry.push_back(Pair("self_revoked", (holding.flags & HOLDER_SELF_REVOKED) != 0));
        }
        holders.push_back(entry);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("asset_name", asset_name));
    result.push_back(Pair("height", height));
    result.push_back(Pair("block_hash", snapshot.IsLegacy() ? "" : snapshot.blockHash.GetHex()));
    result.push_back(Pair("snapshot_hash", snapshot.IsLegacy() ? "" : HashHex(snapshot.snapshotHash)));
    result.push_back(Pair("ready", ready));
    result.push_back(Pair("key_not_revealed", notRevealed));
    result.push_back(Pair("unsupported_type", unsupported));
    result.push_back(Pair("holders", holders));
    return result;
}

#ifdef ENABLE_WALLET
UniValue createdistributionbatch(const JSONRPCRequest& request) {
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 4)
        throw std::runtime_error(
                "createdistributionbatch \"plan_hash\" {plan} batch_index ( {options} )\n"
                "\nBuilds, funds and signs one batch of a distribution plan from this wallet (NIP-048), and locks the inputs it\n"
                "spends. It does NOT broadcast: store the result in your batch records first, then send it with\n"
                "sendrawtransaction. The plan must still hash to plan_hash, so a payment is always bound to the plan the\n"
                "operator approved.\n"
                "To replace a version that left the mempool, build a new one with the same anchor: every version of a batch\n"
                "spends the anchor, so at most one of them can confirm.\n"

                "\nArguments:\n"
                "1. \"plan_hash\"                  (string, required) The approved plan hash, from getdistributionplan\n"
                "2. plan                         (object, required) The plan parameters\n"
                + PLAN_OBJECT_HELP +
                "3. batch_index                  (number, required) The batch to build, from getdistributionbatches\n"
                "4. options                      (object, optional)\n"
                "   {\n"
                "     \"max_outputs\": n,            (number, default " + std::to_string(DEFAULT_DISTRIBUTION_BATCH_OUTPUTS) + ") batch size, as in getdistributionbatches\n"
                "     \"anchor\": {\"txid\": \"hex\", \"vout\": n}, (object, optional) the anchor of earlier versions of this batch\n"
                "     \"max_fee\": x.xxx             (numeric, optional) refuse a fee above this amount of XNA\n"
                "   }\n"

                "\nResult:\n"
                "{\n"
                "  \"plan_hash\": \"hex\",\n"
                "  \"batch_index\": n,\n"
                "  \"batch_id\": \"hex\",\n"
                "  \"txid\": \"hex\",\n"
                "  \"hex\": \"hex\",                     (string) the signed transaction, not broadcast\n"
                "  \"fee\": x.xxx,\n"
                "  \"anchor\": {\"txid\": \"hex\", \"vout\": n}, (object) the XNA input every later version must spend\n"
                "  \"inputs\": [ {\"txid\": \"hex\", \"vout\": n}, ... ] (array) inputs, now locked in this wallet\n"
                "}\n"

                "\nExamples:\n"
                + HelpExampleCli("createdistributionbatch", "\"planhash\" '{\"asset_name\":\"TRONCO\",\"snapshot_height\":12345,\"distribution_asset_name\":\"XNA\",\"amount\":1000}' 0")
        );

    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp))
        return NullUniValue;

    EnsurePlansAvailable();
    const std::string expectedHash = request.params[0].get_str();
    const PlanRequest req = PlanRequestFromObject(request.params[1].get_obj());
    const int batchIndex = request.params[2].get_int();

    uint32_t nMaxOutputs = DEFAULT_DISTRIBUTION_BATCH_OUTPUTS;
    bool fAnchor = false;
    COutPoint anchor;
    CAmount nMaxFee = -1;
    if (request.params.size() > 3) {
        const UniValue& options = request.params[3].get_obj();
        RPCTypeCheckObj(options, {
                {"max_outputs", UniValueType(UniValue::VNUM)},
                {"anchor", UniValueType(UniValue::VOBJ)},
                {"max_fee", UniValueType()},
            }, true, true);
        nMaxOutputs = ParseMaxOutputs(options);
        const UniValue& anchorObj = find_value(options, "anchor");
        if (!anchorObj.isNull()) {
            anchor = COutPoint(ParseHashO(anchorObj, "txid"), find_value(anchorObj, "vout").get_int());
            fAnchor = true;
        }
        if (!find_value(options, "max_fee").isNull())
            nMaxFee = AmountFromValue(find_value(options, "max_fee"));
    }

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);

    const std::shared_ptr<const PlanResult> cached = GetPlan(req);
    const PlanResult& plan = *cached;
    if (HashHex(plan.planHash) != expectedHash)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "plan_hash does not match the plan: the snapshot, the parameters or the chain changed");
    if (batchIndex < 0 || static_cast<size_t>(batchIndex) >= BatchCount(plan, nMaxOutputs))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "batch_index out of range");
    const auto range = BatchRange(plan, nMaxOutputs, batchIndex);

    CCoinControl coinControl;
    if (fAnchor) {
        const CWalletTx* anchorTx = pwallet->GetWalletTx(anchor.hash);
        if (!anchorTx || anchor.n >= anchorTx->tx->vout.size() || pwallet->IsSpent(anchor.hash, anchor.n) ||
            !(pwallet->IsMine(anchorTx->tx->vout[anchor.n]) & ISMINE_SPENDABLE) ||
            anchorTx->tx->vout[anchor.n].scriptPubKey.IsAssetScript())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "The anchor is not an unspent XNA output of this wallet");
        // The previous version locked it; the new version must spend it
        pwallet->UnlockCoin(anchor);
        coinControl.Select(anchor);
        coinControl.fAllowOtherInputs = true;
    }

    CWalletTx wtx;
    CReserveKey reservekey(pwallet);
    CAmount nFee = 0;
    if (plan.header.distributionAsset == "XNA") {
        std::vector<CRecipient> vecSend;
        for (size_t i = range.first; i < range.second; ++i)
            vecSend.push_back({plan.leaves[i].script, plan.leaves[i].amount, false});
        int nChangePos = -1;
        std::string strError;
        if (!pwallet->CreateTransaction(vecSend, wtx, reservekey, nFee, nChangePos, strError, coinControl))
            throw JSONRPCError(RPC_WALLET_ERROR, strError);
    } else {
        std::vector<std::pair<CAssetTransfer, std::string>> transfers;
        for (size_t i = range.first; i < range.second; ++i)
            transfers.emplace_back(CAssetTransfer(plan.header.distributionAsset, plan.leaves[i].amount), plan.leaves[i].address);
        std::pair<int, std::string> error;
        if (!CreateTransferAssetTransaction(pwallet, coinControl, transfers, "", error, wtx, reservekey, nFee))
            throw JSONRPCError(error.first, error.second);
    }
    if (nMaxFee >= 0 && nFee > nMaxFee)
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("The batch needs a fee of %s, above max_fee", FormatMoney(nFee)));

    const CTransaction& tx = *wtx.tx;
    if (!PaysBatch(tx, plan, range))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "The built transaction does not pay the batch");

    // Keep the change key out of the pool, and lock the inputs so that building
    // another batch cannot spend them before this one is broadcast.
    reservekey.KeepKey();
    UniValue inputs(UniValue::VARR);
    for (const CTxIn& txin : tx.vin) {
        pwallet->LockCoin(txin.prevout);
        UniValue input(UniValue::VOBJ);
        input.push_back(Pair("txid", txin.prevout.hash.GetHex()));
        input.push_back(Pair("vout", static_cast<int64_t>(txin.prevout.n)));
        inputs.push_back(input);
        if (!fAnchor) {
            const CWalletTx* prev = pwallet->GetWalletTx(txin.prevout.hash);
            if (prev && !prev->tx->vout[txin.prevout.n].scriptPubKey.IsAssetScript()) {
                anchor = txin.prevout;
                fAnchor = true;
            }
        }
    }
    if (!fAnchor)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "The batch spends no XNA input to use as anchor");

    UniValue anchorObj(UniValue::VOBJ);
    anchorObj.push_back(Pair("txid", anchor.hash.GetHex()));
    anchorObj.push_back(Pair("vout", static_cast<int64_t>(anchor.n)));

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("plan_hash", HashHex(plan.planHash)));
    result.push_back(Pair("batch_index", batchIndex));
    result.push_back(Pair("batch_id", HashHex(DistributionBatchId(plan.planHash, nMaxOutputs, batchIndex))));
    result.push_back(Pair("txid", tx.GetHash().GetHex()));
    result.push_back(Pair("hex", EncodeHexTx(tx)));
    result.push_back(Pair("fee", ValueFromAmount(nFee)));
    result.push_back(Pair("anchor", anchorObj));
    result.push_back(Pair("inputs", inputs));
    return result;
}
#endif

static const CRPCCommand commands[] =
    {           //  category    name                          actor (function)             argNames
                //  ----------- ------------------------      -----------------------      ----------
#ifdef ENABLE_WALLET
            {   "rewards",      "requestsnapshot",            &requestsnapshot,            {"asset_name", "block_height"}},
            {   "rewards",      "getsnapshotrequest",         &getsnapshotrequest,         {"asset_name", "block_height"}},
            {   "rewards",      "listsnapshotrequests",         &listsnapshotrequests,         {"asset_name", "block_height"}},
            {   "rewards",      "cancelsnapshotrequest",      &cancelsnapshotrequest,      {"asset_name", "block_height"}},
            {   "rewards",      "distributereward",           &distributereward,           {"asset_name", "snapshot_height", "distribution_asset_name", "gross_distribution_amount", "exception_addresses", "change_address"}},
            {   "rewards",      "getdistributestatus",        &getdistributestatus,            {"asset_name", "block_height", "distribution_asset_name", "gross_distribution_amount", "exception_addresses"}},
            {   "rewards",      "createdistributionbatch",    &createdistributionbatch,    {"plan_hash", "plan", "batch_index", "options"}},
    #endif
            {   "rewards",      "getdistributionplan",        &getdistributionplan,        {"asset_name", "snapshot_height", "distribution_asset_name", "gross_distribution_amount", "exception_addresses", "options"}},
            {   "rewards",      "getdistributionproof",       &getdistributionproof,       {"plan", "address"}},
            {   "rewards",      "getdistributionbatches",     &getdistributionbatches,     {"plan", "options"}},
            {   "rewards",      "verifydistribution",         &verifydistribution,         {"plan", "batches", "options"}},
            {   "rewards",      "getsnapshotannouncement",    &getsnapshotannouncement,    {"asset_name", "snapshot_height"}},
            {   "rewards",      "replaysnapshot",             &replaysnapshot,             {"asset_name", "snapshot_height", "expected_snapshot_hash"}},
            {   "rewards",      "getsnapshotrecipients",      &getsnapshotrecipients,      {"asset_name", "snapshot_height"}},
    };

void RegisterRewardsRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}


