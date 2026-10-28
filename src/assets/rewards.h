// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAICOIN_REWARDS_H
#define NEURAICOIN_REWARDS_H

#include "amount.h"
#include "tinyformat.h"
#include "assettypes.h"
#include "script/script.h"
#include "uint256.h"

#include <map>
#include <string>
#include <set>
#include <vector>

//  Addresses are delimited by commas
static const std::string ADDRESS_COMMA_DELIMITER = ",";

/** A distribution recorded by the retired in-node payer (NIP-048 B0). The node
 *  no longer creates or resumes these; getdistributestatus still reads them. */
class CRewardSnapshot {
public:
    enum {
        REWARD_ERROR = 0,
        PROCESSING = 1,
        COMPLETE = 2,
        LOW_FUNDS = 3,
        NOT_ENOUGH_FEE = 4,
        LOW_REWARDS = 5,
        STUCK_TX = 6,
        NETWORK_ERROR = 7,
        FAILED_CREATE_TRANSACTION = 8,
        FAILED_COMMIT_TRANSACTION = 9
    };

    std::string strOwnershipAsset;
    std::string strDistributionAsset;
    std::string strExceptionAddresses;
    CAmount nDistributionAmount;
    uint32_t nHeight;
    int nStatus;

    CRewardSnapshot() {
        SetNull();
    }

    CRewardSnapshot(const std::string& p_strOwnershipAsset, const std::string& p_strDistributionAsset, const std::string& p_strExceptionAddresses, const CAmount& p_nDistributionAmount, const uint32_t& p_nHeight) {
        SetNull();
        strOwnershipAsset = p_strOwnershipAsset;
        strDistributionAsset = p_strDistributionAsset;
        strExceptionAddresses = p_strExceptionAddresses;
        nDistributionAmount = p_nDistributionAmount;
        nHeight = p_nHeight;
        nStatus = PROCESSING;
    }

    void SetNull() {
        strOwnershipAsset = "";
        strDistributionAsset = "";
        strExceptionAddresses = "";
        nDistributionAmount = 0;
        nHeight = 0;
        nStatus = REWARD_ERROR;
    }

    uint256 GetHash() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(strOwnershipAsset);
        READWRITE(strDistributionAsset);
        READWRITE(strExceptionAddresses);
        READWRITE(nDistributionAmount);
        READWRITE(nHeight);
        // We don't want to add the status when computing the hash because it changes as the distribution is sent out
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nStatus);
    }
};

/** NIP-048 B1-B2: deterministic reward plans. The node computes who receives
 *  how much from a snapshot and commits to it with a plan hash; it never builds
 *  or sends the payments. Hashes are single SHA-256 with a one-byte domain tag. */

static const uint8_t DISTRIBUTION_PLAN_VERSION = 1;
/** NIP-048 B5: a plan whose snapshot height was announced in advance commits
 *  to the announcement transaction too. */
static const uint8_t DISTRIBUTION_PLAN_VERSION_ANNOUNCED = 2;
/** NIP-048 D3: a plan with a qualifier filter or report weights commits to them. */
static const uint8_t DISTRIBUTION_PLAN_VERSION_RULES = 3;
/** A plan with equal shares or a minimum holding commits to them too. */
static const uint8_t DISTRIBUTION_PLAN_VERSION_ALLOCATION = 4;
static const int DEFAULT_MIN_SNAPSHOT_NOTICE = 60;
/** Snapshot requests accepted at one height: each is captured while the block
 *  connects, reading every holder of its asset. 0: no limit. */
static const int DEFAULT_MAX_SNAPSHOT_REQUESTS = 16;

/** NIP-048 D3: restriction and tag state of a holder at the snapshot height. */
struct SnapshotHolderState {
    bool fFrozen = false;           //!< frozen for the asset: restricted asset or DEPIN owner freeze
    bool fSelfRevoked = false;      //!< a DEPIN holder that revoked itself
    std::vector<std::string> tags;  //!< qualifier tags of the address, sorted

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(fFrozen);
        READWRITE(fSelfRevoked);
        READWRITE(tags);
    }
};

static const uint8_t HOLDER_FROZEN = 0x01;
static const uint8_t HOLDER_SELF_REVOKED = 0x02;

enum class RemainderPolicy : uint8_t {
    PAYER = 0,   //!< the undivided remainder stays with the payer
    LARGEST = 1, //!< one unit each to the largest fractional parts, ties by script
};

enum class DistributionAllocation : uint8_t {
    HOLDINGS = 0, //!< in proportion to the holdings, or to report weights
    EQUAL = 1,    //!< the same share to every eligible holder, whatever it holds
};

/** A holder at the snapshot height. */
struct DistributionHolding {
    std::string address;
    CScript script;
    CAmount held;
    uint8_t flags = 0;              //!< HOLDER_* bits, from a snapshot with holder state
    std::vector<std::string> tags;  //!< sorted qualifier tags, from a snapshot with holder state
};

/** A payment of the plan. */
struct DistributionLeaf {
    std::string address;
    CScript script;
    CAmount held;
    CAmount amount;
};

/** The fields a plan hash commits to besides its leaves. */
struct DistributionPlanHeader {
    std::string network;
    std::string ownershipAsset;
    int height;
    uint256 blockHash;
    uint256 snapshotHash;
    uint256 announcementTxid; //!< null: not announced (format version 1)
    std::string qualifier;    //!< D3: only holders with this tag; empty: no filter
    uint256 reportHash;       //!< D3: weights from this report; null: holdings are the weights
    DistributionAllocation allocation = DistributionAllocation::HOLDINGS;
    CAmount minHeld = 0;      //!< only holders with at least this holding; 0: no minimum
    std::string distributionAsset;
    CAmount amount;
    RemainderPolicy policy;
    std::vector<std::string> exclusions; //!< sorted
    CAmount distributed;
    CAmount remainder;
    uint32_t leafCount;
};

/** Holders with a valid destination, sorted by script bytes. */
std::vector<DistributionHolding> CanonicalHoldings(const std::set<std::pair<std::string, CAmount>>& owners);

/** The same, with the holder state of a D3 snapshot attached. */
std::vector<DistributionHolding> CanonicalHoldings(const std::set<std::pair<std::string, CAmount>>& owners,
                                                   const std::map<std::string, SnapshotHolderState>& states);

/** Commits to a snapshot: asset, height, block hash (null for a legacy
 *  snapshot), then every holding in canonical order. */
uint256 ComputeSnapshotHash(const std::string& asset, int height, const uint256& blockHash,
                            const std::vector<DistributionHolding>& holdings);

/** D3 snapshot (version 2): also the global freeze of the asset and, per
 *  holding, its HOLDER_* flags and qualifier tags. */
uint256 ComputeSnapshotHashV2(const std::string& asset, int height, const uint256& blockHash, bool fGlobalFrozen,
                              const std::vector<DistributionHolding>& holdings);

/** D3: commits to report weights (address -> positive weight), by address. */
uint256 DistributionReportHash(const std::map<std::string, int64_t>& weights);

/** Splits nAmount, a positive multiple of nUnit, among the holdings in whole
 *  units: q_i = floor(A * h_i / H) with exact integer arithmetic. Leaves keep the
 *  holdings order; holders whose share is zero go to zeroAmount. nRemainder is
 *  what stays undistributed (always 0 under LARGEST). */
bool AllocateDistribution(const std::vector<DistributionHolding>& holdings, CAmount nAmount, CAmount nUnit,
                          RemainderPolicy policy, std::vector<DistributionLeaf>& leaves,
                          std::vector<DistributionHolding>& zeroAmount, CAmount& nRemainder, std::string& strError);

uint256 DistributionLeafHash(const DistributionLeaf& leaf);

/** RFC 6962 Merkle tree over the leaf hashes, in leaf order. */
uint256 DistributionMerkleRoot(const std::vector<DistributionLeaf>& leaves);

uint256 ComputePlanHash(const DistributionPlanHeader& header, const uint256& merkleRoot);

/** Format version a header hashes under: 4 with equal shares or a minimum
 *  holding, else 3 with a qualifier filter or report weights, else 2 when it
 *  names an announcement, else 1. */
uint8_t DistributionPlanVersion(const DistributionPlanHeader& header);

/** The message the owner token carries to announce a snapshot height before it
 *  is reached, so that independent nodes request the same snapshot. */
uint256 SnapshotAnnouncementHash(const std::string& network, const std::string& asset, int height);

/** RFC 6962 audit path for the leaf at nIndex, deepest sibling first. */
std::vector<uint256> DistributionMerkleProof(const std::vector<DistributionLeaf>& leaves, size_t nIndex);

/** RFC 9162 inclusion check of a leaf hash at nIndex in a tree of nCount leaves. */
bool VerifyDistributionMerkleProof(const uint256& leafHash, size_t nIndex, size_t nCount,
                                   const std::vector<uint256>& path, const uint256& root);

/** NIP-048 B4: payments are sent in batches of at most nMaxOutputs leaves, in
 *  leaf order. A batch is identified by the plan, the batch size and its index. */
static const unsigned int DEFAULT_DISTRIBUTION_BATCH_OUTPUTS = 500;
static const unsigned int MAX_DISTRIBUTION_BATCH_OUTPUTS = 1000;

uint256 DistributionBatchId(const uint256& planHash, uint32_t nMaxOutputs, uint32_t nIndex);

#endif //NEURAICOIN_REWARDS_H
