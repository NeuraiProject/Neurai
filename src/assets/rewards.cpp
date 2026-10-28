// Copyright (c) 2017-2020 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assets/rewards.h"

#include "arith_uint256.h"
#include "base58.h"
#include "crypto/sha256.h"
#include "hash.h"
#include "script/standard.h"
#include "streams.h"
#include "version.h"

#include <algorithm>
#include <numeric>

uint256 CRewardSnapshot::GetHash() const
{
    return SerializeHash(*this, SER_GETHASH);
}

namespace {

// Domain tags keep leaves, inner nodes, plans and snapshots from colliding.
enum : uint8_t {
    TAG_LEAF = 0x00,
    TAG_NODE = 0x01,
    TAG_PLAN = 0x02,
    TAG_SNAPSHOT = 0x03,
    TAG_BATCH = 0x04,
    TAG_ANNOUNCEMENT = 0x05,
    TAG_SNAPSHOT_V2 = 0x06,
    TAG_REPORT = 0x07,
};

uint256 TaggedHash(uint8_t tag, const CDataStream& data)
{
    uint256 result;
    CSHA256().Write(&tag, 1).Write(reinterpret_cast<const unsigned char*>(data.data()), data.size()).Finalize(result.begin());
    return result;
}

bool ScriptLess(const CScript& a, const CScript& b)
{
    return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end());
}

uint256 NodeHash(const uint256& left, const uint256& right)
{
    const uint8_t tag = TAG_NODE;
    uint256 result;
    CSHA256().Write(&tag, 1).Write(left.begin(), left.size()).Write(right.begin(), right.size()).Finalize(result.begin());
    return result;
}

// RFC 6962: split at the largest power of two smaller than the size
size_t MerkleSplit(size_t size)
{
    size_t split = 1;
    while (split * 2 < size)
        split *= 2;
    return split;
}

uint256 MerkleSubtree(const std::vector<uint256>& hashes, size_t begin, size_t end)
{
    if (end - begin == 1)
        return hashes[begin];
    const size_t split = MerkleSplit(end - begin);
    return NodeHash(MerkleSubtree(hashes, begin, begin + split), MerkleSubtree(hashes, begin + split, end));
}

void MerklePath(const std::vector<uint256>& hashes, size_t index, size_t begin, size_t end, std::vector<uint256>& path)
{
    if (end - begin <= 1)
        return;
    const size_t split = MerkleSplit(end - begin);
    if (index < begin + split) {
        MerklePath(hashes, index, begin, begin + split, path);
        path.push_back(MerkleSubtree(hashes, begin + split, end));
    } else {
        MerklePath(hashes, index, begin + split, end, path);
        path.push_back(MerkleSubtree(hashes, begin, begin + split));
    }
}

} // namespace

std::vector<DistributionHolding> CanonicalHoldings(const std::set<std::pair<std::string, CAmount>>& owners)
{
    std::vector<DistributionHolding> holdings;
    holdings.reserve(owners.size());
    for (const auto& owner : owners) {
        const CTxDestination dest = DecodeDestination(owner.first);
        if (!IsValidDestination(dest))
            continue;
        holdings.push_back({owner.first, GetScriptForDestination(dest), owner.second});
    }
    std::sort(holdings.begin(), holdings.end(), [](const DistributionHolding& a, const DistributionHolding& b) {
        return ScriptLess(a.script, b.script);
    });
    return holdings;
}

std::vector<DistributionHolding> CanonicalHoldings(const std::set<std::pair<std::string, CAmount>>& owners,
                                                   const std::map<std::string, SnapshotHolderState>& states)
{
    std::vector<DistributionHolding> holdings = CanonicalHoldings(owners);
    for (auto& holding : holdings) {
        const auto it = states.find(holding.address);
        if (it == states.end())
            continue;
        holding.flags = (it->second.fFrozen ? HOLDER_FROZEN : 0) | (it->second.fSelfRevoked ? HOLDER_SELF_REVOKED : 0);
        holding.tags = it->second.tags;
        std::sort(holding.tags.begin(), holding.tags.end());
    }
    return holdings;
}

uint256 ComputeSnapshotHashV2(const std::string& asset, int height, const uint256& blockHash, bool fGlobalFrozen,
                              const std::vector<DistributionHolding>& holdings)
{
    CDataStream ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << asset << height << blockHash << static_cast<uint8_t>(fGlobalFrozen ? 1 : 0);
    WriteCompactSize(ss, holdings.size());
    for (const auto& holding : holdings)
        ss << holding.script << holding.held << holding.flags << holding.tags;
    return TaggedHash(TAG_SNAPSHOT_V2, ss);
}

uint256 DistributionReportHash(const std::map<std::string, int64_t>& weights)
{
    CDataStream ss(SER_GETHASH, PROTOCOL_VERSION);
    WriteCompactSize(ss, weights.size());
    for (const auto& weight : weights)
        ss << weight.first << weight.second;
    return TaggedHash(TAG_REPORT, ss);
}

uint256 ComputeSnapshotHash(const std::string& asset, int height, const uint256& blockHash,
                            const std::vector<DistributionHolding>& holdings)
{
    CDataStream ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << asset << height << blockHash;
    WriteCompactSize(ss, holdings.size());
    for (const auto& holding : holdings)
        ss << holding.script << holding.held;
    return TaggedHash(TAG_SNAPSHOT, ss);
}

bool AllocateDistribution(const std::vector<DistributionHolding>& holdings, CAmount nAmount, CAmount nUnit,
                          RemainderPolicy policy, std::vector<DistributionLeaf>& leaves,
                          std::vector<DistributionHolding>& zeroAmount, CAmount& nRemainder, std::string& strError)
{
    leaves.clear();
    zeroAmount.clear();
    nRemainder = 0;

    if (nUnit <= 0 || nAmount <= 0 || nAmount % nUnit != 0) {
        strError = "The amount must be a positive multiple of the distribution asset's smallest unit";
        return false;
    }
    if (holdings.empty()) {
        strError = "No eligible holders";
        return false;
    }

    arith_uint256 total;
    for (const auto& holding : holdings) {
        if (holding.held <= 0) {
            strError = "Holdings must be positive";
            return false;
        }
        total += arith_uint256(static_cast<uint64_t>(holding.held));
    }

    // Shares in whole units. A * h_i needs more than 64 bits, so the products,
    // quotients and fractional parts are exact 256-bit integers.
    const uint64_t units = static_cast<uint64_t>(nAmount / nUnit);
    std::vector<uint64_t> shares(holdings.size());
    std::vector<arith_uint256> fractions(holdings.size());
    uint64_t assigned = 0;
    for (size_t i = 0; i < holdings.size(); ++i) {
        const arith_uint256 product = arith_uint256(units) * arith_uint256(static_cast<uint64_t>(holdings[i].held));
        const arith_uint256 share = product / total;
        shares[i] = share.GetLow64();
        fractions[i] = product - share * total;
        assigned += shares[i];
    }

    // The fractional parts add up to less than one unit per holder.
    uint64_t left = units - assigned;
    if (policy == RemainderPolicy::LARGEST && left > 0) {
        std::vector<size_t> order(holdings.size());
        std::iota(order.begin(), order.end(), 0);
        // Holdings are in script order, so a stable sort breaks ties by script.
        std::stable_sort(order.begin(), order.end(), [&fractions](size_t a, size_t b) {
            return fractions[a] > fractions[b];
        });
        for (size_t i = 0; i < left && i < order.size(); ++i)
            shares[order[i]]++;
        left = 0;
    }

    for (size_t i = 0; i < holdings.size(); ++i) {
        const CAmount amount = static_cast<CAmount>(shares[i]) * nUnit;
        if (amount > 0)
            leaves.push_back({holdings[i].address, holdings[i].script, holdings[i].held, amount});
        else
            zeroAmount.push_back(holdings[i]);
    }
    nRemainder = static_cast<CAmount>(left) * nUnit;
    return true;
}

uint256 DistributionLeafHash(const DistributionLeaf& leaf)
{
    CDataStream ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << leaf.script << leaf.amount;
    return TaggedHash(TAG_LEAF, ss);
}

uint256 DistributionMerkleRoot(const std::vector<DistributionLeaf>& leaves)
{
    if (leaves.empty()) {
        // RFC 6962: the hash of an empty tree is the hash of the empty string
        uint256 result;
        CSHA256().Finalize(result.begin());
        return result;
    }
    std::vector<uint256> hashes;
    hashes.reserve(leaves.size());
    for (const auto& leaf : leaves)
        hashes.push_back(DistributionLeafHash(leaf));
    return MerkleSubtree(hashes, 0, hashes.size());
}

std::vector<uint256> DistributionMerkleProof(const std::vector<DistributionLeaf>& leaves, size_t nIndex)
{
    std::vector<uint256> path;
    if (nIndex >= leaves.size())
        return path;
    std::vector<uint256> hashes;
    hashes.reserve(leaves.size());
    for (const auto& leaf : leaves)
        hashes.push_back(DistributionLeafHash(leaf));
    MerklePath(hashes, nIndex, 0, hashes.size(), path);
    return path;
}

bool VerifyDistributionMerkleProof(const uint256& leafHash, size_t nIndex, size_t nCount,
                                   const std::vector<uint256>& path, const uint256& root)
{
    if (nIndex >= nCount)
        return false;
    size_t fn = nIndex;
    size_t sn = nCount - 1;
    uint256 r = leafHash;
    for (const uint256& p : path) {
        if (sn == 0)
            return false;
        if ((fn & 1) || fn == sn) {
            r = NodeHash(p, r);
            while (!(fn & 1) && fn != 0) {
                fn >>= 1;
                sn >>= 1;
            }
        } else {
            r = NodeHash(r, p);
        }
        fn >>= 1;
        sn >>= 1;
    }
    return sn == 0 && r == root;
}

uint256 DistributionBatchId(const uint256& planHash, uint32_t nMaxOutputs, uint32_t nIndex)
{
    CDataStream ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << planHash << nMaxOutputs << nIndex;
    return TaggedHash(TAG_BATCH, ss);
}

uint8_t DistributionPlanVersion(const DistributionPlanHeader& header)
{
    if (header.allocation != DistributionAllocation::HOLDINGS || header.minHeld != 0)
        return DISTRIBUTION_PLAN_VERSION_ALLOCATION;
    if (!header.qualifier.empty() || !header.reportHash.IsNull())
        return DISTRIBUTION_PLAN_VERSION_RULES;
    return header.announcementTxid.IsNull() ? DISTRIBUTION_PLAN_VERSION : DISTRIBUTION_PLAN_VERSION_ANNOUNCED;
}

uint256 ComputePlanHash(const DistributionPlanHeader& header, const uint256& merkleRoot)
{
    const uint8_t version = DistributionPlanVersion(header);
    CDataStream ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << version << header.network << header.ownershipAsset << header.height
       << header.blockHash << header.snapshotHash;
    if (version >= DISTRIBUTION_PLAN_VERSION_ANNOUNCED)
        ss << header.announcementTxid;
    if (version >= DISTRIBUTION_PLAN_VERSION_RULES)
        ss << header.qualifier << header.reportHash;
    if (version >= DISTRIBUTION_PLAN_VERSION_ALLOCATION)
        ss << static_cast<uint8_t>(header.allocation) << header.minHeld;
    ss << header.distributionAsset << header.amount
       << static_cast<uint8_t>(header.policy) << header.exclusions << header.distributed
       << header.remainder << header.leafCount << merkleRoot;
    return TaggedHash(TAG_PLAN, ss);
}

uint256 SnapshotAnnouncementHash(const std::string& network, const std::string& asset, int height)
{
    CDataStream ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << network << asset << height;
    return TaggedHash(TAG_ANNOUNCEMENT, ss);
}
