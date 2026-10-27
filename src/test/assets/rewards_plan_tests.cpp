// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NIP-048 B1-B2: integer allocation and plan hashing. The pinned hashes come
// from an independent Python implementation of the format in the NIP.

#include <assets/rewards.h>

#include <test/test_neurai.h>

#include <boost/test/unit_test.hpp>

#include <amount.h>
#include <base58.h>
#include <crypto/sha256.h>
#include <script/standard.h>
#include <utilstrencodings.h>
#include <test/data/nip048_vectors.json.h>

#include <univalue.h>

namespace {

CScript P2PKH(unsigned char fill)
{
    return GetScriptForDestination(CKeyID(uint160(std::vector<unsigned char>(20, fill))));
}

DistributionHolding Holding(unsigned char fill, CAmount held)
{
    const CScript script = P2PKH(fill);
    CTxDestination dest;
    ExtractDestination(script, dest);
    return {EncodeDestination(dest), script, held};
}

std::string Hex(const uint256& hash)
{
    return HexStr(hash.begin(), hash.end());
}

CScript ScriptFromHex(const std::string& hex)
{
    const std::vector<unsigned char> bytes = ParseHex(hex);
    return CScript(bytes.begin(), bytes.end());
}

/** A hash given as hex in internal byte order. */
uint256 RawHash(const std::string& hex)
{
    return uint256(ParseHex(hex));
}

std::vector<DistributionLeaf> LeavesOf(const UniValue& items)
{
    std::vector<DistributionLeaf> leaves;
    for (const UniValue& item : items.getValues())
        leaves.push_back({"", ScriptFromHex(item[0].get_str()), 0, item[1].get_int64()});
    return leaves;
}

std::vector<CAmount> Amounts(const std::vector<DistributionLeaf>& leaves)
{
    std::vector<CAmount> amounts;
    for (const auto& leaf : leaves)
        amounts.push_back(leaf.amount);
    return amounts;
}

bool Allocate(const std::vector<DistributionHolding>& holdings, CAmount amount, CAmount unit, RemainderPolicy policy,
              std::vector<DistributionLeaf>& leaves, std::vector<DistributionHolding>& zero, CAmount& remainder)
{
    std::string error;
    return AllocateDistribution(holdings, amount, unit, policy, leaves, zero, remainder, error);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(rewards_plan_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(allocation_floor_and_remainder)
{
    std::vector<DistributionLeaf> leaves;
    std::vector<DistributionHolding> zero;
    CAmount remainder;

    // Exact split
    BOOST_CHECK(Allocate({Holding(1, 100), Holding(2, 200), Holding(3, 300)}, 600, 1, RemainderPolicy::PAYER, leaves, zero, remainder));
    BOOST_CHECK(Amounts(leaves) == std::vector<CAmount>({100, 200, 300}));
    BOOST_CHECK_EQUAL(remainder, 0);

    // Payer keeps what does not divide
    BOOST_CHECK(Allocate({Holding(1, 1), Holding(2, 1), Holding(3, 1)}, 10, 1, RemainderPolicy::PAYER, leaves, zero, remainder));
    BOOST_CHECK(Amounts(leaves) == std::vector<CAmount>({3, 3, 3}));
    BOOST_CHECK_EQUAL(remainder, 1);

    // Largest remainder, equal fractions: the smallest script wins the tie
    BOOST_CHECK(Allocate({Holding(1, 1), Holding(2, 1), Holding(3, 1)}, 10, 1, RemainderPolicy::LARGEST, leaves, zero, remainder));
    BOOST_CHECK(Amounts(leaves) == std::vector<CAmount>({4, 3, 3}));
    BOOST_CHECK_EQUAL(remainder, 0);

    // Largest remainder: 7 * (5, 3, 2) / 10 = (3.5, 2.1, 1.4) -> (4, 2, 1)
    BOOST_CHECK(Allocate({Holding(1, 5), Holding(2, 3), Holding(3, 2)}, 7, 1, RemainderPolicy::LARGEST, leaves, zero, remainder));
    BOOST_CHECK(Amounts(leaves) == std::vector<CAmount>({4, 2, 1}));
    BOOST_CHECK_EQUAL(remainder, 0);
}

BOOST_AUTO_TEST_CASE(allocation_units)
{
    std::vector<DistributionLeaf> leaves;
    std::vector<DistributionHolding> zero;
    CAmount remainder;

    // An asset with 0 units moves in whole coins
    BOOST_CHECK(Allocate({Holding(1, 1), Holding(2, 1), Holding(3, 1)}, 10 * COIN, COIN, RemainderPolicy::PAYER, leaves, zero, remainder));
    BOOST_CHECK(Amounts(leaves) == std::vector<CAmount>({3 * COIN, 3 * COIN, 3 * COIN}));
    BOOST_CHECK_EQUAL(remainder, COIN);

    // The amount must be a whole number of units
    std::string error;
    BOOST_CHECK(!AllocateDistribution({Holding(1, 1)}, COIN + 1, COIN, RemainderPolicy::PAYER, leaves, zero, remainder, error));
    BOOST_CHECK(!AllocateDistribution({Holding(1, 1)}, 0, 1, RemainderPolicy::PAYER, leaves, zero, remainder, error));
    BOOST_CHECK(!AllocateDistribution({}, 10, 1, RemainderPolicy::PAYER, leaves, zero, remainder, error));
    BOOST_CHECK(!AllocateDistribution({Holding(1, 0)}, 10, 1, RemainderPolicy::PAYER, leaves, zero, remainder, error));
}

BOOST_AUTO_TEST_CASE(allocation_zero_shares_and_wide_products)
{
    std::vector<DistributionLeaf> leaves;
    std::vector<DistributionHolding> zero;
    CAmount remainder;

    // A holder whose share rounds to zero is reported, not paid
    BOOST_CHECK(Allocate({Holding(1, 1), Holding(2, 1000000)}, 10, 1, RemainderPolicy::PAYER, leaves, zero, remainder));
    BOOST_CHECK_EQUAL(leaves.size(), 1U);
    BOOST_CHECK_EQUAL(leaves[0].amount, 9);
    BOOST_CHECK_EQUAL(zero.size(), 1U);
    BOOST_CHECK_EQUAL(zero[0].held, 1);
    BOOST_CHECK_EQUAL(remainder, 1);

    // A * h_i far beyond 64 bits stays exact
    const CAmount big = 2100000000000000000LL;
    BOOST_CHECK(Allocate({Holding(1, big - 1), Holding(2, 1)}, big, 1, RemainderPolicy::PAYER, leaves, zero, remainder));
    BOOST_CHECK(Amounts(leaves) == std::vector<CAmount>({big - 1, 1}));
    BOOST_CHECK_EQUAL(remainder, 0);

    BOOST_CHECK(Allocate({Holding(1, big), Holding(2, big), Holding(3, big)}, big, 1, RemainderPolicy::PAYER, leaves, zero, remainder));
    BOOST_CHECK(Amounts(leaves) == std::vector<CAmount>({big / 3, big / 3, big / 3}));
    BOOST_CHECK_EQUAL(remainder, big - 3 * (big / 3));
}

BOOST_AUTO_TEST_CASE(canonical_holdings_state)
{
    std::set<std::pair<std::string, CAmount>> owners;
    const DistributionHolding a = Holding(1, 5), b = Holding(2, 7);
    owners.insert({a.address, a.held});
    owners.insert({b.address, b.held});
    SnapshotHolderState state;
    state.fFrozen = true;
    state.fSelfRevoked = true;
    state.tags = {"#Z", "#A"};
    const std::vector<DistributionHolding> holdings = CanonicalHoldings(owners, {{b.address, state}});
    BOOST_CHECK_EQUAL(holdings[0].flags, 0);
    BOOST_CHECK(holdings[0].tags.empty());
    BOOST_CHECK_EQUAL(holdings[1].flags, HOLDER_FROZEN | HOLDER_SELF_REVOKED);
    BOOST_CHECK(holdings[1].tags == std::vector<std::string>({"#A", "#Z"}));
}

BOOST_AUTO_TEST_CASE(canonical_holdings_order)
{
    std::set<std::pair<std::string, CAmount>> owners;
    for (unsigned char fill : {3, 1, 2}) {
        const DistributionHolding holding = Holding(fill, fill);
        owners.insert({holding.address, holding.held});
    }
    owners.insert({"not-an-address", 5});

    const std::vector<DistributionHolding> holdings = CanonicalHoldings(owners);
    BOOST_CHECK_EQUAL(holdings.size(), 3U);
    for (size_t i = 0; i < holdings.size(); ++i)
        BOOST_CHECK(holdings[i].script == P2PKH(i + 1));
}

BOOST_AUTO_TEST_CASE(merkle_root_structure)
{
    std::vector<DistributionLeaf> leaves;
    for (unsigned char fill = 1; fill <= 5; ++fill)
        leaves.push_back({"", P2PKH(fill), 0, fill});

    auto node = [](const uint256& left, const uint256& right) {
        const unsigned char tag = 0x01;
        uint256 out;
        CSHA256().Write(&tag, 1).Write(left.begin(), 32).Write(right.begin(), 32).Finalize(out.begin());
        return out;
    };
    std::vector<uint256> h;
    for (const auto& leaf : leaves)
        h.push_back(DistributionLeafHash(leaf));

    BOOST_CHECK_EQUAL(Hex(DistributionMerkleRoot({})), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    BOOST_CHECK(DistributionMerkleRoot({leaves[0]}) == h[0]);
    BOOST_CHECK(DistributionMerkleRoot(std::vector<DistributionLeaf>(leaves.begin(), leaves.begin() + 3)) == node(node(h[0], h[1]), h[2]));
    // RFC 6962 splits five leaves as four and one
    BOOST_CHECK(DistributionMerkleRoot(leaves) == node(node(node(h[0], h[1]), node(h[2], h[3])), h[4]));
    BOOST_CHECK_EQUAL(Hex(DistributionMerkleRoot(leaves)), "f097a9a4b4938ed7364b33645e7a51572cc85e906b3d7a01f1e16b8c4f97f69b");
}

BOOST_AUTO_TEST_CASE(merkle_proofs)
{
    const DistributionLeaf stranger{"", P2PKH(0x55), 0, 1};
    for (size_t n = 1; n <= 9; ++n) {
        std::vector<DistributionLeaf> leaves;
        for (size_t i = 0; i < n; ++i)
            leaves.push_back({"", P2PKH(i + 1), 0, static_cast<CAmount>(i + 1)});
        const uint256 root = DistributionMerkleRoot(leaves);
        for (size_t i = 0; i < n; ++i) {
            const std::vector<uint256> path = DistributionMerkleProof(leaves, i);
            const uint256 leaf = DistributionLeafHash(leaves[i]);
            BOOST_CHECK(VerifyDistributionMerkleProof(leaf, i, n, path, root));
            BOOST_CHECK(!VerifyDistributionMerkleProof(DistributionLeafHash(stranger), i, n, path, root));
            if (n > 1)
                BOOST_CHECK(!VerifyDistributionMerkleProof(leaf, (i + 1) % n, n, path, root));
            if (!path.empty()) {
                std::vector<uint256> tampered = path;
                tampered.back() = leaf;
                BOOST_CHECK(!VerifyDistributionMerkleProof(leaf, i, n, tampered, root));
                tampered = path;
                tampered.push_back(root);
                BOOST_CHECK(!VerifyDistributionMerkleProof(leaf, i, n, tampered, root));
            }
        }
        BOOST_CHECK(!VerifyDistributionMerkleProof(DistributionLeafHash(leaves[0]), n, n, {}, root));
        BOOST_CHECK(DistributionMerkleProof(leaves, n).empty());
    }
}

BOOST_AUTO_TEST_CASE(batch_ids)
{
    const uint256 plan = uint256S("2222222222222222222222222222222222222222222222222222222222222222");
    BOOST_CHECK(DistributionBatchId(plan, 500, 0) == DistributionBatchId(plan, 500, 0));
    BOOST_CHECK(DistributionBatchId(plan, 500, 0) != DistributionBatchId(plan, 500, 1));
    BOOST_CHECK(DistributionBatchId(plan, 500, 0) != DistributionBatchId(plan, 499, 0));
    BOOST_CHECK(DistributionBatchId(plan, 500, 0) != DistributionBatchId(uint256(), 500, 0));
}

BOOST_AUTO_TEST_CASE(pinned_vectors)
{
    const uint256 blockHash = uint256S("1111111111111111111111111111111111111111111111111111111111111111");
    const std::vector<DistributionHolding> holdings = {Holding(1, 1), Holding(2, 1), Holding(3, 1)};
    const uint256 snapshotHash = ComputeSnapshotHash("TOKEN", 100, blockHash, holdings);
    BOOST_CHECK_EQUAL(Hex(snapshotHash), "314a6b4e732e079690850586ba03cfae82f36eaede9ecbf2545e4a8121694fd6");

    std::vector<DistributionLeaf> leaves;
    std::vector<DistributionHolding> zero;
    CAmount remainder;
    BOOST_CHECK(Allocate(holdings, 10, 1, RemainderPolicy::LARGEST, leaves, zero, remainder));
    BOOST_CHECK_EQUAL(Hex(DistributionLeafHash(leaves[0])), "cf4afd73ee647fd7bb590c990bed23ff6738b5deade9da3f62c379898cbb8bff");
    const uint256 root = DistributionMerkleRoot(leaves);
    BOOST_CHECK_EQUAL(Hex(root), "3e73b57815e2f840b702c608314d40f87a6a1da9c9fc322f70f9085cbc8b8f70");

    DistributionPlanHeader header;
    header.network = "main";
    header.ownershipAsset = "TOKEN";
    header.height = 100;
    header.blockHash = blockHash;
    header.snapshotHash = snapshotHash;
    header.distributionAsset = "XNA";
    header.amount = 10;
    header.policy = RemainderPolicy::LARGEST;
    header.exclusions = {"EXCLUDED"};
    header.distributed = 10;
    header.remainder = 0;
    header.leafCount = 3;
    BOOST_CHECK_EQUAL(Hex(ComputePlanHash(header, root)), "d6cd4295e094b2bd0220ca17dd2f2847cd4271897b61fea5a6d3217c47a932d5");
    BOOST_CHECK_EQUAL(DistributionPlanVersion(header), DISTRIBUTION_PLAN_VERSION);

    // An announced snapshot height switches to format version 2
    BOOST_CHECK_EQUAL(Hex(SnapshotAnnouncementHash("main", "TOKEN", 100)), "16fd8df89cfdf1ab5773f409b3411ec4d363341de2a8b199bfc715cdb4e6f3c6");
    DistributionPlanHeader announced = header;
    announced.announcementTxid = uint256S("3333333333333333333333333333333333333333333333333333333333333333");
    BOOST_CHECK_EQUAL(DistributionPlanVersion(announced), DISTRIBUTION_PLAN_VERSION_ANNOUNCED);
    BOOST_CHECK_EQUAL(Hex(ComputePlanHash(announced, root)), "f135e81b718b9b438ec56053f74a8496f77a174f7bb0ffbece291a27d5ae7f11");

    // D3: holder state in the snapshot, report weights and a qualifier filter (version 3)
    std::vector<DistributionHolding> withState = holdings;
    withState[0].tags = {"#A"};
    withState[1].flags = HOLDER_FROZEN;
    withState[2].flags = HOLDER_SELF_REVOKED;
    withState[2].tags = {"#A", "#B"};
    BOOST_CHECK_EQUAL(Hex(ComputeSnapshotHashV2("TOKEN", 100, blockHash, false, withState)), "6a0a08d7af75f7bbef593b3cb46488cb49c419dec052317224445440b7a0a847");
    BOOST_CHECK(ComputeSnapshotHashV2("TOKEN", 100, blockHash, true, withState) != ComputeSnapshotHashV2("TOKEN", 100, blockHash, false, withState));
    const uint256 report = DistributionReportHash({{"AAA", 3}, {"BBB", 1}});
    BOOST_CHECK_EQUAL(Hex(report), "7961d43b2c5d98e6f98b9ea00dc7cb6c6604231b186847fd600f440c8fceb921");

    DistributionPlanHeader rules = header;
    rules.qualifier = "#A";
    rules.reportHash = report;
    BOOST_CHECK_EQUAL(DistributionPlanVersion(rules), DISTRIBUTION_PLAN_VERSION_RULES);
    BOOST_CHECK_EQUAL(Hex(ComputePlanHash(rules, root)), "ff5a5e5df0b44e4ddbd5072bdeaff47dc986a1a2506201360f67faef527de5bb");

    // Every committed field changes the plan hash
    const uint256 base = ComputePlanHash(header, root);
    DistributionPlanHeader changed = header;
    changed.policy = RemainderPolicy::PAYER;
    BOOST_CHECK(ComputePlanHash(changed, root) != base);
    changed = header;
    changed.exclusions.clear();
    BOOST_CHECK(ComputePlanHash(changed, root) != base);
    changed = header;
    changed.network = "test";
    BOOST_CHECK(ComputePlanHash(changed, root) != base);
    changed = header;
    changed.blockHash.SetNull();
    BOOST_CHECK(ComputePlanHash(changed, root) != base);
    BOOST_CHECK(ComputePlanHash(header, ComputeSnapshotHash("TOKEN", 101, blockHash, holdings)) != base);
}

// Every vector of src/test/data/nip048_vectors.json, generated by the Python
// reference that SDKs can share (contrib/devtools/nip048-vectors.py)
BOOST_AUTO_TEST_CASE(vectors_file)
{
    UniValue vectors;
    BOOST_REQUIRE(vectors.read(std::string(json_tests::nip048_vectors,
                                           json_tests::nip048_vectors + sizeof(json_tests::nip048_vectors))));

    for (const UniValue& v : vectors["leaf"].getValues()) {
        const DistributionLeaf leaf{"", ScriptFromHex(v["script"].get_str()), 0, v["amount"].get_int64()};
        BOOST_CHECK_EQUAL(Hex(DistributionLeafHash(leaf)), v["hash"].get_str());
    }
    for (const UniValue& v : vectors["merkle"].getValues())
        BOOST_CHECK_EQUAL(Hex(DistributionMerkleRoot(LeavesOf(v["leaves"]))), v["root"].get_str());
    for (const UniValue& v : vectors["proof"].getValues()) {
        const std::vector<DistributionLeaf> leaves = LeavesOf(v["leaves"]);
        const size_t index = v["index"].get_int();
        const std::vector<uint256> path = DistributionMerkleProof(leaves, index);
        BOOST_REQUIRE_EQUAL(path.size(), v["path"].size());
        for (size_t i = 0; i < path.size(); ++i)
            BOOST_CHECK_EQUAL(Hex(path[i]), v["path"][i].get_str());
        BOOST_CHECK(VerifyDistributionMerkleProof(DistributionLeafHash(leaves[index]), index, leaves.size(), path,
                                                  RawHash(v["root"].get_str())));
    }
    for (const UniValue& v : vectors["snapshot_v1"].getValues()) {
        std::vector<DistributionHolding> holdings;
        for (const UniValue& h : v["holdings"].getValues())
            holdings.push_back({"", ScriptFromHex(h[0].get_str()), h[1].get_int64()});
        BOOST_CHECK_EQUAL(Hex(ComputeSnapshotHash(v["asset"].get_str(), v["height"].get_int(),
                                                  RawHash(v["block_hash"].get_str()), holdings)), v["hash"].get_str());
    }
    for (const UniValue& v : vectors["snapshot_v2"].getValues()) {
        std::vector<DistributionHolding> holdings;
        for (const UniValue& h : v["holdings"].getValues()) {
            DistributionHolding holding{"", ScriptFromHex(h[0].get_str()), h[1].get_int64()};
            holding.flags = h[2].get_int();
            for (const UniValue& tag : h[3].getValues())
                holding.tags.push_back(tag.get_str());
            holdings.push_back(holding);
        }
        BOOST_CHECK_EQUAL(Hex(ComputeSnapshotHashV2(v["asset"].get_str(), v["height"].get_int(),
                                                    RawHash(v["block_hash"].get_str()), v["global_frozen"].get_bool(),
                                                    holdings)), v["hash"].get_str());
    }
    for (const UniValue& v : vectors["report"].getValues()) {
        std::map<std::string, int64_t> weights;
        for (const std::string& address : v["weights"].getKeys())
            weights[address] = v["weights"][address].get_int64();
        BOOST_CHECK_EQUAL(Hex(DistributionReportHash(weights)), v["hash"].get_str());
    }
    for (const UniValue& v : vectors["announcement"].getValues())
        BOOST_CHECK_EQUAL(Hex(SnapshotAnnouncementHash(v["network"].get_str(), v["asset"].get_str(), v["height"].get_int())),
                          v["hash"].get_str());
    for (const UniValue& v : vectors["allocation"].getValues()) {
        std::vector<DistributionHolding> holdings;
        for (const UniValue& h : v["holdings"].getValues())
            holdings.push_back({"", ScriptFromHex(h[0].get_str()), h[1].get_int64()});
        std::vector<DistributionLeaf> leaves;
        std::vector<DistributionHolding> zero;
        CAmount remainder;
        std::string error;
        BOOST_REQUIRE(AllocateDistribution(holdings, v["amount"].get_int64(), v["unit"].get_int64(),
                                           static_cast<RemainderPolicy>(v["policy"].get_int()), leaves, zero, remainder, error));
        std::map<CScript, CAmount> paid;
        for (const auto& leaf : leaves)
            paid[leaf.script] = leaf.amount;
        for (size_t i = 0; i < holdings.size(); ++i)
            BOOST_CHECK_EQUAL(paid.count(holdings[i].script) ? paid[holdings[i].script] : 0, v["amounts"][i].get_int64());
        BOOST_CHECK_EQUAL(remainder, v["remainder"].get_int64());
    }
    for (const UniValue& v : vectors["plan"].getValues()) {
        DistributionPlanHeader header;
        header.network = v["network"].get_str();
        header.ownershipAsset = v["asset"].get_str();
        header.height = v["height"].get_int();
        header.blockHash = RawHash(v["block_hash"].get_str());
        header.snapshotHash = RawHash(v["snapshot_hash"].get_str());
        if (!v["announcement"].isNull())
            header.announcementTxid = RawHash(v["announcement"].get_str());
        if (!v["qualifier"].isNull())
            header.qualifier = v["qualifier"].get_str();
        if (!v["report"].isNull())
            header.reportHash = RawHash(v["report"].get_str());
        header.distributionAsset = v["distribution_asset"].get_str();
        header.amount = v["amount"].get_int64();
        header.policy = static_cast<RemainderPolicy>(v["policy"].get_int());
        for (const UniValue& exclusion : v["exclusions"].getValues())
            header.exclusions.push_back(exclusion.get_str());
        header.distributed = v["distributed"].get_int64();
        header.remainder = v["remainder"].get_int64();
        header.leafCount = v["leaf_count"].get_int();
        BOOST_CHECK_EQUAL(DistributionPlanVersion(header), v["version"].get_int());
        BOOST_CHECK_EQUAL(Hex(ComputePlanHash(header, RawHash(v["root"].get_str()))), v["hash"].get_str());
    }
    for (const UniValue& v : vectors["batch_id"].getValues())
        BOOST_CHECK_EQUAL(Hex(DistributionBatchId(RawHash(v["plan_hash"].get_str()), v["max_outputs"].get_int(),
                                                  v["index"].get_int())), v["hash"].get_str());
}

BOOST_AUTO_TEST_SUITE_END()
