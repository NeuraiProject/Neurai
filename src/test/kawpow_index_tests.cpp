// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#include <amount.h>
#include <arith_uint256.h>
#include <assets/assetdb.h>
#include <chainparams.h>
#include <coins.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <crypto/ethash/lib/ethash/ethash-internal.hpp>
#include <hash.h>
#include <header_anchors.h>
#include <miner.h>
#include <pow.h>
#include <test/test_neurai.h>
#include <txdb.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>
#include <fstream>

namespace {
struct FailContextAllocation {
    bool previous{ethash::testing::set_context_allocation_failure(true)};
    ~FailContextAllocation() { ethash::testing::set_context_allocation_failure(previous); }
};

struct IndexPoWSetup : TestingSetup {
    MapCheckpoints checkpoints;
    bool enabled{fCheckpointsEnabled};
    CCoinsViewDB* previousCoins{::pcoinsdbview};
    CAssetsDB* previousAssets{passetsdb};

    explicit IndexPoWSetup(const std::string& network = CBaseChainParams::MAIN) : TestingSetup(network),
        checkpoints(GetParams().Checkpoints().mapCheckpoints)
    {
        ::pcoinsdbview = pcoinsdbview;
        passetsdb = new CAssetsDB(1 << 20, true, true);
        Points().clear();
        fCheckpointsEnabled = true;
    }
    ~IndexPoWSetup()
    {
        GetMainSignals().FlushBackgroundCallbacks();
        delete passetsdb;
        passetsdb = previousAssets;
        Points() = checkpoints;
        fCheckpointsEnabled = enabled;
        ::pcoinsdbview = previousCoins;
    }
    MapCheckpoints& Points()
    {
        return const_cast<CCheckpointData&>(GetParams().Checkpoints()).mapCheckpoints;
    }
    void Mine(CBlock& block)
    {
        block.fChecked = false;
        do { ++block.nNonce64; ++block.nNonce; }
        while (!CheckProofOfWork(block.GetHashFull(block.mix_hash), block.nBits, GetParams().GetConsensus()));
    }
    CBlock Block()
    {
        auto block = BlockAssembler(GetParams()).CreateNewBlock(CScript() << OP_TRUE)->block;
        block.hashMerkleRoot = BlockMerkleRoot(block);
        Mine(block);
        return block;
    }
    CBlock Child(const CBlock& parent)
    {
        auto child = parent;
        child.hashPrevBlock = parent.GetHash();
        ++child.nHeight;
        ++child.nTime;
        CMutableTransaction coinbase(*child.vtx[0]);
        coinbase.vin[0].scriptSig = CScript() << child.nHeight << OP_0;
        child.vtx[0] = MakeTransactionRef(coinbase);
        child.hashMerkleRoot = BlockMerkleRoot(child);
        Mine(child);
        return child;
    }
    void BadMix(CBlock& block)
    {
        const auto mix = block.mix_hash;
        do { block.mix_hash = InsecureRand256(); }
        while (block.mix_hash == mix ||
               !CheckProofOfWork(block.GetHash(), block.nBits, GetParams().GetConsensus()));
        block.fChecked = false;
    }
    void Connect(const CBlock& block)
    {
        if (!block.fChecked) {
            LOCK(cs_main);
            CValidationState state;
            BOOST_REQUIRE_MESSAGE(TestBlockValidity(state, GetParams(), block, chainActive.Tip(), true, true), state.GetRejectReason());
        }
        BOOST_REQUIRE(ProcessNewBlock(GetParams(), std::make_shared<const CBlock>(block), true, nullptr));
        BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == block.GetHash());
    }
    void Flush()
    {
        {
            LOCK(cs_main);
            FlushStateToDisk();
            BOOST_REQUIRE(pcoinsdbview->GetBestBlock() == pcoinsTip->GetBestBlock());
        }
        GetMainSignals().FlushBackgroundCallbacks();
    }
    void SeedHeader(const CBlock& block, int storedHeight = -1)
    {
        CBlockIndex index(block);
        index.nHeight = storedHeight < 0 ? block.nHeight : storedHeight;
        index.nStatus = BLOCK_VALID_TREE;
        CDiskBlockIndex disk(&index);
        disk.hashPrev = block.hashPrevBlock;
        BOOST_REQUIRE(pblocktree->Write(std::make_pair('b', block.GetHash()), disk));
    }
    CBlockIndex* Index(const uint256& hash)
    {
        const auto it = mapBlockIndex.find(hash);
        BOOST_REQUIRE(it != mapBlockIndex.end());
        return it->second;
    }
    // Actually unload and load LevelDB entries; no retained CBlockIndex pointers.
    bool Reload(std::string* error = nullptr, bool recover = true)
    {
        GetMainSignals().FlushBackgroundCallbacks();
        UnloadBlockIndex();
        {
            LOCK(cs_main);
            if (!LoadBlockIndex(GetParams(), error)) return false;
            BOOST_REQUIRE(LoadChainTip(GetParams()));
        }
        if (recover) {
            CValidationState state;
            const bool ok = RecoverBlockIndexPoW(GetParams(), state);
            if (error) *error = state.GetRejectReason();
            if (!ok) return false;
            BOOST_REQUIRE(ActivateBestChain(state, GetParams()));
        }
        return true;
    }
    void EvictEpochZero()
    {
        auto block = GetParams().GenesisBlock().GetBlockHeader();
        block.nTime = nKAWPOWActivationTime + 60;
        uint256 mix;
        for (unsigned height : {15000U, 22500U}) {
            block.nHeight = height;
            KAWPOWHash(block, mix);
        }
    }
    CBlock LegacyActive()
    {
        auto honest = Block();
        auto bad = honest;
        BadMix(bad);
        // Checkpoint absent; sibling at the same height must still be audited.
        Points()[1] = honest.GetHash();
        Flush();
        SeedHeader(bad);
        BOOST_REQUIRE(Reload(nullptr, false));
        // Reproduce old persisted acceptance without weakening production rules.
        bad.fChecked = true;
        Connect(bad);
        bad.fChecked = false;
        Flush();
        return bad;
    }
};
}

BOOST_FIXTURE_TEST_SUITE(kawpow_index_tests, IndexPoWSetup)

BOOST_AUTO_TEST_CASE(new_fork_cannot_use_checkpoint_height)
{
    const auto first = Block();
    Connect(first);
    Points()[1] = first.GetHash();
    auto bad = first;
    BadMix(bad);
    CValidationState state;
    BOOST_CHECK(!ProcessNewBlockHeaders({bad.GetBlockHeader()}, state, GetParams(), nullptr));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "invalid-mix-hash");
    BOOST_CHECK(!mapBlockIndex.count(bad.GetHash()));
}

BOOST_AUTO_TEST_CASE(historical_declared_height_cannot_use_shortcut)
{
    const auto first = Block();
    Connect(first);
    Points()[1] = first.GetHash();
    auto bad = Block(); // Real height 2; declare the old checkpoint height.
    bad.nHeight = 1;
    Mine(bad);
    BadMix(bad);
    CValidationState state;
    BOOST_CHECK(!ProcessNewBlockHeaders({bad.GetBlockHeader()}, state, GetParams(), nullptr));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "invalid-mix-hash");
}

BOOST_AUTO_TEST_CASE(authenticated_ancestor_does_not_build_context)
{
    auto first = Block();
    Connect(first);
    auto second = Block();
    Connect(second);
    Points()[2] = second.GetHash();
    EvictEpochZero();
    const auto before = ethash::testing::context_allocation_count();
    first.fChecked = false;
    CValidationState state;
    BOOST_CHECK(CheckBlock(first, state, GetParams().GetConsensus()));
    BOOST_CHECK_EQUAL(ethash::testing::context_allocation_count(), before);
}

BOOST_AUTO_TEST_CASE(disabled_checkpoints_force_full_pow)
{
    auto block = Block();
    Connect(block);
    Points()[1] = block.GetHash();
    fCheckpointsEnabled = false;
    EvictEpochZero();
    block.fChecked = false;
    const auto before = ethash::testing::context_allocation_count();
    CValidationState state;
    BOOST_CHECK(CheckBlock(block, state, GetParams().GetConsensus()));
    BOOST_CHECK_EQUAL(ethash::testing::context_allocation_count(), before + 1);
}

BOOST_AUTO_TEST_CASE(indexed_block_above_checkpoint_checks_full_pow)
{
    const auto first = Block();
    Connect(first);
    Points()[1] = first.GetHash();
    auto second = Block();
    Connect(second);
    EvictEpochZero();
    second.fChecked = false;
    const auto before = ethash::testing::context_allocation_count();
    CValidationState state;
    BOOST_CHECK(CheckBlock(second, state, GetParams().GetConsensus()));
    BOOST_CHECK_EQUAL(ethash::testing::context_allocation_count(), before + 1);
}

BOOST_AUTO_TEST_CASE(reload_invalidates_header_only_branch_and_persists)
{
    auto honest = Block();
    auto bad = honest;
    BadMix(bad);
    auto child = Child(bad);
    Connect(honest);
    Points()[1] = honest.GetHash();
    Flush();
    SeedHeader(bad);
    SeedHeader(child);
    BOOST_REQUIRE(Reload());
    BOOST_CHECK(Index(bad.GetHash())->nStatus & BLOCK_FAILED_VALID);
    BOOST_CHECK(Index(child.GetHash())->nStatus & BLOCK_FAILED_CHILD);
    BOOST_CHECK(pindexBestHeader->GetBlockHash() == honest.GetHash());
    BOOST_REQUIRE(Reload());
    BOOST_CHECK(Index(bad.GetHash())->nStatus & BLOCK_FAILED_VALID);
    BOOST_CHECK(Index(child.GetHash())->nStatus & BLOCK_FAILED_CHILD);
    BOOST_CHECK(pindexBestHeader->GetBlockHash() == honest.GetHash());
}

BOOST_AUTO_TEST_CASE(processnewblock_recovers_known_invalid_header_after_reload)
{
    auto honest = Block();
    auto bad = honest;
    BadMix(bad);
    const auto child = Child(bad);
    Connect(honest);
    Points()[1] = honest.GetHash();
    Flush();
    SeedHeader(bad);
    SeedHeader(child);
    // Do not apply phase B: exercise the independent runtime defense.
    BOOST_REQUIRE(Reload(nullptr, false));
    BOOST_CHECK(!(Index(bad.GetHash())->nStatus & BLOCK_FAILED_MASK));
    BOOST_CHECK(!ProcessNewBlock(GetParams(), std::make_shared<const CBlock>(bad), true, nullptr));
    BOOST_CHECK(Index(bad.GetHash())->nStatus & BLOCK_FAILED_VALID);
    BOOST_CHECK(Index(child.GetHash())->nStatus & BLOCK_FAILED_CHILD);
    BOOST_CHECK(pindexBestHeader->GetBlockHash() == honest.GetHash());
    BOOST_REQUIRE(Reload());
    BOOST_CHECK(Index(bad.GetHash())->nStatus & BLOCK_FAILED_VALID);
}

BOOST_AUTO_TEST_CASE(recovery_disconnects_invalid_active_chain_before_marking)
{
    const auto bad = LegacyActive();
    BOOST_REQUIRE(Reload());
    BOOST_CHECK_EQUAL(chainActive.Height(), 0);
    BOOST_CHECK(Index(bad.GetHash())->nStatus & BLOCK_FAILED_VALID);
    BOOST_CHECK(pindexBestHeader == chainActive.Tip());
    BOOST_CHECK(!pcoinsTip->HaveCoin(COutPoint(bad.vtx[0]->GetHash(), 0)));
    BOOST_REQUIRE(Reload());
    BOOST_CHECK_EQUAL(chainActive.Height(), 0);
    BOOST_CHECK(Index(bad.GetHash())->nStatus & BLOCK_FAILED_VALID);
}

BOOST_AUTO_TEST_CASE(missing_undo_stops_recovery_without_marking_and_retries)
{
    const auto bad = LegacyActive();
    const auto undo = GetBlockPosFilename(Index(bad.GetHash())->GetUndoPos(), "rev");
    const auto backup = fs::path(undo.string() + ".backup");
    fs::rename(undo, backup);
    std::string error;
    BOOST_CHECK(!Reload(&error));
    BOOST_CHECK(error.find("-reindex") != std::string::npos);
    BOOST_CHECK_EQUAL(chainActive.Height(), 1);
    BOOST_CHECK(!(Index(bad.GetHash())->nStatus & BLOCK_FAILED_MASK));
    CDiskBlockIndex disk;
    BOOST_REQUIRE(pblocktree->Read(std::make_pair('b', bad.GetHash()), disk));
    BOOST_CHECK(!(disk.nStatus & BLOCK_FAILED_MASK));
    fs::rename(backup, undo);
    BOOST_REQUIRE(Reload());
    BOOST_CHECK_EQUAL(chainActive.Height(), 0);
    BOOST_CHECK(Index(bad.GetHash())->nStatus & BLOCK_FAILED_VALID);
}

// Choose both outcomes explicitly: neither regression depends on a lucky hash.
BOOST_AUTO_TEST_CASE(identity_mismatch_is_discarded_for_both_cheap_pow_outcomes)
{
    for (bool reconstructedPass : {true, false}) {
        auto block = Block();
        block.nBits = 0x207fffff;
        CDiskBlockIndex disk;
        do {
            Mine(block);
            CBlockIndex index(block);
            index.nHeight = block.nHeight + 1;
            disk = CDiskBlockIndex(&index);
            disk.hashPrev = block.hashPrevBlock;
        } while (CheckProofOfWork(disk.GetBlockHash(), block.nBits, GetParams().GetConsensus()) != reconstructedPass);
        const auto child = Child(block);
        BOOST_REQUIRE(block.GetHash() != disk.GetBlockHash());
        BOOST_REQUIRE(CheckProofOfWork(block.GetHash(), block.nBits, GetParams().GetConsensus()));
        Flush();
        SeedHeader(block, disk.nHeight);
        SeedHeader(child);
        BOOST_REQUIRE(Reload());
        BOOST_CHECK(!mapBlockIndex.count(block.GetHash()));
        BOOST_CHECK(!mapBlockIndex.count(disk.GetBlockHash()));
        BOOST_CHECK(!mapBlockIndex.count(child.GetHash()));
    }
}

BOOST_AUTO_TEST_CASE(allocation_error_stops_load_without_exposing_or_invalidating_header)
{
    auto honest = Block();
    auto bad = honest;
    BadMix(bad);
    Connect(honest);
    Points()[1] = honest.GetHash();
    Flush();
    SeedHeader(bad);
    EvictEpochZero();
    {
        FailContextAllocation fail;
        std::string error;
        BOOST_CHECK(!Reload(&error));
        BOOST_CHECK(error.find("Free memory and restart") != std::string::npos);
        BOOST_CHECK(pindexBestHeader == nullptr);
        BOOST_CHECK(chainActive.Tip() == nullptr);
        BOOST_CHECK(!(Index(bad.GetHash())->nStatus & BLOCK_FAILED_MASK));
        CDiskBlockIndex disk;
        BOOST_REQUIRE(pblocktree->Read(std::make_pair('b', bad.GetHash()), disk));
        BOOST_CHECK(!(disk.nStatus & BLOCK_FAILED_MASK));
    }
    BOOST_REQUIRE(Reload());
    BOOST_CHECK(Index(bad.GetHash())->nStatus & BLOCK_FAILED_VALID);
}

BOOST_AUTO_TEST_CASE(corrupt_body_does_not_invalidate_honest_header)
{
    const auto block = Block();
    CValidationState state;
    BOOST_REQUIRE(ProcessNewBlockHeaders({block.GetBlockHeader()}, state, GetParams(), nullptr));
    auto corrupt = block;
    CMutableTransaction coinbase(*corrupt.vtx[0]);
    ++coinbase.vout[0].nValue;
    corrupt.vtx[0] = MakeTransactionRef(coinbase);
    BOOST_CHECK(!ProcessNewBlock(GetParams(), std::make_shared<const CBlock>(corrupt), true, nullptr));
    BOOST_CHECK(!(Index(block.GetHash())->nStatus & BLOCK_FAILED_MASK));
    Connect(block);
}

BOOST_AUTO_TEST_CASE(indexed_fixed_anchor_authenticates_ancestors_only_while_enabled)
{
    auto first = Block();
    Connect(first);
    Flush();
    // Populate a committed chain of header-only entries, as loaded from an old
    // index. The fixture supplies the fixed anchor; no per-header verified bit.
    auto header = first;
    uint256 previous = first.GetHash();
    for (int height = 2; height <= HEADER_ANCHOR_INTERVAL; ++height) {
        header.hashPrevBlock = previous;
        header.nHeight = height;
        ++header.nTime;
        do { ++header.nNonce64; }
        while (!CheckProofOfWork(header.GetHash(), header.nBits, GetParams().GetConsensus()));
        SeedHeader(header);
        previous = header.GetHash();
    }
    auto& anchors = const_cast<std::vector<uint256>&>(GetParams().HeaderAnchors());
    struct Restore {
        std::vector<uint256>& target;
        std::vector<uint256> saved;
        ~Restore() { target = saved; }
    } restore{anchors, anchors};
    anchors = {previous};
    BOOST_REQUIRE(Reload());
    EvictEpochZero();
    const auto before = ethash::testing::context_allocation_count();
    first.fChecked = false;
    CValidationState state;
    BOOST_CHECK(CheckBlock(first, state, GetParams().GetConsensus()));
    BOOST_CHECK_EQUAL(ethash::testing::context_allocation_count(), before);
    LOCK(cs_main);
    BOOST_CHECK(!NeedsFullKAWPOWCheck(first));
    fCheckpointsEnabled = false;
    BOOST_CHECK(NeedsFullKAWPOWCheck(first));
    fCheckpointsEnabled = true;
    auto index = Index(previous);
    const auto status = index->nStatus;
    index->nStatus |= BLOCK_FAILED_VALID;
    BOOST_CHECK(NeedsFullKAWPOWCheck(first));
    index->nStatus = status;
}

BOOST_AUTO_TEST_CASE(preflight_checks_the_whole_active_suffix_before_disconnecting)
{
    const auto bad = LegacyActive();
    const auto child = Child(bad);
    Connect(child);
    Flush();
    const auto pos = Index(bad.GetHash())->GetUndoPos();
    const auto path = GetBlockPosFilename(pos, "rev");
    BOOST_REQUIRE_EQUAL(bad.vtx.size(), 1U);
    // Coinbase-only undo is one zero CompactSize byte, followed by its checksum.
    // Damage the older record only: the child's undo in the same file stays valid.
    std::fstream undo(path.string(), std::ios::in | std::ios::out | std::ios::binary);
    BOOST_REQUIRE(undo.is_open());
    undo.seekg(pos.nPos + 1);
    const auto original = undo.get();
    BOOST_REQUIRE(original != std::char_traits<char>::eof());
    undo.seekp(pos.nPos + 1);
    undo.put(char(original ^ 1));
    undo.flush();
    std::string error;
    BOOST_CHECK(!Reload(&error));
    BOOST_CHECK(error.find("-reindex") != std::string::npos);
    BOOST_CHECK_EQUAL(chainActive.Height(), 2);
    BOOST_CHECK(!(Index(bad.GetHash())->nStatus & BLOCK_FAILED_MASK));
    BOOST_CHECK(!(Index(child.GetHash())->nStatus & BLOCK_FAILED_MASK));
    undo.seekp(pos.nPos + 1);
    undo.put(char(original));
    undo.close();
    BOOST_REQUIRE(Reload());
    BOOST_CHECK_EQUAL(chainActive.Height(), 0);
    BOOST_CHECK(Index(bad.GetHash())->nStatus & BLOCK_FAILED_VALID);
    BOOST_CHECK(Index(child.GetHash())->nStatus & BLOCK_FAILED_CHILD);
}

BOOST_AUTO_TEST_CASE(partial_sync_restart_does_not_recheck_above_the_indexed_checkpoint)
{
    const auto first = Block();
    Connect(first);
    Points()[1] = first.GetHash();
    Points()[1000] = InsecureRand256(); // Future fixed checkpoint not reached yet.
    const auto second = Block();
    Connect(second);
    Flush();
    EvictEpochZero();
    const auto before = ethash::testing::context_allocation_count();
    std::string error;
    bool loaded;
    {
        FailContextAllocation fail;
        loaded = Reload(&error);
    }
    BOOST_REQUIRE_MESSAGE(loaded, error);
    BOOST_CHECK_EQUAL(ethash::testing::context_allocation_count(), before);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == second.GetHash());
}

BOOST_AUTO_TEST_CASE(runtime_recovery_disconnects_invalid_active_chain)
{
    const auto bad = LegacyActive();
    BOOST_CHECK(!ProcessNewBlock(GetParams(), std::make_shared<const CBlock>(bad), true, nullptr));
    BOOST_CHECK_EQUAL(chainActive.Height(), 0);
    BOOST_CHECK(Index(bad.GetHash())->nStatus & BLOCK_FAILED_VALID);
    BOOST_CHECK(pindexBestHeader == chainActive.Tip());
    BOOST_REQUIRE(Reload());
    BOOST_CHECK_EQUAL(chainActive.Height(), 0);
    BOOST_CHECK(Index(bad.GetHash())->nStatus & BLOCK_FAILED_VALID);
}

BOOST_AUTO_TEST_CASE(runtime_allocation_error_leaves_known_header_retryable)
{
    const auto block = Block();
    CValidationState state;
    BOOST_REQUIRE(ProcessNewBlockHeaders({block.GetBlockHeader()}, state, GetParams(), nullptr));
    EvictEpochZero();
    bool accepted;
    {
        FailContextAllocation fail;
        accepted = ProcessNewBlock(GetParams(), std::make_shared<const CBlock>(block), true, nullptr);
    }
    BOOST_CHECK(!accepted);
    BOOST_CHECK(!(Index(block.GetHash())->nStatus & BLOCK_FAILED_MASK));
    BOOST_CHECK_EQUAL(chainActive.Height(), 0);
    Connect(block);
}

BOOST_AUTO_TEST_SUITE_END()

namespace {
struct NativeTestnetIndexSetup : IndexPoWSetup {
    NativeTestnetIndexSetup() : IndexPoWSetup(CBaseChainParams::TESTNET) {}
};
}
BOOST_FIXTURE_TEST_SUITE(kawpow_index_native_testnet, NativeTestnetIndexSetup)
BOOST_AUTO_TEST_CASE(honest_chain_survives_native_network_reload)
{
    // Use each branch's actual algorithm: KAWPOW in main, SHA256d in DePIN.
    const auto first = Block();
    Connect(first);
    Points()[1] = first.GetHash();
    const auto second = Block();
    Connect(second);
    Flush();
    BOOST_REQUIRE(Reload());
    BOOST_CHECK_EQUAL(chainActive.Height(), 2);
    BOOST_CHECK(chainActive.Tip()->GetBlockHash() == second.GetHash());
    BOOST_CHECK(!(Index(second.GetHash())->nStatus & BLOCK_FAILED_MASK));
    fCheckpointsEnabled = false;
    auto check = first;
    check.fChecked = false;
    CValidationState state;
    BOOST_CHECK(CheckBlock(check, state, GetParams().GetConsensus()));
}
BOOST_AUTO_TEST_SUITE_END()
