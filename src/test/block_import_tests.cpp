// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <coins.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#include <miner.h>
#include <pow.h>
#include <streams.h>
#include <test/test_neurai.h>
#include <utiltime.h>
#include <validation.h>
#include <validationinterface.h>

#include <boost/test/unit_test.hpp>

namespace {
struct ImportSetup : TestingSetup {
    const bool sha{bNetwork.fSHA256Mining};
    const uint32_t activation{nKAWPOWActivationTime};

    ImportSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        bNetwork.fSHA256Mining = false;
        nKAWPOWActivationTime = 0;
    }
    ~ImportSetup()
    {
        bNetwork.fSHA256Mining = sha;
        nKAWPOWActivationTime = activation;
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
        unsigned int extra_nonce = 0;
        {
            LOCK(cs_main);
            IncrementExtraNonce(&block, chainActive.Tip(), extra_nonce);
        }
        Mine(block);
        return block;
    }
    bool ImportBlocks(const std::vector<CBlock>& blocks, bool reindex = false)
    {
        // Exercise the real disk importer, including serialization (fChecked
        // must not survive it), rather than calling a validation helper.
        CDiskBlockPos position(1, 0); // Genesis occupies file zero in the fixture.
        const auto path = reindex ? GetBlockPosFilename(position, "blk") : pathTemp / "import.dat";
        {
            CAutoFile file(fsbridge::fopen(path, "wb"), SER_DISK, CLIENT_VERSION);
            BOOST_REQUIRE(!file.IsNull());
            for (const auto& block : blocks) {
                file << FLATDATA(GetParams().MessageStart());
                file << static_cast<uint32_t>(GetSerializeSize(block, SER_DISK, CLIENT_VERSION));
                file << block;
            }
        }
        FILE* file = fsbridge::fopen(path, "rb");
        BOOST_REQUIRE(file != nullptr);
        return LoadExternalBlockFile(GetParams(), file, reindex ? &position : nullptr); // Takes ownership.
    }
    bool Import(const CBlock& block) { return ImportBlocks({block}); }
    CBlockIndex* Index(const CBlock& block)
    {
        AssertLockHeld(cs_main);
        const auto it = mapBlockIndex.find(block.GetHash());
        BOOST_REQUIRE(it != mapBlockIndex.end());
        return it->second;
    }
    void AcceptHeader(const CBlock& block, bool prechecked = false)
    {
        CValidationState state;
        const std::vector<uint8_t> checked{1};
        BOOST_REQUIRE(ProcessNewBlockHeaders({block.GetBlockHeader()}, state, GetParams(),
                                            nullptr, nullptr, prechecked ? &checked : nullptr));
    }
    void Connect(const CBlock& block)
    {
        CValidationState state;
        BOOST_REQUIRE_MESSAGE(ActivateBestChain(state, GetParams()), state.GetRejectReason());
        LOCK(cs_main);
        BOOST_CHECK(chainActive.Tip()->GetBlockHash() == block.GetHash());
        BOOST_CHECK(pcoinsTip->HaveCoin(COutPoint(block.vtx[0]->GetHash(), 0)));
    }
};

struct CheckedBlockObserver : CValidationInterface {
    std::shared_ptr<const CBlock> received;
    const int64_t previous_time{GetMockTime()};
    CheckedBlockObserver()
    {
        // Make the regtest tip current so AcceptBlock emits NewPoWValidBlock.
        SetMockTime(chainActive.Tip()->GetBlockTime() + 60);
        RegisterValidationInterface(this);
    }
    ~CheckedBlockObserver()
    {
        UnregisterValidationInterface(this);
        SetMockTime(previous_time);
    }
    void NewPoWValidBlock(const CBlockIndex*, const std::shared_ptr<const CBlock>& block) override
    {
        received = block;
    }
};
}

BOOST_FIXTURE_TEST_SUITE(block_import_tests, ImportSetup)

BOOST_AUTO_TEST_CASE(new_headers_check_pow_once)
{
    for (int i = 0; i < 3; ++i) {
        const auto block = Block();
        const auto before = GetFullKawpowCheckCount();
        BOOST_REQUIRE(Import(block));
        BOOST_CHECK_EQUAL(GetFullKawpowCheckCount() - before, 1U);
        Connect(block);
    }
}

BOOST_AUTO_TEST_CASE(known_headers_still_check_block_pow)
{
    const auto block = Block();
    AcceptHeader(block);
    const auto before = GetFullKawpowCheckCount();
    BOOST_REQUIRE(Import(block));
    BOOST_CHECK_EQUAL(GetFullKawpowCheckCount() - before, 1U);
    Connect(block);
}

BOOST_AUTO_TEST_CASE(reindex_reuses_pow_for_out_of_order_children)
{
    const auto parent = Block();
    auto child = parent;
    child.hashPrevBlock = parent.GetHash();
    ++child.nHeight;
    ++child.nTime;
    {
        LOCK(cs_main);
        CBlockIndex parent_index(parent);
        parent_index.nHeight = parent.nHeight;
        parent_index.pprev = chainActive.Tip();
        child.nBits = GetNextWorkRequired(&parent_index, &child, GetParams().GetConsensus());
    }
    CMutableTransaction coinbase(*child.vtx[0]);
    coinbase.vin[0].scriptSig = CScript() << child.nHeight << OP_0;
    child.vtx[0] = MakeTransactionRef(coinbase);
    child.hashMerkleRoot = BlockMerkleRoot(child);
    Mine(child);
    const auto before = GetFullKawpowCheckCount();
    BOOST_REQUIRE(ImportBlocks({child, parent}, true));
    BOOST_CHECK_EQUAL(GetFullKawpowCheckCount() - before, 2U);
    {
        LOCK(cs_main);
        BOOST_CHECK(Index(parent)->nStatus & BLOCK_HAVE_DATA);
        BOOST_CHECK(Index(child)->nStatus & BLOCK_HAVE_DATA);
    }
    Connect(child);
}

BOOST_AUTO_TEST_CASE(completed_block_checks_remain_cached)
{
    CheckedBlockObserver observer;
    const auto block = Block();
    BOOST_REQUIRE(Import(block));
    BOOST_REQUIRE(observer.received);
    BOOST_REQUIRE(observer.received->fChecked);
    const auto before = GetFullKawpowCheckCount();
    CValidationState state;
    BOOST_REQUIRE(CheckBlock(*observer.received, state, GetParams().GetConsensus()));
    BOOST_CHECK_EQUAL(GetFullKawpowCheckCount(), before);
}

BOOST_AUTO_TEST_CASE(prechecked_header_cannot_skip_invalid_mix)
{
    auto block = Block();
    // Keep the full PoW valid but supply a false mix with a passing cheap hash.
    // This header is accepted through the same mark used for trusted anchors.
    const auto real_mix = block.mix_hash;
    do { block.mix_hash = InsecureRand256(); }
    while (block.mix_hash == real_mix || !CheckProofOfWork(block.GetHash(), block.nBits, GetParams().GetConsensus()));
    AcceptHeader(block, true);
    CValidationState state;
    BOOST_CHECK(!CheckBlock(block, state, GetParams().GetConsensus()));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "invalid-mix-hash");
    const auto before = GetFullKawpowCheckCount();
    BOOST_CHECK(!Import(block));
    BOOST_CHECK_EQUAL(GetFullKawpowCheckCount() - before, 1U);
    LOCK(cs_main);
    BOOST_CHECK(!(Index(block)->nStatus & BLOCK_HAVE_DATA));
    BOOST_CHECK(Index(block)->nStatus & BLOCK_FAILED_VALID);
}

BOOST_AUTO_TEST_CASE(new_header_with_bad_pow_is_rejected)
{
    auto block = Block();
    // Regtest's min-difficulty target is almost UINT256_MAX. Use a target
    // with a 50% failure rate; PoW rejection precedes contextual nBits checks.
    block.nBits = 0x207fffff;
    do { ++block.nNonce64; }
    while (CheckProofOfWork(block.GetHashFull(block.mix_hash), block.nBits, GetParams().GetConsensus()));
    const auto before = GetFullKawpowCheckCount();
    BOOST_CHECK(!Import(block));
    BOOST_CHECK_EQUAL(GetFullKawpowCheckCount() - before, 1U);
    LOCK(cs_main);
    BOOST_CHECK(mapBlockIndex.count(block.GetHash()) == 0);
}

BOOST_AUTO_TEST_CASE(bad_merkle_root_allows_correct_body_to_be_retried)
{
    const auto block = Block();
    auto corrupt = block;
    CMutableTransaction coinbase(*corrupt.vtx[0]);
    ++coinbase.vout[0].nValue;
    corrupt.vtx[0] = MakeTransactionRef(coinbase);
    const auto before = GetFullKawpowCheckCount();
    BOOST_CHECK(!Import(corrupt));
    BOOST_CHECK_EQUAL(GetFullKawpowCheckCount() - before, 1U);
    {
        LOCK(cs_main);
        BOOST_CHECK(!(Index(block)->nStatus & (BLOCK_HAVE_DATA | BLOCK_FAILED_MASK)));
    }
    BOOST_REQUIRE(Import(block));
    BOOST_CHECK_EQUAL(GetFullKawpowCheckCount() - before, 2U);
    Connect(block);
}

BOOST_AUTO_TEST_CASE(valid_pow_does_not_skip_transaction_checks)
{
    auto block = Block();
    block.vtx.push_back(block.vtx[0]);
    // Two identical leaves also violate the merkle mutation check. Use a
    // distinct second coinbase so the transaction check itself rejects it.
    CMutableTransaction other(*block.vtx[0]);
    other.vin[0].scriptSig << OP_1;
    block.vtx[1] = MakeTransactionRef(other);
    block.hashMerkleRoot = BlockMerkleRoot(block);
    Mine(block);
    const auto before = GetFullKawpowCheckCount();
    BOOST_CHECK(!Import(block));
    BOOST_CHECK_EQUAL(GetFullKawpowCheckCount() - before, 1U);
    LOCK(cs_main);
    BOOST_CHECK(Index(block)->nStatus & BLOCK_FAILED_VALID);
    BOOST_CHECK(!(Index(block)->nStatus & BLOCK_HAVE_DATA));
}

BOOST_AUTO_TEST_CASE(valid_pow_does_not_skip_contextual_checks)
{
    auto block = Block();
    CMutableTransaction coinbase(*block.vtx[0]);
    coinbase.vin[0].scriptSig = CScript() << 999 << OP_0;
    block.vtx[0] = MakeTransactionRef(coinbase);
    block.hashMerkleRoot = BlockMerkleRoot(block);
    Mine(block);
    const auto before = GetFullKawpowCheckCount();
    BOOST_CHECK(!Import(block));
    BOOST_CHECK_EQUAL(GetFullKawpowCheckCount() - before, 1U);
    LOCK(cs_main);
    BOOST_CHECK(Index(block)->nStatus & BLOCK_FAILED_VALID);
    BOOST_CHECK(!(Index(block)->nStatus & BLOCK_HAVE_DATA));
}

BOOST_AUTO_TEST_CASE(serialized_checked_flag_is_not_trusted)
{
    auto block = Block();
    block.nBits = 0x207fffff;
    do { ++block.nNonce64; }
    while (CheckProofOfWork(block.GetHashFull(block.mix_hash), block.nBits, GetParams().GetConsensus()));
    block.fChecked = true;
    BOOST_CHECK(!Import(block));
    LOCK(cs_main);
    BOOST_CHECK(mapBlockIndex.count(block.GetHash()) == 0);
}

BOOST_AUTO_TEST_CASE(sha256_import_retains_validation)
{
    bNetwork.fSHA256Mining = true;
    nKAWPOWActivationTime = activation;
    const auto block = Block();
    BOOST_REQUIRE(Import(block));
    Connect(block);
    auto invalid = Block();
    invalid.nBits = 0x207fffff;
    uint256 mix;
    do { ++invalid.nNonce; }
    while (CheckProofOfWork(invalid.GetHashFull(mix), invalid.nBits, GetParams().GetConsensus()));
    BOOST_CHECK(!Import(invalid));
    LOCK(cs_main);
    BOOST_CHECK(mapBlockIndex.count(invalid.GetHash()) == 0);
}

BOOST_AUTO_TEST_SUITE_END()
