// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Consensus cleanup (Neurai port of BIP-54): block timestamp bounds, the
// per-transaction limit on executed legacy signature operations and the
// invalidity of 64-byte transactions.

#include "arith_uint256.h"
#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "key.h"
#include "miner.h"
#include "policy/policy.h"
#include "pow.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/standard.h"
#include "test/test_neurai.h"
#include "txmempool.h"
#include "utiltime.h"
#include "validation.h"
#include "versionbits.h"

#include <algorithm>
#include <limits>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

// Blocks [nFirstHeight, nFirstHeight + count), linked; the vector never
// reallocates so pprev stays valid.
struct IndexChain
{
    std::vector<CBlockIndex> blocks;
    int nFirst;
    IndexChain(int nFirstHeight, size_t capacity) : nFirst(nFirstHeight) { blocks.reserve(capacity); }
    CBlockIndex& Tip() { return blocks.back(); }
    void Add(uint32_t nTime, uint32_t nBits = 0x1b0404cb)
    {
        BOOST_REQUIRE(blocks.size() < blocks.capacity());
        CBlockIndex index;
        index.pprev = blocks.empty() ? nullptr : &blocks.back();
        index.nHeight = nFirst + blocks.size();
        index.nTime = nTime;
        index.nBits = nBits;
        blocks.push_back(index);
    }
};

const uint32_t SIMULATION_START_TIME = 1800000000;
const uint32_t EQUILIBRIUM_BITS = 0x1b0404cb;

struct StampRun
{
    int nBlocks = 0;          // blocks found within the simulated time
    double lowestDiff = 1.0;  // lowest difficulty, relative to EQUILIBRIUM_BITS
};

// One miner holds the whole (constant) hashrate. `pattern` gives, block after
// block, the timestamp it uses: 'H' the latest the network accepts, 'L' the
// earliest GetMinimumBlockTime allows, 'N' its clock. `hashrate` is relative
// to the one that finds a block of EQUILIBRIUM_BITS every 60 seconds.
StampRun SimulateStamps(const Consensus::Params& params, double hashrate, const std::string& pattern, int64_t nSeconds)
{
    const int nFirstHeight = 2000000;
    const int nCapacity = 400 + 200000;
    IndexChain chain(nFirstHeight, nCapacity);
    arith_uint256 equilibrium;
    equilibrium.SetCompact(EQUILIBRIUM_BITS);
    const double spacing = 60.0 / hashrate;
    double now = SIMULATION_START_TIME;
    for (int i = 0; i < 400; i++) {
        now += spacing;
        chain.Add((uint32_t)now, EQUILIBRIUM_BITS);
    }
    const double start = now;
    StampRun run;
    for (size_t i = 0; now - start < nSeconds; i++) {
        BOOST_REQUIRE(chain.blocks.size() < chain.blocks.capacity());
        CBlockHeader header;
        header.nTime = chain.Tip().nTime + 1;
        const uint32_t nBits = GetNextWorkRequired(&chain.Tip(), &header, params);
        arith_uint256 target;
        target.SetCompact(nBits);
        now += 60.0 * equilibrium.getdouble() / target.getdouble() / hashrate;
        run.lowestDiff = std::min(run.lowestDiff, equilibrium.getdouble() / target.getdouble());

        const int64_t nEarliest = GetMinimumBlockTime(&chain.Tip());
        int64_t nLatest = (int64_t)now + MAX_FUTURE_BLOCK_TIME_DGW;
        if (nEarliest > nLatest) {
            // No valid stamp exists until real time catches up.
            now = nEarliest - MAX_FUTURE_BLOCK_TIME_DGW;
            nLatest = nEarliest;
        }
        const char c = pattern[i % pattern.size()];
        const int64_t nTime = c == 'H' ? nLatest : c == 'L' ? nEarliest : std::max<int64_t>(nEarliest, (int64_t)now);
        BOOST_REQUIRE(nTime >= GetConsensusCleanupMinimumTime(&chain.Tip()));
        chain.Add((uint32_t)nTime, nBits);
        run.nBlocks++;
    }
    return run;
}

Consensus::Params MainnetParams(bool fBlockTimeReduction)
{
    Consensus::Params params = CreateChainParams(CBaseChainParams::MAIN)->GetConsensus();
    params.nConsensusCleanupHeight = 0;
    params.nBlockTimeReductionHeight = fBlockTimeReduction ? 0 : std::numeric_limits<int>::max();
    return params;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(consensus_cleanup_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(minimum_time_follows_the_parent_and_the_window)
{
    IndexChain chain(0, 400);
    for (int i = 0; i < 100; i++) chain.Add(SIMULATION_START_TIME + 60 * i);
    // Short chain: only the parent bound applies.
    BOOST_CHECK_EQUAL(GetConsensusCleanupMinimumTime(&chain.Tip()), (int64_t)chain.Tip().nTime - MAX_BLOCK_TIME_REGRESSION);

    // The block at height 179 closes the window [0, 179]: it may not be earlier
    // than block 0, however close its parent is.
    while (chain.Tip().nHeight < 178) chain.Add(chain.Tip().nTime + 60);
    chain.blocks[0].nTime = chain.Tip().nTime + 5000;
    BOOST_CHECK_EQUAL(GetConsensusCleanupMinimumTime(&chain.Tip()), (int64_t)chain.blocks[0].nTime);
    chain.blocks[0].nTime = SIMULATION_START_TIME;
    BOOST_CHECK_EQUAL(GetConsensusCleanupMinimumTime(&chain.Tip()), (int64_t)chain.Tip().nTime - MAX_BLOCK_TIME_REGRESSION);

    // GetMinimumBlockTime also keeps the median time past rule.
    BOOST_CHECK_EQUAL(GetMinimumBlockTime(&chain.Tip()),
                      std::max<int64_t>(chain.Tip().GetMedianTimePast() + 1, GetConsensusCleanupMinimumTime(&chain.Tip())));
}

BOOST_AUTO_TEST_CASE(extreme_timestamps_keep_the_retarget_bounded)
{
    // Whichever valid timestamps a miner with all the hashrate chooses, the
    // block rate stays the honest one and the difficulty stays within a small
    // factor of it, before and after the NIP-028 block-time reduction.
    const int64_t nWeek = 7 * 24 * 60 * 60;
    for (const bool fReduction : {false, true}) {
        const Consensus::Params params = MainnetParams(fReduction);
        const double hashrate = fReduction ? 2.0 : 1.0; // equilibrium at EQUILIBRIUM_BITS
        const StampRun honest = SimulateStamps(params, hashrate, "N", nWeek);
        const std::vector<std::string> patterns{"HHHLLLHHLLL", "HHHHHLLLLLL", "HLLLLLLLLLLLL", "HHLLLLLLLLL", "HLL",
                                                "H" + std::string(59, 'L'), "HL", "L"};
        for (const std::string& pattern : patterns) {
            const StampRun run = SimulateStamps(params, hashrate, pattern, nWeek);
            BOOST_TEST_MESSAGE("spacing " << (fReduction ? 30 : 60) << " s, pattern " << pattern << ": "
                               << run.nBlocks << " blocks (honest " << honest.nBlocks << "), lowest difficulty "
                               << run.lowestDiff);
            BOOST_CHECK_MESSAGE(run.nBlocks <= honest.nBlocks * 1.02,
                                "pattern " << pattern << " found " << run.nBlocks << " blocks, honest " << honest.nBlocks);
            BOOST_CHECK_MESSAGE(run.lowestDiff >= 0.4,
                                "pattern " << pattern << " lowered the difficulty to " << run.lowestDiff);
        }
    }
}

BOOST_AUTO_TEST_CASE(legacy_sigops_count_where_they_execute)
{
    CCoinsView base;
    CCoinsViewCache view(&base);
    CKey key;
    key.MakeNewKey(true);
    const std::vector<unsigned char> pubkey = ToByteVector(key.GetPubKey());

    // Spent scriptPubKeys, one per input.
    const CScript bareChecksig = CScript() << pubkey << OP_CHECKSIG;                            // 1
    const CScript bareMultisig = CScript() << OP_1 << pubkey << pubkey << OP_2 << OP_CHECKMULTISIG; // 2
    const CScript bareUncounted = CScript() << OP_CHECKMULTISIG;                                // 20: no OP_n before it
    const CScript redeem = CScript() << OP_2 << pubkey << pubkey << pubkey << OP_3 << OP_CHECKMULTISIG; // 3
    const CScript p2sh = GetScriptForDestination(CScriptID(redeem));
    const CScript witness = CScript() << OP_0 << std::vector<unsigned char>(32, 1);            // 0
    const CScript checkSigAdd = CScript() << OP_0 << pubkey << OP_CHECKSIGADD;                 // 1 with its flag

    CMutableTransaction mtx;
    const std::vector<CScript> spent{bareChecksig, bareMultisig, bareUncounted, p2sh, witness, checkSigAdd};
    for (size_t i = 0; i < spent.size(); i++) {
        COutPoint outpoint(InsecureRand256(), 0);
        view.AddCoin(outpoint, Coin(CTxOut(1000, spent[i]), 1, false), false);
        mtx.vin.emplace_back(outpoint);
    }
    // The scriptSig counts too: one CHECKSIG pushed as an opcode, plus the
    // redeem script of the P2SH input.
    mtx.vin[0].scriptSig = CScript() << OP_CHECKSIG;
    mtx.vin[3].scriptSig = CScript() << OP_0 << std::vector<unsigned char>(redeem.begin(), redeem.end());
    mtx.vout.emplace_back(500, CScript() << OP_TRUE);
    const CTransaction tx(mtx);

    const unsigned int nBase = 1 + 1 + 2 + 20 + 3 + 0;
    BOOST_CHECK_EQUAL(GetLegacyExecutedSigOpCount(tx, view, SCRIPT_VERIFY_P2SH), nBase);
    BOOST_CHECK_EQUAL(GetLegacyExecutedSigOpCount(tx, view, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CHECKSIGADD), nBase + 1);
    // The block-wide legacy count does not see the spent scriptPubKeys.
    BOOST_CHECK_EQUAL(GetLegacySigOpCount(tx), 1u);

    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].scriptSig = CScript() << OP_CHECKSIG << OP_CHECKSIG;
    coinbase.vout.emplace_back(1, CScript() << OP_TRUE);
    BOOST_CHECK_EQUAL(GetLegacyExecutedSigOpCount(CTransaction(coinbase), view, SCRIPT_VERIFY_P2SH), 0u);
}

BOOST_AUTO_TEST_SUITE_END()

namespace {

// Regtest chain of headers from genesis, to exercise ContextualCheckBlockHeader.
struct HeaderChainSetup : public TestingSetup
{
    HeaderChainSetup() : TestingSetup(CBaseChainParams::REGTEST) {}

    CBlockHeader Next(const CBlockIndex* pprev, int64_t nTime) const
    {
        CBlockHeader header;
        header.nVersion = VERSIONBITS_TOP_BITS_ASSETS;
        header.hashPrevBlock = pprev->GetBlockHash();
        header.nHeight = pprev->nHeight + 1;
        header.nTime = nTime;
        header.nBits = GetNextWorkRequired(pprev, &header, GetParams().GetConsensus());
        while (!CheckProofOfWork(header.GetHash(), header.nBits, GetParams().GetConsensus())) ++header.nNonce;
        return header;
    }

    // The index of the accepted header, or nullptr with the reason in `reason`.
    const CBlockIndex* Accept(const CBlockHeader& header, std::string& reason) const
    {
        CValidationState state;
        const CBlockIndex* pindex = nullptr;
        if (!ProcessNewBlockHeaders({header}, state, GetParams(), &pindex)) {
            reason = state.GetRejectReason();
            return nullptr;
        }
        return pindex;
    }

    const CBlockIndex* Genesis() const
    {
        LOCK(cs_main);
        return chainActive.Genesis();
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(consensus_cleanup_header_tests, HeaderChainSetup)

BOOST_AUTO_TEST_CASE(timestamp_may_not_fall_too_far_behind_the_parent)
{
    std::string reason;
    const CBlockIndex* pindex = Genesis();
    const int64_t base = pindex->GetBlockTime();
    for (int i = 1; i <= 12; i++) {
        pindex = Accept(Next(pindex, base + 60 * i), reason);
        BOOST_REQUIRE_MESSAGE(pindex, reason);
    }
    // A parent stamped ahead of its neighbours, as a clock running fast does.
    const CBlockIndex* parent = Accept(Next(pindex, base + 60 * 13 + 600), reason);
    BOOST_REQUIRE_MESSAGE(parent, reason);
    const int64_t nParent = parent->GetBlockTime();
    BOOST_REQUIRE(nParent - MAX_BLOCK_TIME_REGRESSION - 1 > parent->GetMedianTimePast());

    BOOST_CHECK(!Accept(Next(parent, nParent - MAX_BLOCK_TIME_REGRESSION - 1), reason));
    BOOST_CHECK_EQUAL(reason, "time-too-early-for-parent");
    BOOST_CHECK_MESSAGE(Accept(Next(parent, nParent - MAX_BLOCK_TIME_REGRESSION), reason), reason);

    // Below the activation height the median time past is the only bound.
    UpdateConsensusCleanupHeight(std::numeric_limits<int>::max());
    BOOST_CHECK_MESSAGE(Accept(Next(parent, nParent - MAX_BLOCK_TIME_REGRESSION - 2), reason), reason);
    UpdateConsensusCleanupHeight(0);
}

BOOST_AUTO_TEST_CASE(timestamp_may_not_precede_the_start_of_its_window)
{
    std::string reason;
    const CBlockIndex* pindex = Genesis();
    const int64_t base = pindex->GetBlockTime();
    for (int i = 1; i <= 20; i++) {
        pindex = Accept(Next(pindex, base + 60 * i), reason);
        BOOST_REQUIRE_MESSAGE(pindex, reason);
    }
    // Block K far ahead of the others; the blocks after it stay close to the
    // parent bound, so that 179 blocks later the window would span backwards.
    const int64_t nFirst = base + 60 * 21 + 10000;
    const CBlockIndex* first = Accept(Next(pindex, nFirst), reason);
    BOOST_REQUIRE_MESSAGE(first, reason);
    pindex = first;
    for (int j = 1; j < DGW_PAST_BLOCKS - 1; j++) {
        pindex = Accept(Next(pindex, nFirst - MAX_BLOCK_TIME_REGRESSION + j), reason);
        BOOST_REQUIRE_MESSAGE(pindex, reason);
    }
    BOOST_REQUIRE_EQUAL(pindex->nHeight + 1 - (DGW_PAST_BLOCKS - 1), first->nHeight);
    BOOST_REQUIRE(nFirst - 1 >= pindex->GetBlockTime() - MAX_BLOCK_TIME_REGRESSION);
    BOOST_REQUIRE(nFirst - 1 > pindex->GetMedianTimePast());

    BOOST_CHECK(!Accept(Next(pindex, nFirst - 1), reason));
    BOOST_CHECK_EQUAL(reason, "time-too-early-for-window");
    BOOST_CHECK_MESSAGE(Accept(Next(pindex, nFirst), reason), reason);
}

BOOST_AUTO_TEST_SUITE_END()

namespace {

// Mines `block` on the current tip at `nTime` and processes it.
void MineAt(CBlock& block, int64_t nTime)
{
    const CChainParams& chainparams = GetParams();
    {
        LOCK(cs_main);
        block.nTime = nTime;
        block.nBits = GetNextWorkRequired(chainActive.Tip(), &block, chainparams.GetConsensus());
        unsigned int extraNonce = 0;
        IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);
    }
    uint256 mix_hash;
    while (!CheckProofOfWork(block.GetHashFull(mix_hash), block.nBits, chainparams.GetConsensus())) { ++block.nNonce64; ++block.nNonce; }
    block.mix_hash = mix_hash;
    ProcessNewBlock(chainparams, std::make_shared<const CBlock>(block), true, nullptr);
}

uint256 TipHash()
{
    LOCK(cs_main);
    return chainActive.Tip()->GetBlockHash();
}

// Spends a mature coinbase of the setup into outputs with the given scripts.
CMutableTransaction Fund(const CTransaction& coinbase, const CKey& key, const std::vector<CScript>& scripts, CAmount nEach)
{
    CMutableTransaction mtx;
    mtx.nVersion = 1;
    mtx.vin.emplace_back(COutPoint(coinbase.GetHash(), 0));
    for (const CScript& script : scripts) mtx.vout.emplace_back(nEach, script);
    const CScript spent = coinbase.vout[0].scriptPubKey;
    std::vector<unsigned char> vchSig;
    const uint256 hash = SignatureHash(spent, mtx, 0, SIGHASH_ALL, 0, SIGVERSION_BASE);
    BOOST_REQUIRE(key.Sign(hash, vchSig));
    vchSig.push_back((unsigned char)SIGHASH_ALL);
    mtx.vin[0].scriptSig << vchSig;
    return mtx;
}

// A bare script that executes nMultisig CHECKMULTISIG with no keys (each
// counted as 20) and nOne CHECKMULTISIG with one key (each counted as 1).
CScript CountedScript(int nMultisig, int nOne)
{
    CScript script;
    for (int i = 0; i < nMultisig; i++) script << OP_0 << OP_0 << OP_0 << OP_CHECKMULTISIG << OP_DROP;
    for (int i = 0; i < nOne; i++) script << OP_0 << OP_0 << std::vector<unsigned char>(33, 2) << OP_1 << OP_CHECKMULTISIG << OP_DROP;
    script << OP_TRUE;
    return script;
}

// Spends outputs [nFirst, nFirst + nCount) of `funding` to OP_TRUE.
CMutableTransaction SpendRange(const CTransaction& funding, size_t nFirst, size_t nCount, CAmount nFee)
{
    CMutableTransaction mtx;
    mtx.nVersion = 1;
    CAmount nIn = 0;
    for (size_t i = nFirst; i < nFirst + nCount; i++) {
        mtx.vin.emplace_back(COutPoint(funding.GetHash(), i));
        nIn += funding.vout[i].nValue;
    }
    mtx.vout.emplace_back(nIn - nFee, CScript() << OP_TRUE);
    return mtx;
}

bool ToMempool(const CMutableTransaction& mtx, std::string& reason)
{
    LOCK(cs_main);
    CValidationState state;
    const bool fAccepted = AcceptToMemoryPool(mempool, state, MakeTransactionRef(mtx), nullptr, true, 0);
    reason = state.GetRejectReason();
    return fAccepted;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(consensus_cleanup_block_tests, TestChain100Setup)

BOOST_AUTO_TEST_CASE(template_time_respects_the_parent_bound)
{
    const CScript script = CScript() << OP_TRUE;
    int64_t T;
    {
        LOCK(cs_main);
        T = std::max<int64_t>(chainActive.Tip()->GetMedianTimePast() + 1000, GetTime());
    }
    SetMockTime(T);
    // A parent stamped at the future limit of a node whose clock reads T.
    std::unique_ptr<CBlockTemplate> parent = BlockAssembler(GetParams()).CreateNewBlock(script);
    MineAt(parent->block, T + MAX_FUTURE_BLOCK_TIME_DGW);
    BOOST_REQUIRE(TipHash() == parent->block.GetHash());

    // The clock then reads 300 seconds less. The template keeps the parent
    // bound instead of the clock, and is valid (CreateNewBlock checks it).
    SetMockTime(T - 300);
    std::unique_ptr<CBlockTemplate> next = BlockAssembler(GetParams()).CreateNewBlock(script);
    BOOST_CHECK_EQUAL(next->block.GetBlockTime(), T);
    {
        LOCK(cs_main);
        BOOST_CHECK_EQUAL(GetMinimumBlockTime(chainActive.Tip()), T);
    }
    SetMockTime(0);
}

BOOST_AUTO_TEST_CASE(legacy_sigop_limit_applies_per_transaction)
{
    const CScript coinbaseScript = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    // 17 outputs of 7 x 20 and one of 6 x 20: spending all of them executes
    // exactly MAX_TX_LEGACY_SIGOPS; one more output of a single counted sigop
    // goes one over.
    std::vector<CScript> scripts(17, CountedScript(7, 0));
    scripts.push_back(CountedScript(6, 0));
    std::vector<CScript> over = scripts;
    over.push_back(CountedScript(0, 1));

    std::vector<CScript> all = scripts;
    all.insert(all.end(), over.begin(), over.end());
    // Only the first coinbase of the setup is mature at the next height.
    const CMutableTransaction fund = Fund(coinbaseTxns[0], coinbaseKey, all, 10 * CENT);
    const CMutableTransaction atLimitTx = SpendRange(CTransaction(fund), 0, scripts.size(), CENT);
    const CMutableTransaction overLimitTx = SpendRange(CTransaction(fund), scripts.size(), over.size(), CENT);
    CreateAndProcessBlock({fund}, coinbaseScript);
    {
        LOCK(cs_main);
        CCoinsViewCache view(pcoinsTip);
        BOOST_REQUIRE(view.HaveCoin(COutPoint(fund.GetHash(), 0)));
        BOOST_CHECK_EQUAL(GetLegacyExecutedSigOpCount(CTransaction(atLimitTx), view, SCRIPT_VERIFY_P2SH), MAX_TX_LEGACY_SIGOPS);
        BOOST_CHECK_EQUAL(GetLegacyExecutedSigOpCount(CTransaction(overLimitTx), view, SCRIPT_VERIFY_P2SH), MAX_TX_LEGACY_SIGOPS + 1);
    }

    // The mempool refuses the transaction over the limit on every network.
    const bool fStandard = fRequireStandard;
    fRequireStandard = false;
    std::string reason;
    BOOST_CHECK(!ToMempool(overLimitTx, reason));
    BOOST_CHECK_EQUAL(reason, "bad-txns-legacy-sigops");
    fRequireStandard = fStandard;

    // In a block: over the limit is invalid, at the limit is valid.
    const uint256 before = TipHash();
    CreateAndProcessBlock({overLimitTx}, coinbaseScript);
    BOOST_CHECK(TipHash() == before);
    const CBlock atLimit = CreateAndProcessBlock({atLimitTx}, coinbaseScript);
    BOOST_CHECK(TipHash() == atLimit.GetHash());

    // Below the activation height only the block-wide limit applies.
    UpdateConsensusCleanupHeight(std::numeric_limits<int>::max());
    const CBlock overLimit = CreateAndProcessBlock({overLimitTx}, coinbaseScript);
    BOOST_CHECK(TipHash() == overLimit.GetHash());
    UpdateConsensusCleanupHeight(0);
}

BOOST_AUTO_TEST_CASE(transactions_of_64_bytes_are_invalid)
{
    const CScript coinbaseScript = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    const CMutableTransaction fund = Fund(coinbaseTxns[0], coinbaseKey,
                                          {CScript() << OP_TRUE, CScript() << OP_TRUE, CScript() << OP_TRUE}, 10 * CENT);
    CreateAndProcessBlock({fund}, coinbaseScript);

    // One input with an empty scriptSig and one output: 60 bytes plus the
    // output script.
    auto Spend = [&](unsigned int n, size_t nScript) {
        CMutableTransaction mtx;
        mtx.nVersion = 1;
        mtx.vin.emplace_back(COutPoint(fund.GetHash(), n));
        mtx.vout.emplace_back(9 * CENT, CScript() << OP_RETURN << std::vector<unsigned char>(nScript - 2, 0x42));
        return mtx;
    };
    const CMutableTransaction tx64 = Spend(0, 4);
    const CMutableTransaction tx65 = Spend(1, 5);
    BOOST_REQUIRE_EQUAL(::GetSerializeSize(CTransaction(tx64), SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS), 64u);
    BOOST_REQUIRE_EQUAL(::GetSerializeSize(CTransaction(tx65), SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS), 65u);

    // Policy: below 65 bytes is not standard.
    std::string reason;
    BOOST_CHECK(!IsStandardTx(CTransaction(tx64), reason, true));
    BOOST_CHECK_EQUAL(reason, "tx-size-small");
    BOOST_CHECK(IsStandardTx(CTransaction(tx65), reason, true));

    // The mempool refuses it even when non-standard transactions are accepted.
    const bool fStandard = fRequireStandard;
    fRequireStandard = false;
    BOOST_CHECK(!ToMempool(tx64, reason));
    BOOST_CHECK_EQUAL(reason, "bad-txns-64-byte");
    fRequireStandard = fStandard;

    const uint256 before = TipHash();
    CreateAndProcessBlock({tx64}, coinbaseScript);
    BOOST_CHECK(TipHash() == before);
    const CBlock with65 = CreateAndProcessBlock({tx65}, coinbaseScript);
    BOOST_CHECK(TipHash() == with65.GetHash());

    UpdateConsensusCleanupHeight(std::numeric_limits<int>::max());
    const CBlock with64 = CreateAndProcessBlock({tx64}, coinbaseScript);
    BOOST_CHECK(TipHash() == with64.GetHash());
    UpdateConsensusCleanupHeight(0);
}

BOOST_AUTO_TEST_CASE(reference_inputs_stay_in_the_measured_size)
{
    // The size the rule measures is the txid preimage, which keeps the
    // reference inputs record: a transaction with them cannot be 64 bytes.
    CMutableTransaction mtx;
    mtx.nVersion = 3;
    mtx.vin.emplace_back(COutPoint(InsecureRand256(), 0));
    mtx.vout.emplace_back(1, CScript());
    mtx.vrefin.emplace_back(InsecureRand256(), 0);
    const CTransaction tx(mtx);
    CMutableTransaction plain(mtx);
    plain.vrefin.clear();
    BOOST_CHECK_EQUAL(::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS),
                      ::GetSerializeSize(CTransaction(plain), SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) + 2 + 1 + 36);
}

BOOST_AUTO_TEST_SUITE_END()
