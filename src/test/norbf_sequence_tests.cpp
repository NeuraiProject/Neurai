// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// No-RBF sequence rule: from Consensus::Params::nNoRbfHeight a sequence that
// only signals BIP 125 replaceability makes a transaction invalid, while final
// sequences, 0xfffffffe and BIP 68 relative locks stay valid. Transaction
// replacement no longer exists in the mempool.

#include "chainparams.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "keystore.h"
#include "miner.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "script/sign.h"
#include "script/standard.h"
#include "test/test_neurai.h"
#include "txdb.h"
#include "txmempool.h"
#include "validation.h"

#include <limits>

#include <boost/test/unit_test.hpp>

namespace {

const uint32_t SIGNAL = 0xfffffffd;               // BIP 125 signal, disable flag set
const uint32_t NON_FINAL = CTxIn::SEQUENCE_FINAL - 1; // enables nLockTime, no signal

CMutableTransaction TxWithSequences(int32_t nVersion, const std::vector<uint32_t>& sequences)
{
    CMutableTransaction mtx;
    mtx.nVersion = nVersion;
    for (size_t i = 0; i < sequences.size(); ++i) {
        mtx.vin.emplace_back(COutPoint(uint256S("0101"), i), CScript(), sequences[i]);
    }
    mtx.vout.emplace_back(1, CScript() << OP_TRUE);
    return mtx;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(norbf_sequence_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(predicate_table)
{
    // Values at every frontier of the rule.
    const std::vector<uint32_t> relative = {0x00000000, 0x00000001, 0x0000ffff, 0x00400005, 0x7fffffff};
    const std::vector<uint32_t> signals = {0x80000000, 0x80000001, 0xfffffff0, SIGNAL};
    const std::vector<uint32_t> always = {NON_FINAL, CTxIn::SEQUENCE_FINAL};

    // Versions that enforce BIP 68: 2, 3 and any value that is >= 2 as uint32_t.
    for (int32_t nVersion : {2, 3, 4, -1, std::numeric_limits<int32_t>::min()}) {
        for (uint32_t seq : relative) BOOST_CHECK_MESSAGE(CTxIn::IsNoRbfSequenceAllowed(nVersion, seq), nVersion << " " << seq);
        for (uint32_t seq : signals) BOOST_CHECK_MESSAGE(!CTxIn::IsNoRbfSequenceAllowed(nVersion, seq), nVersion << " " << seq);
        for (uint32_t seq : always) BOOST_CHECK(CTxIn::IsNoRbfSequenceAllowed(nVersion, seq));
    }
    // Versions 0 and 1 give no meaning to any value below 0xfffffffe.
    for (int32_t nVersion : {0, 1}) {
        for (uint32_t seq : relative) BOOST_CHECK_MESSAGE(!CTxIn::IsNoRbfSequenceAllowed(nVersion, seq), nVersion << " " << seq);
        for (uint32_t seq : signals) BOOST_CHECK_MESSAGE(!CTxIn::IsNoRbfSequenceAllowed(nVersion, seq), nVersion << " " << seq);
        for (uint32_t seq : always) BOOST_CHECK(CTxIn::IsNoRbfSequenceAllowed(nVersion, seq));
    }
}

BOOST_AUTO_TEST_CASE(check_rejects_any_signaling_input)
{
    CValidationState ok;
    BOOST_CHECK(Consensus::CheckNoRbfSequences(CTransaction(TxWithSequences(2, {CTxIn::SEQUENCE_FINAL, NON_FINAL, 1})), ok));
    BOOST_CHECK(ok.IsValid());

    // The offending input may be any of them; the whole transaction is invalid.
    CValidationState state;
    BOOST_CHECK(!Consensus::CheckNoRbfSequences(CTransaction(TxWithSequences(2, {CTxIn::SEQUENCE_FINAL, NON_FINAL, SIGNAL})), state));
    int nDoS = 0;
    BOOST_CHECK(state.IsInvalid(nDoS));
    BOOST_CHECK_EQUAL(nDoS, 100);
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-rbf-sequence");
    BOOST_CHECK(state.GetDebugMessage().find("input 2") != std::string::npos);
    BOOST_CHECK(state.GetDebugMessage().find("0xfffffffd") != std::string::npos);

    // A relative-lock value is a signal in a version 1 transaction.
    CValidationState v1;
    BOOST_CHECK(!Consensus::CheckNoRbfSequences(CTransaction(TxWithSequences(1, {1})), v1));
    BOOST_CHECK_EQUAL(v1.GetRejectReason(), "bad-txns-rbf-sequence");
}

BOOST_AUTO_TEST_CASE(coinbase_is_exempt)
{
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << 1 << OP_0;
    coinbase.vin[0].nSequence = 0;
    coinbase.vout.emplace_back(1, CScript() << OP_TRUE);
    for (int32_t nVersion : {1, 2}) {
        coinbase.nVersion = nVersion;
        CValidationState state;
        BOOST_CHECK(CTransaction(coinbase).IsCoinBase());
        BOOST_CHECK(Consensus::CheckNoRbfSequences(CTransaction(coinbase), state));
    }
}

BOOST_AUTO_TEST_CASE(activation_height_per_network)
{
    const int never = std::numeric_limits<int>::max();

    SelectParams(CBaseChainParams::MAIN);
    BOOST_CHECK_EQUAL(GetParams().GetConsensus().nNoRbfHeight, never);
    BOOST_CHECK(!GetParams().GetConsensus().IsNoRbfActive(never - 1));

    SelectParams(CBaseChainParams::TESTNET);
    BOOST_CHECK_EQUAL(GetParams().GetConsensus().nNoRbfHeight, 10);
    BOOST_CHECK(!GetParams().GetConsensus().IsNoRbfActive(9));
    BOOST_CHECK(GetParams().GetConsensus().IsNoRbfActive(10));
    BOOST_CHECK_EQUAL(GetParams().GetConsensus().nNoRbfHeight, GetParams().GetConsensus().nDepinTransferStateHeight);

    SelectParams(CBaseChainParams::REGTEST);
    BOOST_CHECK_EQUAL(GetParams().GetConsensus().nNoRbfHeight, 0);
    BOOST_CHECK(GetParams().GetConsensus().IsNoRbfActive(0));
    UpdateNoRbfHeight(5);
    BOOST_CHECK(!GetParams().GetConsensus().IsNoRbfActive(4));
    BOOST_CHECK(GetParams().GetConsensus().IsNoRbfActive(5));
    UpdateNoRbfHeight(0);

    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_SUITE_END()

namespace {

struct NoRbfChainSetup : public TestChain100Setup {
    CBasicKeyStore keystore;
    CScript payScript;
    unsigned int nBlockSalt = 0;

    NoRbfChainSetup() : TestChain100Setup()
    {
        keystore.AddKey(coinbaseKey);
        payScript = GetScriptForDestination(coinbaseKey.GetPubKey().GetID());
        // Ten more blocks, so the coinbases of blocks 1 to 11 are mature.
        for (int i = 0; i < 10; i++) {
            BOOST_REQUIRE(Mine({}));
        }
    }

    ~NoRbfChainSetup()
    {
        UpdateNoRbfHeight(0); // the regtest default
        mempool.clear();
    }

    // Spend the output `n` of `prev` (paying to coinbaseKey) back to coinbaseKey.
    CMutableTransaction Spend(const CTransaction& prev, unsigned int n, int32_t nVersion, uint32_t nSequence, CAmount fee)
    {
        CMutableTransaction mtx;
        mtx.nVersion = nVersion;
        mtx.vin.emplace_back(COutPoint(prev.GetHash(), n), CScript(), nSequence);
        mtx.vout.emplace_back(prev.vout[n].nValue - fee, payScript);
        BOOST_REQUIRE(SignSignature(keystore, prev.vout[n].scriptPubKey, mtx, 0, prev.vout[n].nValue, SIGHASH_ALL));
        return mtx;
    }

    CMutableTransaction SpendCoinbase(unsigned int index, int32_t nVersion, uint32_t nSequence, CAmount fee = COIN)
    {
        return Spend(coinbaseTxns.at(index), 0, nVersion, nSequence, fee);
    }

    // Build a block with `txns` on the current tip without processing it. The
    // template's mempool transactions are dropped together with their fees
    // (vTxFees[0] is minus their total), the witness commitment is rebuilt for
    // our transaction list, and the extra nonce is fresh (re-mining after a
    // disconnect must not rebuild an invalid block).
    CBlock BuildBlock(const std::vector<CMutableTransaction>& txns, uint32_t nCoinbaseSequence = CTxIn::SEQUENCE_FINAL)
    {
        CScript coinbaseScript = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
        std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(GetParams()).CreateNewBlock(coinbaseScript);
        CBlock block = pblocktemplate->block;
        block.vtx.resize(1);
        for (const CMutableTransaction& tx : txns)
            block.vtx.push_back(MakeTransactionRef(tx));

        CMutableTransaction coinbase(*block.vtx[0]);
        coinbase.vout[0].nValue += pblocktemplate->vTxFees[0];
        coinbase.vin[0].nSequence = nCoinbaseSequence;
        for (size_t i = 0; i < coinbase.vout.size(); i++) {
            const CScript& script = coinbase.vout[i].scriptPubKey;
            if (script.size() >= 38 && script[0] == OP_RETURN && script[1] == 0x24 &&
                script[2] == 0xaa && script[3] == 0x21 && script[4] == 0xa9 && script[5] == 0xed) {
                coinbase.vout.erase(coinbase.vout.begin() + i);
                break;
            }
        }
        block.vtx[0] = MakeTransactionRef(std::move(coinbase));
        GenerateCoinbaseCommitment(block, chainActive.Tip(), GetParams().GetConsensus());
        unsigned int extraNonce = ++nBlockSalt;
        IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);
        return block;
    }

    // Mine `txns` into a block; true when the tip advanced to it.
    bool Mine(const std::vector<CMutableTransaction>& txns, uint32_t nCoinbaseSequence = CTxIn::SEQUENCE_FINAL)
    {
        const int nPrev = chainActive.Height();
        CBlock block = BuildBlock(txns, nCoinbaseSequence);
        uint256 mix_hash;
        while (!CheckProofOfWork(block.GetHashFull(mix_hash), block.nBits, GetParams().GetConsensus())) {
            ++block.nNonce64;
            ++block.nNonce;
        }
        block.mix_hash = mix_hash;
        ProcessNewBlock(GetParams(), std::make_shared<const CBlock>(block), true, nullptr);
        return chainActive.Height() == nPrev + 1 && chainActive.Tip()->GetBlockHash() == block.GetHash();
    }

    // Consensus verdict of a whole block via the fJustCheck path.
    bool BlockVerdict(const std::vector<CMutableTransaction>& txns, std::string& reason)
    {
        const CBlock block = BuildBlock(txns);
        CValidationState state;
        bool ok;
        {
            LOCK(cs_main);
            ok = TestBlockValidity(state, GetParams(), block, chainActive.Tip(), false, true);
        }
        reason = state.GetRejectReason();
        return ok;
    }

    bool ToMempool(const CMutableTransaction& mtx, std::string& reason, bool test_accept = false)
    {
        CValidationState state;
        bool ok;
        {
            LOCK(cs_main);
            ok = AcceptToMemoryPool(mempool, state, MakeTransactionRef(mtx), nullptr,
                                    false /* bypass_limits */, 0, test_accept);
        }
        reason = state.GetRejectReason();
        return ok;
    }

    void UndoTip()
    {
        CValidationState state;
        {
            LOCK(cs_main);
            BOOST_REQUIRE(InvalidateBlock(state, GetParams(), chainActive.Tip()));
        }
        BOOST_REQUIRE(state.IsValid());
    }

    bool InMempool(const CMutableTransaction& mtx) const { return mempool.exists(mtx.GetHash()); }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(norbf_sequence_chain_tests, NoRbfChainSetup)

// Blocks: H-1 accepts a signal, H rejects it; relative locks, 0xfffffffe and
// final sequences stay valid at H, and the coinbase sequence is free.
BOOST_AUTO_TEST_CASE(block_frontier)
{
    std::string reason;
    const int H = chainActive.Height() + 2;
    UpdateNoRbfHeight(H);

    // Next block is H-1: the signal is still valid.
    BOOST_CHECK(BlockVerdict({SpendCoinbase(0, 2, SIGNAL)}, reason));
    BOOST_REQUIRE(Mine({SpendCoinbase(0, 2, SIGNAL), SpendCoinbase(1, 1, 1)}));
    BOOST_REQUIRE_EQUAL(chainActive.Height(), H - 1);

    // Next block is H.
    for (const CMutableTransaction& bad : {SpendCoinbase(2, 2, SIGNAL),
                                           SpendCoinbase(2, 2, 0x80000000),
                                           SpendCoinbase(2, 3, 0xfffffff0),
                                           SpendCoinbase(2, 1, 1),
                                           SpendCoinbase(2, 1, 0)}) {
        BOOST_CHECK(!BlockVerdict({bad}, reason));
        BOOST_CHECK_EQUAL(reason, "bad-txns-rbf-sequence");
    }
    BOOST_CHECK(!Mine({SpendCoinbase(2, 2, SIGNAL)}));
    BOOST_CHECK_EQUAL(chainActive.Height(), H - 1);

    // A valid transaction does not rescue a block with one signaling input.
    CMutableTransaction twoInputs = SpendCoinbase(3, 2, NON_FINAL);
    twoInputs.vin.emplace_back(COutPoint(coinbaseTxns[4].GetHash(), 0), CScript(), SIGNAL);
    twoInputs.vout[0].nValue += coinbaseTxns[4].vout[0].nValue;
    BOOST_REQUIRE(SignSignature(keystore, coinbaseTxns[3].vout[0].scriptPubKey, twoInputs, 0, coinbaseTxns[3].vout[0].nValue, SIGHASH_ALL));
    BOOST_REQUIRE(SignSignature(keystore, coinbaseTxns[4].vout[0].scriptPubKey, twoInputs, 1, coinbaseTxns[4].vout[0].nValue, SIGHASH_ALL));
    BOOST_CHECK(!BlockVerdict({SpendCoinbase(5, 2, CTxIn::SEQUENCE_FINAL), twoInputs}, reason));
    BOOST_CHECK_EQUAL(reason, "bad-txns-rbf-sequence");

    // At H: relative locks (of one block, and of zero blocks: still a lock,
    // not a signal), 0xfffffffe, final sequences and a coinbase with sequence 0.
    BOOST_CHECK(Mine({SpendCoinbase(2, 2, 1),
                      SpendCoinbase(3, 3, 0),
                      SpendCoinbase(4, 2, NON_FINAL),
                      SpendCoinbase(5, 1, CTxIn::SEQUENCE_FINAL),
                      SpendCoinbase(6, 1, NON_FINAL)},
                     /*nCoinbaseSequence=*/0));
    BOOST_CHECK_EQUAL(chainActive.Height(), H);
}

// Mempool: admission follows the next block's height; connecting H-1 evicts
// signaling entries and their descendants, and a disconnect back below H
// admits them again.
BOOST_AUTO_TEST_CASE(mempool_frontier_purge_and_reorg)
{
    std::string reason;
    const int H = chainActive.Height() + 2;
    UpdateNoRbfHeight(H);

    // Next block is H-1.
    CMutableTransaction parent = SpendCoinbase(0, 2, SIGNAL);
    CMutableTransaction child = Spend(CTransaction(parent), 0, 2, CTxIn::SEQUENCE_FINAL, COIN);
    CMutableTransaction plain = SpendCoinbase(1, 2, NON_FINAL);
    CMutableTransaction relative = SpendCoinbase(2, 2, 1);
    for (const CMutableTransaction* tx : {&parent, &child, &plain, &relative}) {
        BOOST_REQUIRE_MESSAGE(ToMempool(*tx, reason), reason);
    }

    // Connecting H-1 makes the next block H: the signal and its descendant go.
    BOOST_REQUIRE(Mine({}));
    BOOST_CHECK(!InMempool(parent));
    BOOST_CHECK(!InMempool(child));
    BOOST_CHECK(InMempool(plain));
    BOOST_CHECK(InMempool(relative));
    BOOST_CHECK(!ToMempool(parent, reason));
    BOOST_CHECK_EQUAL(reason, "bad-txns-rbf-sequence");
    BOOST_CHECK(!ToMempool(parent, reason, /*test_accept=*/true));
    BOOST_CHECK_EQUAL(reason, "bad-txns-rbf-sequence");

    // The template stays valid and contains what is left.
    std::unique_ptr<CBlockTemplate> tmpl = BlockAssembler(GetParams()).CreateNewBlock(payScript);
    BOOST_REQUIRE(tmpl);
    BOOST_CHECK_EQUAL(tmpl->block.vtx.size(), 3U);

    // Disconnecting H-1 moves the next block back below H.
    UndoTip();
    BOOST_CHECK(ToMempool(parent, reason));
    BOOST_CHECK(ToMempool(child, reason));

    // Connecting H-1 again purges them again.
    BOOST_REQUIRE(Mine({}));
    BOOST_CHECK(!InMempool(parent));
    BOOST_CHECK(!InMempool(child));
    BOOST_CHECK(InMempool(plain));
}

// A stale signaling entry (one the transition purge would never leave behind)
// is kept out of the template instead of making CreateNewBlock fail.
BOOST_AUTO_TEST_CASE(miner_skips_signaling_entry)
{
    const CTransaction stale(SpendCoinbase(0, 2, SIGNAL));
    const CTransaction good(SpendCoinbase(1, 2, NON_FINAL));
    TestMemPoolEntryHelper entry;
    mempool.addUnchecked(stale.GetHash(), entry.Fee(COIN).FromTx(stale));
    mempool.addUnchecked(good.GetHash(), entry.Fee(COIN).FromTx(good));

    std::unique_ptr<CBlockTemplate> tmpl;
    BOOST_CHECK_NO_THROW(tmpl = BlockAssembler(GetParams()).CreateNewBlock(payScript));
    BOOST_REQUIRE(tmpl);
    bool hasStale = false, hasGood = false;
    for (const CTransactionRef& tx : tmpl->block.vtx) {
        hasStale |= tx->GetHash() == stale.GetHash();
        hasGood |= tx->GetHash() == good.GetHash();
    }
    BOOST_CHECK(!hasStale);
    BOOST_CHECK(hasGood);
}

// Transaction replacement is gone: a conflict is rejected whatever its fee and
// sequences, including while signals are still valid.
BOOST_AUTO_TEST_CASE(conflicts_always_rejected)
{
    std::string reason;

    UpdateNoRbfHeight(std::numeric_limits<int>::max());
    CMutableTransaction first = SpendCoinbase(0, 2, SIGNAL, COIN);
    BOOST_REQUIRE_MESSAGE(ToMempool(first, reason), reason);
    for (uint32_t seq : {SIGNAL, NON_FINAL, CTxIn::SEQUENCE_FINAL}) {
        CMutableTransaction higher = SpendCoinbase(0, 2, seq, 10 * COIN);
        BOOST_CHECK(!ToMempool(higher, reason, /*test_accept=*/true));
        BOOST_CHECK_EQUAL(reason, "txn-mempool-conflict");
        BOOST_CHECK(!ToMempool(higher, reason));
        BOOST_CHECK_EQUAL(reason, "txn-mempool-conflict");
        BOOST_CHECK(!InMempool(higher));
    }
    BOOST_CHECK(InMempool(first));
    mempool.clear();

    UpdateNoRbfHeight(0);
    CMutableTransaction firstFinal = SpendCoinbase(1, 2, NON_FINAL, COIN);
    BOOST_REQUIRE_MESSAGE(ToMempool(firstFinal, reason), reason);
    CMutableTransaction higherFinal = SpendCoinbase(1, 2, CTxIn::SEQUENCE_FINAL, 10 * COIN);
    BOOST_CHECK(!ToMempool(higherFinal, reason));
    BOOST_CHECK_EQUAL(reason, "txn-mempool-conflict");
    BOOST_CHECK(InMempool(firstFinal));
}

// A stored block is checked again whenever it is connected from disk
// (reconsiderblock, reindex, VerifyDB), which skips ContextualCheckBlock.
BOOST_AUTO_TEST_CASE(stored_block_rechecked_on_connect)
{
    UpdateNoRbfHeight(std::numeric_limits<int>::max());
    BOOST_REQUIRE(Mine({SpendCoinbase(0, 2, SIGNAL)}));
    CBlockIndex* pindexSignal = chainActive.Tip();

    // Reconnecting from disk while the rule is off restores the tip.
    auto reconnect = [&]() {
        UndoTip();
        {
            LOCK(cs_main);
            BOOST_REQUIRE(ResetBlockFailureFlags(pindexSignal));
        }
        CValidationState state;
        ActivateBestChain(state, GetParams());
    };
    reconnect();
    BOOST_CHECK(chainActive.Tip() == pindexSignal);

    // With the rule on at its height, the same block fails to connect.
    UpdateNoRbfHeight(pindexSignal->nHeight);
    reconnect();
    BOOST_CHECK(chainActive.Tip() == pindexSignal->pprev);
    BOOST_CHECK(pindexSignal->nStatus & BLOCK_FAILED_VALID);
}

// Startup: the active chain blocks that were connected with a higher
// activation height are read back and checked once.
BOOST_AUTO_TEST_CASE(startup_check_of_stored_blocks)
{
    std::string error;
    auto flag = []() {
        int value = -1;
        BOOST_REQUIRE(pblocktree->ReadIntFlag(NO_RBF_HEIGHT_FLAG, value));
        return value;
    };

    UpdateNoRbfHeight(std::numeric_limits<int>::max());
    BOOST_REQUIRE(Mine({}));
    BOOST_REQUIRE(Mine({SpendCoinbase(0, 2, SIGNAL)}));
    const int nSignal = chainActive.Height();
    BOOST_REQUIRE(Mine({}));
    BOOST_REQUIRE(Mine({}));

    // A datadir from an older build has no flag: every block from the
    // activation height is checked.
    UpdateNoRbfHeight(nSignal);
    BOOST_CHECK(!CheckNoRbfChainstate(GetParams(), error));
    int nUnset;
    BOOST_CHECK(!pblocktree->ReadIntFlag(NO_RBF_HEIGHT_FLAG, nUnset));

    // While the rule is off, nothing is checked and that is recorded.
    UpdateNoRbfHeight(std::numeric_limits<int>::max());
    BOOST_CHECK_MESSAGE(CheckNoRbfChainstate(GetParams(), error), error);
    BOOST_CHECK_EQUAL(flag(), std::numeric_limits<int>::max());

    // The blocks above the signal pass and the lower height is recorded.
    UpdateNoRbfHeight(nSignal + 1);
    BOOST_CHECK_MESSAGE(CheckNoRbfChainstate(GetParams(), error), error);
    BOOST_CHECK_EQUAL(flag(), nSignal + 1);

    // Reaching the signal fails and leaves the flag as it was.
    for (int nHeight : {nSignal, 0}) {
        UpdateNoRbfHeight(nHeight);
        error.clear();
        BOOST_CHECK(!CheckNoRbfChainstate(GetParams(), error));
        BOOST_CHECK(error.find(strprintf("Block %s at height %d breaks the no-RBF sequence rule",
                                         chainActive[nSignal]->GetBlockHash().ToString(), nSignal)) != std::string::npos);
        BOOST_CHECK(error.find("bad-txns-rbf-sequence") != std::string::npos);
        BOOST_CHECK(error.find("-reindex-chainstate") != std::string::npos);
        BOOST_CHECK_EQUAL(flag(), nSignal + 1);
    }

    // Raising the height needs no check; coming back down only checks the
    // blocks below the recorded height.
    UpdateNoRbfHeight(nSignal + 3);
    BOOST_CHECK_MESSAGE(CheckNoRbfChainstate(GetParams(), error), error);
    BOOST_CHECK_EQUAL(flag(), nSignal + 3);
    UpdateNoRbfHeight(nSignal + 1);
    BOOST_CHECK_MESSAGE(CheckNoRbfChainstate(GetParams(), error), error);
    BOOST_CHECK_EQUAL(flag(), nSignal + 1);
    UpdateNoRbfHeight(nSignal);
    BOOST_CHECK(!CheckNoRbfChainstate(GetParams(), error));

    // A height above the tip passes whatever was recorded.
    UpdateNoRbfHeight(chainActive.Height() + 1);
    BOOST_CHECK_MESSAGE(CheckNoRbfChainstate(GetParams(), error), error);
    BOOST_CHECK_EQUAL(flag(), chainActive.Height() + 1);
}

BOOST_AUTO_TEST_SUITE_END()
