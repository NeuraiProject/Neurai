// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The spent index must follow the active chain. DisconnectBlock used to collect
// the entries of the disconnected block without writing them, so after a reorg
// getspentinfo kept pointing at a spender that was no longer in the chain.
// VerifyDB disconnects blocks on a scratch view and must leave the index alone.

#include "amount.h"
#include "assets/assetdb.h"
#include "assets/assets.h"
#include "assets/assettypes.h"
#include "assets/restricteddb.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "keystore.h"
#include "miner.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "script/sign.h"
#include "script/standard.h"
#include "spentindex.h"
#include "test/test_neurai.h"
#include "txdb.h"
#include "txmempool.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

namespace {

// A 100-block regtest chain with in-memory asset databases (DisconnectBlock
// reads the asset undo data) and the spent index enabled.
struct SpentIndexSetup : public TestChain100Setup {
    CBasicKeyStore keystore;
    unsigned int nBlockSalt = 0;
    std::string strLastReject;

    SpentIndexSetup() : TestChain100Setup()
    {
        passetsdb = new CAssetsDB(1 << 20, true, true);
        passetsCache = new CLRUCache<std::string, CDatabasedAssetData>(100);
        prestricteddb = new CRestrictedDB(1 << 20, true, true);
        passetsVerifierCache = new CLRUCache<std::string, CNullAssetTxVerifierString>(100);
        passetsQualifierCache = new CLRUCache<std::string, int8_t>(100);
        passetsRestrictionCache = new CLRUCache<std::string, int8_t>(100);
        passetsGlobalRestrictionCache = new CLRUCache<std::string, int8_t>(100);
        passetsDepinTransferStateCache = new CLRUCache<std::string, int8_t>(100);
        keystore.AddKey(coinbaseKey);
        fSpentIndex = true;
    }

    ~SpentIndexSetup()
    {
        fSpentIndex = false;
        delete passetsDepinTransferStateCache; passetsDepinTransferStateCache = nullptr;
        delete passetsGlobalRestrictionCache; passetsGlobalRestrictionCache = nullptr;
        delete passetsRestrictionCache; passetsRestrictionCache = nullptr;
        delete passetsQualifierCache; passetsQualifierCache = nullptr;
        delete passetsVerifierCache; passetsVerifierCache = nullptr;
        delete prestricteddb; prestricteddb = nullptr;
        delete passetsCache; passetsCache = nullptr;
        delete passetsdb; passetsdb = nullptr;
    }

    // Spend output 0 of the first (mature) coinbase back to the coinbase key.
    CMutableTransaction SpendCoinbase()
    {
        const CTransaction& coinbase = coinbaseTxns[0];
        CMutableTransaction mut;
        mut.vin.emplace_back(COutPoint(coinbase.GetHash(), 0));
        mut.vout.emplace_back(coinbase.vout[0].nValue - COIN / 100,
                              GetScriptForDestination(coinbaseKey.GetPubKey().GetID()));
        BOOST_REQUIRE(SignSignature(keystore, coinbase.vout[0].scriptPubKey, mut, 0,
                                    coinbase.vout[0].nValue, SIGHASH_ALL));
        return mut;
    }

    // A block with `txns` on the tip, as in asset_read_flush_tests: the template
    // committed to its own transaction list, so the witness commitment is rebuilt
    // for ours, and a fresh extra nonce keeps re-mined blocks distinct.
    bool Mine(const std::vector<CMutableTransaction>& txns)
    {
        const int nPrev = chainActive.Height();
        CScript coinbaseScript = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
        std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(GetParams()).CreateNewBlock(coinbaseScript);
        CBlock block = pblocktemplate->block;
        block.vtx.resize(1);
        for (const CMutableTransaction& tx : txns)
            block.vtx.push_back(MakeTransactionRef(tx));

        CMutableTransaction coinbase(*block.vtx[0]);
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

        {
            LOCK(cs_main);
            CValidationState state;
            if (!TestBlockValidity(state, GetParams(), block, chainActive.Tip(), false, true)) {
                strLastReject = state.GetRejectReason();
                return false;
            }
        }

        uint256 mix_hash;
        while (!CheckProofOfWork(block.GetHashFull(mix_hash), block.nBits, GetParams().GetConsensus())) {
            ++block.nNonce64;
            ++block.nNonce;
        }
        block.mix_hash = mix_hash;
        ProcessNewBlock(GetParams(), std::make_shared<const CBlock>(block), true, nullptr);
        return chainActive.Height() == nPrev + 1 && chainActive.Tip()->GetBlockHash() == block.GetHash();
    }

    bool ReadSpent(const COutPoint& out, CSpentIndexValue& value)
    {
        CSpentIndexKey key(out.hash, out.n);
        return pblocktree->ReadSpentIndex(key, value);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(spentindex_reorg_tests, SpentIndexSetup)

BOOST_AUTO_TEST_CASE(spent_index_follows_disconnect_and_reconnect)
{
    const COutPoint spent(coinbaseTxns[0].GetHash(), 0);
    const CMutableTransaction spend = SpendCoinbase();
    const uint256 spendHash = spend.GetHash();

    BOOST_REQUIRE_MESSAGE(Mine({spend}), strLastReject);
    const uint256 spendBlockHash = chainActive.Tip()->GetBlockHash();
    const int spendHeight = chainActive.Height();

    CSpentIndexValue value;
    BOOST_REQUIRE(ReadSpent(spent, value));
    BOOST_CHECK(value.txid == spendHash);
    BOOST_CHECK_EQUAL(value.inputIndex, 0U);
    BOOST_CHECK_EQUAL(value.blockHeight, spendHeight);

    // VerifyDB disconnects and reconnects on a scratch view: the index must not change.
    {
        LOCK(cs_main);
        BOOST_REQUIRE(CVerifyDB().VerifyDB(GetParams(), pcoinsTip, 4, 2));
    }
    BOOST_REQUIRE(ReadSpent(spent, value));
    BOOST_CHECK(value.txid == spendHash);

    // Disconnect the spending block; drop the transaction it returns to the
    // mempool so the next block does not include it.
    CValidationState state;
    {
        LOCK(cs_main);
        BOOST_REQUIRE(InvalidateBlock(state, GetParams(), mapBlockIndex.at(spendBlockHash)));
    }
    BOOST_REQUIRE(state.IsValid());
    mempool.clear();
    BOOST_CHECK(!ReadSpent(spent, value));

    // A competing block at the same height that does not spend the output.
    BOOST_REQUIRE_MESSAGE(Mine({}), strLastReject);
    BOOST_CHECK_EQUAL(chainActive.Height(), spendHeight);
    BOOST_CHECK(!ReadSpent(spent, value));

    // Switch back to the original branch by invalidating the competing block.
    {
        LOCK(cs_main);
        BOOST_REQUIRE(ResetBlockFailureFlags(mapBlockIndex.at(spendBlockHash)));
        BOOST_REQUIRE(InvalidateBlock(state, GetParams(), chainActive.Tip()));
    }
    BOOST_REQUIRE(state.IsValid());
    BOOST_REQUIRE(ActivateBestChain(state, GetParams()));
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == spendBlockHash);
    BOOST_REQUIRE(ReadSpent(spent, value));
    BOOST_CHECK(value.txid == spendHash);
    BOOST_CHECK_EQUAL(value.blockHeight, spendHeight);
}

BOOST_AUTO_TEST_SUITE_END()
