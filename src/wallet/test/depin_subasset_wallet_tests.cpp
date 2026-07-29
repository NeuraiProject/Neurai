// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Wallet-level integration for sub-DEPIN issuance: exercises the real
// CreateAssetTransaction() path (no mocks) so the wallet changes that go with
// the consensus rule -- attaching and returning the parent's owner token -- are
// covered automatically rather than only by manual regtest walkthroughs.
//
// Runs on TESTNET rather than REGTEST on purpose: DEPIN names only validate on
// testnet/regtest, and only testnet activates assets by height
// (nAssetActivationHeight = 1, chainparams.cpp), which AreAssetsDeployed()
// needs for AvailableAssets() to see the owner-token UTXO at all. Testnet also
// has a trivial PoW target and a coinbase maturity of 5, so the chain the
// fixture mines is cheap.

#include "wallet/wallet.h"

#include "assets/assets.h"
#include "assets/assetdb.h"
#include "assets/assettypes.h"
#include "base58.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "miner.h"
#include "net.h" // g_connman
#include "test/test_neurai.h"
#include "validation.h"
#include "wallet/coincontrol.h"
#include "wallet/test/wallet_test_fixture.h"

#include <boost/test/unit_test.hpp>
#include <string>
#include <vector>

namespace {

const std::string PARENT_ASSET = "&PADRE";
const std::string CHILD_ASSET = "&PADRE/HIJO";

// Mines on testnet and hands out a wallet that owns the coinbases, mirroring
// ListCoinsTestingSetup (wallet_tests.cpp) but on a network where DEPIN names
// are valid and assets activate by height.
struct DepinWalletSetup : public TestingSetup {
    CKey coinbaseKey;
    std::unique_ptr<CWallet> wallet;

    DepinWalletSetup() : TestingSetup(CBaseChainParams::TESTNET)
    {
        // TestingSetup builds passets but not the asset database/cache, and
        // connecting a block that issues an asset dereferences passetsdb
        // unguarded (assets.cpp CAssetsCache::DumpCacheToDatabase,
        // validation.cpp WriteBlockUndoAssetData). In-memory, wiped per test.
        passetsdb = new CAssetsDB(1 << 20, true, true);
        passetsCache = new CLRUCache<std::string, CDatabasedAssetData>(MAX_CACHE_ASSETS_SIZE);

        coinbaseKey.MakeNewKey(true);
        const CScript coinbaseScript = GetScriptForRawPubKey(coinbaseKey.GetPubKey());

        // Enough blocks to mature coinbases (5 on testnet) with margin; any
        // height >= 1 already switches AreAssetsDeployed() on for this network.
        for (int i = 0; i < GetCoinbaseMaturity() + 3; ++i) {
            MineBlock(coinbaseScript);
        }

        ::bitdb.MakeMock();
        wallet.reset(new CWallet(std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, "depin_subasset_wallet_test.dat"))));
        bool firstRun = false;
        wallet->LoadWallet(firstRun);
        // CommitTransaction() only reaches AcceptToMemoryPool() when broadcast
        // is enabled; without this an issuance would be committed to the wallet
        // but never enter the mempool, so it could never be mined.
        wallet->SetBroadcastTransactions(true);
        {
            LOCK(wallet->cs_wallet);
            wallet->AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey());
        }
        // fUpdate=true is required: the issuance is already in mapWallet from
        // CommitTransaction, and AddToWalletIfInvolvingMe() bails out on
        // already-known transactions unless told to update them, leaving the
        // freshly mined block position (and therefore the depth) unset.
        wallet->ScanForWalletTransactions(chainActive.Genesis(), nullptr, true);

        // VerifyWalletHasAsset() resolves the wallet through vpwallets[0].
        vpwallets.insert(vpwallets.begin(), wallet.get());
    }

    ~DepinWalletSetup()
    {
        vpwallets.erase(std::remove(vpwallets.begin(), vpwallets.end(), wallet.get()), vpwallets.end());
        wallet.reset();
        ::bitdb.Flush(true);
        ::bitdb.Reset();

        delete passetsCache;
        passetsCache = nullptr;
        delete passetsdb;
        passetsdb = nullptr;
    }

    // includeMempool=false mines an empty block (BlockAssembler would otherwise
    // pull in whatever is pending); true keeps the assembler's selection, which
    // is how a committed issuance gets confirmed.
    void MineBlock(const CScript& scriptPubKey, bool includeMempool = false)
    {
        const CChainParams& chainparams = GetParams();
        std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
        CBlock& block = pblocktemplate->block;
        if (!includeMempool) block.vtx.resize(1);

        unsigned int extraNonce = 0;
        IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);

        uint256 mix_hash;
        while (!CheckProofOfWork(block.GetHashFull(mix_hash), block.nBits, chainparams.GetConsensus())) {
            ++block.nNonce64;
            ++block.nNonce;
        }
        block.mix_hash = mix_hash;

        std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(block);
        ProcessNewBlock(chainparams, shared_pblock, true, nullptr);
    }

    // Build an issuance for `assetName` through the real CreateAssetTransaction
    // path. Returns the wallet transaction; does not confirm it.
    CWalletTx BuildIssuance(const std::string& assetName, CAmount amount,
                            std::pair<int, std::string>& error, bool& ok)
    {
        CNewAsset asset(assetName, amount, DEPIN_ASSET_UNITS, 0, 0, "");
        CCoinControl coinControl;
        CWalletTx wtx;
        CReserveKey reservekey(wallet.get());
        CAmount nFeeRequired = 0;

        CPubKey destPubKey;
        BOOST_REQUIRE(wallet->GetKeyFromPool(destPubKey));

        ok = CreateAssetTransaction(wallet.get(), coinControl, asset,
                                    EncodeDestination(destPubKey.GetID()),
                                    error, wtx, reservekey, nFeeRequired);
        return wtx;
    }

    // Issue `assetName` for real: build it, commit it to the mempool and mine
    // it, so the wallet ends up owning the asset and its owner token through
    // the same path a node would take. No synthetic UTXOs.
    void IssueAssetAndConfirm(const std::string& assetName, CAmount amount)
    {
        std::pair<int, std::string> error;
        bool ok = false;
        CWalletTx wtx = BuildIssuance(assetName, amount, error, ok);
        BOOST_REQUIRE_MESSAGE(ok, "issuing " + assetName + ": " + error.second);

        CReserveKey reservekey(wallet.get());
        CValidationState state;
        BOOST_REQUIRE_MESSAGE(wallet->CommitTransaction(wtx, reservekey, g_connman.get(), state),
                              "committing " + assetName + ": " + state.GetRejectReason());

        // Fail at the real point of breakage rather than later, on a confusing
        // "wallet doesn't have the asset".
        BOOST_REQUIRE_MESSAGE(mempool.exists(wtx.GetHash()),
                              "issuance of " + assetName + " never reached the mempool");

        MineBlock(GetScriptForRawPubKey(coinbaseKey.GetPubKey()), /*includeMempool=*/true);

        BOOST_REQUIRE_MESSAGE(!mempool.exists(wtx.GetHash()),
                              "issuance of " + assetName + " was not mined into a block");

        // This fixture runs no scheduler thread, so validation-interface
        // callbacks that would normally update the wallet are unreliable
        // (see the comment in TestingSetup). Refresh explicitly.
        // fUpdate=true is required: the issuance is already in mapWallet from
        // CommitTransaction, and AddToWalletIfInvolvingMe() bails out on
        // already-known transactions unless told to update them, leaving the
        // freshly mined block position (and therefore the depth) unset.
        wallet->ScanForWalletTransactions(chainActive.Genesis(), nullptr, true);
    }
};

// Does the transaction hand `assetName` back to an address we own?
bool TxReturnsOwnerToken(CWallet& wallet, const CTransaction& tx,
                         const std::string& assetName, CAmount expectedAmount)
{
    for (const CTxOut& out : tx.vout) {
        CAssetTransfer transfer;
        std::string address;
        if (!TransferAssetFromScript(out.scriptPubKey, transfer, address)) continue;
        if (transfer.strName != assetName) continue;
        if (transfer.nAmount != expectedAmount) continue;

        LOCK(wallet.cs_wallet);
        if (IsMine(wallet, DecodeDestination(address))) return true;
    }
    return false;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(depin_subasset_wallet_tests, DepinWalletSetup)

// A wallet holding &PADRE! can issue &PADRE/HIJO, and the transaction it builds
// spends that owner token and hands it back to itself.
BOOST_AUTO_TEST_CASE(subdepin_issuance_attaches_parent_owner)
{
    BOOST_REQUIRE(AreAssetsDeployed());
    BOOST_REQUIRE(wallet->GetBalance() > 0);

    // Issue the parent for real and mine it, so &PADRE! is a genuine confirmed
    // UTXO produced by a consensus-valid issuance.
    IssueAssetAndConfirm(PARENT_ASSET, CAmount(1000 * COIN));

    // Precondition: the wallet really does see the owner token.
    std::pair<int, std::string> verifyError;
    BOOST_REQUIRE_MESSAGE(VerifyWalletHasAsset(PARENT_ASSET + OWNER_TAG, verifyError),
                          verifyError.second);

    // Which UTXO holds it, so we can assert the child issuance spends that one.
    std::map<std::string, std::vector<COutput>> mapAssetCoins;
    {
        LOCK2(cs_main, wallet->cs_wallet);
        wallet->AvailableAssets(mapAssetCoins);
    }
    BOOST_REQUIRE(mapAssetCoins.count(PARENT_ASSET + OWNER_TAG));
    BOOST_REQUIRE(!mapAssetCoins[PARENT_ASSET + OWNER_TAG].empty());
    const uint256 ownerUtxoTxid = mapAssetCoins[PARENT_ASSET + OWNER_TAG][0].tx->GetHash();

    std::pair<int, std::string> error;
    bool ok = false;
    CWalletTx wtxNew = BuildIssuance(CHILD_ASSET, CAmount(100 * COIN), error, ok);
    BOOST_REQUIRE_MESSAGE(ok, error.second);

    const CTransaction& tx = *wtxNew.tx;

    // It spends the real owner-token UTXO...
    bool spendsOwnerUtxo = false;
    for (const CTxIn& in : tx.vin) {
        if (in.prevout.hash == ownerUtxoTxid) {
            spendsOwnerUtxo = true;
            break;
        }
    }
    BOOST_CHECK_MESSAGE(spendsOwnerUtxo, "transaction does not spend the parent owner-token UTXO");

    // ...and returns it to an address of ours, rather than burning it.
    BOOST_CHECK_MESSAGE(TxReturnsOwnerToken(*wallet, tx, PARENT_ASSET + OWNER_TAG, OWNER_ASSET_AMOUNT),
                        "transaction does not return " + PARENT_ASSET + OWNER_TAG + " to a wallet address");

    // And the result satisfies the consensus rule this whole change exists for.
    std::string verifyNewAssetError;
    BOOST_CHECK_MESSAGE(tx.VerifyNewAsset(verifyNewAssetError), verifyNewAssetError);
}

// The same issuance from a wallet that has XNA but not &PADRE! must be refused
// by the wallet, with no usable transaction produced.
BOOST_AUTO_TEST_CASE(subdepin_issuance_without_parent_owner_is_refused)
{
    BOOST_REQUIRE(AreAssetsDeployed());
    BOOST_REQUIRE(wallet->GetBalance() > 0);

    // Deliberately no IssueAssetAndConfirm(PARENT_ASSET) call here.
    std::pair<int, std::string> verifyError;
    BOOST_REQUIRE(!VerifyWalletHasAsset(PARENT_ASSET + OWNER_TAG, verifyError));

    std::pair<int, std::string> error;
    bool ok = true;
    CWalletTx wtxNew = BuildIssuance(CHILD_ASSET, CAmount(100 * COIN), error, ok);

    BOOST_CHECK(!ok);
    BOOST_CHECK_MESSAGE(error.second.find(PARENT_ASSET + OWNER_TAG) != std::string::npos,
                        "expected the VerifyWalletHasAsset error naming " + PARENT_ASSET + OWNER_TAG +
                            ", got: " + error.second);

    // No usable transaction was left behind.
    BOOST_CHECK(wtxNew.tx == nullptr || wtxNew.tx->vout.empty());
}

// A root DEPIN token has no parent, so it must still issue with no owner token
// in the wallet -- the rule must not leak into root issuance.
BOOST_AUTO_TEST_CASE(root_depin_issuance_needs_no_owner_token)
{
    BOOST_REQUIRE(AreAssetsDeployed());

    std::pair<int, std::string> error;
    bool ok = false;
    BuildIssuance("&OTRORAIZ", CAmount(100 * COIN), error, ok);
    BOOST_CHECK_MESSAGE(ok, error.second);
}

BOOST_AUTO_TEST_SUITE_END()
