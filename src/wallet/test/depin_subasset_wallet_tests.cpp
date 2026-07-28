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
#include "assets/assettypes.h"
#include "base58.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "miner.h"
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
        {
            LOCK(wallet->cs_wallet);
            wallet->AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey());
        }
        wallet->ScanForWalletTransactions(chainActive.Genesis(), nullptr);

        // VerifyWalletHasAsset() resolves the wallet through vpwallets[0].
        vpwallets.insert(vpwallets.begin(), wallet.get());
    }

    ~DepinWalletSetup()
    {
        vpwallets.erase(std::remove(vpwallets.begin(), vpwallets.end(), wallet.get()), vpwallets.end());
        wallet.reset();
        ::bitdb.Flush(true);
        ::bitdb.Reset();
    }

    void MineBlock(const CScript& scriptPubKey)
    {
        const CChainParams& chainparams = GetParams();
        std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey);
        CBlock& block = pblocktemplate->block;
        block.vtx.resize(1);

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

    // Give the wallet a confirmed UTXO holding `assetName`, so AvailableAssets()
    // reports it and coin selection can spend it. Returns the funding txid.
    uint256 GiveWalletAsset(const std::string& assetName, CAmount amount)
    {
        CPubKey pubkey;
        BOOST_REQUIRE(wallet->GetKeyFromPool(pubkey));
        CScript script = GetScriptForDestination(pubkey.GetID());
        CAssetTransfer transfer(assetName, amount);
        transfer.ConstructTransaction(script);

        CMutableTransaction mtx;
        mtx.vin.resize(1);
        // A non-null prevout on purpose: a null one would make this look like a
        // coinbase, and AvailableCoins() would then skip it as immature.
        mtx.vin[0].prevout = COutPoint(GetRandHash(), 0);
        mtx.vout.resize(1);
        mtx.vout[0].nValue = 0;
        mtx.vout[0].scriptPubKey = script;

        CWalletTx wtx(wallet.get(), MakeTransactionRef(mtx));
        // Index 1, i.e. not the coinbase slot, and one confirmation deep so the
        // wallet considers it trusted.
        wtx.SetMerkleBranch(chainActive.Tip(), 1);
        {
            LOCK(wallet->cs_wallet);
            wallet->AddToWallet(wtx);
        }
        return wtx.GetHash();
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

    const uint256 ownerFundingTxid = GiveWalletAsset(PARENT_ASSET + OWNER_TAG, OWNER_ASSET_AMOUNT);

    // Precondition: the wallet really does see the owner token.
    std::pair<int, std::string> verifyError;
    BOOST_REQUIRE_MESSAGE(VerifyWalletHasAsset(PARENT_ASSET + OWNER_TAG, verifyError),
                          verifyError.second);

    CNewAsset child(CHILD_ASSET, CAmount(100 * COIN), DEPIN_ASSET_UNITS, 0, 0, "");
    CCoinControl coinControl;
    CWalletTx wtxNew;
    CReserveKey reservekey(wallet.get());
    CAmount nFeeRequired = 0;
    std::pair<int, std::string> error;

    CPubKey destPubKey;
    BOOST_REQUIRE(wallet->GetKeyFromPool(destPubKey));
    const std::string destAddress = EncodeDestination(destPubKey.GetID());

    BOOST_REQUIRE_MESSAGE(
        CreateAssetTransaction(wallet.get(), coinControl, child, destAddress, error, wtxNew, reservekey, nFeeRequired),
        error.second);

    const CTransaction& tx = *wtxNew.tx;

    // It spends the owner-token UTXO we planted...
    bool spendsOwnerUtxo = false;
    for (const CTxIn& in : tx.vin) {
        if (in.prevout.hash == ownerFundingTxid) {
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

    // Deliberately no GiveWalletAsset() call here.
    std::pair<int, std::string> verifyError;
    BOOST_REQUIRE(!VerifyWalletHasAsset(PARENT_ASSET + OWNER_TAG, verifyError));

    CNewAsset child(CHILD_ASSET, CAmount(100 * COIN), DEPIN_ASSET_UNITS, 0, 0, "");
    CCoinControl coinControl;
    CWalletTx wtxNew;
    CReserveKey reservekey(wallet.get());
    CAmount nFeeRequired = 0;
    std::pair<int, std::string> error;

    CPubKey destPubKey;
    BOOST_REQUIRE(wallet->GetKeyFromPool(destPubKey));
    const std::string destAddress = EncodeDestination(destPubKey.GetID());

    BOOST_CHECK(!CreateAssetTransaction(wallet.get(), coinControl, child, destAddress,
                                        error, wtxNew, reservekey, nFeeRequired));
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

    CNewAsset root("&OTRORAIZ", CAmount(100 * COIN), DEPIN_ASSET_UNITS, 0, 0, "");
    CCoinControl coinControl;
    CWalletTx wtxNew;
    CReserveKey reservekey(wallet.get());
    CAmount nFeeRequired = 0;
    std::pair<int, std::string> error;

    CPubKey destPubKey;
    BOOST_REQUIRE(wallet->GetKeyFromPool(destPubKey));
    const std::string destAddress = EncodeDestination(destPubKey.GetID());

    BOOST_CHECK_MESSAGE(
        CreateAssetTransaction(wallet.get(), coinControl, root, destAddress, error, wtxNew, reservekey, nFeeRequired),
        error.second);
}

BOOST_AUTO_TEST_SUITE_END()
