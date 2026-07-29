// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// End-to-end DEPIN self-revocation: the selfrevokedepin RPC builds the
// self-relocation (one pinned &X UTXO spent and returned to its own address,
// plus the flag-1 null data), the mempool accepts it with real signatures, a
// mined block writes the 'S' flag, and unfreezedepin recovers the address.
//
// This is the path that was impossible before the soulbound exception: the
// same RPC used to die with
// "bad-txns-tx-contains-depin-asset-null-tx-without-asset-transfer".
//
// TESTNET for the same reasons as depin_subasset_wallet_tests.cpp: DEPIN names
// only validate on testnet/regtest, and only testnet activates assets by
// height with a trivial PoW target and a coinbase maturity of 5.

#include "wallet/wallet.h"

#include "assets/assets.h"
#include "assets/assetdb.h"
#include "assets/assettypes.h"
#include "assets/restricteddb.h"
#include "base58.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "miner.h"
#include "net.h" // g_connman
#include "rpc/server.h"
#include "test/test_neurai.h"
#include "validation.h"
#include "wallet/coincontrol.h"
#include "wallet/test/wallet_test_fixture.h"

#include <boost/test/unit_test.hpp>
#include <string>
#include <univalue.h>
#include <vector>

namespace {

const std::string PARENT_ASSET = "&PADRE";

// Mines on testnet and hands out a wallet that owns the coinbases. Extends the
// depin_subasset_wallet_tests fixture with the restriction databases:
// DumpCacheToDatabase dereferences prestricteddb and passetsRestrictionCache
// unguarded once a block carries a self-restriction, so mining a self-revoke
// without them would crash rather than fail.
struct DepinSelfRevokeWalletSetup : public TestingSetup {
    CKey coinbaseKey;
    std::unique_ptr<CWallet> wallet;

    DepinSelfRevokeWalletSetup() : TestingSetup(CBaseChainParams::TESTNET)
    {
        passetsdb = new CAssetsDB(1 << 20, true, true);
        passetsCache = new CLRUCache<std::string, CDatabasedAssetData>(MAX_CACHE_ASSETS_SIZE);
        prestricteddb = new CRestrictedDB(1 << 20, true, true);
        passetsRestrictionCache = new CLRUCache<std::string, int8_t>(MAX_CACHE_ASSETS_SIZE);
        passetsGlobalRestrictionCache = new CLRUCache<std::string, int8_t>(MAX_CACHE_ASSETS_SIZE);

        coinbaseKey.MakeNewKey(true);
        const CScript coinbaseScript = GetScriptForRawPubKey(coinbaseKey.GetPubKey());
        for (int i = 0; i < GetCoinbaseMaturity() + 3; ++i) {
            MineBlock(coinbaseScript);
        }

        ::bitdb.MakeMock();
        wallet.reset(new CWallet(std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, "depin_selfrevoke_wallet_test.dat"))));
        bool firstRun = false;
        wallet->LoadWallet(firstRun);
        wallet->SetBroadcastTransactions(true);
        {
            LOCK(wallet->cs_wallet);
            wallet->AddKeyPubKey(coinbaseKey, coinbaseKey.GetPubKey());
        }
        wallet->ScanForWalletTransactions(chainActive.Genesis(), nullptr, true);
        vpwallets.insert(vpwallets.begin(), wallet.get());
    }

    ~DepinSelfRevokeWalletSetup()
    {
        vpwallets.erase(std::remove(vpwallets.begin(), vpwallets.end(), wallet.get()), vpwallets.end());
        wallet.reset();
        ::bitdb.Flush(true);
        ::bitdb.Reset();

        delete passetsGlobalRestrictionCache;
        passetsGlobalRestrictionCache = nullptr;
        delete passetsRestrictionCache;
        passetsRestrictionCache = nullptr;
        delete prestricteddb;
        prestricteddb = nullptr;
        delete passetsCache;
        passetsCache = nullptr;
        delete passetsdb;
        passetsdb = nullptr;
    }

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

    // Commit `wtx`, require it in the mempool, mine it, refresh the wallet.
    void ConfirmTransaction(CWalletTx& wtx, const std::string& what)
    {
        CReserveKey reservekey(wallet.get());
        CValidationState state;
        BOOST_REQUIRE_MESSAGE(wallet->CommitTransaction(wtx, reservekey, g_connman.get(), state),
                              "committing " + what + ": " + state.GetRejectReason());
        BOOST_REQUIRE_MESSAGE(mempool.exists(wtx.GetHash()),
                              what + " never reached the mempool");
        MineBlock(GetScriptForRawPubKey(coinbaseKey.GetPubKey()), /*includeMempool=*/true);
        BOOST_REQUIRE_MESSAGE(!mempool.exists(wtx.GetHash()),
                              what + " was not mined into a block");
        wallet->ScanForWalletTransactions(chainActive.Genesis(), nullptr, true);
    }

    // Issue `assetName` through the real path and confirm it.
    void IssueAssetAndConfirm(const std::string& assetName, CAmount amount)
    {
        CNewAsset asset(assetName, amount, DEPIN_ASSET_UNITS, 0, 0, "");
        CCoinControl coinControl;
        CWalletTx wtx;
        CReserveKey reservekey(wallet.get());
        CAmount nFeeRequired = 0;

        CPubKey destPubKey;
        BOOST_REQUIRE(wallet->GetKeyFromPool(destPubKey));

        std::pair<int, std::string> error;
        BOOST_REQUIRE_MESSAGE(CreateAssetTransaction(wallet.get(), coinControl, asset,
                                                     EncodeDestination(destPubKey.GetID()),
                                                     error, wtx, reservekey, nFeeRequired),
                              "issuing " + assetName + ": " + error.second);
        ConfirmTransaction(wtx, "issuance of " + assetName);
    }

    // Owner-transfer `amount` of `assetName` to `toAddress` and confirm. The
    // owner token is auto-attached by CreateTransferAssetTransaction.
    void TransferAndConfirm(const std::string& assetName, CAmount amount, const std::string& toAddress)
    {
        CCoinControl ctrl;
        CWalletTx wtx;
        CReserveKey reservekey(wallet.get());
        CAmount nFeeRequired = 0;
        std::pair<int, std::string> error;
        std::vector<std::pair<CAssetTransfer, std::string>> transfers;
        transfers.emplace_back(std::make_pair(CAssetTransfer(assetName, amount), toAddress));

        BOOST_REQUIRE_MESSAGE(CreateTransferAssetTransaction(wallet.get(), ctrl, transfers, "",
                                                             error, wtx, reservekey, nFeeRequired),
                              "transferring " + assetName + ": " + error.second);
        ConfirmTransaction(wtx, "transfer of " + assetName);
    }

    std::string NewWalletAddress()
    {
        CPubKey pubKey;
        BOOST_REQUIRE(wallet->GetKeyFromPool(pubKey));
        return EncodeDestination(pubKey.GetID());
    }

    UniValue CallRpc(const std::string& method, const std::vector<UniValue>& args)
    {
        JSONRPCRequest request;
        request.strMethod = method;
        request.params = UniValue(UniValue::VARR);
        for (const UniValue& arg : args) request.params.push_back(arg);
        request.fHelp = false;
        BOOST_REQUIRE_MESSAGE(tableRPC[method], "RPC not registered: " + method);
        return (*tableRPC[method]->actor)(request);
    }

    // The mined transaction, fetched back from the wallet by txid.
    const CWalletTx& GetWalletTx(const uint256& txid)
    {
        LOCK(wallet->cs_wallet);
        const auto it = wallet->mapWallet.find(txid);
        BOOST_REQUIRE_MESSAGE(it != wallet->mapWallet.end(), "tx not in wallet");
        return it->second;
    }
};

// All &X outputs of `tx`, as (address, amount).
std::vector<std::pair<std::string, CAmount>> AssetOutputs(const CTransaction& tx, const std::string& assetName)
{
    std::vector<std::pair<std::string, CAmount>> outs;
    for (const CTxOut& out : tx.vout) {
        CAssetTransfer transfer;
        std::string address;
        if (TransferAssetFromScript(out.scriptPubKey, transfer, address) && transfer.strName == assetName) {
            outs.emplace_back(address, transfer.nAmount);
        }
    }
    return outs;
}

bool TxHasAssetOutput(const CTransaction& tx, const std::string& assetName)
{
    return !AssetOutputs(tx, assetName).empty();
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(depin_selfrevoke_wallet_tests, DepinSelfRevokeWalletSetup)

// (19)(20)(20b)(15)(22) The whole life of a self-revocation, through the real
// RPC: build, mempool, block, state, recovery.
BOOST_AUTO_TEST_CASE(selfrevoke_roundtrip_with_recovery)
{
    BOOST_REQUIRE(AreAssetsDeployed());

    // The owner issues &PADRE (asset + owner token land together) and
    // distributes ALL units to a plain holder address of this same wallet.
    // All of them on purpose: a partial transfer leaves asset change at a
    // fresh change address without the owner token, which is a second eligible
    // holding -- the picker could legitimately choose it and every assertion
    // below would be testing luck.
    IssueAssetAndConfirm(PARENT_ASSET, 1000 * COIN);
    const std::string holder = NewWalletAddress();
    TransferAndConfirm(PARENT_ASSET, 1000 * COIN, holder);

    // Sanity: the wallet still holds the owner token somewhere -- that is what
    // makes (20b) meaningful.
    std::string ownerAddress;
    BOOST_REQUIRE(GetWalletOwnerTokenAddress(wallet.get(), PARENT_ASSET + OWNER_TAG, ownerAddress));
    BOOST_REQUIRE(ownerAddress != holder);

    // The call that used to die with bad-txns-...-without-asset-transfer.
    const UniValue result = CallRpc("selfrevokedepin", {UniValue(PARENT_ASSET)});
    BOOST_REQUIRE(result.isArray() && result.size() == 1);
    const uint256 txid = uint256S(result[0].get_str());

    // (20) The built transaction is the self-relocation: every &PADRE output
    // pays the holder, for exactly the amount distributed to it.
    const CWalletTx& wtx = GetWalletTx(txid);
    const auto outs = AssetOutputs(*wtx.tx, PARENT_ASSET);
    BOOST_REQUIRE(!outs.empty());
    CAmount total = 0;
    for (const auto& out : outs) {
        BOOST_CHECK_EQUAL(out.first, holder);
        total += out.second;
    }
    BOOST_CHECK_EQUAL(total, 1000 * COIN);

    // (20b) No owner-token transfer, although the wallet HAS the owner token.
    // Attaching it would have reclassified the action as an owner freeze.
    BOOST_CHECK_MESSAGE(!TxHasAssetOutput(*wtx.tx, PARENT_ASSET + OWNER_TAG),
                        "the self-revocation must not move the owner token");

    // It was committed by the RPC; confirm it through a real block.
    BOOST_REQUIRE_MESSAGE(mempool.exists(txid), "self-revocation never reached the mempool");
    MineBlock(GetScriptForRawPubKey(coinbaseKey.GetPubKey()), /*includeMempool=*/true);
    BOOST_REQUIRE_MESSAGE(!mempool.exists(txid), "self-revocation was not mined");
    wallet->ScanForWalletTransactions(chainActive.Genesis(), nullptr, true);

    // (15) The block connection wrote the 'S' flag; the read path every
    // consumer uses sees the address as blocked.
    BOOST_CHECK(passets->CheckForDEPINSelfRestriction(PARENT_ASSET, holder));
    BOOST_CHECK(passets->CheckForDEPINRestriction(PARENT_ASSET, holder));

    // A second self-revocation must now be refused: the only eligible holding
    // is the one just revoked, and the RPC checks its restriction state.
    bool threw = false;
    try {
        CallRpc("selfrevokedepin", {UniValue(PARENT_ASSET)});
    } catch (const UniValue& e) {
        threw = true;
    }
    BOOST_CHECK_MESSAGE(threw, "re-revoking an already revoked holding must fail");

    // (22) Recovery: the owner token lives at another address, so a single
    // unfreezedepin over the holder is enough (the two-transaction dance is
    // only needed when the REVOKED address held the owner token).
    const UniValue unfreeze = CallRpc("unfreezedepin", {UniValue(PARENT_ASSET), UniValue(holder)});
    BOOST_REQUIRE(unfreeze.isArray() && unfreeze.size() == 1);
    MineBlock(GetScriptForRawPubKey(coinbaseKey.GetPubKey()), /*includeMempool=*/true);
    wallet->ScanForWalletTransactions(chainActive.Genesis(), nullptr, true);

    BOOST_CHECK(!passets->CheckForDEPINSelfRestriction(PARENT_ASSET, holder));
    BOOST_CHECK(!passets->CheckForDEPINRestriction(PARENT_ASSET, holder));
}

// (20c) Several UTXOs across several addresses: the transaction pins ONE
// outpoint and re-transfers exactly its amount. With aggregate-balance
// selection this test goes red -- coin selection recruits inputs from other
// addresses and the amounts stop matching a single UTXO.
BOOST_AUTO_TEST_CASE(selfrevoke_pins_one_outpoint)
{
    BOOST_REQUIRE(AreAssetsDeployed());

    IssueAssetAndConfirm(PARENT_ASSET, 1000 * COIN);
    const std::string holderA = NewWalletAddress();
    const std::string holderB = NewWalletAddress();

    // Three distinct UTXOs: two at A (70 and 100), one at B (50).
    TransferAndConfirm(PARENT_ASSET, 70 * COIN, holderA);
    TransferAndConfirm(PARENT_ASSET, 100 * COIN, holderA);
    TransferAndConfirm(PARENT_ASSET, 50 * COIN, holderB);

    const UniValue result = CallRpc("selfrevokedepin", {UniValue(PARENT_ASSET)});
    const uint256 txid = uint256S(result[0].get_str());
    const CWalletTx& wtx = GetWalletTx(txid);

    // Exactly one &PADRE input, and the outputs return exactly its amount to
    // exactly its address.
    unsigned int nAssetInputs = 0;
    std::string spentAddress;
    CAmount spentAmount = 0;
    {
        LOCK(wallet->cs_wallet);
        for (const CTxIn& txin : wtx.tx->vin) {
            const auto it = wallet->mapWallet.find(txin.prevout.hash);
            if (it == wallet->mapWallet.end()) continue;
            const CTxOut& prevOut = it->second.tx->vout[txin.prevout.n];

            CAssetOutputEntry entry;
            if (!prevOut.scriptPubKey.IsAssetScript() || !GetAssetData(prevOut.scriptPubKey, entry))
                continue;
            BOOST_CHECK_MESSAGE(entry.assetName == PARENT_ASSET,
                                "unexpected asset input: " + entry.assetName);
            nAssetInputs++;
            spentAddress = EncodeDestination(entry.destination);
            spentAmount = entry.nAmount;
        }
    }
    BOOST_CHECK_EQUAL(nAssetInputs, 1U);

    const auto outs = AssetOutputs(*wtx.tx, PARENT_ASSET);
    CAmount total = 0;
    for (const auto& out : outs) {
        BOOST_CHECK_EQUAL(out.first, spentAddress);
        total += out.second;
    }
    BOOST_CHECK_EQUAL(total, spentAmount);

    // And it still confirms.
    MineBlock(GetScriptForRawPubKey(coinbaseKey.GetPubKey()), /*includeMempool=*/true);
    BOOST_CHECK(!mempool.exists(txid));
    BOOST_CHECK(passets->CheckForDEPINSelfRestriction(PARENT_ASSET, spentAddress));
}

// (21) Failure modes speak the wallet's language, not raw consensus errors.
BOOST_AUTO_TEST_CASE(selfrevoke_failure_messages)
{
    BOOST_REQUIRE(AreAssetsDeployed());

    // An asset this wallet does not hold at all.
    {
        bool threw = false;
        try {
            CallRpc("selfrevokedepin", {UniValue("&NADIE")});
        } catch (const UniValue& e) {
            threw = true;
            const std::string message = find_value(e, "message").get_str();
            BOOST_CHECK_MESSAGE(message.find("does not hold") != std::string::npos,
                                "unexpected message: " + message);
        }
        BOOST_CHECK(threw);
    }

    // Only owner-controlled holdings: the wallet refuses to auto-pick the
    // address that would need the two-transaction recovery.
    {
        IssueAssetAndConfirm("&SOLO", 100 * COIN);
        bool threw = false;
        try {
            CallRpc("selfrevokedepin", {UniValue("&SOLO")});
        } catch (const UniValue& e) {
            threw = true;
            const std::string message = find_value(e, "message").get_str();
            BOOST_CHECK_MESSAGE(message.find("owner token") != std::string::npos,
                                "unexpected message: " + message);
        }
        BOOST_CHECK(threw);
    }
}

// (16 del NIP) Disconnecting the block that wrote SELF_RESTRICTED_FLAG undoes
// it. This undo path (validation.cpp, DisconnectBlock's DEPIN branch) had never
// run before, for the simple reason that the write it reverses was unreachable.
BOOST_AUTO_TEST_CASE(disconnecting_the_block_reverts_the_self_revocation)
{
    BOOST_REQUIRE(AreAssetsDeployed());

    IssueAssetAndConfirm(PARENT_ASSET, 1000 * COIN);
    const std::string holder = NewWalletAddress();
    TransferAndConfirm(PARENT_ASSET, 1000 * COIN, holder);

    CallRpc("selfrevokedepin", {UniValue(PARENT_ASSET)});
    MineBlock(GetScriptForRawPubKey(coinbaseKey.GetPubKey()), /*includeMempool=*/true);
    wallet->ScanForWalletTransactions(chainActive.Genesis(), nullptr, true);

    BOOST_REQUIRE(passets->CheckForDEPINSelfRestriction(PARENT_ASSET, holder));

    // Disconnect the block that carried the self-revocation.
    CBlockIndex* revokeBlock = chainActive.Tip();
    {
        CValidationState state;
        LOCK(cs_main);
        BOOST_REQUIRE_MESSAGE(InvalidateBlock(state, GetParams(), revokeBlock),
                              "InvalidateBlock failed: " + state.GetRejectReason());
    }
    // The disconnected transactions flow back into the mempool; drop them so
    // nothing re-applies the revocation behind the assertion's back.
    mempool.clear();

    BOOST_CHECK_MESSAGE(!passets->CheckForDEPINSelfRestriction(PARENT_ASSET, holder),
                        "the 'S' flag must be undone by the disconnect");
    BOOST_CHECK(!passets->CheckForDEPINRestriction(PARENT_ASSET, holder));

    // Reconnecting the same block writes it again: the undo is symmetric.
    {
        LOCK(cs_main);
        BOOST_REQUIRE(ResetBlockFailureFlags(revokeBlock));
    }
    CValidationState state;
    BOOST_REQUIRE(ActivateBestChain(state, GetParams()));
    BOOST_CHECK_MESSAGE(passets->CheckForDEPINSelfRestriction(PARENT_ASSET, holder),
                        "reconnecting the block must restore the 'S' flag");
}

// (22 del NIP, el caso especial) Recovery when the REVOKED address held the
// owner token. A direct unfreezedepin cannot work: it would spend &X! from the
// very address named in its null data, and the structural owner check rejects
// that. The recovery is two transactions -- move &X! elsewhere, then unfreeze.
//
// The revocation itself is built by hand: the RPC deliberately refuses to
// auto-pick the owner-holding address, but consensus permits the act, and this
// is also the end-to-end proof of that (test 10's wallet-level counterpart).
BOOST_AUTO_TEST_CASE(owner_holder_recovery_takes_two_transactions)
{
    BOOST_REQUIRE(AreAssetsDeployed());

    const std::string SOLO = "&SOLO";
    IssueAssetAndConfirm(SOLO, 100 * COIN);

    // Where did issuance put the asset (and with it, the owner token)?
    std::string ownerHolder;
    COutPoint outpoint;
    CAmount amount = 0;
    {
        std::map<std::string, std::vector<COutput>> mapAssetCoins;
        {
            LOCK2(cs_main, wallet->cs_wallet);
            wallet->AvailableAssets(mapAssetCoins);
        }
        BOOST_REQUIRE(mapAssetCoins.count(SOLO));
        const COutput& output = mapAssetCoins[SOLO].front();
        CAssetOutputEntry entry;
        BOOST_REQUIRE(GetAssetData(output.tx->tx->vout[output.i].scriptPubKey, entry));
        ownerHolder = EncodeDestination(entry.destination);
        outpoint = COutPoint(output.tx->GetHash(), output.i);
        amount = entry.nAmount;
    }
    std::string ownerTokenAddress;
    BOOST_REQUIRE(GetWalletOwnerTokenAddress(wallet.get(), SOLO + OWNER_TAG, ownerTokenAddress));
    BOOST_REQUIRE_EQUAL(ownerTokenAddress, ownerHolder);

    // Hand-built self-revocation of the owner-holding address.
    {
        CCoinControl ctrl;
        ctrl.SelectAsset(outpoint);
        CWalletTx wtx;
        CReserveKey reservekey(wallet.get());
        CAmount nFeeRequired = 0;
        std::pair<int, std::string> error;
        std::vector<std::pair<CAssetTransfer, std::string>> transfers;
        transfers.emplace_back(std::make_pair(CAssetTransfer(SOLO, amount), ownerHolder));
        std::vector<std::pair<CNullAssetTxData, std::string>> nullData;
        nullData.push_back(std::make_pair(CNullAssetTxData(SOLO, 1), ownerHolder));

        BOOST_REQUIRE_MESSAGE(CreateTransferAssetTransaction(wallet.get(), ctrl, transfers, "",
                                                             error, wtx, reservekey, nFeeRequired,
                                                             &nullData),
                              "building owner-holder self-revocation: " + error.second);
        ConfirmTransaction(wtx, "owner-holder self-revocation");
    }
    BOOST_REQUIRE(passets->CheckForDEPINSelfRestriction(SOLO, ownerHolder));

    // A direct unfreeze must fail: it spends the owner token FROM the revoked
    // address, which the structural check rejects.
    {
        bool threw = false;
        try {
            CallRpc("unfreezedepin", {UniValue(SOLO), UniValue(ownerHolder)});
        } catch (const UniValue& e) {
            threw = true;
        }
        BOOST_CHECK_MESSAGE(threw, "a direct unfreeze from the revoked owner address must fail");
        BOOST_CHECK(passets->CheckForDEPINSelfRestriction(SOLO, ownerHolder));
        mempool.clear();
    }

    // Transaction 1 of the recovery: move the owner token to another address.
    const std::string ownerNewHome = NewWalletAddress();
    TransferAndConfirm(SOLO + OWNER_TAG, OWNER_ASSET_AMOUNT, ownerNewHome);

    // Transaction 2: now the owner token neither leaves nor enters the revoked
    // address, and the unfreeze goes through.
    CallRpc("unfreezedepin", {UniValue(SOLO), UniValue(ownerHolder)});
    MineBlock(GetScriptForRawPubKey(coinbaseKey.GetPubKey()), /*includeMempool=*/true);
    wallet->ScanForWalletTransactions(chainActive.Genesis(), nullptr, true);

    BOOST_CHECK_MESSAGE(!passets->CheckForDEPINSelfRestriction(SOLO, ownerHolder),
                        "the two-transaction recovery must clear the 'S' flag");
    BOOST_CHECK(!passets->CheckForDEPINRestriction(SOLO, ownerHolder));
}

BOOST_AUTO_TEST_SUITE_END()
