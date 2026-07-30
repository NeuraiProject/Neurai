// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Integration for hierarchical DePIN sections against a REAL chain: assets are
// issued through CreateAssetTransaction, mined into blocks, and the section
// machinery (per-tip snapshot, inherited access, scoped purge, listsections)
// is exercised on the state those blocks produced -- no direct database
// seeding on the read side, unlike the unit tests.
//
// TESTNET for the same reasons as depin_subasset_wallet_tests.cpp: DEPIN names
// only validate on testnet/regtest, assets activate at height 1, trivial PoW.
//
// fAssetIndex is ON for the whole fixture: the section access checks read the
// asset-address index that ConnectBlock only maintains under that flag.

#include "wallet/wallet.h"

#include "assets/assets.h"
#include "assets/assetdb.h"
#include "assets/assettypes.h"
#include "assets/restricteddb.h"
#include "base58.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "depinecies.h"
#include "depinmsgpool.h"
#include "depinmsgpoolnet.h"
#include "miner.h"
#include "pubkeyindex.h"
#include "streams.h"
#include "net.h" // g_connman
#include "rpc/server.h"
#include "test/test_neurai.h"
#include "utiltime.h"
#include "validation.h"
#include "wallet/coincontrol.h"
#include "wallet/test/wallet_test_fixture.h"

#include <boost/test/unit_test.hpp>
#include <string>
#include <univalue.h>
#include <vector>

namespace {

const std::string PARENT_ASSET = "&PADRE";
const std::string CHILD_ASSET = "&PADRE/HIJO";

struct DepinSectionsWalletSetup : public TestingSetup {
    CKey coinbaseKey;
    std::unique_ptr<CWallet> wallet;
    bool prevAssetIndex;
    bool prevPubKeyIndex;

    DepinSectionsWalletSetup() : TestingSetup(CBaseChainParams::TESTNET)
    {
        prevAssetIndex = fAssetIndex;
        prevPubKeyIndex = fPubKeyIndex;
        // Before the first block: ConnectBlock only maintains the
        // asset-address index (what the access checks read) under fAssetIndex.
        fAssetIndex = true;
        fPubKeyIndex = true;

        passetsdb = new CAssetsDB(1 << 20, true, true);
        passetsCache = new CLRUCache<std::string, CDatabasedAssetData>(MAX_CACHE_ASSETS_SIZE);
        // Once any block flushes with restrictions around, DumpCacheToDatabase
        // dereferences these unguarded. In-memory, wiped per test.
        prestricteddb = new CRestrictedDB(1 << 20, true, true);
        passetsRestrictionCache = new CLRUCache<std::string, int8_t>(MAX_CACHE_ASSETS_SIZE);
        passetsGlobalRestrictionCache = new CLRUCache<std::string, int8_t>(MAX_CACHE_ASSETS_SIZE);

        coinbaseKey.MakeNewKey(true);
        const CScript coinbaseScript = GetScriptForRawPubKey(coinbaseKey.GetPubKey());

        for (int i = 0; i < GetCoinbaseMaturity() + 3; ++i) {
            MineBlock(coinbaseScript);
        }

        ::bitdb.MakeMock();
        wallet.reset(new CWallet(std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, "depin_sections_wallet_test.dat"))));
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

    ~DepinSectionsWalletSetup()
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

        fPubKeyIndex = prevPubKeyIndex;
        fAssetIndex = prevAssetIndex;
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

    // Issue `assetName` for real, mine it, and return the address that
    // received the tokens -- the section tests key access off that address.
    // pubkeyOut hands back the destination key for tests that need to seed the
    // pubkey index (encryption requires revealed keys).
    std::string IssueAssetAndConfirm(const std::string& assetName, CAmount amount,
                                     CPubKey* pubkeyOut = nullptr)
    {
        CNewAsset asset(assetName, amount, DEPIN_ASSET_UNITS, 0, 0, "");
        CCoinControl coinControl;
        CWalletTx wtx;
        CReserveKey reservekey(wallet.get());
        CAmount nFeeRequired = 0;

        CPubKey destPubKey;
        BOOST_REQUIRE(wallet->GetKeyFromPool(destPubKey));
        if (pubkeyOut) *pubkeyOut = destPubKey;
        const std::string destAddress = EncodeDestination(destPubKey.GetID());

        std::pair<int, std::string> error;
        BOOST_REQUIRE_MESSAGE(CreateAssetTransaction(wallet.get(), coinControl, asset,
                                                     destAddress, error, wtx, reservekey, nFeeRequired),
                              "issuing " + assetName + ": " + error.second);

        CValidationState state;
        BOOST_REQUIRE_MESSAGE(wallet->CommitTransaction(wtx, reservekey, g_connman.get(), state),
                              "committing " + assetName + ": " + state.GetRejectReason());
        BOOST_REQUIRE_MESSAGE(mempool.exists(wtx.GetHash()),
                              "issuance of " + assetName + " never reached the mempool");

        MineBlock(GetScriptForRawPubKey(coinbaseKey.GetPubKey()), /*includeMempool=*/true);

        BOOST_REQUIRE_MESSAGE(!mempool.exists(wtx.GetHash()),
                              "issuance of " + assetName + " was not mined into a block");

        wallet->ScanForWalletTransactions(chainActive.Genesis(), nullptr, true);
        return destAddress;
    }

    // The access checks read FLUSHED state by contract (they never flush
    // themselves -- that is the whole lock/freshness design). The test plays
    // the role of the node's periodic flush.
    void FlushChainState()
    {
        LOCK(cs_main);
        FlushStateToDisk();
    }
};

// RAII: swap in an Initialize()d global pool, restore the previous one.
struct ScopedInitializedPool {
    std::unique_ptr<CDepinMsgPool> previous;

    explicit ScopedInitializedPool(const std::string& token,
                                   unsigned int maxRecipients = DEFAULT_MAX_DEPIN_RECIPIENTS)
        : previous(std::move(pDepinMsgPool))
    {
        pDepinMsgPool.reset(new CDepinMsgPool());
        BOOST_REQUIRE(pDepinMsgPool->Initialize(token, DEFAULT_DEPIN_MSG_PORT,
                                                maxRecipients,
                                                DEFAULT_DEPIN_MESSAGE_SIZE,
                                                DEFAULT_DEPIN_MESSAGE_EXPIRY_HOURS,
                                                DEFAULT_DEPIN_POOL_SIZE_MB));
    }

    ~ScopedInitializedPool()
    {
        pDepinMsgPool = std::move(previous);
    }
};

CDepinMessage MakeMessage(const std::string& token, const std::string& sender)
{
    CDepinMessage msg;
    msg.token = token;
    msg.senderAddress = sender;
    msg.timestamp = GetTime();
    msg.messageType = 0x02;
    msg.encryptedPayload = {0x01, 0x02, 0x03};  // undeserializable: cap probe passes it
    return msg;
}

UniValue CallDepinRPC(const std::string& method, const UniValue& params)
{
    JSONRPCRequest request;
    request.strMethod = method;
    request.params = params;
    request.fHelp = false;

    BOOST_REQUIRE(tableRPC[method]);
    return (*tableRPC[method]->actor)(request);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(depin_sections_wallet_tests, DepinSectionsWalletSetup)

// The per-tip snapshot rebuilds when -- and only when -- the tip moves: a
// section issued and MINED shows up, because mining changed the tip.
BOOST_AUTO_TEST_CASE(sections_snapshot_rebuilds_on_new_tip)
{
    BOOST_REQUIRE(AreAssetsDeployed());
    ScopedInitializedPool pool(PARENT_ASSET);

    IssueAssetAndConfirm(PARENT_ASSET, CAmount(1000 * COIN));

    std::vector<std::string> sections;
    std::string error;
    BOOST_REQUIRE_MESSAGE(pDepinMsgPool->GetSections(sections, error), error);
    BOOST_REQUIRE_EQUAL(sections.size(), 1U);
    BOOST_CHECK_EQUAL(sections[0], PARENT_ASSET);

    // Issuing and mining the child moves the tip; the next call must rebuild
    // and see it. If the snapshot ignored the tip, this stays at size 1.
    IssueAssetAndConfirm(CHILD_ASSET, CAmount(100 * COIN));

    BOOST_REQUIRE_MESSAGE(pDepinMsgPool->GetSections(sections, error), error);
    BOOST_REQUIRE_EQUAL(sections.size(), 2U);
    BOOST_CHECK_EQUAL(sections[0], PARENT_ASSET);
    BOOST_CHECK_EQUAL(sections[1], CHILD_ASSET);
}

// Inherited access on state produced by real blocks: the parent's address
// reaches the child section, the child's address never reaches the root.
// (The two issuances land on different wallet addresses by construction.)
BOOST_AUTO_TEST_CASE(access_follows_real_issuance)
{
    BOOST_REQUIRE(AreAssetsDeployed());

    const std::string parentAddress = IssueAssetAndConfirm(PARENT_ASSET, CAmount(1000 * COIN));
    const std::string childAddress = IssueAssetAndConfirm(CHILD_ASSET, CAmount(100 * COIN));
    BOOST_REQUIRE(parentAddress != childAddress);

    FlushChainState();

    std::string error;
    BOOST_CHECK_MESSAGE(HasDepinSectionAccess(parentAddress, CHILD_ASSET, PARENT_ASSET, error), error);
    BOOST_CHECK_MESSAGE(HasDepinSectionAccess(parentAddress, PARENT_ASSET, PARENT_ASSET, error), error);

    BOOST_CHECK_MESSAGE(HasDepinSectionAccess(childAddress, CHILD_ASSET, PARENT_ASSET, error), error);
    BOOST_CHECK(!HasDepinSectionAccess(childAddress, PARENT_ASSET, PARENT_ASSET, error));

    // Owner authority from the real issuance: the issuing wallet received
    // &PADRE! somewhere; the child address specifically does NOT hold it, so
    // owner access must be denied for it.
    BOOST_CHECK(!HasDepinSectionOwnerAccess(childAddress, PARENT_ASSET, PARENT_ASSET, error));
}

// depinclearmsg with a scope purges exactly one subtree; depinlistsections
// reports access-aware tabs for a real holder.
BOOST_AUTO_TEST_CASE(scoped_purge_and_listsections_rpc)
{
    BOOST_REQUIRE(AreAssetsDeployed());
    ScopedInitializedPool pool(PARENT_ASSET);

    const std::string parentAddress = IssueAssetAndConfirm(PARENT_ASSET, CAmount(1000 * COIN));
    const std::string childAddress = IssueAssetAndConfirm(CHILD_ASSET, CAmount(100 * COIN));
    FlushChainState();

    // One message at the root (parent address may publish anywhere), two in
    // the child section.
    std::string error;
    CDepinMessage rootMsg = MakeMessage(PARENT_ASSET, parentAddress);
    BOOST_REQUIRE_MESSAGE(pDepinMsgPool->AddMessage(rootMsg, error, true), error);
    CDepinMessage childMsg1 = MakeMessage(CHILD_ASSET, childAddress);
    BOOST_REQUIRE_MESSAGE(pDepinMsgPool->AddMessage(childMsg1, error, true), error);
    CDepinMessage childMsg2 = MakeMessage(CHILD_ASSET, parentAddress);
    childMsg2.timestamp -= 1;  // distinct hash
    BOOST_REQUIRE_MESSAGE(pDepinMsgPool->AddMessage(childMsg2, error, true), error);

    BOOST_REQUIRE_EQUAL(pDepinMsgPool->GetMessageCount(), 3U);

    // listsections for the CHILD address: sees both tabs, has access only to
    // the child one, and the message counter appears only there.
    UniValue listParams(UniValue::VARR);
    listParams.push_back(childAddress);
    UniValue listing = CallDepinRPC("depinlistsections", listParams);
    BOOST_REQUIRE_EQUAL(listing.size(), 2U);

    BOOST_CHECK_EQUAL(listing[0]["name"].get_str(), PARENT_ASSET);
    BOOST_CHECK_EQUAL(listing[0]["access"].get_bool(), false);
    BOOST_CHECK(listing[0]["messages"].isNull());  // no counter without access

    BOOST_CHECK_EQUAL(listing[1]["name"].get_str(), CHILD_ASSET);
    BOOST_CHECK_EQUAL(listing[1]["label"].get_str(), "HIJO");
    BOOST_CHECK_EQUAL(listing[1]["access"].get_bool(), true);
    BOOST_CHECK_EQUAL(listing[1]["messages"].get_int(), 2);

    // Scoped purge: clearing the CHILD subtree removes its two messages and
    // leaves the root's untouched -- never parents, never siblings.
    UniValue clearParams(UniValue::VARR);
    clearParams.push_back("all");
    clearParams.push_back(CHILD_ASSET);
    UniValue cleared = CallDepinRPC("depinclearmsg", clearParams);
    BOOST_CHECK_EQUAL(cleared["removed"].get_int(), 2);
    BOOST_CHECK_EQUAL(cleared["remaining"].get_int(), 1);

    std::vector<CDepinMessage> remaining = pDepinMsgPool->GetAllMessages();
    BOOST_REQUIRE_EQUAL(remaining.size(), 1U);
    BOOST_CHECK_EQUAL(remaining[0].token, PARENT_ASSET);

    // A scope outside the subtree is refused.
    UniValue badParams(UniValue::VARR);
    badParams.push_back("all");
    badParams.push_back("&OTRO");
    BOOST_CHECK_THROW(CallDepinRPC("depinclearmsg", badParams), UniValue);
}

#if defined(ENABLE_DEPIN_GATEWAY) && !defined(WIN32)
// The reviewer's remote-send scenario, end to end and in-process: a pool
// serves &PADRE/HIJO with maxRecipients = 2 (< the global 50); the message
// goes to &PADRE/HIJO/NIETO; the wallet ALSO holds &PADRE, whose holder is
// outside that pool and must NOT appear in recipientKeys -- the pool's port
// exposes raw payloads, so an extra entry is an extra reader. The scope comes
// from the remote INFO (token as stopAt, maxRecipients as the limit).
BOOST_AUTO_TEST_CASE(remote_send_scopes_recipients_to_the_serving_pool)
{
    BOOST_REQUIRE(AreAssetsDeployed());
    const std::string GRANDCHILD_ASSET = "&PADRE/HIJO/NIETO";

    CPubKey parentPubKey, childPubKey, grandchildPubKey;
    const std::string parentAddress = IssueAssetAndConfirm(PARENT_ASSET, CAmount(1000 * COIN), &parentPubKey);
    const std::string childAddress = IssueAssetAndConfirm(CHILD_ASSET, CAmount(100 * COIN), &childPubKey);
    const std::string grandchildAddress = IssueAssetAndConfirm(GRANDCHILD_ASSET, CAmount(10 * COIN), &grandchildPubKey);
    FlushChainState();

    // Encryption keys must be revealed on chain; seed the index the way a
    // spend from each address would have.
    for (const auto& entry : {std::make_pair(parentAddress, parentPubKey),
                              std::make_pair(childAddress, childPubKey),
                              std::make_pair(grandchildAddress, grandchildPubKey)}) {
        CTxDestination dest = DecodeDestination(entry.first);
        CDestinationIndexData addressData;
        BOOST_REQUIRE(GetDestinationIndexData(dest, addressData));
        std::vector<std::pair<CPubKeyIndexKey, CPubKeyIndexValue> > entries;
        entries.emplace_back(CPubKeyIndexKey(addressData), CPubKeyIndexValue(entry.second, 1, uint256()));
        BOOST_REQUIRE(pblocktree->WritePubKeyIndex(entries));
    }

    // The serving pool: root &PADRE/HIJO, remote limit 2 (< 50).
    ScopedInitializedPool pool(CHILD_ASSET, /*maxRecipients=*/2);
    CDepinMsgPoolServer server;
    int serverPort = -1;
    for (int p = 34651; p < 34681; ++p) {
        if (server.Start(p)) { serverPort = p; break; }
    }
    BOOST_REQUIRE(serverPort > 0);

    // Remote send through the real RPC: INFO -> scope -> resolve -> encrypt ->
    // sign -> submit over the port -> remote depinsubmitmsg -> AddMessage.
    UniValue params(UniValue::VARR);
    params.push_back(GRANDCHILD_ASSET);
    params.push_back(strprintf("127.0.0.1:%d", serverPort));
    params.push_back("hola seccion");
    params.push_back(childAddress);

    const UniValue result = CallDepinRPC("depinsendmsg", params);
    server.Stop();

    BOOST_CHECK_EQUAL(result["result"].get_str(), "success");
    BOOST_CHECK_EQUAL(result["token"].get_str(), GRANDCHILD_ASSET);
    // Ancestors stop at the pool root: NIETO, HIJO -- never PADRE.
    BOOST_REQUIRE_EQUAL(result["ancestors"].size(), 2U);
    BOOST_CHECK_EQUAL(result["ancestors"][0].get_str(), GRANDCHILD_ASSET);
    BOOST_CHECK_EQUAL(result["ancestors"][1].get_str(), CHILD_ASSET);
    BOOST_CHECK_EQUAL(result["recipients"].get_int(), 2);

    // The message reached the serving pool through the port.
    BOOST_REQUIRE_EQUAL(pDepinMsgPool->GetMessageCount(), 1U);
    std::vector<CDepinMessage> messages = pDepinMsgPool->GetAllMessages();
    BOOST_REQUIRE_EQUAL(messages.size(), 1U);
    BOOST_CHECK_EQUAL(messages[0].token, GRANDCHILD_ASSET);

    // The decisive check: recipientKeys holds the pool's audience and nobody
    // above its root. An entry for &PADRE's holder would be the leak.
    CECIESEncryptedMessage ecies;
    CDataStream ss(messages[0].encryptedPayload, SER_NETWORK, PROTOCOL_VERSION);
    ss >> ecies;
    BOOST_CHECK_EQUAL(ecies.recipientKeys.size(), 2U);
    BOOST_CHECK(ecies.recipientKeys.count(uint160(childPubKey.GetID())) > 0);
    BOOST_CHECK(ecies.recipientKeys.count(uint160(grandchildPubKey.GetID())) > 0);
    BOOST_CHECK(ecies.recipientKeys.count(uint160(parentPubKey.GetID())) == 0);

    // And a token the pool does not serve is refused up front by the INFO
    // scope check -- before anything is encrypted or submitted.
    CDepinMsgPoolServer server2;
    int server2Port = -1;
    for (int p = 34651; p < 34681; ++p) {
        if (server2.Start(p)) { server2Port = p; break; }
    }
    BOOST_REQUIRE(server2Port > 0);
    UniValue outsideParams(UniValue::VARR);
    outsideParams.push_back(PARENT_ASSET);  // ancestor of the pool root, not served
    outsideParams.push_back(strprintf("127.0.0.1:%d", server2Port));
    outsideParams.push_back("no deberia salir");
    outsideParams.push_back(parentAddress);
    BOOST_CHECK_THROW(CallDepinRPC("depinsendmsg", outsideParams), UniValue);
    server2.Stop();
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetMessageCount(), 1U);
}
#endif // ENABLE_DEPIN_GATEWAY && !WIN32

BOOST_AUTO_TEST_SUITE_END()
