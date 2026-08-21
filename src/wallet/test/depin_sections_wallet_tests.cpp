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
#include "depinpoolkey.h"
#include "miner.h"
#include "pubkeyindex.h"
#include "streams.h"
#include "utilstrencodings.h"
#include "version.h"
#include "net.h" // g_connman
#include "rpc/server.h"
#include "script/standard.h"
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
    CKey poolKey;

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

        // Every DePIN response is signed with the pool key.
        poolKey.MakeNewKey(true);
        SetDepinPoolKey(poolKey, "test");
    }

    ~DepinSectionsWalletSetup()
    {
        ClearDepinPoolKey();
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
        BOOST_REQUIRE(pDepinMsgPool->Initialize(token,
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

    CPubKey parentPubKey, childPubKey;
    const std::string parentAddress = IssueAssetAndConfirm(PARENT_ASSET, CAmount(1000 * COIN), &parentPubKey);
    const std::string childAddress = IssueAssetAndConfirm(CHILD_ASSET, CAmount(100 * COIN), &childPubKey);
    FlushChainState();

    // The authenticated RPCs encrypt for the caller's revealed key.
    for (const auto& entry : {std::make_pair(parentAddress, parentPubKey),
                              std::make_pair(childAddress, childPubKey)}) {
        CTxDestination dest = DecodeDestination(entry.first);
        CDestinationIndexData addressData;
        BOOST_REQUIRE(GetDestinationIndexData(dest, addressData));
        std::vector<std::pair<CPubKeyIndexKey, CPubKeyIndexValue> > entries;
        entries.emplace_back(CPubKeyIndexKey(addressData), CPubKeyIndexValue(entry.second, 1, uint256()));
        BOOST_REQUIRE(pblocktree->WritePubKeyIndex(entries));
    }

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

    // The client flow with the wallet's own RPCs: depinchallenge -> decrypt
    // with the wallet key -> depinsignchallenge -> the authenticated call.
    // A refused call surfaces its JSON-RPC error instead of Boost's "unknown type".
    auto call = [&](const std::string& method, const UniValue& params) {
        try {
            return CallDepinRPC(method, params);
        } catch (const UniValue& e) {
            BOOST_FAIL(method + " failed: " + e.write());
            return UniValue();
        }
    };
    auto walletKey = [&](const std::string& address) {
        CTxDestination dest = DecodeDestination(address);
        const CKeyID* keyID = boost::get<CKeyID>(&dest);
        BOOST_REQUIRE(keyID != nullptr);
        CKey key;
        BOOST_REQUIRE(wallet->GetKey(*keyID, key));
        return key;
    };
    // Replies are opened with depindecrypt, the wallet RPC a neurai-cli client
    // uses for the same purpose.
    auto open = [&](const UniValue& response, const std::string& address) {
        BOOST_REQUIRE_MESSAGE(response.exists("encrypted"), response.write());
        BOOST_REQUIRE(response.exists("poolsig"));
        UniValue params(UniValue::VARR);
        params.push_back(address);
        params.push_back(response["encrypted"].get_str());
        return call("depindecrypt", params);
    };
    auto challenge = [&](const std::string& token, const std::string& address, const std::string& type) {
        UniValue params(UniValue::VARR);
        params.push_back(token);
        params.push_back(address);
        params.push_back(type);
        return open(call("depinchallenge", params), address)["challenge"].get_str();
    };
    auto sign = [&](const std::string& address, const std::string& token, const std::string& nonce, const std::string& type) {
        UniValue params(UniValue::VARR);
        params.push_back(address);
        params.push_back(token);
        params.push_back(nonce);
        params.push_back(type);
        return call("depinsignchallenge", params)["signature"].get_str();
    };

    // listsections for the CHILD address, scoped to its own section: access
    // and the counter for that tab; the root is outside what it can prove.
    {
        const std::string nonce = challenge(CHILD_ASSET, childAddress, "receive");
        UniValue listParams(UniValue::VARR);
        listParams.push_back(childAddress);
        listParams.push_back(CHILD_ASSET);
        listParams.push_back(nonce);
        listParams.push_back(sign(childAddress, CHILD_ASSET, nonce, "receive"));
        const UniValue sections = open(call("depinlistsections", listParams), childAddress)["sections"];
        BOOST_REQUIRE_EQUAL(sections.size(), 1U);
        BOOST_CHECK_EQUAL(sections[0]["name"].get_str(), CHILD_ASSET);
        BOOST_CHECK_EQUAL(sections[0]["label"].get_str(), "HIJO");
        BOOST_CHECK_EQUAL(sections[0]["access"].get_bool(), true);
        BOOST_CHECK_EQUAL(sections[0]["messages"].get_int(), 2);
    }
    // The child address gets no challenge for the root: no access there.
    {
        UniValue params(UniValue::VARR);
        params.push_back(PARENT_ASSET);
        params.push_back(childAddress);
        BOOST_CHECK_THROW(CallDepinRPC("depinchallenge", params), UniValue);
    }
    // The parent address, with a root challenge, sees both tabs.
    {
        const std::string nonce = challenge(PARENT_ASSET, parentAddress, "receive");
        UniValue listParams(UniValue::VARR);
        listParams.push_back(parentAddress);
        listParams.push_back(PARENT_ASSET);
        listParams.push_back(nonce);
        listParams.push_back(sign(parentAddress, PARENT_ASSET, nonce, "receive"));
        const UniValue sections = open(call("depinlistsections", listParams), parentAddress)["sections"];
        BOOST_REQUIRE_EQUAL(sections.size(), 2U);
        BOOST_CHECK_EQUAL(sections[0]["name"].get_str(), PARENT_ASSET);
        BOOST_CHECK_EQUAL(sections[0]["access"].get_bool(), true);
        BOOST_CHECK_EQUAL(sections[0]["messages"].get_int(), 3);
        BOOST_CHECK_EQUAL(sections[1]["name"].get_str(), CHILD_ASSET);
        BOOST_CHECK_EQUAL(sections[1]["access"].get_bool(), true);
        BOOST_CHECK_EQUAL(sections[1]["messages"].get_int(), 2);
    }

    // The owner token &PADRE! went to whichever wallet address the issuance
    // picked for it, not to the asset's destination: find that address, it
    // is the one allowed to purge (an ancestor owner qualifies for CHILD).
    std::string ownerAddress;
    {
        LOCK2(cs_main, wallet->cs_wallet);
        std::map<std::string, std::vector<COutput>> mapAssetCoins;
        wallet->AvailableAssets(mapAssetCoins);
        const auto it = mapAssetCoins.find(PARENT_ASSET + OWNER_TAG);
        BOOST_REQUIRE(it != mapAssetCoins.end() && !it->second.empty());
        CTxDestination dest;
        BOOST_REQUIRE(ExtractDestination(it->second[0].tx->tx->vout[it->second[0].i].scriptPubKey, dest));
        ownerAddress = EncodeDestination(dest);
    }
    {
        CTxDestination dest = DecodeDestination(ownerAddress);
        CDestinationIndexData addressData;
        BOOST_REQUIRE(GetDestinationIndexData(dest, addressData));
        std::vector<std::pair<CPubKeyIndexKey, CPubKeyIndexValue> > entries;
        entries.emplace_back(CPubKeyIndexKey(addressData), CPubKeyIndexValue(walletKey(ownerAddress).GetPubKey(), 1, uint256()));
        BOOST_REQUIRE(pblocktree->WritePubKeyIndex(entries));
    }
    // A plain holder of the root is not an owner: no admin challenge for it.
    {
        UniValue params(UniValue::VARR);
        params.push_back(CHILD_ASSET);
        params.push_back(parentAddress);
        params.push_back("admin");
        BOOST_CHECK_THROW(CallDepinRPC("depinchallenge", params), UniValue);
    }

    // Scoped purge by the owner of the root (an ancestor owner qualifies):
    // clearing the CHILD subtree removes its two messages and leaves the
    // root's untouched -- never parents, never siblings.
    {
        const std::string nonce = challenge(CHILD_ASSET, ownerAddress, "admin");
        UniValue clearParams(UniValue::VARR);
        clearParams.push_back(CHILD_ASSET);
        clearParams.push_back(ownerAddress);
        clearParams.push_back(nonce);
        clearParams.push_back(sign(ownerAddress, CHILD_ASSET, nonce, "admin"));
        clearParams.push_back("all");
        const UniValue cleared = open(call("depinclearmsg", clearParams), ownerAddress);
        BOOST_CHECK_EQUAL(cleared["removed"].get_int(), 2);
        BOOST_CHECK_EQUAL(cleared["remaining"].get_int(), 1);
    }

    std::vector<CDepinMessage> remaining = pDepinMsgPool->GetAllMessages();
    BOOST_REQUIRE_EQUAL(remaining.size(), 1U);
    BOOST_CHECK_EQUAL(remaining[0].token, PARENT_ASSET);

    // A scope outside the subtree is refused before any authentication.
    {
        UniValue badParams(UniValue::VARR);
        badParams.push_back("&OTRO");
        badParams.push_back(ownerAddress);
        badParams.push_back(std::string(64, 'a'));
        badParams.push_back("sig");
        badParams.push_back("all");
        BOOST_CHECK_THROW(CallDepinRPC("depinclearmsg", badParams), UniValue);
    }
}

// The reviewer's scope scenario, end to end and in-process: a pool serves
// &PADRE/HIJO with maxRecipients = 2 (< the global 50); the message goes to
// &PADRE/HIJO/NIETO; the wallet ALSO holds &PADRE, whose holder is outside
// that pool and must NOT appear in recipientKeys -- the pool hands its
// payloads to anyone who authenticates, so an extra entry is an extra reader.
// The scope comes from the serving pool itself (root as stopAt, its
// maxRecipients as the limit).
BOOST_AUTO_TEST_CASE(send_scopes_recipients_to_the_serving_pool)
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

    // The serving pool: root &PADRE/HIJO, limit 2 (< 50).
    ScopedInitializedPool pool(CHILD_ASSET, /*maxRecipients=*/2);

    // Through the real RPC: resolve -> encrypt -> sign -> AddMessage.
    UniValue params(UniValue::VARR);
    params.push_back(GRANDCHILD_ASSET);
    params.push_back("hola seccion");
    params.push_back(childAddress);

    const UniValue result = CallDepinRPC("depinsendmsg", params);

    BOOST_CHECK_EQUAL(result["result"].get_str(), "success");
    BOOST_CHECK_EQUAL(result["token"].get_str(), GRANDCHILD_ASSET);
    // Ancestors stop at the pool root: NIETO, HIJO -- never PADRE.
    BOOST_REQUIRE_EQUAL(result["ancestors"].size(), 2U);
    BOOST_CHECK_EQUAL(result["ancestors"][0].get_str(), GRANDCHILD_ASSET);
    BOOST_CHECK_EQUAL(result["ancestors"][1].get_str(), CHILD_ASSET);
    BOOST_CHECK_EQUAL(result["recipients"].get_int(), 2);

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

    // And a token the pool does not serve is refused up front -- before
    // anything is encrypted or added.
    UniValue outsideParams(UniValue::VARR);
    outsideParams.push_back(PARENT_ASSET);  // ancestor of the pool root, not served
    outsideParams.push_back("no deberia salir");
    outsideParams.push_back(parentAddress);
    BOOST_CHECK_THROW(CallDepinRPC("depinsendmsg", outsideParams), UniValue);
    BOOST_CHECK_EQUAL(pDepinMsgPool->GetMessageCount(), 1U);
}

// SignDepinMessage (the wallet signing path) and VerifyDepinMessageSignature
// agree on a single preimage: the message identifier (GetHash), which covers
// messageType. Flipping the type after signing must invalidate the signature;
// under the removed pre-v2.1.3 fallback it did not.
BOOST_AUTO_TEST_CASE(sign_depin_message_roundtrip)
{
    CKey senderKey;
    senderKey.MakeNewKey(true);
    const CPubKey senderPubKey = senderKey.GetPubKey();
    const std::string senderAddress = EncodeDestination(senderPubKey.GetID());

    // SignDepinMessage looks the key up in vpwallets[0]; verification reads
    // the revealed pubkey from the index.
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->AddKeyPubKey(senderKey, senderPubKey));
    }
    CTxDestination dest = DecodeDestination(senderAddress);
    CDestinationIndexData addressData;
    BOOST_REQUIRE(GetDestinationIndexData(dest, addressData));
    std::vector<std::pair<CPubKeyIndexKey, CPubKeyIndexValue> > entries;
    entries.emplace_back(CPubKeyIndexKey(addressData), CPubKeyIndexValue(senderPubKey, 1, uint256()));
    BOOST_REQUIRE(pblocktree->WritePubKeyIndex(entries));

    CDepinMessage msg = MakeMessage(PARENT_ASSET, senderAddress);
    BOOST_REQUIRE(SignDepinMessage(msg, senderAddress));
    BOOST_CHECK(VerifyDepinMessageSignature(msg));

    msg.messageType = 0x01;
    BOOST_CHECK(!VerifyDepinMessageSignature(msg));
}

// The pubkey index must ingest keys revealed by P2PKH spends even when
// -addressindex and -spentindex are OFF -- this fixture's exact
// configuration. ConnectBlock's extraction loop used to sit under
// `if (fAddressIndex || fSpentIndex)`, so a node with only -pubkeyindex
// indexed nothing. The coinbases here are P2PK, whose spends reveal no
// pubkey in the scriptSig, so the test builds the revealing P2PKH spend
// itself: fund a P2PKH output for coinbaseKey, then spend exactly that
// outpoint.
BOOST_AUTO_TEST_CASE(pubkeyindex_ingests_p2pkh_spend_without_addressindex)
{
    BOOST_REQUIRE(!fAddressIndex);
    BOOST_REQUIRE(!fSpentIndex);

    const CPubKey senderPubKey = coinbaseKey.GetPubKey();
    const std::string senderAddress = EncodeDestination(senderPubKey.GetID());
    const CScript p2pkh = GetScriptForDestination(senderPubKey.GetID());

    CPubKey indexed;
    std::string error;
    BOOST_CHECK(!CheckAddressHasPublicKey(senderAddress, indexed, error));

    // tx1: a P2PKH UTXO for coinbaseKey, funded from the P2PK coinbases.
    // Large enough to cover tx2's payment and fee on its own:
    // CCoinControl::fAllowOtherInputs is false by default, so tx2 can only
    // draw from this outpoint.
    CWalletTx wtx1;
    {
        CReserveKey reservekey(wallet.get());
        CAmount fee = 0;
        int changePos = -1;
        std::string failReason;
        CCoinControl noControl;
        CRecipient to{p2pkh, 10 * COIN, false};
        BOOST_REQUIRE_MESSAGE(wallet->CreateTransaction({to}, wtx1, reservekey, fee, changePos,
                                                        failReason, noControl), failReason);
        CValidationState state;
        BOOST_REQUIRE(wallet->CommitTransaction(wtx1, reservekey, g_connman.get(), state));
    }
    MineBlock(GetScriptForRawPubKey(coinbaseKey.GetPubKey()), /*includeMempool=*/true);
    wallet->ScanForWalletTransactions(chainActive.Genesis(), nullptr, true);

    int nOut = -1;
    for (size_t i = 0; i < wtx1.tx->vout.size(); ++i) {
        if (wtx1.tx->vout[i].scriptPubKey == p2pkh) { nOut = (int)i; break; }
    }
    BOOST_REQUIRE(nOut >= 0);

    // Paying TO the address reveals nothing; only spending FROM it does.
    BOOST_CHECK(!CheckAddressHasPublicKey(senderAddress, indexed, error));

    // tx2: spend exactly that outpoint. Its scriptSig [sig, pubkey] is what
    // ConnectBlock's extractor indexes.
    CWalletTx wtx2;
    {
        CReserveKey reservekey(wallet.get());
        CAmount fee = 0;
        int changePos = -1;
        std::string failReason;
        CCoinControl control;
        control.Select(COutPoint(wtx1.GetHash(), nOut));
        CPubKey destPubKey;
        BOOST_REQUIRE(wallet->GetKeyFromPool(destPubKey));
        CRecipient to{GetScriptForDestination(destPubKey.GetID()), 5 * COIN, false};
        BOOST_REQUIRE_MESSAGE(wallet->CreateTransaction({to}, wtx2, reservekey, fee, changePos,
                                                        failReason, control), failReason);
        BOOST_REQUIRE_EQUAL(wtx2.tx->vin.size(), 1U);
        BOOST_REQUIRE(wtx2.tx->vin[0].prevout == COutPoint(wtx1.GetHash(), nOut));
        CValidationState state;
        BOOST_REQUIRE(wallet->CommitTransaction(wtx2, reservekey, g_connman.get(), state));
    }
    MineBlock(GetScriptForRawPubKey(coinbaseKey.GetPubKey()), /*includeMempool=*/true);

    error.clear();
    BOOST_CHECK_MESSAGE(CheckAddressHasPublicKey(senderAddress, indexed, error), error);
    BOOST_CHECK(indexed == senderPubKey);
}

BOOST_AUTO_TEST_SUITE_END()
