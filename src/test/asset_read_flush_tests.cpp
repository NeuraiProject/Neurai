// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Direct reads of the coins, asset and restricted-asset databases:
// gettxoutsetinfo, listassets, listaddressesbyasset, listassetbalancesbyaddress,
// listdepinholders, listdepinaddresses, listtagsforaddress, listaddressesfortag,
// listaddressrestrictions and listglobalrestrictions, all public through RPC
// proxies.
//
// Each reader used to force a FLUSH_STATE_ALWAYS (fsync, block index and UTXO
// writes, under cs_main) on every call. FlushStateForDatabaseReads() flushes once
// per chainstate instead, which is only correct if the databases then answer
// exactly what a flush would have made them answer: the reorg case below mines
// real issuances and freezes and checks every read against them. The
// directory readers also stop counting at the end of the rows they count, and
// a negative start skips back from the end instead of returning nothing.
//
// Flushes are counted with nFullStateFlushes, not inferred from
// FlushStateForDatabaseReads()'s return value: after an unconditional flush the
// marker would say "nothing to do" just as well.

#include "amount.h"
#include "assets/assetdb.h"
#include "assets/assets.h"
#include "assets/assettypes.h"
#include "assets/restricteddb.h"
#include "base58.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/validation.h"
#include "key.h"
#include "keystore.h"
#include "miner.h"
#include "policy/policy.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "rpc/server.h"
#include "script/sign.h"
#include "script/standard.h"
#include "test/test_neurai.h"
#include "txdb.h"
#include "txmempool.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <climits>
#include <string>
#include <thread>
#include <utility>
#include <vector>

// test/rpc_tests.cpp
extern UniValue CallRPC(std::string args);

namespace {

typedef std::vector<std::string> Names;
typedef std::vector<std::pair<std::string, CAmount> > Rows;

// Regtest is xna-native from height 1 (NIP-040).
const AssetMarker MARKER = AssetMarker::NEURAI_XNA;
const std::string DEVICE = "&DEVICE";
const std::string DEVICE_OWNER = "&DEVICE!";

std::string AddressOf(const CKey& key)
{
    return EncodeDestination(key.GetPubKey().GetID());
}

CScript TransferScript(const std::string& name, CAmount amount, const std::string& address)
{
    CAssetTransfer transfer(name, amount);
    CScript script = GetScriptForDestination(DecodeDestination(address));
    transfer.ConstructTransaction(script, MARKER);
    return script;
}

// Owner freeze of `address` for `name` (flag 1).
CScript FreezeScript(const std::string& name, const std::string& address)
{
    CNullAssetTxData data(name, 1);
    CScript script = GetScriptForNullAssetDataDestination(DecodeDestination(address));
    data.ConstructTransaction(script);
    return script;
}

COutPoint FakeOutPoint(unsigned int n)
{
    std::vector<unsigned char> bytes(32, 0x44);
    for (int i = 0; i < 4; i++) bytes[i] = (unsigned char)((n >> (8 * i)) & 0xff);
    return COutPoint(uint256(bytes), 0);
}

// A 100-block regtest chain (assets deployed) with in-memory asset
// databases, so a full flush really dumps the asset cache.
struct AssetReadSetup : public TestChain100Setup {
    CBasicKeyStore keystore;
    CKey ownerKey, holderKey;
    std::string ownerAddr, holderAddr;
    unsigned int nNextSeed = 0;
    unsigned int nBlockSalt = 0;
    std::string strLastReject; // why the last Mine() was refused, for the failure message

    AssetReadSetup() : TestChain100Setup()
    {
        passetsdb = new CAssetsDB(1 << 20, true, true);
        passetsCache = new CLRUCache<std::string, CDatabasedAssetData>(100);
        prestricteddb = new CRestrictedDB(1 << 20, true, true);
        passetsVerifierCache = new CLRUCache<std::string, CNullAssetTxVerifierString>(100);
        passetsQualifierCache = new CLRUCache<std::string, int8_t>(100);
        passetsRestrictionCache = new CLRUCache<std::string, int8_t>(100);
        passetsGlobalRestrictionCache = new CLRUCache<std::string, int8_t>(100);
        passetsDepinTransferStateCache = new CLRUCache<std::string, int8_t>(100);
        // TestingSetup keeps the coins database in a member that hides the
        // global, which gettxoutsetinfo reads; point the global at it.
        ::pcoinsdbview = pcoinsdbview;

        // &DEVICE exists as far as the metadata lookups are concerned; its
        // owner token is seeded into the UTXO set by the tests that freeze.
        BOOST_REQUIRE(passetsdb->WriteAssetData(CNewAsset(DEVICE, 1000 * COIN, DEPIN_ASSET_UNITS, 1, 0, ""),
                                                chainActive.Height(), chainActive.Tip()->GetBlockHash()));

        keystore.AddKey(coinbaseKey);
        for (CKey* key : {&ownerKey, &holderKey}) {
            key->MakeNewKey(true);
            keystore.AddKey(*key);
        }
        ownerAddr = AddressOf(ownerKey);
        holderAddr = AddressOf(holderKey);
    }

    ~AssetReadSetup()
    {
        ::pcoinsdbview = nullptr;
        delete passetsDepinTransferStateCache; passetsDepinTransferStateCache = nullptr;
        delete passetsGlobalRestrictionCache; passetsGlobalRestrictionCache = nullptr;
        delete passetsRestrictionCache; passetsRestrictionCache = nullptr;
        delete passetsQualifierCache; passetsQualifierCache = nullptr;
        delete passetsVerifierCache; passetsVerifierCache = nullptr;
        delete prestricteddb; prestricteddb = nullptr;
        delete passetsCache; passetsCache = nullptr;
        delete passetsdb; passetsdb = nullptr;
    }

    COutPoint Seed(const CScript& script)
    {
        const COutPoint out = FakeOutPoint(0x2000 + nNextSeed++);
        pcoinsTip->AddCoin(out, Coin(CTxOut(0, script), chainActive.Height(), false), false);
        return out;
    }

    // The cache size FlushStateToDisk() weighs against its budget (the
    // message caches are empty here).
    size_t CacheUsage() const
    {
        return pcoinsTip->DynamicMemoryUsage() + passets->DynamicMemoryUsage() + passets->GetCacheSizeV2();
    }

    // Seed throwaway coins until the cache holds more than `target` bytes.
    void FillCache(size_t target)
    {
        const CScript filler = GetScriptForDestination(coinbaseKey.GetPubKey().GetID());
        for (int n = 0; CacheUsage() <= target; n++) {
            BOOST_REQUIRE(n < 1000000);
            Seed(filler);
        }
    }

    void Sign(CMutableTransaction& mut) const
    {
        for (unsigned int i = 0; i < mut.vin.size(); i++) {
            const Coin& coin = pcoinsTip->AccessCoin(mut.vin[i].prevout);
            BOOST_REQUIRE(!coin.IsSpent());
            BOOST_REQUIRE(SignSignature(keystore, coin.out.scriptPubKey, mut, i, coin.out.nValue, SIGHASH_ALL));
        }
    }

    // A root asset and its owner token issued to `to` (consensus wants both at
    // one address), paid with the first (mature) coinbase:
    // [burn, change, owner token, asset], the shape VerifyNewAsset() expects.
    CMutableTransaction Issue(const std::string& name, CAmount amount, const std::string& to)
    {
        const CTransaction& coinbase = coinbaseTxns[0];
        const CAmount burn = GetBurnAmount(AssetType::ROOT);
        const CAmount fee = COIN / 100;
        BOOST_REQUIRE(coinbase.vout[0].nValue > burn + fee);

        CMutableTransaction mut;
        mut.vin.emplace_back(COutPoint(coinbase.GetHash(), 0));
        mut.vout.emplace_back(burn, GetScriptForDestination(DecodeDestination(GetBurnAddress(AssetType::ROOT))));
        mut.vout.emplace_back(coinbase.vout[0].nValue - burn - fee, GetScriptForDestination(coinbaseKey.GetPubKey().GetID()));

        CNewAsset asset(name, amount, 0, 1, 0, "");
        CScript ownerScript = GetScriptForDestination(DecodeDestination(to));
        asset.ConstructOwnerTransaction(ownerScript, MARKER);
        mut.vout.emplace_back(0, ownerScript);
        CScript assetScript = GetScriptForDestination(DecodeDestination(to));
        asset.ConstructTransaction(assetScript, MARKER);
        mut.vout.emplace_back(0, assetScript);
        Sign(mut);
        return mut;
    }

    // Spend a coin of `address`: its scriptSig reveals the address's pubkey.
    CMutableTransaction Spend(const COutPoint& out, const std::string& address)
    {
        CMutableTransaction mut;
        mut.vin.emplace_back(out);
        mut.vout.emplace_back(0, GetScriptForDestination(DecodeDestination(address)));
        Sign(mut);
        return mut;
    }

    // The owner of &DEVICE freezes `address`, re-emitting the owner token.
    CMutableTransaction Freeze(const COutPoint& ownerOut, const std::string& address)
    {
        CMutableTransaction mut;
        mut.vin.emplace_back(ownerOut);
        mut.vout.emplace_back(0, TransferScript(DEVICE_OWNER, OWNER_ASSET_AMOUNT, ownerAddr));
        mut.vout.emplace_back(0, FreezeScript(DEVICE, address));
        Sign(mut);
        return mut;
    }

    // A block with `txns` on the tip. The template committed to its own
    // transaction list, so the witness commitment is rebuilt for ours, and a
    // fresh extra nonce keeps a re-mined block from repeating an invalidated one.
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
            // TestBlockValidity() requires cs_main; the lock CreateNewBlock()
            // took ended when it returned the template.
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

    // Disconnect the tip; its transactions, resurrected into the mempool,
    // are dropped so the next block is exactly what the test mines.
    void UndoTip()
    {
        CValidationState state;
        {
            // InvalidateBlock() requires cs_main, as the invalidateblock RPC holds it.
            LOCK(cs_main);
            BOOST_REQUIRE(InvalidateBlock(state, GetParams(), chainActive.Tip()));
        }
        BOOST_REQUIRE(state.IsValid());
        mempool.clear();
    }
};

// A cache budget of `budget` bytes and no mempool allowance, as on a node
// whose -dbcache is that small.
struct CacheBudget {
    const size_t nPrevCoinCacheUsage;
    const std::string strPrevMaxMempool;
    explicit CacheBudget(size_t budget)
        : nPrevCoinCacheUsage(nCoinCacheUsage),
          strPrevMaxMempool(gArgs.GetArg("-maxmempool", std::to_string(DEFAULT_MAX_MEMPOOL_SIZE)))
    {
        nCoinCacheUsage = budget;
        gArgs.ForceSetArg("-maxmempool", "0");
    }
    ~CacheBudget()
    {
        nCoinCacheUsage = nPrevCoinCacheUsage;
        gArgs.ForceSetArg("-maxmempool", strPrevMaxMempool);
    }
};

// Address balances are only tracked with -assetindex.
struct AssetIndexGuard {
    const bool fPrevious;
    AssetIndexGuard() : fPrevious(fAssetIndex) { fAssetIndex = true; }
    ~AssetIndexGuard() { fAssetIndex = fPrevious; }
};

void Hold(const std::string& asset, const Names& addresses)
{
    for (const std::string& address : addresses) {
        BOOST_REQUIRE(passetsdb->WriteAssetAddressQuantity(asset, address, COIN));
        BOOST_REQUIRE(passetsdb->WriteAddressAssetQuantity(address, asset, COIN));
    }
}

Names Firsts(const Rows& rows)
{
    Names names;
    for (const auto& row : rows) names.push_back(row.first);
    return names;
}

Rows HolderRows(const std::string& asset, size_t count = INT_MAX, long start = 0)
{
    Rows rows;
    int total = 0;
    BOOST_REQUIRE(passetsdb->AssetAddressDir(rows, total, false, asset, count, start));
    return rows;
}

Names HoldersOf(const std::string& asset, size_t count, long start)
{
    return Firsts(HolderRows(asset, count, start));
}

Names AssetsOf(const std::string& address, size_t count = INT_MAX, long start = 0)
{
    Rows rows;
    int total = 0;
    BOOST_REQUIRE(passetsdb->AddressDir(rows, total, false, address, count, start));
    return Firsts(rows);
}

Names AssetNames(const std::string& filter, size_t count = 100, long start = 0)
{
    std::vector<CDatabasedAssetData> assets;
    BOOST_REQUIRE(passetsdb->AssetDir(assets, filter, count, start));
    Names names;
    for (const auto& data : assets) names.push_back(data.asset.strName);
    return names;
}

Names RestrictionsOf(std::string address)
{
    Names restrictions;
    BOOST_REQUIRE(prestricteddb->GetAddressRestrictions(address, restrictions));
    return restrictions;
}

bool Contains(const Names& names, const std::string& name)
{
    return std::find(names.begin(), names.end(), name) != names.end();
}

// Whether this thread holds cs_main, asked from another thread: TRY_LOCK
// there fails only if the lock is taken.
bool HoldsCsMain()
{
    bool fTaken = false;
    std::thread probe([&fTaken]() {
        TRY_LOCK(cs_main, lockMain);
        fTaken = !lockMain;
    });
    probe.join();
    return fTaken;
}

struct PubKeyIndexGuard {
    const bool fPrevious;
    PubKeyIndexGuard() : fPrevious(fPubKeyIndex) { fPubKeyIndex = true; }
    ~PubKeyIndexGuard() { fPubKeyIndex = fPrevious; }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(asset_read_flush_tests, AssetReadSetup)

BOOST_AUTO_TEST_CASE(one_flush_per_chainstate)
{
    // A full flush from anywhere leaves nothing for the readers to flush.
    FlushStateToDisk();
    uint64_t flushes = nFullStateFlushes;
    BOOST_CHECK(!FlushStateForDatabaseReads());
    BOOST_CHECK(!FlushStateForDatabaseReads());
    BOOST_CHECK_EQUAL(nFullStateFlushes - flushes, 0U);

    // A new block: one flush, however many reads follow.
    BOOST_REQUIRE(Mine({}));
    flushes = nFullStateFlushes;
    BOOST_CHECK(FlushStateForDatabaseReads());
    BOOST_CHECK(!FlushStateForDatabaseReads());
    BOOST_CHECK(!FlushStateForDatabaseReads());
    BOOST_CHECK_EQUAL(nFullStateFlushes - flushes, 1U);

    // Reorg after that flush: the databases hold the disconnected block, so
    // the previous block needs a flush although it was flushed before.
    UndoTip();
    flushes = nFullStateFlushes;
    BOOST_CHECK(FlushStateForDatabaseReads());
    BOOST_CHECK(!FlushStateForDatabaseReads());
    BOOST_CHECK_EQUAL(nFullStateFlushes - flushes, 1U);

    // A block connected and disconnected with no read in between never
    // reached the databases: they still match the block they were flushed at.
    BOOST_REQUIRE(Mine({}));
    UndoTip();
    flushes = nFullStateFlushes;
    BOOST_CHECK(!FlushStateForDatabaseReads());
    BOOST_CHECK_EQUAL(nFullStateFlushes - flushes, 0U);
}

// Every reader goes through FlushStateForDatabaseReads(). With the former
// unconditional FlushStateToDisk() this loop made 16 full flushes.
BOOST_AUTO_TEST_CASE(repeated_reads_flush_once)
{
    Hold("TOKEN", {"addr1"});
    BOOST_REQUIRE(Mine({}));
    const uint64_t flushes = nFullStateFlushes;
    for (int round = 0; round < 2; round++) {
        Rows rows;
        int total = 0;
        BOOST_CHECK(passetsdb->AssetAddressDir(rows, total, true, "TOKEN", INT_MAX, 0));
        BOOST_CHECK(passetsdb->AssetAddressDir(rows, total, false, "TOKEN", INT_MAX, 0));
        BOOST_CHECK(passetsdb->AddressDir(rows, total, true, "addr1", INT_MAX, 0));
        std::vector<CDatabasedAssetData> assets;
        BOOST_CHECK(passetsdb->AssetDir(assets, "*", 10, 0));

        std::string qualifier = "#TAG", address = "addr1";
        std::vector<std::string> names;
        BOOST_CHECK(prestricteddb->GetQualifierAddresses(qualifier, names));
        BOOST_CHECK(prestricteddb->GetAddressQualifiers(address, names));
        BOOST_CHECK(prestricteddb->GetAddressRestrictions(address, names));
        BOOST_CHECK(prestricteddb->GetGlobalRestrictions(names));
    }
    BOOST_CHECK_EQUAL(nFullStateFlushes - flushes, 1U);
}

// Balances, metadata and restrictions written by real blocks, read through
// the databases at every step of a reorg: each read must answer what an
// unconditional flush would have made it answer.
BOOST_AUTO_TEST_CASE(reads_follow_asset_changes_through_a_reorg)
{
    AssetIndexGuard assetIndex;
    const COutPoint ownerOut = Seed(TransferScript(DEVICE_OWNER, OWNER_ASSET_AMOUNT, ownerAddr));
    const CMutableTransaction issue = Issue("NEWTOKEN", 5 * COIN, holderAddr);
    const CMutableTransaction freeze = Freeze(ownerOut, holderAddr);

    // Block A: NEWTOKEN is issued to holderAddr
    BOOST_REQUIRE_MESSAGE(Mine({issue}), strLastReject);
    BOOST_CHECK(AssetNames("NEWTOKEN") == Names({"NEWTOKEN"}));
    BOOST_CHECK(HolderRows("NEWTOKEN") == Rows({{holderAddr, 5 * COIN}}));
    BOOST_CHECK(Contains(AssetsOf(holderAddr), "NEWTOKEN"));
    BOOST_CHECK(RestrictionsOf(holderAddr).empty());

    // Block B: the owner of &DEVICE freezes holderAddr
    BOOST_REQUIRE_MESSAGE(Mine({freeze}), strLastReject);
    BOOST_CHECK(RestrictionsOf(holderAddr) == Names({DEVICE}));
    BOOST_CHECK(HolderRows("NEWTOKEN") == Rows({{holderAddr, 5 * COIN}}));

    // Undo B after it was flushed: the freeze leaves the database, the
    // issuance stays
    UndoTip();
    BOOST_CHECK(RestrictionsOf(holderAddr).empty());
    BOOST_CHECK(AssetNames("NEWTOKEN") == Names({"NEWTOKEN"}));
    BOOST_CHECK(HolderRows("NEWTOKEN") == Rows({{holderAddr, 5 * COIN}}));

    // B again, undone before any read: the database never saw it, and the
    // read after the undo needs no flush to say so
    BOOST_REQUIRE_MESSAGE(Mine({freeze}), strLastReject);
    UndoTip();
    const uint64_t flushes = nFullStateFlushes;
    BOOST_CHECK(RestrictionsOf(holderAddr).empty());
    BOOST_CHECK_EQUAL(nFullStateFlushes - flushes, 0U);

    // Undo A: the asset and its balance leave the database
    UndoTip();
    BOOST_CHECK(AssetNames("NEWTOKEN").empty());
    BOOST_CHECK(HolderRows("NEWTOKEN").empty());
    BOOST_CHECK(!Contains(AssetsOf(holderAddr), "NEWTOKEN"));
}

// ConnectTip and DisconnectTip flush after applying the block but before
// UpdateTip, so chainActive still names the previous tip while the databases
// already hold the new state; the marker records the coins view's best block
// for that reason. This case makes exactly those flushes happen, and nothing
// after them, then checks the reads that depend on the marker they left.
BOOST_AUTO_TEST_CASE(flushes_inside_connect_and_disconnect_tip)
{
    AssetIndexGuard assetIndex;
    const CMutableTransaction issue = Issue("NEWTOKEN", 5 * COIN, holderAddr);

    // A budget above what the cache drops back to after a full flush, by more
    // than the 10% FLUSH_STATE_PERIODIC allows, and below a filled cache. The
    // flush inside ConnectTip or DisconnectTip then fires, while the periodic
    // ones after UpdateTip -- ActivateBestChain's, and AcceptToMemoryPool's for
    // the transactions a disconnect sends back -- find the cache drained and
    // leave the marker alone. (A fill grows the cache's bucket array, which a
    // flush keeps: the first, larger fill sizes it for the later ones.)
    FillCache(CacheUsage() + (8 << 20));
    FlushStateToDisk();
    const size_t drained = CacheUsage();
    const size_t budget = 2 * drained;

    // Connect over budget, then disconnect with an ordinary cache and no read
    // in between. The databases hold the issuance; a marker naming the parent
    // (chainActive's tip during ConnectTip) would let the read skip its flush.
    FillCache(budget + (1 << 20));
    uint64_t flushes = nFullStateFlushes;
    {
        CacheBudget overBudget(budget);
        BOOST_REQUIRE_MESSAGE(Mine({issue}), strLastReject);
    }
    BOOST_REQUIRE_EQUAL(nFullStateFlushes - flushes, 1U); // the one inside ConnectTip
    UndoTip();
    BOOST_CHECK(AssetNames("NEWTOKEN").empty());
    BOOST_CHECK(HolderRows("NEWTOKEN").empty());

    // Connect and read (the databases and the marker at the issuance), then
    // disconnect over budget: the databases go back to the parent. Reconnect
    // that very block with an ordinary cache, so nothing flushes on the way; a
    // marker naming the block (chainActive's tip during DisconnectTip) would
    // let the read skip its flush and miss the issuance.
    BOOST_REQUIRE_MESSAGE(Mine({issue}), strLastReject);
    const uint256 hashIssued = chainActive.Tip()->GetBlockHash();
    BOOST_CHECK(AssetNames("NEWTOKEN") == Names({"NEWTOKEN"}));
    FillCache(budget + (1 << 20));
    flushes = nFullStateFlushes;
    {
        CacheBudget overBudget(budget);
        UndoTip();
    }
    BOOST_REQUIRE_EQUAL(nFullStateFlushes - flushes, 1U); // the one inside DisconnectTip
    {
        LOCK(cs_main);
        BOOST_REQUIRE(ResetBlockFailureFlags(mapBlockIndex.at(hashIssued)));
    }
    CValidationState state;
    BOOST_REQUIRE(ActivateBestChain(state, GetParams()));
    BOOST_REQUIRE(chainActive.Tip()->GetBlockHash() == hashIssued);
    BOOST_CHECK(AssetNames("NEWTOKEN") == Names({"NEWTOKEN"}));
    BOOST_CHECK(HolderRows("NEWTOKEN") == Rows({{holderAddr, 5 * COIN}}));
}

// The listing RPCs scan without cs_main and take it only for the asset cache.
// A block arriving during the scan sends it round again, so the answer never
// pairs rows of one chainstate with cache data of another; after two retries
// the scan runs under cs_main.
BOOST_AUTO_TEST_CASE(read_at_one_chainstate_retries_when_a_block_arrives)
{
    for (int blocksDuringScan = 0; blocksDuringScan <= 2; blocksDuringScan++) {
        int scans = 0, finishes = 0;
        std::vector<bool> scanHeldLock;
        uint256 hashScanned, hashFinished;
        ReadAtOneChainstate(
            [&]() {
                scans++;
                scanHeldLock.push_back(HoldsCsMain());
                if (scans <= blocksDuringScan) BOOST_REQUIRE(Mine({}));
                LOCK(cs_main);
                hashScanned = pcoinsTip->GetBestBlock();
            },
            [&]() {
                finishes++;
                BOOST_CHECK(HoldsCsMain());
                hashFinished = pcoinsTip->GetBestBlock();
            });
        BOOST_CHECK_EQUAL(scans, blocksDuringScan + 1);
        BOOST_CHECK_EQUAL(finishes, 1);
        BOOST_CHECK(hashScanned == hashFinished);
        // Only the last resort holds the lock through the scan
        for (int i = 0; i < scans; i++) {
            BOOST_CHECK_EQUAL(scanHeldLock[i], i == 2);
        }
    }

    // A reorg that leaves and comes back during the scan (A -> B -> A) ends
    // on the same tip, but the scan may have read B: it still runs again.
    Hold("TOKEN", {"addr1"});
    int scans = 0;
    ReadAtOneChainstate(
        [&]() {
            scans++;
            if (scans == 1) {
                BOOST_REQUIRE(Mine({}));
                HoldersOf("TOKEN", 10, 0);
                UndoTip();
            }
        },
        [&]() {});
    BOOST_CHECK_EQUAL(scans, 2);
}

// The four listings rewritten around ReadAtOneChainstate, and listassets,
// after real blocks.
BOOST_AUTO_TEST_CASE(listing_rpcs_after_real_blocks)
{
    AssetIndexGuard assetIndex;
    PubKeyIndexGuard pubKeyIndex;
    Hold(DEVICE, {holderAddr}); // a holder of &DEVICE, straight into the index
    const COutPoint ownerOut = Seed(TransferScript(DEVICE_OWNER, OWNER_ASSET_AMOUNT, ownerAddr));
    const COutPoint holderCoin = Seed(GetScriptForDestination(DecodeDestination(holderAddr)));
    const CPubKey holderKeyPub = holderKey.GetPubKey();
    const std::string holderPubKey = HexStr(holderKeyPub.begin(), holderKeyPub.end());

    // NEWTOKEN is issued to holderAddr, which also spends a coin and so
    // reveals its pubkey: listdepinaddresses lists it, valid
    BOOST_REQUIRE_MESSAGE(Mine({Issue("NEWTOKEN", 5 * COIN, holderAddr), Spend(holderCoin, holderAddr)}), strLastReject);
    UniValue revealed = CallRPC("listdepinaddresses " + DEVICE);
    BOOST_REQUIRE_EQUAL(revealed.size(), 1U);
    BOOST_CHECK_EQUAL(revealed[0]["address"].get_str(), holderAddr);
    BOOST_CHECK_EQUAL(revealed[0]["pubkey"].get_str(), holderPubKey);
    BOOST_CHECK_EQUAL(revealed[0]["valid"].get_int(), 1);

    BOOST_REQUIRE_MESSAGE(Mine({Freeze(ownerOut, holderAddr)}), strLastReject);

    const UniValue holders = CallRPC("listaddressesbyasset NEWTOKEN");
    BOOST_CHECK_EQUAL(holders.size(), 1U);
    BOOST_CHECK_EQUAL(holders[holderAddr].get_real(), 5);
    BOOST_CHECK_EQUAL(CallRPC("listaddressesbyasset NEWTOKEN true").get_int(), 1);

    const UniValue balances = CallRPC("listassetbalancesbyaddress " + holderAddr);
    BOOST_CHECK_EQUAL(balances.size(), 3U);
    BOOST_CHECK_EQUAL(balances["NEWTOKEN"].get_real(), 5);
    BOOST_CHECK_EQUAL(balances["NEWTOKEN!"].get_real(), 1);
    BOOST_CHECK_EQUAL(balances[DEVICE].get_real(), 1);
    BOOST_CHECK_EQUAL(CallRPC("listassetbalancesbyaddress " + holderAddr + " true").get_int(), 3);

    // holderAddr is frozen for &DEVICE: listed, but not valid
    const UniValue depinHolders = CallRPC("listdepinholders " + DEVICE);
    BOOST_REQUIRE_EQUAL(depinHolders.size(), 1U);
    BOOST_CHECK_EQUAL(depinHolders[0]["address"].get_str(), holderAddr);
    BOOST_CHECK_EQUAL(depinHolders[0]["valid"].get_int(), 0);

    // ... and listdepinaddresses still lists it, no longer valid
    revealed = CallRPC("listdepinaddresses " + DEVICE);
    BOOST_REQUIRE_EQUAL(revealed.size(), 1U);
    BOOST_CHECK_EQUAL(revealed[0]["pubkey"].get_str(), holderPubKey);
    BOOST_CHECK_EQUAL(revealed[0]["valid"].get_int(), 0);

    // listassets verbose formats with the units read in its own scan
    const UniValue assets = CallRPC("listassets NEWTOKEN true");
    BOOST_CHECK_EQUAL(assets["NEWTOKEN"]["amount"].get_real(), 5);
    BOOST_CHECK_EQUAL(assets["NEWTOKEN"]["units"].get_int(), 0);
}

// gettxoutsetinfo reads the coins database like the asset readers read theirs:
// at most one full flush per chainstate, and the marker is shared with them.
BOOST_AUTO_TEST_CASE(gettxoutsetinfo_flushes_at_most_once_per_chainstate)
{
    // A block not flushed yet: the first call flushes it, the others do not
    BOOST_REQUIRE(Mine({}));
    uint64_t flushes = nFullStateFlushes;
    for (int i = 0; i < 3; i++) CallRPC("gettxoutsetinfo");
    BOOST_CHECK_EQUAL(nFullStateFlushes - flushes, 1U);

    // A block someone else already flushed: no flush at all
    BOOST_REQUIRE(Mine({}));
    FlushStateToDisk();
    flushes = nFullStateFlushes;
    CallRPC("gettxoutsetinfo");
    BOOST_CHECK_EQUAL(nFullStateFlushes - flushes, 0U);

    // Asset readers and gettxoutsetinfo share the marker, in either order
    BOOST_REQUIRE(Mine({}));
    flushes = nFullStateFlushes;
    AssetNames("*");
    CallRPC("gettxoutsetinfo");
    BOOST_CHECK_EQUAL(nFullStateFlushes - flushes, 1U);
    BOOST_REQUIRE(Mine({}));
    flushes = nFullStateFlushes;
    CallRPC("gettxoutsetinfo");
    AssetNames("*");
    BOOST_CHECK_EQUAL(nFullStateFlushes - flushes, 1U);
}

BOOST_AUTO_TEST_CASE(gettxoutsetinfo_answers_the_current_chainstate)
{
    const UniValue before = CallRPC("gettxoutsetinfo");
    BOOST_CHECK_EQUAL(before["height"].get_int(), chainActive.Height());
    BOOST_CHECK_EQUAL(before["bestblock"].get_str(), chainActive.Tip()->GetBlockHash().GetHex());

    // A new block adds its coinbase
    BOOST_REQUIRE(Mine({}));
    const UniValue mined = CallRPC("gettxoutsetinfo");
    BOOST_CHECK_EQUAL(mined["height"].get_int(), before["height"].get_int() + 1);
    BOOST_CHECK_EQUAL(mined["bestblock"].get_str(), chainActive.Tip()->GetBlockHash().GetHex());
    BOOST_CHECK(mined["total_amount"].get_real() > before["total_amount"].get_real());

    // Undoing it gives back exactly the set from before
    UndoTip();
    const UniValue undone = CallRPC("gettxoutsetinfo");
    BOOST_CHECK_EQUAL(undone["height"].get_int(), before["height"].get_int());
    BOOST_CHECK_EQUAL(undone["bestblock"].get_str(), before["bestblock"].get_str());
    BOOST_CHECK_EQUAL(undone["total_amount"].getValStr(), before["total_amount"].getValStr());
    BOOST_CHECK_EQUAL(undone["hash_serialized_2"].get_str(), before["hash_serialized_2"].get_str());
}

// A best block the index does not know -- what a cursor opened between the
// batches of a flush would read -- is an error, not a dereference of
// mapBlockIndex.end(). With the marker current, gettxoutsetinfo does not flush
// first, so the coins database is read as it is. (That the cursor is opened
// under cs_main, which keeps it off a half-written flush, is checked by the
// AssertLockHeld in CCoinsViewDB::Cursor() when built with DEBUG_LOCKORDER.)
BOOST_AUTO_TEST_CASE(gettxoutsetinfo_unknown_best_block_is_an_error)
{
    FlushStateToDisk();
    CCoinsMap noCoins;
    BOOST_REQUIRE(pcoinsdbview->BatchWrite(noCoins, uint256S("0x1234")));
    BOOST_CHECK_THROW(CallRPC("gettxoutsetinfo"), std::runtime_error);

    // A full flush writes the real best block back
    FlushStateToDisk();
    BOOST_CHECK_NO_THROW(CallRPC("gettxoutsetinfo"));
}

// UnloadBlockIndex() precedes reopening or rebuilding the databases: the
// block they matched before must not exempt the next read from flushing.
BOOST_AUTO_TEST_CASE(unload_forgets_the_flushed_block)
{
    FlushStateToDisk();
    BOOST_CHECK(!FlushStateForDatabaseReads());
    UnloadBlockIndex();
    const uint64_t flushes = nFullStateFlushes;
    BOOST_CHECK(FlushStateForDatabaseReads());
    BOOST_CHECK_EQUAL(nFullStateFlushes - flushes, 1U);
}

// Asset names sort by length first ("AA" < "AAA" < "AAB" < "AAAA"), so the
// counted asset has neighbours on both sides; the count must stop at its own
// rows and still include all of them.
BOOST_AUTO_TEST_CASE(counts_cover_exactly_the_asked_rows)
{
    Hold("AA", {"addr1"});
    Hold("AAA", {"addr1", "addr2", "addr3"});
    Hold("AAB", {"addr2"});
    Hold("AAAA", {"addr3"});

    Rows rows;
    int total = -1;
    BOOST_CHECK(passetsdb->AssetAddressDir(rows, total, true, "AAA", INT_MAX, 0));
    BOOST_CHECK_EQUAL(total, 3);
    BOOST_CHECK(rows.empty());
    BOOST_CHECK(passetsdb->AssetAddressDir(rows, total, true, "AAB", INT_MAX, 0));
    BOOST_CHECK_EQUAL(total, 1);
    BOOST_CHECK(passetsdb->AssetAddressDir(rows, total, true, "MISSING", INT_MAX, 0));
    BOOST_CHECK_EQUAL(total, 0);

    BOOST_CHECK(passetsdb->AddressDir(rows, total, true, "addr1", INT_MAX, 0));
    BOOST_CHECK_EQUAL(total, 2);
    BOOST_CHECK(passetsdb->AddressDir(rows, total, true, "addr3", INT_MAX, 0));
    BOOST_CHECK_EQUAL(total, 2);
    BOOST_CHECK(passetsdb->AddressDir(rows, total, true, "nobody", INT_MAX, 0));
    BOOST_CHECK_EQUAL(total, 0);
}

// "if negative it skips back from the end" (RPC help). Before the fix the
// cursor went back to the first key of the whole database and every call
// with a negative start returned nothing.
BOOST_AUTO_TEST_CASE(negative_start_skips_back_from_the_end)
{
    Hold("AA", {"addr1"});
    Hold("AAA", {"addr1", "addr2", "addr3"});
    Hold("AAB", {"addr2"});
    for (const std::string& name : {"AA", "AAA", "AAB"}) {
        BOOST_REQUIRE(passetsdb->WriteAssetData(CNewAsset(name, 1000 * COIN, 0, 1, 0, ""),
                                                chainActive.Height(), chainActive.Tip()->GetBlockHash()));
    }

    // Holders of an asset, ordered by address
    BOOST_CHECK(HoldersOf("AAA", 10, 0) == Names({"addr1", "addr2", "addr3"}));
    BOOST_CHECK(HoldersOf("AAA", 10, -2) == Names({"addr2", "addr3"}));
    BOOST_CHECK(HoldersOf("AAA", 1, -2) == Names({"addr2"}));
    BOOST_CHECK(HoldersOf("AAA", 10, -10) == Names({"addr1", "addr2", "addr3"}));
    BOOST_CHECK(HoldersOf("MISSING", 10, -1).empty());

    // Assets of an address, ordered by asset key
    BOOST_CHECK(AssetsOf("addr2", 10, 0) == Names({"AAA", "AAB"}));
    BOOST_CHECK(AssetsOf("addr2", 10, -1) == Names({"AAB"}));
    BOOST_CHECK(AssetsOf("addr1", 10, -5) == Names({"AA", "AAA"}));

    // Asset metadata (the fixture's &DEVICE sorts after these: longer name)
    BOOST_CHECK(AssetNames("*", 10, 0) == Names({"AA", "AAA", "AAB", DEVICE}));
    BOOST_CHECK(AssetNames("*", 10, -2) == Names({"AAB", DEVICE}));
    BOOST_CHECK(AssetNames("AAA*", 10, -1) == Names({"AAA"}));
    BOOST_CHECK(AssetNames("AA", 10, -1) == Names({"AA"}));
}

BOOST_AUTO_TEST_SUITE_END()
