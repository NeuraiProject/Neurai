// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NIP025-patch1: asset protection is policy, not a sequence restriction.
// CheckTxInputs does not replace BIP68/CSV or full asset validation.

#include "chainparams.h"
#include "coins.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "test/test_neurai.h"
#include "assets/assettypes.h"
#include "policy/rbf.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(asset_rbf_block_tests, BasicTestingSetup)

namespace {

// Build an asset-wrapped AuthScript v1 scriptPubKey using the asset layer's
// own builders, mirroring how asset_tx_tests.cpp crafts PQ asset UTXOs.
CScript MakeAssetAuthScriptSpk(const std::string& assetName, CAmount amount,
                               uint8_t commitmentFill)
{
    uint256 commitment = uint256S(std::string(64, '0'));
    // Deterministic but distinguishable commitments per test.
    std::vector<unsigned char> bytes(32, commitmentFill);
    std::copy(bytes.begin(), bytes.end(), commitment.begin());
    CTxDestination dest = WitnessV1AuthScript(commitment);
    CScript spk = GetScriptForDestination(dest);
    CAssetTransfer transfer(assetName, amount);
    transfer.ConstructTransaction(spk, AssetMarker::LEGACY_RVN);
    return spk;
}

// Build an asset-wrapped P2PKH scriptPubKey — same asset wrapper but legacy
// destination. Should NOT trigger NIP-025.
CScript MakeAssetP2PKHSpk(const std::string& assetName, CAmount amount,
                          uint8_t pkhFill)
{
    std::vector<unsigned char> pkh(20, pkhFill);
    CTxDestination dest = CKeyID(uint160(pkh));
    CScript spk = GetScriptForDestination(dest);
    CAssetTransfer transfer(assetName, amount);
    transfer.ConstructTransaction(spk, AssetMarker::LEGACY_RVN);
    return spk;
}

// Build a bare AuthScript v1 scriptPubKey (witness v1, no asset wrapper).
CScript MakeBareAuthScriptSpk(uint8_t commitmentFill)
{
    std::vector<unsigned char> commitment(32, commitmentFill);
    CScript spk;
    spk << OP_1 << commitment;
    return spk;
}

// Build a plain P2PKH scriptPubKey.
CScript MakeP2PKHSpk(uint8_t pkhFill)
{
    std::vector<unsigned char> pkh(20, pkhFill);
    CScript spk;
    spk << OP_DUP << OP_HASH160 << pkh << OP_EQUALVERIFY << OP_CHECKSIG;
    return spk;
}

// Create a dummy source tx with the given outputs, register it in the coin
// cache, and return its txid.
uint256 AddDummyCoins(CCoinsViewCache& coins, const std::vector<CTxOut>& outs)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    CTxIn in;
    in.prevout.hash = uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    in.prevout.n = 0;
    mtx.vin.push_back(in);
    for (const auto& o : outs) mtx.vout.push_back(o);
    CTransaction tx(mtx);
    AddCoins(coins, tx, /*height=*/100, uint256());
    return tx.GetHash();
}

// Build a spending tx with custom per-input sequences. Each entry of
// `ins` is (prevout_hash, vout_index, sequence).
CMutableTransaction MakeSpendingTx(
    const std::vector<std::tuple<uint256, uint32_t, uint32_t>>& ins)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    for (const auto& [h, n, seq] : ins) {
        CTxIn in;
        in.prevout.hash = h;
        in.prevout.n = n;
        in.nSequence = seq;
        mtx.vin.push_back(in);
    }
    // One trivial output so the tx isn't malformed; value doesn't matter here —
    // CheckTxInputs' "value in >= value out" check is satisfied because our
    // dummy prevouts carry positive nValue and our output asks for 1 sat.
    CTxOut out;
    out.nValue = 1;
    out.scriptPubKey = MakeP2PKHSpk(0xff);
    mtx.vout.push_back(out);
    return mtx;
}

// Run Consensus::CheckTxInputs against a coin cache and return (ok, reject).
struct CheckResult {
    bool ok;
    std::string reject;
};
CheckResult RunCheck(const CMutableTransaction& mtx, const CCoinsViewCache& coins,
                     int spendHeight = 200)
{
    CTransaction tx(mtx);
    CValidationState state;
    CAmount txfee = 0;
    bool ok = Consensus::CheckTxInputs(tx, state, coins, spendHeight, txfee);
    return { ok, state.GetRejectReason() };
}

// Temporarily select regtest.
struct RegtestParamsScope {
    RegtestParamsScope() { SelectParams(CBaseChainParams::REGTEST); }
    ~RegtestParamsScope() { SelectParams(CBaseChainParams::MAIN); }
};

// Also cover mainnet consensus.
struct MainnetParamsScope {
    MainnetParamsScope() { SelectParams(CBaseChainParams::MAIN); }
    ~MainnetParamsScope() { SelectParams(CBaseChainParams::MAIN); }
};

} // namespace

// ─── Predicate-level tests ───────────────────────────────────────────────

BOOST_AUTO_TEST_CASE(IsAssetAuthScript_matches_pq_asset_transfer)
{
    CScript spk = MakeAssetAuthScriptSpk("CAT", 100 * COIN, 0x11);
    BOOST_CHECK(spk.IsAssetAuthScript());
}

BOOST_AUTO_TEST_CASE(IsAssetAuthScript_rejects_p2pkh_asset_transfer)
{
    CScript spk = MakeAssetP2PKHSpk("CAT", 100 * COIN, 0x22);
    BOOST_CHECK(spk.IsAssetScript());      // has asset wrapper
    BOOST_CHECK(!spk.IsAssetAuthScript()); // but P2PKH prefix, not AuthScript
}

BOOST_AUTO_TEST_CASE(IsAssetAuthScript_rejects_bare_authscript)
{
    CScript spk = MakeBareAuthScriptSpk(0x33);
    BOOST_CHECK(!spk.IsAssetScript());     // no asset wrapper
    BOOST_CHECK(!spk.IsAssetAuthScript()); // no asset wrapper
}

BOOST_AUTO_TEST_CASE(IsAssetAuthScript_rejects_plain_p2pkh)
{
    CScript spk = MakeP2PKHSpk(0x44);
    BOOST_CHECK(!spk.IsAssetAuthScript());
}

// ─── Consensus-rule tests (flag ON, regtest) ─────────────────────────────

BOOST_AUTO_TEST_CASE(AssetAuthScript_Input_RBF_ConsensusAccepted)
{
    RegtestParamsScope scope;
    CCoinsView base;
    CCoinsViewCache coins(&base);

    CTxOut assetOut;
    assetOut.nValue = 10000; // enough XNA for the synthetic output
    assetOut.scriptPubKey = MakeAssetAuthScriptSpk("CAT", 10 * COIN, 0x11);
    CTxOut xnaOut;
    xnaOut.nValue = 100000;
    xnaOut.scriptPubKey = MakeP2PKHSpk(0x22);
    uint256 srcHash = AddDummyCoins(coins, { assetOut, xnaOut });

    auto mtx = MakeSpendingTx({ { srcHash, 0, 0xfffffffdU } }); // RBF on the only input
    auto r = RunCheck(mtx, coins);
    BOOST_CHECK(r.ok); // Sequence policy no longer restricts consensus.
}

BOOST_AUTO_TEST_CASE(AssetAuthScript_Input_NonRBF_Accepted)
{
    RegtestParamsScope scope;
    CCoinsView base;
    CCoinsViewCache coins(&base);

    CTxOut assetOut;
    assetOut.nValue = 10000; // enough XNA to cover the output
    assetOut.scriptPubKey = MakeAssetAuthScriptSpk("CAT", 10 * COIN, 0x11);
    uint256 srcHash = AddDummyCoins(coins, { assetOut });

    auto mtx = MakeSpendingTx({ { srcHash, 0, 0xfffffffeU } });
    auto r = RunCheck(mtx, coins);
    BOOST_CHECK(r.ok);
}

BOOST_AUTO_TEST_CASE(AssetAuthScript_Input_Final_Accepted)
{
    RegtestParamsScope scope;
    CCoinsView base;
    CCoinsViewCache coins(&base);

    CTxOut assetOut;
    assetOut.nValue = 10000;
    assetOut.scriptPubKey = MakeAssetAuthScriptSpk("CAT", 10 * COIN, 0x11);
    uint256 srcHash = AddDummyCoins(coins, { assetOut });

    auto mtx = MakeSpendingTx({ { srcHash, 0, 0xffffffffU } }); // final
    auto r = RunCheck(mtx, coins);
    BOOST_CHECK(r.ok);
}

BOOST_AUTO_TEST_CASE(P2PKHAssetTransfer_RBF_Accepted)
{
    RegtestParamsScope scope;
    CCoinsView base;
    CCoinsViewCache coins(&base);

    CTxOut out;
    out.nValue = 10000;
    out.scriptPubKey = MakeAssetP2PKHSpk("CAT", 10 * COIN, 0x22);
    uint256 srcHash = AddDummyCoins(coins, { out });

    auto mtx = MakeSpendingTx({ { srcHash, 0, 0xfffffffdU } });
    auto r = RunCheck(mtx, coins);
    BOOST_CHECK(r.ok); // consensus accepts; policy separately protects this asset
}

BOOST_AUTO_TEST_CASE(BareAuthScript_RBF_Accepted)
{
    RegtestParamsScope scope;
    CCoinsView base;
    CCoinsViewCache coins(&base);

    CTxOut out;
    out.nValue = 10000;
    out.scriptPubKey = MakeBareAuthScriptSpk(0x33);
    uint256 srcHash = AddDummyCoins(coins, { out });

    auto mtx = MakeSpendingTx({ { srcHash, 0, 0xfffffffdU } });
    auto r = RunCheck(mtx, coins);
    BOOST_CHECK(r.ok); // no asset wrapper → rule doesn't trigger
}

BOOST_AUTO_TEST_CASE(PlainP2PKH_RBF_Accepted)
{
    RegtestParamsScope scope;
    CCoinsView base;
    CCoinsViewCache coins(&base);

    CTxOut out;
    out.nValue = 10000;
    out.scriptPubKey = MakeP2PKHSpk(0x44);
    uint256 srcHash = AddDummyCoins(coins, { out });

    auto mtx = MakeSpendingTx({ { srcHash, 0, 0xfffffffdU } });
    auto r = RunCheck(mtx, coins);
    BOOST_CHECK(r.ok); // baseline — ordinary tx keeps BIP125 RBF
}

// The old rejection is now exercised by replacement policy instead.
BOOST_AUTO_TEST_CASE(OneAssetAuthScriptPlusOneXnaRBF_ConsensusAccepted)
{
    RegtestParamsScope scope;
    CCoinsView base;
    CCoinsViewCache coins(&base);

    CTxOut assetOut;
    assetOut.nValue = 0;
    assetOut.scriptPubKey = MakeAssetAuthScriptSpk("CAT", 10 * COIN, 0x11);
    CTxOut xnaOut;
    xnaOut.nValue = 200000;
    xnaOut.scriptPubKey = MakeP2PKHSpk(0x55);
    uint256 srcHash = AddDummyCoins(coins, { assetOut, xnaOut });

    auto mtx = MakeSpendingTx({
        { srcHash, 0, 0xfffffffeU }, // covenant/asset input: non-RBF
        { srcHash, 1, 0xfffffffdU }, // XNA input: RBF ← triggers rule
    });
    auto r = RunCheck(mtx, coins);
    BOOST_CHECK(r.ok); // Sequence policy no longer restricts consensus.
}

BOOST_AUTO_TEST_CASE(OnlyXnaRBF_Accepted)
{
    RegtestParamsScope scope;
    CCoinsView base;
    CCoinsViewCache coins(&base);

    CTxOut xnaOut;
    xnaOut.nValue = 200000;
    xnaOut.scriptPubKey = MakeP2PKHSpk(0x66);
    uint256 srcHash = AddDummyCoins(coins, { xnaOut });

    auto mtx = MakeSpendingTx({ { srcHash, 0, 0xfffffffdU } });
    auto r = RunCheck(mtx, coins);
    BOOST_CHECK(r.ok); // no asset-AuthScript input means the rule doesn't fire
}

BOOST_AUTO_TEST_CASE(TwoAssetAuthScript_MixedSequences_ConsensusAccepted)
{
    RegtestParamsScope scope;
    CCoinsView base;
    CCoinsViewCache coins(&base);

    CTxOut a;
    a.nValue = 10000;
    a.scriptPubKey = MakeAssetAuthScriptSpk("CAT", 5 * COIN, 0x11);
    CTxOut b;
    b.nValue = 10000;
    b.scriptPubKey = MakeAssetAuthScriptSpk("CAT", 5 * COIN, 0x12);
    uint256 srcHash = AddDummyCoins(coins, { a, b });

    auto mtx = MakeSpendingTx({
        { srcHash, 0, 0xfffffffeU }, // OK
        { srcHash, 1, 0xfffffffdU }, // RBF
    });
    auto r = RunCheck(mtx, coins);
    BOOST_CHECK(r.ok); // Sequence policy no longer restricts consensus.
}

// ─── Flag off (mainnet default) ──────────────────────────────────────────

BOOST_AUTO_TEST_CASE(Mainnet_AnySequence_ConsensusAccepted)
{
    MainnetParamsScope scope; // same sequence semantics on mainnet
    CCoinsView base;
    CCoinsViewCache coins(&base);

    CTxOut out;
    out.nValue = 10000;
    out.scriptPubKey = MakeAssetAuthScriptSpk("CAT", 10 * COIN, 0x11);
    uint256 srcHash = AddDummyCoins(coins, { out });

    auto mtx = MakeSpendingTx({ { srcHash, 0, 0xfffffffdU } }); // RBF
    auto r = RunCheck(mtx, coins);
    BOOST_CHECK(r.ok); // no consensus sequence restriction
}

// Classification uses real asset builders, but does not claim that these
// synthetic transactions satisfy asset balance/authorization consensus.
BOOST_AUTO_TEST_CASE(policy_all_asset_forms_and_context)
{
    RegtestParamsScope scope;
    CStrictAuthScriptContext active(true);
    CCoinsView base; CCoinsViewCache coins(&base);
    const auto source=AddDummyCoins(coins,{CTxOut(100000,MakeP2PKHSpk(4))});
    CMutableTransaction plain=MakeSpendingTx({{source,0,1440}});
    BOOST_CHECK(!InvolvesAssets(CTransaction(plain),coins));
    BOOST_CHECK(SignalsOptInRBF(CTransaction(plain))); // meaning of BIP125 unchanged
    for (auto marker : {AssetMarker::LEGACY_RVN,AssetMarker::NEURAI_XNA}) {
        for (int family : {0,1,2,3}) {
            const CScript prefix=family ? CScript()<<CScript::EncodeOP_N(family)<<std::vector<unsigned char>(32,5) : MakeP2PKHSpk(5);
            for (const std::string name : {"CAT","CAT#UNIQUE","CAT!","#QUALIFIER","$RESTRICTED"}) {
                CScript transfer=prefix; CAssetTransfer(name,COIN).ConstructTransaction(transfer,marker);
                auto tx=plain; tx.vout[0].scriptPubKey=transfer;
                BOOST_CHECK(InvolvesAssets(CTransaction(tx),coins));
                CCoinsView inputBase; CCoinsViewCache inputCoins(&inputBase);
                auto input=AddDummyCoins(inputCoins,{CTxOut(10000,transfer)});
                auto spend=MakeSpendingTx({{input,0,1440}});
                BOOST_CHECK(InvolvesAssets(CTransaction(spend),inputCoins));
            }
            CNewAsset asset("NEW",COIN,0,1,0,"");
            CScript issue=prefix; asset.ConstructTransaction(issue,marker);
            CScript owner=prefix; asset.ConstructOwnerTransaction(owner,marker);
            CScript reissue=prefix; CReissueAsset("NEW",COIN,-1,0,"").ConstructTransaction(reissue,marker);
            for(const auto& output:{issue,owner,reissue}) {
                auto tx=plain; tx.vout[0].scriptPubKey=output;
                BOOST_CHECK(InvolvesAssets(CTransaction(tx),coins));
            }
            auto bare=plain; bare.vout[0].scriptPubKey=prefix;
            BOOST_CHECK(!InvolvesAssets(CTransaction(bare),coins));
        }
    }
    CScript tag=CScript()<<OP_XNA_ASSET<<std::vector<unsigned char>(20,5); CNullAssetTxData("#TAG",1).ConstructTransaction(tag);
    CScript global; CNullAssetTxData("$CAT",1).ConstructGlobalRestrictionTransaction(global);
    CScript verifier; CNullAssetTxVerifierString("true").ConstructTransaction(verifier);
    for(const auto& script:{tag,global,verifier}) {
        auto tx=plain; tx.vout[0].scriptPubKey=script;
        BOOST_CHECK(InvolvesAssets(CTransaction(tx),coins));
    }
    auto data=plain; data.vout[0].scriptPubKey=CScript()<<OP_RETURN<<std::vector<unsigned char>{0xc0,'x','n','a','t'};
    BOOST_CHECK(!InvolvesAssets(CTransaction(data),coins));
    data.nVersion=3; data.vrefin.emplace_back(uint256S("1234"),0);
    BOOST_CHECK(!InvolvesAssets(CTransaction(data),coins));
    auto missing=plain; missing.vin[0].prevout.n=9;
    BOOST_CHECK(InvolvesAssets(CTransaction(missing),coins)); // cannot bypass on missing coins
    CScript strict=CScript()<<OP_2<<std::vector<unsigned char>(32,5);
    CAssetTransfer("CAT",COIN).ConstructTransaction(strict,AssetMarker::NEURAI_XNA);
    auto tx=plain; tx.vout[0].scriptPubKey=strict;
    { CStrictAuthScriptContext inactive(false); BOOST_CHECK(!InvolvesAssets(CTransaction(tx),coins)); }
    BOOST_CHECK(InvolvesAssets(CTransaction(tx),coins)); // no stale metadata
}

BOOST_AUTO_TEST_CASE(sequence_restriction_removed_on_mainnet_and_regtest)
{
    for (const auto& network : {CBaseChainParams::MAIN,CBaseChainParams::REGTEST}) {
        SelectParams(network);
        CCoinsView base; CCoinsViewCache coins(&base);
        auto source=AddDummyCoins(coins,{CTxOut(10000,MakeAssetAuthScriptSpk("CAT",COIN,3))});
        for(uint32_t seq : {0U,1440U,0x004005a0U,0xfffffffdU,0xfffffffeU,0xffffffffU}) {
            BOOST_CHECK(RunCheck(MakeSpendingTx({{source,0,seq}}),coins).ok);
        }
    }
    SelectParams(CBaseChainParams::MAIN);
}

BOOST_AUTO_TEST_CASE(policy_eviction_graph_live_coins)
{
    RegtestParamsScope scope;
    CCoinsView base; CCoinsViewCache chain(&base);
    const auto source=AddDummyCoins(chain,{CTxOut(100000,MakeP2PKHSpk(1))});
    CTxMemPool pool; TestMemPoolEntryHelper entry;
    auto parent=MakeSpendingTx({{source,0,0xfffffffdU}});
    parent.vout[0].nValue=90000;
    const CTransaction parentTx(parent);
    pool.addUnchecked(parentTx.GetHash(),entry.FromTx(parentTx));
    auto child=MakeSpendingTx({{parentTx.GetHash(),0,0xfffffffdU}});
    child.vout[0].nValue=80000;
    const CTransaction childTx(child);
    pool.addUnchecked(childTx.GetHash(),entry.FromTx(childTx));
    auto grandchild=MakeSpendingTx({{childTx.GetHash(),0,0xfffffffdU}});
    grandchild.vout[0].scriptPubKey=MakeAssetP2PKHSpk("CAT",COIN,3);
    const CTransaction grandTx(grandchild);
    pool.addUnchecked(grandTx.GetHash(),entry.FromTx(grandTx));
    CCoinsViewMemPool overlay(&chain,pool); CCoinsViewCache view(&overlay);
    auto candidate=parent; candidate.vout[0].nValue=50000;
    CTxMemPool::setEntries all,direct;
    LOCK(pool.cs);
    auto it=pool.mapTx.find(parentTx.GetHash());direct.insert(it);
    pool.CalculateDescendants(it,all);
    BOOST_REQUIRE_EQUAL(all.size(),3);
    BOOST_CHECK(!ReplacementInvolvesAssets(CTransaction(candidate),direct,view));
    BOOST_CHECK(ReplacementInvolvesAssets(CTransaction(candidate),all,view));
    candidate.vout[0].scriptPubKey=MakeAssetAuthScriptSpk("CAT",COIN,4);
    BOOST_CHECK(ReplacementInvolvesAssets(CTransaction(candidate),direct,view));
    BOOST_CHECK_EQUAL(pool.size(),3); // decisions do not remove anything
    pool.removeRecursive(grandTx,MemPoolRemovalReason::EXPIRY);
    CCoinsViewCache fresh(&overlay);all.clear();pool.CalculateDescendants(it,all);
    candidate.vout[0].scriptPubKey=MakeP2PKHSpk(1);
    BOOST_CHECK(!ReplacementInvolvesAssets(CTransaction(candidate),all,fresh));
}

BOOST_AUTO_TEST_SUITE_END()
