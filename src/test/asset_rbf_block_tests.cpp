// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for NIP-025: Non-replaceable sequence requirement for transactions
// spending asset-wrapped AuthScript v1 UTXOs.

#include "chainparams.h"
#include "coins.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "test/test_neurai.h"
#include "assets/assettypes.h"

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

// Temporarily override the current chain params so the regtest branch
// (nASSETRBFBlockEnabled = true) is active during the test.
struct RegtestParamsScope {
    RegtestParamsScope() { SelectParams(CBaseChainParams::REGTEST); }
    ~RegtestParamsScope() { SelectParams(CBaseChainParams::MAIN); }
};

// Override to mainnet (flag off) for the one "flag off" test.
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

BOOST_AUTO_TEST_CASE(AssetAuthScript_Input_RBF_Rejected)
{
    RegtestParamsScope scope;
    CCoinsView base;
    CCoinsViewCache coins(&base);

    CTxOut assetOut;
    assetOut.nValue = 0; // asset UTXOs typically have zero XNA
    assetOut.scriptPubKey = MakeAssetAuthScriptSpk("CAT", 10 * COIN, 0x11);
    CTxOut xnaOut;
    xnaOut.nValue = 100000;
    xnaOut.scriptPubKey = MakeP2PKHSpk(0x22);
    uint256 srcHash = AddDummyCoins(coins, { assetOut, xnaOut });

    auto mtx = MakeSpendingTx({ { srcHash, 0, 0xfffffffdU } }); // RBF on the only input
    auto r = RunCheck(mtx, coins);
    BOOST_CHECK(!r.ok);
    BOOST_CHECK_EQUAL(r.reject, "bad-txns-asset-authscript-input-rbf");
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
    BOOST_CHECK(r.ok); // rule does NOT trigger for P2PKH+asset
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

// The v1-blocker regression test: the NIP-v1 rule would accept this because
// only the XNA input signals RBF; the asset-AuthScript input itself is
// non-RBF. But BIP125 treats the whole tx as replaceable, so v2's tx-level
// rule must reject it.
BOOST_AUTO_TEST_CASE(OneAssetAuthScriptPlusOneXnaRBF_Rejected)
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
    BOOST_CHECK(!r.ok);
    BOOST_CHECK_EQUAL(r.reject, "bad-txns-asset-authscript-input-rbf");
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

BOOST_AUTO_TEST_CASE(TwoAssetAuthScript_MixedSequences_Rejected)
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
        { srcHash, 1, 0xfffffffdU }, // offender
    });
    auto r = RunCheck(mtx, coins);
    BOOST_CHECK(!r.ok);
    BOOST_CHECK_EQUAL(r.reject, "bad-txns-asset-authscript-input-rbf");
}

// ─── Flag off (mainnet default) ──────────────────────────────────────────

BOOST_AUTO_TEST_CASE(FlagOff_AnyShape_Accepted)
{
    MainnetParamsScope scope; // nASSETRBFBlockEnabled = false on mainnet
    CCoinsView base;
    CCoinsViewCache coins(&base);

    CTxOut out;
    out.nValue = 10000;
    out.scriptPubKey = MakeAssetAuthScriptSpk("CAT", 10 * COIN, 0x11);
    uint256 srcHash = AddDummyCoins(coins, { out });

    auto mtx = MakeSpendingTx({ { srcHash, 0, 0xfffffffdU } }); // RBF
    auto r = RunCheck(mtx, coins);
    BOOST_CHECK(r.ok); // flag off → rule is a no-op
}

BOOST_AUTO_TEST_SUITE_END()
