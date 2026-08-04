// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NIP-040: migration of the asset payload marker from "rvn" to "xna".
// Covers the dual parser (P2PKH and AuthScript wrappers, both markers, the
// doubled-OP_XNA_ASSET offset and its nesting fidelity), the activation
// helpers, the four constructors, and the CheckTxAssets height frontier.
// Parser tests run under mainnet AND testnet params: the dual parser itself
// is network-independent, but the fallback placement rule for unrecognized
// OP_XNA_ASSET scripts differs per network (nXNAAssetStrictEnabled).

#include "amount.h"
#include "assets/assets.h"
#include "base58.h"
#include "chainparams.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/standard.h"
#include "test/test_neurai.h"
#include "utilstrencodings.h"

#include <limits>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

CScript ScriptFromHex(const std::string& hex)
{
    std::vector<unsigned char> data = ParseHex(hex);
    return CScript(data.begin(), data.end());
}

CScript P2pkhPrefix()
{
    return CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x11)
                     << OP_EQUALVERIFY << OP_CHECKSIG;
}

CScript AuthScriptPrefix()
{
    return CScript() << OP_1 << std::vector<unsigned char>(32, 0xab);
}

struct ParsedAsset {
    bool fIsAsset = false;
    int nType = 0;
    bool fIsOwner = false;
    int nStartingIndex = 0;
    AssetMarker marker = AssetMarker::LEGACY_RVN;
};

// Regtest ships with the INT_MAX sentinel (fork not scheduled) so existing
// functional tests keep emitting legacy markers; these tests inject a finite
// height and restore the sentinel on scope exit. Select the network BEFORE
// creating the guard — it mutates the currently selected params.
class Nip040HeightGuard
{
public:
    explicit Nip040HeightGuard(int nHeight)
        : nPrevious(GetParams().GetConsensus().nAssetMarkerNip040Height)
    {
        UpdateAssetMarkerNip040Height(nHeight);
    }
    ~Nip040HeightGuard() { UpdateAssetMarkerNip040Height(nPrevious); }

private:
    int nPrevious;
};

ParsedAsset Parse(const CScript& spk)
{
    ParsedAsset r;
    r.fIsAsset = spk.IsAssetScript(r.nType, r.fIsOwner, r.nStartingIndex, r.marker);
    return r;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(asset_marker_nip040_tests, BasicTestingSetup)

// --- Activation helpers -----------------------------------------------------

BOOST_AUTO_TEST_CASE(activation_helper_boundary)
{
    SelectParams(CBaseChainParams::REGTEST);

    // Default is the INT_MAX sentinel: fork not scheduled, explicitly
    // inactive even for a candidate height of INT_MAX itself.
    {
        const Consensus::Params& regtest = GetParams().GetConsensus();
        BOOST_REQUIRE_EQUAL(regtest.nAssetMarkerNip040Height, std::numeric_limits<int>::max());
        BOOST_CHECK(!IsAssetMarkerNip040Active(std::numeric_limits<int>::max(), regtest));
        BOOST_CHECK(MarkerForNewAssetOutput(std::numeric_limits<int>::max(), regtest) == AssetMarker::LEGACY_RVN);
    }

    // Injected height: exact boundary.
    {
        Nip040HeightGuard guard(200);
        const Consensus::Params& regtest = GetParams().GetConsensus();
        const int H = 200;

        BOOST_CHECK(!IsAssetMarkerNip040Active(H - 1, regtest));
        BOOST_CHECK(IsAssetMarkerNip040Active(H, regtest));
        BOOST_CHECK(IsAssetMarkerNip040Active(H + 1, regtest));

        BOOST_CHECK(MarkerForNewAssetOutput(H - 1, regtest) == AssetMarker::LEGACY_RVN);
        BOOST_CHECK(MarkerForNewAssetOutput(H, regtest) == AssetMarker::NEURAI_XNA);
        BOOST_CHECK(MarkerForNewAssetOutput(H + 1, regtest) == AssetMarker::NEURAI_XNA);
    }

    // The guard restored the sentinel.
    BOOST_CHECK_EQUAL(GetParams().GetConsensus().nAssetMarkerNip040Height, std::numeric_limits<int>::max());

    // Mainnet has not scheduled the fork: never active, whatever the height.
    SelectParams(CBaseChainParams::MAIN);
    const Consensus::Params& mainnet = GetParams().GetConsensus();
    BOOST_CHECK(!IsAssetMarkerNip040Active(10000000, mainnet));
    BOOST_CHECK(MarkerForNewAssetOutput(10000000, mainnet) == AssetMarker::LEGACY_RVN);
}

// --- Constructors and dual parser, both wrappers, both networks -------------

BOOST_AUTO_TEST_CASE(p2pkh_all_operations_both_markers_both_networks)
{
    const std::vector<std::string> networks = {
        CBaseChainParams::MAIN, CBaseChainParams::TESTNET};
    const std::vector<AssetMarker> markers = {
        AssetMarker::LEGACY_RVN, AssetMarker::NEURAI_XNA};

    for (const auto& network : networks) {
        SelectParams(network);
        for (const auto marker : markers) {
            // q: new asset
            {
                CScript spk = P2pkhPrefix();
                CNewAsset asset("GOLD", 1000 * COIN, 0, 1, 0, "");
                asset.ConstructTransaction(spk, marker);
                ParsedAsset p = Parse(spk);
                BOOST_REQUIRE(p.fIsAsset);
                BOOST_CHECK_EQUAL(p.nType, (int)TX_NEW_ASSET);
                BOOST_CHECK(!p.fIsOwner);
                BOOST_CHECK(p.marker == marker);
                CNewAsset out;
                std::string address;
                BOOST_REQUIRE(AssetFromScript(spk, out, address));
                BOOST_CHECK_EQUAL(out.strName, "GOLD");
                BOOST_CHECK_EQUAL(out.nAmount, 1000 * COIN);
            }
            // o: owner token
            {
                CScript spk = P2pkhPrefix();
                CNewAsset asset("GOLD", 1000 * COIN, 0, 1, 0, "");
                asset.ConstructOwnerTransaction(spk, marker);
                ParsedAsset p = Parse(spk);
                BOOST_REQUIRE(p.fIsAsset);
                BOOST_CHECK_EQUAL(p.nType, (int)TX_NEW_ASSET);
                BOOST_CHECK(p.fIsOwner);
                BOOST_CHECK(p.marker == marker);
                std::string name, address;
                BOOST_REQUIRE(OwnerAssetFromScript(spk, name, address));
                BOOST_CHECK_EQUAL(name, "GOLD!");
            }
            // t: transfer
            {
                CScript spk = P2pkhPrefix();
                CAssetTransfer transfer("GOLD", 25 * COIN);
                transfer.ConstructTransaction(spk, marker);
                ParsedAsset p = Parse(spk);
                BOOST_REQUIRE(p.fIsAsset);
                BOOST_CHECK_EQUAL(p.nType, (int)TX_TRANSFER_ASSET);
                BOOST_CHECK(p.marker == marker);
                // Single c0, direct push: prefix at 27, op byte at 30, data at 31.
                BOOST_CHECK_EQUAL(p.nStartingIndex, 31);
                CAssetTransfer out;
                std::string address;
                BOOST_REQUIRE(TransferAssetFromScript(spk, out, address));
                BOOST_CHECK_EQUAL(out.strName, "GOLD");
                BOOST_CHECK_EQUAL(out.nAmount, 25 * COIN);
            }
            // r: reissue
            {
                CScript spk = P2pkhPrefix();
                CReissueAsset reissue("GOLD", 500 * COIN, 0, 1, "");
                reissue.ConstructTransaction(spk, marker);
                ParsedAsset p = Parse(spk);
                BOOST_REQUIRE(p.fIsAsset);
                BOOST_CHECK_EQUAL(p.nType, (int)TX_REISSUE_ASSET);
                BOOST_CHECK(p.marker == marker);
                CReissueAsset out;
                std::string address;
                BOOST_REQUIRE(ReissueAssetFromScript(spk, out, address));
                BOOST_CHECK_EQUAL(out.strName, "GOLD");
                BOOST_CHECK_EQUAL(out.nAmount, 500 * COIN);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(authscript_both_markers)
{
    SelectParams(CBaseChainParams::MAIN);
    for (const auto marker : {AssetMarker::LEGACY_RVN, AssetMarker::NEURAI_XNA}) {
        CScript spk = AuthScriptPrefix();
        CAssetTransfer transfer("GOLD", 25 * COIN);
        transfer.ConstructTransaction(spk, marker);

        ParsedAsset p = Parse(spk);
        BOOST_REQUIRE(p.fIsAsset);
        BOOST_CHECK_EQUAL(p.nType, (int)TX_TRANSFER_ASSET);
        BOOST_CHECK(p.marker == marker);
        BOOST_CHECK(spk.IsAssetAuthScript());

        CAssetTransfer out;
        std::string address;
        BOOST_REQUIRE(TransferAssetFromScript(spk, out, address));
        BOOST_CHECK_EQUAL(out.strName, "GOLD");
        BOOST_CHECK_EQUAL(out.nAmount, 25 * COIN);
    }
}

// The marker bytes actually written on-chain: "rvn" vs "xna" at byte 27.
BOOST_AUTO_TEST_CASE(constructed_bytes_are_the_selected_marker)
{
    CScript legacy = P2pkhPrefix();
    CScript neurai = P2pkhPrefix();
    CAssetTransfer transfer("GOLD", 25 * COIN);
    transfer.ConstructTransaction(legacy, AssetMarker::LEGACY_RVN);
    transfer.ConstructTransaction(neurai, AssetMarker::NEURAI_XNA);

    BOOST_CHECK_EQUAL(legacy[27], 'r');
    BOOST_CHECK_EQUAL(legacy[28], 'v');
    BOOST_CHECK_EQUAL(legacy[29], 'n');
    BOOST_CHECK_EQUAL(neurai[27], 'x');
    BOOST_CHECK_EQUAL(neurai[28], 'n');
    BOOST_CHECK_EQUAL(neurai[29], 'a');
    // Everything but the marker prefix is identical.
    BOOST_CHECK_EQUAL(legacy.size(), neurai.size());
}

// --- Doubled-c0 offset and nesting fidelity ---------------------------------

// The xna twin of the mainnet RCNF regression vector: doubled OP_XNA_ASSET,
// prefix at byte 28, "xnat" instead of "rvnt".
BOOST_AUTO_TEST_CASE(doubled_op_xna_asset_xna_marker_recognized)
{
    const CScript spk = ScriptFromHex(
        "76a914cea85af9eb3b5db01239cf97ef1cc1786469be1988ac"
        "c0c011786e61740452434e460065cd1d0000000075");

    ParsedAsset p = Parse(spk);
    BOOST_REQUIRE(p.fIsAsset);
    BOOST_CHECK_EQUAL(p.nType, (int)TX_TRANSFER_ASSET);
    BOOST_CHECK(!p.fIsOwner);
    BOOST_CHECK(p.marker == AssetMarker::NEURAI_XNA);
    // "xna" at byte 28 -> type marker at 31 -> serialized data starts at 32
    BOOST_CHECK_EQUAL(p.nStartingIndex, 32);

    CAssetTransfer transfer;
    std::string strAddress;
    BOOST_REQUIRE(TransferAssetFromScript(spk, transfer, strAddress));
    BOOST_CHECK_EQUAL(transfer.strName, "RCNF");
    BOOST_CHECK_EQUAL(transfer.nAmount, 5 * COIN);
}

// Mirror of the origin/main nesting rule: byte 27 = 'x' enters the xna branch
// and must reject there when "na" does not follow — never retrying offset 28
// (bytes 28..30 spell a valid "xna" here, exactly like the "r r v n" vector).
BOOST_AUTO_TEST_CASE(xna_nesting_mirror_fidelity)
{
    const CScript spk = ScriptFromHex(
        "76a914cea85af9eb3b5db01239cf97ef1cc1786469be1988ac"
        "c0c078786e6174000000000000000075");

    int nType = 0;
    bool fIsOwner = false;
    int nStartingIndex = 0;
    BOOST_CHECK(!spk.IsAssetScript(nType, fIsOwner, nStartingIndex));
}

// The legacy "r r v n" rejection vector must stay rejected by the dual parser
// (the rvn branch fails and the bytes never form a valid xna prefix either).
BOOST_AUTO_TEST_CASE(legacy_nesting_vector_still_rejected)
{
    const CScript spk = ScriptFromHex(
        "76a914cea85af9eb3b5db01239cf97ef1cc1786469be1988ac"
        "c0c07272766e74000000000000000075");

    int nType = 0;
    bool fIsOwner = false;
    int nStartingIndex = 0;
    BOOST_CHECK(!spk.IsAssetScript(nType, fIsOwner, nStartingIndex));
}

// --- Malformed markers ------------------------------------------------------

BOOST_AUTO_TEST_CASE(malformed_markers_rejected)
{
    // Build a well-formed legacy transfer, then corrupt the marker bytes in
    // place so length/structure stay valid and only the marker is wrong.
    CScript base = P2pkhPrefix();
    CAssetTransfer transfer("GOLD", 25 * COIN);
    transfer.ConstructTransaction(base, AssetMarker::LEGACY_RVN);

    const std::vector<std::vector<unsigned char>> badPrefixes = {
        {'x', 'n', 'n'},  // xnn: half-migrated mix
        {'x', 'r', 'n'},  // xrn: mix
        {'r', 'n', 'a'},  // rna: mix
        {'X', 'N', 'A'},  // wrong case
    };
    for (const auto& prefix : badPrefixes) {
        CScript spk = base;
        spk[27] = prefix[0];
        spk[28] = prefix[1];
        spk[29] = prefix[2];
        int nType = 0;
        bool fIsOwner = false;
        int nStartingIndex = 0;
        BOOST_CHECK(!spk.IsAssetScript(nType, fIsOwner, nStartingIndex));
    }

    // Unknown fourth byte on a valid xna prefix ("xnav") must reject too.
    CScript spk = base;
    spk[27] = 'x';
    spk[28] = 'n';
    spk[29] = 'a';
    spk[30] = 'v';
    int nType = 0;
    bool fIsOwner = false;
    int nStartingIndex = 0;
    BOOST_CHECK(!spk.IsAssetScript(nType, fIsOwner, nStartingIndex));
}

// AuthScript wrapper: marker mixes rejected on the GetOp route as well.
BOOST_AUTO_TEST_CASE(malformed_markers_rejected_authscript)
{
    CScript base = AuthScriptPrefix();
    CAssetTransfer transfer("GOLD", 25 * COIN);
    transfer.ConstructTransaction(base, AssetMarker::NEURAI_XNA);

    // The pushed payload starts right after OP_XNA_ASSET (byte 34) and its
    // push-length byte: marker bytes live at 36..38.
    CScript spk = base;
    BOOST_REQUIRE(spk.size() > 39);
    BOOST_REQUIRE_EQUAL(spk[36], 'x');
    spk[37] = 'x'; // "xxa"
    int nType = 0;
    bool fIsOwner = false;
    int nStartingIndex = 0;
    BOOST_CHECK(!spk.IsAssetScript(nType, fIsOwner, nStartingIndex));
}

// --- Placement of unrecognized OP_XNA_ASSET scripts differs per network -----

BOOST_AUTO_TEST_CASE(unrecognized_scripts_placement_by_network)
{
    // A malformed marker ("xnn") makes the script unparseable, so it falls
    // through to the placement rule, whose verdict is network-dependent.
    CScript spk = P2pkhPrefix();
    CAssetTransfer transfer("GOLD", 25 * COIN);
    transfer.ConstructTransaction(spk, AssetMarker::NEURAI_XNA);
    spk[29] = 'n'; // "xnn"
    BOOST_REQUIRE(!spk.IsAssetScript());

    // Mainnet legacy rule: OP_XNA_ASSET anywhere but byte 0 is misplaced.
    BOOST_CHECK(CheckXnaAssetOutputPlacement(spk, /*strict=*/false) == XnaAssetPlacement::NotInRightLocation);
    // Testnet/regtest strict rule: well-placed but unparseable.
    BOOST_CHECK(CheckXnaAssetOutputPlacement(spk, /*strict=*/true) == XnaAssetPlacement::BadAssetScript);
}

// --- CheckTxAssets frontier -------------------------------------------------

namespace {

// One legacy transfer input coin plus one transfer output with the given
// marker; returns CheckTxAssets' verdict and reject reason at nHeight.
bool RunTransferAtHeight(AssetMarker outputMarker, int nHeight, std::string& rejectReason)
{
    // Input UTXO: legacy marker, created long before the fork.
    CScript inputScript = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));
    CAssetTransfer inputTransfer("NEURAITEST", 1000);
    inputTransfer.ConstructTransaction(inputScript, AssetMarker::LEGACY_RVN);

    CTxOut inputOut;
    inputOut.nValue = 0;
    inputOut.scriptPubKey = inputScript;

    CCoinsView view;
    CCoinsViewCache coins(&view);
    COutPoint outpoint(uint256S("BF50CB9A63BE0019171456252989A459A7D0A5F494735278290079D22AB704A2"), 1);
    coins.AddCoin(outpoint, Coin(inputOut, 10, 0), true);

    // Output: same asset and amount, marker under test.
    CScript outputScript = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));
    CAssetTransfer outputTransfer("NEURAITEST", 1000);
    outputTransfer.ConstructTransaction(outputScript, outputMarker);

    CMutableTransaction mutTx;
    CTxIn in;
    in.prevout = outpoint;
    mutTx.vin.emplace_back(in);
    mutTx.vout.emplace_back(CTxOut(0, outputScript));

    CTransaction tx(mutTx);
    CValidationState state;
    std::vector<std::pair<std::string, uint256>> vReissueAssets;
    const bool ok = Consensus::CheckTxAssets(tx, state, coins, nullptr, nHeight, false, vReissueAssets, true);
    rejectReason = state.GetRejectReason();
    return ok;
}

} // namespace

BOOST_AUTO_TEST_CASE(check_tx_assets_marker_frontier)
{
    std::string reason;

    {
        SelectParams(CBaseChainParams::REGTEST);
        Nip040HeightGuard guard(200);
        const int H = 200;

        // Below H: legacy accepted, xna rejected.
        BOOST_CHECK_MESSAGE(RunTransferAtHeight(AssetMarker::LEGACY_RVN, H - 1, reason), reason);
        BOOST_CHECK(!RunTransferAtHeight(AssetMarker::NEURAI_XNA, H - 1, reason));
        BOOST_CHECK_EQUAL(reason, "bad-txns-asset-marker-before-nip040");

        // At and after H: the rule inverts. The passing xna cases also prove
        // the migration path — the input coin always carries the legacy
        // marker and is spendable at any height.
        BOOST_CHECK_MESSAGE(RunTransferAtHeight(AssetMarker::NEURAI_XNA, H, reason), reason);
        BOOST_CHECK(!RunTransferAtHeight(AssetMarker::LEGACY_RVN, H, reason));
        BOOST_CHECK_EQUAL(reason, "bad-txns-legacy-asset-marker-after-nip040");

        BOOST_CHECK_MESSAGE(RunTransferAtHeight(AssetMarker::NEURAI_XNA, H + 1, reason), reason);
        BOOST_CHECK(!RunTransferAtHeight(AssetMarker::LEGACY_RVN, H + 1, reason));
    }

    // Mainnet params: the fork is unscheduled, legacy stays valid and xna
    // stays rejected at any plausible height.
    SelectParams(CBaseChainParams::MAIN);
    BOOST_CHECK_MESSAGE(RunTransferAtHeight(AssetMarker::LEGACY_RVN, 10000000, reason), reason);
    BOOST_CHECK(!RunTransferAtHeight(AssetMarker::NEURAI_XNA, 10000000, reason));
    BOOST_CHECK_EQUAL(reason, "bad-txns-asset-marker-before-nip040");
}

BOOST_AUTO_TEST_SUITE_END()
