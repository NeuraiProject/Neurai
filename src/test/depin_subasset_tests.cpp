// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Sub-DEPIN assets ("&TOKEN/SUB") must require the parent's owner token
// ("&TOKEN!") to be transferred in the issuing transaction, the same way
// AssetType::SUB sub-assets do. They are AssetType::DEPIN rather than
// AssetType::SUB, so VerifyNewAsset() needs an explicit check for them, and
// GetParentName() needs a DEPIN branch to resolve "&TOKEN/SUB" -> "&TOKEN".
//
// Naming note: every '/'-separated component of a DEPIN name must be at least
// MIN_ASSET_LENGTH (3) characters, so "&TOKEN/A/B" is NOT a valid name.
// Positive cases below use components of >= 3 chars; "&TOKEN/A/B" appears only
// as a deliberate negative case.

#include "assets/assets.h"
#include "assets/assettypes.h"
#include "test/test_neurai.h"
#include "chainparams.h"
#include "base58.h"
#include "key.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/standard.h"

#include <boost/test/unit_test.hpp>
#include <string>

namespace {

// RAII guard: SelectParams mutates the global CChainParams; restore it so the
// switch does not leak into later test cases. DEPIN names only validate on
// testnet/regtest, so these tests must select one of those networks.
struct NetworkGuard {
    std::string previous;
    explicit NetworkGuard(const std::string& net) : previous(GetParams().NetworkIDString()) {
        SelectParams(net);
    }
    ~NetworkGuard() {
        if (previous == "main") SelectParams(CBaseChainParams::MAIN);
        else if (previous == "test") SelectParams(CBaseChainParams::TESTNET);
        else SelectParams(CBaseChainParams::REGTEST);
    }
};

CScript NewDestinationScript()
{
    CKey key;
    key.MakeNewKey(true);
    return GetScriptForDestination(key.GetPubKey().GetID());
}

// Build an issuance transaction shaped the way VerifyNewAsset() expects:
// [burn, (optional parent-owner transfer), owner data, asset data].
// parentOwnerToTransfer is the full owner-token name (e.g. "&TOKEN!"); pass an
// empty string to omit that output, which is the unauthorized case.
CMutableTransaction BuildIssuanceTx(const std::string& assetName,
                                    const std::string& parentOwnerToTransfer)
{
    AssetType assetType;
    BOOST_REQUIRE(IsAssetNameValid(assetName, assetType));

    CMutableTransaction mutTx;

    // Burn output for this asset type
    CScript burnScript = GetScriptForDestination(DecodeDestination(GetBurnAddress(assetType)));
    mutTx.vout.emplace_back(GetBurnAmount(assetType), burnScript);

    // Optional: transfer of the parent's owner token back to ourselves
    if (!parentOwnerToTransfer.empty()) {
        CScript transferScript = NewDestinationScript();
        CAssetTransfer transfer(parentOwnerToTransfer, OWNER_ASSET_AMOUNT);
        transfer.ConstructTransaction(transferScript, AssetMarker::LEGACY_RVN);
        mutTx.vout.emplace_back(0, transferScript);
    }

    CNewAsset asset(assetName, CAmount(1 * COIN), DEPIN_ASSET_UNITS, 0, 0, "");

    // Owner token of the asset being created (second to last output)
    CScript ownerScript = NewDestinationScript();
    asset.ConstructOwnerTransaction(ownerScript, AssetMarker::LEGACY_RVN);
    mutTx.vout.emplace_back(0, ownerScript);

    // Asset data (must be the last output)
    CScript assetScript = NewDestinationScript();
    asset.ConstructTransaction(assetScript, AssetMarker::LEGACY_RVN);
    mutTx.vout.emplace_back(0, assetScript);

    return mutTx;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(depin_subasset_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// (a) GetParentName()
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(get_parent_name_depin)
{
    NetworkGuard g(CBaseChainParams::REGTEST);

    // Regression test: before the fix GetParentName() had no DEPIN branch and
    // returned the full name unchanged.
    BOOST_CHECK_EQUAL(GetParentName("&TOKEN/SUB"), "&TOKEN");

    // A root DEPIN has no parent and resolves to itself, like ROOT/QUALIFIER.
    BOOST_CHECK_EQUAL(GetParentName("&TOKEN"), "&TOKEN");

    // Immediate-parent policy (deliberate): branch delegation is allowed, so a
    // third-level name resolves to its direct parent, not to the root. If this
    // ever changes to find_first_of() the authorization model changes with it,
    // and this assertion is what catches it.
    BOOST_CHECK_EQUAL(GetParentName("&TOKEN/RAMA/HOJA"), "&TOKEN/RAMA");

    // Non-regression: normal sub-assets are unaffected.
    BOOST_CHECK_EQUAL(GetParentName("TOKEN/SUB"), "TOKEN");

    // Invalid name (component shorter than MIN_ASSET_LENGTH) yields an empty
    // string. Asserted explicitly so a carelessly written case with short
    // components cannot pass by comparing "" against "".
    BOOST_CHECK_EQUAL(GetParentName("&TOKEN/A/B"), "");
}

// ---------------------------------------------------------------------------
// (b) IsAssetNameASubDEPIN()
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(is_asset_name_a_sub_depin)
{
    NetworkGuard g(CBaseChainParams::REGTEST);

    BOOST_CHECK(IsAssetNameASubDEPIN("&TOKEN/SUB"));
    BOOST_CHECK(IsAssetNameASubDEPIN("&TOKEN/RAMA/HOJA"));

    BOOST_CHECK(!IsAssetNameASubDEPIN("&TOKEN"));      // root DEPIN, no parent
    BOOST_CHECK(!IsAssetNameASubDEPIN("TOKEN/SUB"));   // normal sub-asset
    BOOST_CHECK(!IsAssetNameASubDEPIN("&TOKEN/A/B"));  // invalid: component < 3 chars
}

// ---------------------------------------------------------------------------
// (c) VerifyNewAsset() -- the authorization rule being fixed
// ---------------------------------------------------------------------------

// Core regression test: without the parent's owner token, issuing a sub-DEPIN
// must be rejected. Before the fix this passed, letting anyone squat names
// under someone else's DEPIN namespace.
BOOST_AUTO_TEST_CASE(sub_depin_without_parent_owner_is_rejected)
{
    NetworkGuard g(CBaseChainParams::REGTEST);

    CMutableTransaction mutTx = BuildIssuanceTx("&TOKEN/SUB", "");
    CTransaction tx(mutTx);

    std::string error;
    BOOST_CHECK(!tx.VerifyNewAsset(error));
    BOOST_CHECK_EQUAL(error, "bad-txns-issue-new-asset-missing-owner-asset");
}

BOOST_AUTO_TEST_CASE(sub_depin_with_parent_owner_is_accepted)
{
    NetworkGuard g(CBaseChainParams::REGTEST);

    CMutableTransaction mutTx = BuildIssuanceTx("&TOKEN/SUB", "&TOKEN" + std::string(OWNER_TAG));
    CTransaction tx(mutTx);

    std::string error;
    BOOST_CHECK_MESSAGE(tx.VerifyNewAsset(error), error);
}

// Issuing a root DEPIN must keep working: it has no parent, so no foreign owner
// token may be demanded of it.
BOOST_AUTO_TEST_CASE(root_depin_needs_no_parent_owner)
{
    NetworkGuard g(CBaseChainParams::REGTEST);

    CMutableTransaction mutTx = BuildIssuanceTx("&TOKEN", "");
    CTransaction tx(mutTx);

    std::string error;
    BOOST_CHECK_MESSAGE(tx.VerifyNewAsset(error), error);
}

// Multi-level, pinning the immediate-parent policy in code: "&TOKEN/RAMA/HOJA"
// is authorized by "&TOKEN/RAMA!", and specifically NOT by the root "&TOKEN!".
// This pair documents that branch delegation is intentional.
BOOST_AUTO_TEST_CASE(sub_depin_multilevel_uses_immediate_parent_owner)
{
    NetworkGuard g(CBaseChainParams::REGTEST);

    {
        CMutableTransaction mutTx =
            BuildIssuanceTx("&TOKEN/RAMA/HOJA", "&TOKEN/RAMA" + std::string(OWNER_TAG));
        CTransaction tx(mutTx);
        std::string error;
        BOOST_CHECK_MESSAGE(tx.VerifyNewAsset(error), error);
    }

    {
        // Holding only the root owner token is not enough for a third-level name.
        CMutableTransaction mutTx =
            BuildIssuanceTx("&TOKEN/RAMA/HOJA", "&TOKEN" + std::string(OWNER_TAG));
        CTransaction tx(mutTx);
        std::string error;
        BOOST_CHECK(!tx.VerifyNewAsset(error));
        BOOST_CHECK_EQUAL(error, "bad-txns-issue-new-asset-missing-owner-asset");
    }
}

// Non-regression: normal sub-assets keep requiring their parent's owner token.
BOOST_AUTO_TEST_CASE(normal_subasset_still_requires_parent_owner)
{
    NetworkGuard g(CBaseChainParams::REGTEST);

    CMutableTransaction mutTx = BuildIssuanceTx("TOKEN/SUB", "");
    CTransaction tx(mutTx);

    std::string error;
    BOOST_CHECK(!tx.VerifyNewAsset(error));
    BOOST_CHECK_EQUAL(error, "bad-txns-issue-new-asset-missing-owner-asset");
}

BOOST_AUTO_TEST_SUITE_END()
