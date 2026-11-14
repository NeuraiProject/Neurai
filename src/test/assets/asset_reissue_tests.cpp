// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include <assets/assets.h>

#include <test/test_neurai.h>

#include <boost/test/unit_test.hpp>

#include <amount.h>
#include <script/standard.h>
#include <base58.h>
#include <consensus/validation.h>
#include <consensus/tx_verify.h>
#include <validation.h>

#include <memory>

namespace {
// Owns the global cache these tests install, which used to be leaked. passets
// keeps pointing at it after each test, as before.
std::unique_ptr<CAssetsCache> g_reissue_assets_cache;

void ResetGlobalAssetsCache()
{
    g_reissue_assets_cache.reset(new CAssetsCache());
    passets = g_reissue_assets_cache.get();
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(asset_reissue_tests, BasicTestingSetup)


    BOOST_AUTO_TEST_CASE(reissue_cache_test_ipfs)
    {
        BOOST_TEST_MESSAGE("Running Reissue Cache Test");

        SelectParams(CBaseChainParams::MAIN);

        fAssetIndex = true; // We only cache if fAssetIndex is true
        ResetGlobalAssetsCache();
        // Create assets cache
        CAssetsCache cache;

        CNewAsset asset1("XNAASSET", CAmount(100 * COIN), 8, 1, 0, "");

        // Add an asset to a valid xna address
        uint256 hash = uint256();
        BOOST_CHECK_MESSAGE(cache.AddNewAsset(asset1, GetParams().GlobalBurnAddress(), 0, hash), "Failed to add new asset");

        // Create a reissuance of the asset
        CReissueAsset reissue1("XNAASSET", CAmount(1 * COIN), 8, 1, DecodeAssetData("QmacSRmrkVmvJfbCpmU6pK72furJ8E8fbKHindrLxmYMQo"));
        COutPoint out(uint256S("BF50CB9A63BE0019171456252989A459A7D0A5F494735278290079D22AB704A4"), 1);

        // Add an reissuance of the asset to the cache
        BOOST_CHECK_MESSAGE(cache.AddReissueAsset(reissue1, GetParams().GlobalBurnAddress(), out), "Failed to add reissue");

        // Check to see if the reissue changed the cache data correctly
        BOOST_CHECK_MESSAGE(cache.mapReissuedAssetData.count("XNAASSET"), "Map Reissued Asset should contain the asset \"XNAASSET\"");
        BOOST_CHECK_MESSAGE(cache.mapAssetsAddressAmount.at(make_pair("XNAASSET", GetParams().GlobalBurnAddress())) == CAmount(101 * COIN), "Reissued amount wasn't added to the previous total");

        // Get the new asset data from the cache
        CNewAsset asset2;
        BOOST_CHECK_MESSAGE(cache.GetAssetMetaDataIfExists("XNAASSET", asset2), "Failed to get the asset2");

        // Chech the asset metadata
        BOOST_CHECK_MESSAGE(asset2.nReissuable == 1, "Asset2: Reissuable isn't 1");
        BOOST_CHECK_MESSAGE(asset2.nAmount == CAmount(101 * COIN), "Asset2: Amount isn't 101");
        BOOST_CHECK_MESSAGE(asset2.strName == "XNAASSET", "Asset2: Asset name is wrong");
        BOOST_CHECK_MESSAGE(asset2.units == 8, "Asset2: Units is wrong");
        BOOST_CHECK_MESSAGE(EncodeAssetData(asset2.strIPFSHash) == "QmacSRmrkVmvJfbCpmU6pK72furJ8E8fbKHindrLxmYMQo", "Asset2: IPFS hash is wrong");

        // Remove the reissue from the cache
        std::vector<std::pair<std::string, CBlockAssetUndo> > undoBlockData;
        undoBlockData.emplace_back(std::make_pair("XNAASSET", CBlockAssetUndo{true, false, "", 0, ASSET_UNDO_INCLUDES_VERIFIER_STRING, false, ""}));
        BOOST_CHECK_MESSAGE(cache.RemoveReissueAsset(reissue1, GetParams().GlobalBurnAddress(), out, undoBlockData), "Failed to remove reissue");

        // Get the asset data from the cache now that the reissuance was removed
        CNewAsset asset3;
        BOOST_CHECK_MESSAGE(cache.GetAssetMetaDataIfExists("XNAASSET", asset3), "Failed to get the asset3");

        // Chech the asset3 metadata and make sure all the changed from the reissue were removed
        BOOST_CHECK_MESSAGE(asset3.nReissuable == 1, "Asset3: Reissuable isn't 1");
        BOOST_CHECK_MESSAGE(asset3.nAmount == CAmount(100 * COIN), "Asset3: Amount isn't 100");
        BOOST_CHECK_MESSAGE(asset3.strName == "XNAASSET", "Asset3: Asset name is wrong");
        BOOST_CHECK_MESSAGE(asset3.units == 8, "Asset3: Units is wrong");
        BOOST_CHECK_MESSAGE(asset3.strIPFSHash == "", "Asset3: IPFS hash is wrong");

        // Check to see if the reissue removal updated the cache correctly
        BOOST_CHECK_MESSAGE(cache.mapReissuedAssetData.count("XNAASSET"), "Map of reissued data was removed, even though changes were made and not databased yet");
        BOOST_CHECK_MESSAGE(cache.mapAssetsAddressAmount.at(make_pair("XNAASSET", GetParams().GlobalBurnAddress())) == CAmount(100 * COIN), "Assets total wasn't undone when reissuance was");
    }

    BOOST_AUTO_TEST_CASE(reissue_cache_test_txid)
    {
        BOOST_TEST_MESSAGE("Running Reissue Cache Test");

        SelectParams(CBaseChainParams::MAIN);

        fAssetIndex = true; // We only cache if fAssetIndex is true
        ResetGlobalAssetsCache();
        // Create assets cache
        CAssetsCache cache;

        CNewAsset asset1("XNAASSET", CAmount(100 * COIN), 8, 1, 0, "");

        // Add an asset to a valid xna address
        uint256 hash = uint256();
        BOOST_CHECK_MESSAGE(cache.AddNewAsset(asset1, GetParams().GlobalBurnAddress(), 0, hash), "Failed to add new asset");

        // Create a reissuance of the asset
        CReissueAsset reissue1("XNAASSET", CAmount(1 * COIN), 8, 1, DecodeAssetData("9c2c8e121a0139ba39bffd3ca97267bca9d4c0c1e84ac0c34a883c28e7a912ca"));
        COutPoint out(uint256S("BF50CB9A63BE0019171456252989A459A7D0A5F494735278290079D22AB704A4"), 1);

        // Add an reissuance of the asset to the cache
        BOOST_CHECK_MESSAGE(cache.AddReissueAsset(reissue1, GetParams().GlobalBurnAddress(), out), "Failed to add reissue");

        // Check to see if the reissue changed the cache data correctly
        BOOST_CHECK_MESSAGE(cache.mapReissuedAssetData.count("XNAASSET"), "Map Reissued Asset should contain the asset \"XNAASSET\"");
        BOOST_CHECK_MESSAGE(cache.mapAssetsAddressAmount.at(make_pair("XNAASSET", GetParams().GlobalBurnAddress())) == CAmount(101 * COIN), "Reissued amount wasn't added to the previous total");

        // Get the new asset data from the cache
        CNewAsset asset2;
        BOOST_CHECK_MESSAGE(cache.GetAssetMetaDataIfExists("XNAASSET", asset2), "Failed to get the asset2");

        // Chech the asset metadata
        BOOST_CHECK_MESSAGE(asset2.nReissuable == 1, "Asset2: Reissuable isn't 1");
        BOOST_CHECK_MESSAGE(asset2.nAmount == CAmount(101 * COIN), "Asset2: Amount isn't 101");
        BOOST_CHECK_MESSAGE(asset2.strName == "XNAASSET", "Asset2: Asset name is wrong");
        BOOST_CHECK_MESSAGE(asset2.units == 8, "Asset2: Units is wrong");
        BOOST_CHECK_MESSAGE(EncodeAssetData(asset2.strIPFSHash) == "9c2c8e121a0139ba39bffd3ca97267bca9d4c0c1e84ac0c34a883c28e7a912ca", "Asset2: txid hash is wrong");

        // Remove the reissue from the cache
        std::vector<std::pair<std::string, CBlockAssetUndo> > undoBlockData;
        undoBlockData.emplace_back(std::make_pair("XNAASSET", CBlockAssetUndo{true, false, "", 0, ASSET_UNDO_INCLUDES_VERIFIER_STRING, false, ""}));
        BOOST_CHECK_MESSAGE(cache.RemoveReissueAsset(reissue1, GetParams().GlobalBurnAddress(), out, undoBlockData), "Failed to remove reissue");

        // Get the asset data from the cache now that the reissuance was removed
        CNewAsset asset3;
        BOOST_CHECK_MESSAGE(cache.GetAssetMetaDataIfExists("XNAASSET", asset3), "Failed to get the asset3");

        // Chech the asset3 metadata and make sure all the changed from the reissue were removed
        BOOST_CHECK_MESSAGE(asset3.nReissuable == 1, "Asset3: Reissuable isn't 1");
        BOOST_CHECK_MESSAGE(asset3.nAmount == CAmount(100 * COIN), "Asset3: Amount isn't 100");
        BOOST_CHECK_MESSAGE(asset3.strName == "XNAASSET", "Asset3: Asset name is wrong");
        BOOST_CHECK_MESSAGE(asset3.units == 8, "Asset3: Units is wrong");
        BOOST_CHECK_MESSAGE(asset3.strIPFSHash == "", "Asset3: IPFS/Txid hash is wrong");

        // Check to see if the reissue removal updated the cache correctly
        BOOST_CHECK_MESSAGE(cache.mapReissuedAssetData.count("XNAASSET"), "Map of reissued data was removed, even though changes were made and not databased yet");
        BOOST_CHECK_MESSAGE(cache.mapAssetsAddressAmount.at(make_pair("XNAASSET", GetParams().GlobalBurnAddress())) == CAmount(100 * COIN), "Assets total wasn't undone when reissuance was");
    }


    BOOST_AUTO_TEST_CASE(reissue_isvalid_test)
    {
        BOOST_TEST_MESSAGE("Running Reissue IsValid Test");

        SelectParams(CBaseChainParams::MAIN);

        // Create assets cache
        CAssetsCache cache;

        CNewAsset asset1("XNAASSET", CAmount(100 * COIN), 8, 1, 0, "");

        // Add an asset to a valid xna address
        BOOST_CHECK_MESSAGE(cache.AddNewAsset(asset1, GetParams().GlobalBurnAddress(), 0, uint256()), "Failed to add new asset");

        // Create a reissuance of the asset that is valid
        CReissueAsset reissue1("XNAASSET", CAmount(1 * COIN), 8, 1, DecodeAssetData("QmacSRmrkVmvJfbCpmU6pK72furJ8E8fbKHindrLxmYMQo"));

        std::string error;
        BOOST_CHECK_MESSAGE(ContextualCheckReissueAsset(&cache, reissue1, error), "Reissue should have been valid");

        // Create a reissuance of the asset that is not valid
        CReissueAsset reissue2("NOTEXIST", CAmount(1 * COIN), 8, 1, DecodeAssetData("QmacSRmrkVmvJfbCpmU6pK72furJ8E8fbKHindrLxmYMQo"));

        BOOST_CHECK_MESSAGE(!ContextualCheckReissueAsset(&cache, reissue2, error), "Reissue shouldn't of been valid");

        // Create a reissuance of the asset that is not valid (unit is smaller than current asset)
        CReissueAsset reissue3("XNAASSET", CAmount(1 * COIN), 7, 1, DecodeAssetData("QmacSRmrkVmvJfbCpmU6pK72furJ8E8fbKHindrLxmYMQo"));

        BOOST_CHECK_MESSAGE(!ContextualCheckReissueAsset(&cache, reissue3, error), "Reissue shouldn't of been valid because of units");

        // Create a reissuance of the asset that is not valid (unit is not changed)
        CReissueAsset reissue4("XNAASSET", CAmount(1 * COIN), -1, 1, DecodeAssetData("QmacSRmrkVmvJfbCpmU6pK72furJ8E8fbKHindrLxmYMQo"));

        BOOST_CHECK_MESSAGE(ContextualCheckReissueAsset(&cache, reissue4, error), "Reissue4 wasn't valid");

        // Create a new asset object with units of 0
        CNewAsset asset2("XNAASSET2", CAmount(100 * COIN), 0, 1, 0, "");

        // Add new asset2 to a valid xna address
        BOOST_CHECK_MESSAGE(cache.AddNewAsset(asset2, GetParams().GlobalBurnAddress(), 0, uint256()), "Failed to add new asset");

        // Create a reissuance of the asset that is valid unit go from 0 -> 1 and change the ipfs hash
        CReissueAsset reissue5("XNAASSET2", CAmount(1 * COIN), 1, 1, DecodeAssetData("QmacSRmrkVmvJfbCpmU6pK72furJ8E8fbKHindrLxmYMQo"));

        BOOST_CHECK_MESSAGE(ContextualCheckReissueAsset(&cache, reissue5, error), "Reissue5 wasn't valid");

        // Create a reissuance of the asset that is valid unit go from 1 -> 1 and change the ipfs hash
        CReissueAsset reissue6("XNAASSET2", CAmount(1 * COIN), 1, 1, DecodeAssetData("QmacSRmrkVmvJfbCpmU6pK72furJ8E8fbKHindrLxmYMQo"));

        BOOST_CHECK_MESSAGE(ContextualCheckReissueAsset(&cache, reissue6, error), "Reissue6 wasn't valid");

        // Create a new asset3 object
        CNewAsset asset3("DATAHASH", CAmount(100 * COIN), 8, 1, 0, "");

        // Add new asset3 to a valid xna address
        BOOST_CHECK_MESSAGE(cache.AddNewAsset(asset3, GetParams().GlobalBurnAddress(), 0, uint256()), "Failed to add new asset");

        // Create a reissuance of the asset that is valid txid but messaging isn't active in unit tests
        CReissueAsset reissue7("DATAHASH", CAmount(1 * COIN), 8, 1, DecodeAssetData("9c2c8e121a0139ba39bffd3ca97267bca9d4c0c1e84ac0c34a883c28e7a912ca"));

        BOOST_CHECK_MESSAGE(!ContextualCheckReissueAsset(&cache, reissue7, error), "Reissue should have been not valid because messaging isn't active yet, and txid aren't allowed until messaging is active");
    }


    BOOST_AUTO_TEST_CASE(reissue_undo_is_split_by_database)
    {
        // A reissue that changed the verifier string. The verifier lives in the
        // restricted database and the rest of the reissue in the asset
        // database: each part is undone by a cache for its own database,
        // without reading or changing the other.
        const std::string name = "$RESTRICTED";
        std::vector<std::pair<std::string, CBlockAssetUndo> > undoBlockData;
        undoBlockData.emplace_back(std::make_pair(name, CBlockAssetUndo{false, false, "", 0, ASSET_UNDO_INCLUDES_VERIFIER_STRING, true, "true"}));
        const CReissueAsset reissue(name, CAmount(1 * COIN), 8, 1, "");

        CAssetsCache restrictedOnly;
        restrictedOnly.nStateDatabases = ASSET_STATE_DB_RESTRICTED;
        BOOST_CHECK(restrictedOnly.RemoveReissueVerifier(name, undoBlockData));
        BOOST_REQUIRE_EQUAL(restrictedOnly.setNewRestrictedVerifierToRemove.size(), 1u);
        BOOST_CHECK_EQUAL(restrictedOnly.setNewRestrictedVerifierToRemove.begin()->assetName, name);
        BOOST_CHECK_EQUAL(restrictedOnly.setNewRestrictedVerifierToRemove.begin()->verifier, "true");
        BOOST_CHECK(restrictedOnly.setNewRestrictedVerifierToRemove.begin()->fUndoingRessiue);
        BOOST_CHECK(restrictedOnly.RemoveReissueAsset(reissue, GetParams().GlobalBurnAddress(), COutPoint(), undoBlockData));
        BOOST_CHECK(restrictedOnly.setNewReissueToRemove.empty());
        BOOST_CHECK(restrictedOnly.mapReissuedAssetData.empty());

        CAssetsCache assetsOnly;
        assetsOnly.nStateDatabases = ASSET_STATE_DB_ASSETS;
        BOOST_CHECK(assetsOnly.RemoveReissueVerifier(name, undoBlockData));
        BOOST_CHECK(assetsOnly.setNewRestrictedVerifierToRemove.empty());

        // A reissue that left the verifier alone has nothing to undo there.
        std::vector<std::pair<std::string, CBlockAssetUndo> > undoWithoutVerifier;
        undoWithoutVerifier.emplace_back(std::make_pair(name, CBlockAssetUndo{true, true, "", 0, ASSET_UNDO_INCLUDES_VERIFIER_STRING, false, ""}));
        CAssetsCache both;
        BOOST_CHECK(both.RemoveReissueVerifier(name, undoWithoutVerifier));
        BOOST_CHECK(both.RemoveReissueVerifier("$OTHER", undoBlockData));
        BOOST_CHECK(both.setNewRestrictedVerifierToRemove.empty());
    }

    BOOST_AUTO_TEST_CASE(reissue_keeps_the_block_the_asset_was_issued_in)
    {
        // The data of a reissue that is not on disk yet carries no block. The
        // lookup still answers with the block the asset was issued in, also
        // for the next reissue and for the undo, which store it again.
        SelectParams(CBaseChainParams::MAIN);
        fAssetIndex = true;
        ResetGlobalAssetsCache();
        CAssetsCache cache;

        const std::string name = "ISSUEBLOCK";
        const std::string address = GetParams().GlobalBurnAddress();
        const int issueHeight = 1234;
        const uint256 issueBlock = uint256S("c0ffee0000000000000000000000000000000000000000000000000000000001");
        BOOST_REQUIRE(cache.AddNewAsset(CNewAsset(name, CAmount(100 * COIN), 0, 1, 0, ""), address, issueHeight, issueBlock));

        CNewAsset found;
        int height = -1;
        uint256 block = uint256S("01");
        BOOST_REQUIRE(cache.GetAssetMetaDataIfExists(name, found, height, block));
        BOOST_CHECK_EQUAL(height, issueHeight);
        BOOST_CHECK(block == issueBlock);

        const CReissueAsset first(name, CAmount(1 * COIN), -1, 1, "");
        const COutPoint firstOut(uint256S("01"), 1);
        BOOST_REQUIRE(cache.AddReissueAsset(first, address, firstOut));
        height = -1;
        block = uint256S("01");
        BOOST_REQUIRE(cache.GetAssetMetaDataIfExists(name, found, height, block));
        BOOST_CHECK_EQUAL(found.nAmount, CAmount(101 * COIN));
        BOOST_CHECK_EQUAL(height, issueHeight);
        BOOST_CHECK(block == issueBlock);

        // A second reissue on top of the first, and its undo
        const CReissueAsset second(name, CAmount(2 * COIN), -1, 1, "");
        const COutPoint secondOut(uint256S("02"), 1);
        BOOST_REQUIRE(cache.AddReissueAsset(second, address, secondOut));
        for (const auto& reissue : cache.setNewReissueToAdd) {
            BOOST_CHECK_EQUAL(reissue.blockHeight, issueHeight);
            BOOST_CHECK(reissue.blockHash == issueBlock);
        }
        std::vector<std::pair<std::string, CBlockAssetUndo> > undoBlockData;
        BOOST_REQUIRE(cache.RemoveReissueAsset(second, address, secondOut, undoBlockData));
        BOOST_REQUIRE_EQUAL(cache.setNewReissueToRemove.size(), 1u);
        BOOST_CHECK_EQUAL(cache.setNewReissueToRemove.begin()->blockHeight, issueHeight);
        BOOST_CHECK(cache.setNewReissueToRemove.begin()->blockHash == issueBlock);

        // An asset that does not exist leaves no block behind
        height = -1;
        block = uint256S("01");
        BOOST_CHECK(!cache.GetAssetMetaDataIfExists("NOSUCHASSET", found, height, block));
        BOOST_CHECK_EQUAL(height, 0);
        BOOST_CHECK(block.IsNull());
    }

    BOOST_AUTO_TEST_CASE(asset_issued_again_over_a_pending_removal)
    {
        // The cache below holds the removal of an asset that was issued and
        // reissued in blocks that were disconnected. A cache layered on it
        // issues the name again: there the asset exists, with the properties
        // of the new issue, and it cannot be issued twice.
        SelectParams(CBaseChainParams::MAIN);
        fAssetIndex = true;
        ResetGlobalAssetsCache();

        const std::string name = "TWICEISSUED";
        const std::string address = GetParams().GlobalBurnAddress();
        const CNewAsset first(name, CAmount(100 * COIN), 0, 1, 0, "");
        const CReissueAsset reissue(name, CAmount(50 * COIN), 2, 1, "");
        const COutPoint reissueOut(uint256S("01"), 1);
        std::vector<std::pair<std::string, CBlockAssetUndo> > undoBlockData;
        undoBlockData.emplace_back(std::make_pair(name, CBlockAssetUndo{false, true, "", 0, ASSET_UNDO_INCLUDES_VERIFIER_STRING, false, ""}));

        BOOST_REQUIRE(passets->AddNewAsset(first, address, 10, uint256S("0a")));
        BOOST_REQUIRE(passets->AddReissueAsset(reissue, address, reissueOut));
        BOOST_REQUIRE(passets->RemoveReissueAsset(reissue, address, reissueOut, undoBlockData));
        BOOST_CHECK_EQUAL(passets->mapReissuedAssetData.count(name), 1u);
        BOOST_REQUIRE(passets->RemoveNewAsset(first, address));

        CNewAsset found;
        BOOST_CHECK(!passets->GetAssetMetaDataIfExists(name, found));
        BOOST_CHECK(!passets->CheckIfAssetExists(name));
        // The reissue data went with the asset
        BOOST_CHECK_EQUAL(passets->mapReissuedAssetData.count(name), 0u);

        CAssetsCache block;
        BOOST_CHECK(!block.GetAssetMetaDataIfExists(name, found));
        const CNewAsset second(name, CAmount(1000 * COIN), 4, 0, 0, "");
        BOOST_REQUIRE(block.AddNewAsset(second, address, 20, uint256S("0b")));
        int height = -1;
        uint256 hash;
        BOOST_REQUIRE(block.GetAssetMetaDataIfExists(name, found, height, hash));
        BOOST_CHECK_EQUAL(found.nAmount, CAmount(1000 * COIN));
        BOOST_CHECK_EQUAL((int)found.units, 4);
        BOOST_CHECK_EQUAL(height, 20);
        BOOST_CHECK(hash == uint256S("0b"));
        BOOST_CHECK(block.CheckIfAssetExists(name));
        BOOST_CHECK(!block.AddNewAsset(second, address, 20, uint256S("0b")));
        // The cache below still holds the removal
        BOOST_CHECK(!passets->GetAssetMetaDataIfExists(name, found));

        // ...until the block is connected
        BOOST_REQUIRE(block.Flush());
        BOOST_REQUIRE(passets->GetAssetMetaDataIfExists(name, found, height, hash));
        BOOST_CHECK_EQUAL(found.nAmount, CAmount(1000 * COIN));
        BOOST_CHECK_EQUAL((int)found.units, 4);
        BOOST_CHECK_EQUAL(height, 20);
        BOOST_CHECK(passets->setNewAssetsToRemove.empty());
    }

BOOST_AUTO_TEST_SUITE_END()