// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include <assets/assets.h>
#include <test/test_neurai.h>
#include <boost/test/unit_test.hpp>
#include <amount.h>
#include <base58.h>
#include <chainparams.h>
#include <key.h>

BOOST_FIXTURE_TEST_SUITE(null_asset_data_tests, BasicTestingSetup)

    BOOST_AUTO_TEST_CASE(null_data_from_script_test)
    {
        BOOST_TEST_MESSAGE("Running Null data from script");

        // Create the correct script
        CScript nullDataScript = GetScriptForNullAssetDataDestination(DecodeDestination(GetParams().GlobalBurnAddress()));

        CNullAssetTxData nullData("#ADDTAG", (int)QualifierType::ADD_QUALIFIER);
        nullData.ConstructTransaction(nullDataScript);

        CNullAssetTxData fetchedData;
        std::string fetchedAddress;

        BOOST_CHECK_MESSAGE(AssetNullDataFromScript(nullDataScript, fetchedData, fetchedAddress), "Null Data From Script Test 1: Failed to get NullDataFromScript");

    }

    BOOST_AUTO_TEST_CASE(null_data_from_script_fail_test)
    {
        BOOST_TEST_MESSAGE("Running Null data from script failure");

        // Create an invalid script
        CScript nullDataScript = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));

        CNullAssetTxData fetchedData;
        std::string fetchedAddress;
        BOOST_CHECK_MESSAGE(!AssetNullDataFromScript(nullDataScript, fetchedData, fetchedAddress), "Null Data Failure Test 1: should have failed");
    }

    BOOST_AUTO_TEST_CASE(null_data_from_pq_script_test)
    {
        BOOST_TEST_MESSAGE("Running Null data from PQ script");

        SelectParams(CBaseChainParams::TESTNET);

        CKey key;
        key.MakeNewKeyPQ();
        CPubKey pubkey = key.GetPubKey();

        CScript witnessScript;
        witnessScript << OP_TRUE;
        CTxDestination pqDest = WitnessV1AuthScript(GetAuthScriptCommitment(0x01, &pubkey, witnessScript));

        CScript nullDataScript = GetScriptForNullAssetDataDestination(pqDest);

        CNullAssetTxData nullData("#QUALITY", (int)QualifierType::ADD_QUALIFIER);
        nullData.ConstructTransaction(nullDataScript);

        CNullAssetTxData fetchedData;
        std::string fetchedAddress;

        BOOST_CHECK_MESSAGE(AssetNullDataFromScript(nullDataScript, fetchedData, fetchedAddress), "PQ Null Data From Script: failed to decode");
        BOOST_CHECK_EQUAL(fetchedData.asset_name, nullData.asset_name);
        BOOST_CHECK_EQUAL(fetchedData.flag, nullData.flag);
        BOOST_CHECK_EQUAL(fetchedAddress, EncodeDestination(pqDest));
    }

    BOOST_AUTO_TEST_CASE(global_null_data_from_script_test)
    {
        BOOST_TEST_MESSAGE("Running Global Null data from script");

        // Create the correct script
        CScript nullGlobalDataScript;

        CNullAssetTxData nullGlobalData("$ADDRESTRICTION", (int)RestrictedType::GLOBAL_FREEZE);
        nullGlobalData.ConstructGlobalRestrictionTransaction(nullGlobalDataScript);

        CNullAssetTxData fetchedData;
        BOOST_CHECK_MESSAGE(GlobalAssetNullDataFromScript(nullGlobalDataScript, fetchedData), "Null Global Data From Script Test 1: Failed to get NullGlobalDataFromScript");
    }

    BOOST_AUTO_TEST_CASE(global_null_data_from_script_fail_test)
    {
        BOOST_TEST_MESSAGE("Running Global Null data from script");

        // Create the correct script
        CScript nullGlobalDataScript;

        CNullAssetTxData nullGlobalData("$ADDRESTRICTION", (int)RestrictedType::GLOBAL_FREEZE);

        // Construct the wrong type of script
        nullGlobalData.ConstructTransaction(nullGlobalDataScript);

        CNullAssetTxData fetchedData;

        BOOST_CHECK_MESSAGE(!GlobalAssetNullDataFromScript(nullGlobalDataScript, fetchedData), "Null Global Data From Script Failure Test 1: should have failed");
    }


BOOST_AUTO_TEST_SUITE_END()
