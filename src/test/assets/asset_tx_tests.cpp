// Copyright (c) 2017-2021 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <assets/assets.h>

#include <test/test_neurai.h>

#include <boost/test/unit_test.hpp>

#include <amount.h>
#include <key.h>
#include <keystore.h>
#include <policy/policy.h>
#include <script/standard.h>
#include <script/interpreter.h>
#include <script/sign.h>
#include <base58.h>
#include <coins.h>
#include <consensus/validation.h>
#include <consensus/tx_verify.h>
#include <validation.h>
#ifdef ENABLE_WALLET
#include <wallet/db.h>
#include <wallet/wallet.h>
#endif

BOOST_FIXTURE_TEST_SUITE(asset_tx_tests, BasicTestingSetup)

    static CTxDestination GetDefaultPQAuthScriptDestination(const CPubKey& pubkey)
    {
        CScript witnessScript;
        witnessScript << OP_TRUE;
        return CTxDestination(WitnessV1AuthScript(GetAuthScriptCommitment(0x01, &pubkey, witnessScript)));
    }

    static void AddDefaultPQAuthScriptSpendData(CBasicKeyStore& keystore, const CPubKey& pubkey)
    {
        CScript witnessScript;
        witnessScript << OP_TRUE;
        AuthScriptSpendData spendData;
        spendData.auth_type = 0x01;
        spendData.witnessScript = witnessScript;
        spendData.pubkey = pubkey;
        spendData.key_id = pubkey.GetID();
        spendData.is_default_template = true;
        keystore.AddAuthScriptSpendData(GetAuthScriptCommitment(0x01, &pubkey, witnessScript), spendData);
    }

    BOOST_AUTO_TEST_CASE(asset_tx_valid_test)
    {
        BOOST_TEST_MESSAGE("Running Asset TX Valid Test");

        SelectParams(CBaseChainParams::MAIN);

        // Create the asset scriptPubKey
        CAssetTransfer asset("NEURAITEST", 1000);
        CScript scriptPubKey = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));
        asset.ConstructTransaction(scriptPubKey);

        CCoinsView view;
        CCoinsViewCache coins(&view);

        CAssetsCache assetCache;

        // Create CTxOut and add it to a coin
        CTxOut txOut;
        txOut.nValue = 0;
        txOut.scriptPubKey = scriptPubKey;

        // Create a random hash
        uint256 hash = uint256S("BF50CB9A63BE0019171456252989A459A7D0A5F494735278290079D22AB704A2");

        // Add the coin to the cache
        COutPoint outpoint(hash, 1);
        coins.AddCoin(outpoint, Coin(txOut, 10, 0), true);

        // Create transaction and input for the outpoint of the coin we just created
        CMutableTransaction mutTx;

        CTxIn in;
        in.prevout = outpoint;

        // Add the input, and an output into the transaction
        mutTx.vin.emplace_back(in);
        mutTx.vout.emplace_back(txOut);

        CTransaction tx(mutTx);
        CValidationState state;

        // The inputs are spending 1000 Assets
        // The outputs are assigning a destination to 1000 Assets
        // This test should pass because all assets are assigned a destination
        std::vector<std::pair<std::string, uint256>> vReissueAssets;
        BOOST_CHECK_MESSAGE(Consensus::CheckTxAssets(tx, state, coins, nullptr, false, vReissueAssets, true), "CheckTxAssets Failed");
    }

    BOOST_AUTO_TEST_CASE(asset_tx_not_valid_test)
    {
        BOOST_TEST_MESSAGE("Running Asset TX Not Valid Test");

        SelectParams(CBaseChainParams::MAIN);

        // Create the asset scriptPubKey
        CAssetTransfer asset("NEURAITEST", 1000);
        CScript scriptPubKey = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));
        asset.ConstructTransaction(scriptPubKey);

        CCoinsView view;
        CCoinsViewCache coins(&view);
        CAssetsCache assetCache;

        // Create CTxOut and add it to a coin
        CTxOut txOut;
        txOut.nValue = 0;
        txOut.scriptPubKey = scriptPubKey;

        // Create a random hash
        uint256 hash = uint256S("BF50CB9A63BE0019171456252989A459A7D0A5F494735278290079D22AB704A2");

        // Add the coin to the cache
        COutPoint outpoint(hash, 1);
        coins.AddCoin(outpoint, Coin(txOut, 10, 0), true);

        // Create transaction and input for the outpoint of the coin we just created
        CMutableTransaction mutTx;

        CTxIn in;
        in.prevout = outpoint;

        // Create CTxOut that will only send 100 of the asset
        // This should fail because 900 NEURAI doesn't have a destination
        CAssetTransfer assetTransfer("NEURAITEST", 100);
        CScript scriptLess = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));
        assetTransfer.ConstructTransaction(scriptLess);

        CTxOut txOut2;
        txOut2.nValue = 0;
        txOut2.scriptPubKey = scriptLess;

        // Add the input, and an output into the transaction
        mutTx.vin.emplace_back(in);
        mutTx.vout.emplace_back(txOut2);

        CTransaction tx(mutTx);
        CValidationState state;

        // The inputs of this transaction are spending 1000 Assets
        // The outputs are assigning a destination to only 100 Assets
        // This should fail because 900 Assets aren't being assigned a destination (Trying to burn 900 Assets)
        std::vector<std::pair<std::string, uint256>> vReissueAssets;
        BOOST_CHECK_MESSAGE(!Consensus::CheckTxAssets(tx, state, coins, nullptr, false, vReissueAssets, true), "CheckTxAssets should have failed");
    }

    BOOST_AUTO_TEST_CASE(asset_tx_valid_multiple_outs_test)
    {
        BOOST_TEST_MESSAGE("Running Asset TX Valid Multiple Outs Test");

        SelectParams(CBaseChainParams::MAIN);

        // Create the asset scriptPubKey
        CAssetTransfer asset("NEURAITEST", 1000);
        CScript scriptPubKey = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));
        asset.ConstructTransaction(scriptPubKey);

        CCoinsView view;
        CCoinsViewCache coins(&view);
        CAssetsCache assetCache;

        // Create CTxOut and add it to a coin
        CTxOut txOut;
        txOut.nValue = 0;
        txOut.scriptPubKey = scriptPubKey;

        // Create a random hash
        uint256 hash = uint256S("BF50CB9A63BE0019171456252989A459A7D0A5F494735278290079D22AB704A2");

        // Add the coin to the cache
        COutPoint outpoint(hash, 1);
        coins.AddCoin(outpoint, Coin(txOut, 10, 0), true);

        // Create transaction and input for the outpoint of the coin we just created
        CMutableTransaction mutTx;

        CTxIn in;
        in.prevout = outpoint;

        // Create CTxOut that will only send 100 of the asset 10 times total = 1000
        for (int i = 0; i < 10; i++)
        {
            CAssetTransfer asset2("NEURAITEST", 100);
            CScript scriptPubKey2 = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));
            asset2.ConstructTransaction(scriptPubKey2);

            CTxOut txOut2;
            txOut2.nValue = 0;
            txOut2.scriptPubKey = scriptPubKey2;

            // Add the output into the transaction
            mutTx.vout.emplace_back(txOut2);
        }

        // Add the input, and an output into the transaction
        mutTx.vin.emplace_back(in);

        CTransaction tx(mutTx);
        CValidationState state;

        // The inputs are spending 1000 Assets
        // The outputs are assigned 100 Assets to 10 destinations (10 * 100) = 1000
        // This test should pass all assets that are being spent are assigned to a destination
        std::vector<std::pair<std::string, uint256>> vReissueAssets;
        BOOST_CHECK_MESSAGE(Consensus::CheckTxAssets(tx, state, coins, nullptr, false, vReissueAssets, true), "CheckTxAssets failed");
    }

    BOOST_AUTO_TEST_CASE(asset_tx_multiple_outs_invalid_test)
    {
        BOOST_TEST_MESSAGE("Running Asset TX Multiple Outs Invalid Test");

        SelectParams(CBaseChainParams::MAIN);

        // Create the asset scriptPubKey
        CAssetTransfer asset("NEURAITEST", 1000);
        CScript scriptPubKey = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));
        asset.ConstructTransaction(scriptPubKey);

        CCoinsView view;
        CCoinsViewCache coins(&view);
        CAssetsCache assetCache;

        // Create CTxOut and add it to a coin
        CTxOut txOut;
        txOut.nValue = 0;
        txOut.scriptPubKey = scriptPubKey;

        // Create a random hash
        uint256 hash = uint256S("BF50CB9A63BE0019171456252989A459A7D0A5F494735278290079D22AB704A2");

        // Add the coin to the cache
        COutPoint outpoint(hash, 1);
        coins.AddCoin(outpoint, Coin(txOut, 10, 0), true);

        // Create transaction and input for the outpoint of the coin we just created
        CMutableTransaction mutTx;

        CTxIn in;
        in.prevout = outpoint;

        // Create CTxOut that will only send 100 of the asset 12 times, total = 1200
        for (int i = 0; i < 12; i++)
        {
            CAssetTransfer asset2("NEURAITEST", 100);
            CScript scriptPubKey2 = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));
            asset2.ConstructTransaction(scriptPubKey2);

            CTxOut txOut2;
            txOut2.nValue = 0;
            txOut2.scriptPubKey = scriptPubKey2;

            // Add the output into the transaction
            mutTx.vout.emplace_back(txOut2);
        }

        // Add the input, and an output into the transaction
        mutTx.vin.emplace_back(in);

        CTransaction tx(mutTx);
        CValidationState state;

        // The inputs are spending 1000 Assets
        // The outputs are assigning 100 Assets to 12 destinations (12 * 100 = 1200)
        // This test should fail because the Outputs are greater than the inputs
        std::vector<std::pair<std::string, uint256>> vReissueAssets;
        BOOST_CHECK_MESSAGE(!Consensus::CheckTxAssets(tx, state, coins, nullptr, false, vReissueAssets, true), "CheckTxAssets passed when it should have failed");
    }

    BOOST_AUTO_TEST_CASE(asset_tx_multiple_assets_test)
    {
        BOOST_TEST_MESSAGE("Running Asset TX Multiple Assets Test");

        SelectParams(CBaseChainParams::MAIN);

        // Create the asset scriptPubKeys
        CAssetTransfer asset("NEURAITEST", 1000);
        CScript scriptPubKey = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));
        asset.ConstructTransaction(scriptPubKey);

        CAssetTransfer asset2("NEURAITESTTEST", 1000);
        CScript scriptPubKey2 = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));
        asset2.ConstructTransaction(scriptPubKey2);

        CAssetTransfer asset3("NEURAITESTTESTTEST", 1000);
        CScript scriptPubKey3 = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));
        asset3.ConstructTransaction(scriptPubKey3);

        CCoinsView view;
        CCoinsViewCache coins(&view);
        CAssetsCache assetCache;

        // Create CTxOuts
        CTxOut txOut;
        txOut.nValue = 0;
        txOut.scriptPubKey = scriptPubKey;

        CTxOut txOut2;
        txOut2.nValue = 0;
        txOut2.scriptPubKey = scriptPubKey2;

        CTxOut txOut3;
        txOut3.nValue = 0;
        txOut3.scriptPubKey = scriptPubKey3;

        // Create a random hash
        uint256 hash = uint256S("BF50CB9A63BE0019171456252989A459A7D0A5F494735278290079D22AB704A2");
        uint256 hash2 = uint256S("BF50CB9A63BE0019171456252989A459A7D0A5F494735278290079D22AB704A3");
        uint256 hash3 = uint256S("BF50CB9A63BE0019171456252989A459A7D0A5F494735278290079D22AB704A4");

        // Add the coins to the cache
        COutPoint outpoint(hash, 1);
        coins.AddCoin(outpoint, Coin(txOut, 10, 0), true);

        COutPoint outpoint2(hash2, 1);
        coins.AddCoin(outpoint2, Coin(txOut2, 10, 0), true);

        COutPoint outpoint3(hash3, 1);
        coins.AddCoin(outpoint3, Coin(txOut3, 10, 0), true);

        Coin coinTemp;
        BOOST_CHECK_MESSAGE(coins.GetCoin(outpoint, coinTemp), "Failed to get coin 1");
        BOOST_CHECK_MESSAGE(coins.GetCoin(outpoint2, coinTemp), "Failed to get coin 2");
        BOOST_CHECK_MESSAGE(coins.GetCoin(outpoint3, coinTemp), "Failed to get coin 3");

        // Create transaction and input for the outpoint of the coin we just created
        CMutableTransaction mutTx;

        CTxIn in;
        in.prevout = outpoint;

        CTxIn in2;
        in2.prevout = outpoint2;

        CTxIn in3;
        in3.prevout = outpoint3;

        // Create CTxOut for each asset that spends 100 assets 10 time = 1000 asset in total
        for (int i = 0; i < 10; i++)
        {
            // Add the first asset
            CAssetTransfer outAsset("NEURAITEST", 100);
            CScript outScript = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));
            outAsset.ConstructTransaction(outScript);

            CTxOut txOutNew;
            txOutNew.nValue = 0;
            txOutNew.scriptPubKey = outScript;

            mutTx.vout.emplace_back(txOutNew);

            // Add the second asset
            CAssetTransfer outAsset2("NEURAITESTTEST", 100);
            CScript outScript2 = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));
            outAsset2.ConstructTransaction(outScript2);

            CTxOut txOutNew2;
            txOutNew2.nValue = 0;
            txOutNew2.scriptPubKey = outScript2;

            mutTx.vout.emplace_back(txOutNew2);

            // Add the third asset
            CAssetTransfer outAsset3("NEURAITESTTESTTEST", 100);
            CScript outScript3 = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));
            outAsset3.ConstructTransaction(outScript3);

            CTxOut txOutNew3;
            txOutNew3.nValue = 0;
            txOutNew3.scriptPubKey = outScript3;

            mutTx.vout.emplace_back(txOutNew3);
        }

        // Add the inputs
        mutTx.vin.emplace_back(in);
        mutTx.vin.emplace_back(in2);
        mutTx.vin.emplace_back(in3);

        CTransaction tx(mutTx);
        CValidationState state;

        // The inputs are spending 3000 Assets (1000 of each NEURAI, NEURAITEST, NEURAITESTTEST)
        // The outputs are spending 100 Assets to 10 destinations (10 * 100 = 1000) (of each NEURAI, NEURAITEST, NEURAITESTTEST)
        // This test should pass because for each asset that is spent. It is assigned a destination
        std::vector<std::pair<std::string, uint256>> vReissueAssets;
        BOOST_CHECK_MESSAGE(Consensus::CheckTxAssets(tx, state, coins, nullptr, false, vReissueAssets, true), state.GetDebugMessage());


        // Try it not but only spend 900 of each asset instead of 1000
        CMutableTransaction mutTx2;

        // Create CTxOut for each asset that spends 100 assets 9 time = 900 asset in total
        for (int i = 0; i < 9; i++)
        {
            // Add the first asset
            CAssetTransfer outAsset("NEURAITEST", 100);
            CScript outScript = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));
            outAsset.ConstructTransaction(outScript);

            CTxOut txOutNew;
            txOutNew.nValue = 0;
            txOutNew.scriptPubKey = outScript;

            mutTx2.vout.emplace_back(txOutNew);

            // Add the second asset
            CAssetTransfer outAsset2("NEURAITESTTEST", 100);
            CScript outScript2 = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));
            outAsset2.ConstructTransaction(outScript2);

            CTxOut txOutNew2;
            txOutNew2.nValue = 0;
            txOutNew2.scriptPubKey = outScript2;

            mutTx2.vout.emplace_back(txOutNew2);

            // Add the third asset
            CAssetTransfer outAsset3("NEURAITESTTESTTEST", 100);
            CScript outScript3 = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));
            outAsset3.ConstructTransaction(outScript3);

            CTxOut txOutNew3;
            txOutNew3.nValue = 0;
            txOutNew3.scriptPubKey = outScript3;

            mutTx2.vout.emplace_back(txOutNew3);
        }

        // Add the inputs
        mutTx2.vin.emplace_back(in);
        mutTx2.vin.emplace_back(in2);
        mutTx2.vin.emplace_back(in3);

        CTransaction tx2(mutTx2);

        // Check the transaction that contains inputs that are spending 1000 Assets for 3 different assets
        // While only outputs only contain 900 Assets being sent to a destination
        // This should fail because 100 of each Asset isn't being sent to a destination (Trying to burn 100 Assets each)
        BOOST_CHECK_MESSAGE(!Consensus::CheckTxAssets(tx2, state, coins, nullptr, false, vReissueAssets, true), "CheckTxAssets should have failed");
    }

    BOOST_AUTO_TEST_CASE(asset_tx_issue_units_test)
    {
        BOOST_TEST_MESSAGE("Running Asset TX Issue Units Test");

        std::string error;
        CAssetsCache cache;

        // Amount = 1.00000000
        CNewAsset asset("ASSET", CAmount(100000000), 8, false, false, "");

        BOOST_CHECK_MESSAGE(CheckNewAsset(asset, error), "Test1: " + error);

        // Amount = 1.00000000
        asset = CNewAsset("ASSET", CAmount(100000000), 0, false, false, "");
        BOOST_CHECK_MESSAGE(CheckNewAsset(asset, error), "Test2: " + error);

        // Amount = 0.10000000
        asset = CNewAsset("ASSET", CAmount(10000000), 8, false, false, "");
        BOOST_CHECK_MESSAGE(CheckNewAsset(asset, error), "Test3: " + error);

        // Amount = 0.10000000
        asset = CNewAsset("ASSET", CAmount(10000000), 2, false, false, "");
        BOOST_CHECK_MESSAGE(CheckNewAsset(asset, error), "Test4: " + error);

        // Amount = 0.10000000
        asset = CNewAsset("ASSET", CAmount(10000000), 0, false, false, "");
        BOOST_CHECK_MESSAGE(!CheckNewAsset(asset, error), "Test5: " + error);

        // Amount = 0.01000000
        asset = CNewAsset("ASSET", CAmount(1000000), 0, false, false, "");
        BOOST_CHECK_MESSAGE(!CheckNewAsset(asset, error), "Test6: " + error);

        // Amount = 0.01000000
        asset = CNewAsset("ASSET", CAmount(1000000), 1, false, false, "");
        BOOST_CHECK_MESSAGE(!CheckNewAsset(asset, error), "Test7: " + error);

        // Amount = 0.01000000
        asset = CNewAsset("ASSET", CAmount(1000000), 2, false, false, "");
        BOOST_CHECK_MESSAGE(CheckNewAsset(asset, error), "Test8: " + error);

        // Amount = 0.00000001
        asset = CNewAsset("ASSET", CAmount(1), 8, false, false, "");
        BOOST_CHECK_MESSAGE(CheckNewAsset(asset, error), "Test9: " + error);

        // Amount = 0.00000010
        asset = CNewAsset("ASSET", CAmount(10), 7, false, false, "");
        BOOST_CHECK_MESSAGE(CheckNewAsset(asset, error), "Test10: " + error);

        // Amount = 0.00000001
        asset = CNewAsset("ASSET", CAmount(1), 7, false, false, "");
        BOOST_CHECK_MESSAGE(!CheckNewAsset(asset, error), "Test11: " + error);

        // Amount = 0.00000100
        asset = CNewAsset("ASSET", CAmount(100), 6, false, false, "");
        BOOST_CHECK_MESSAGE(CheckNewAsset(asset, error), "Test12: " + error);

        // Amount = 0.00000100
        asset = CNewAsset("ASSET", CAmount(100), 5, false, false, "");
        BOOST_CHECK_MESSAGE(!CheckNewAsset(asset, error), "Test13: " + error);
    }

    BOOST_AUTO_TEST_CASE(asset_tx_enforce_value_test)
    {
        BOOST_TEST_MESSAGE("Running Asset TX Enforce Value Test");

        SelectParams(CBaseChainParams::MAIN);

        // Create the reissue asset
        CReissueAsset reissueAsset("ENFORCE_VALUE", 100, 8, true, "");
        CScript scriptPubKey = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));
        reissueAsset.ConstructTransaction(scriptPubKey);

        // Create an invalid reissue asset with nValue not equal to zero
        CTxOut txOut;
        txOut.nValue = 500;
        txOut.scriptPubKey = scriptPubKey;

        // Create views
        CCoinsView view;
        CCoinsViewCache coins(&view);
        CAssetsCache assetCache;

        // Create a random hash
        uint256 hash = uint256S("BF50CB9A63BE0019171456252989A459A7D0A5F494735278290079D22AB704A2");

        // Add the coin to the cache
        COutPoint outpoint(hash, 1);
        coins.AddCoin(outpoint, Coin(txOut, 10, 0), true);

        // Create input
        CTxIn in;
        in.prevout = outpoint;

        // Create transaction and input for the outpoint of the coin we just created
        CMutableTransaction mutTx;

        // Add the input, and an output into the transaction
        mutTx.vin.emplace_back(in);
        mutTx.vout.emplace_back(txOut);

        CTransaction tx(mutTx);
        CValidationState state;

        bool fCheckMempool = true;
        bool fCheckBlock = false;

        // Check that the CheckTransaction will fail when trying to add it to the mempool
        bool fCheck = !CheckTransaction(tx, state, true, fCheckMempool, fCheckBlock);

        BOOST_CHECK(fCheck);
        BOOST_CHECK(state.GetRejectReason() == "bad-mempool-txns-asset-reissued-amount-isn't-zero");

        // Check that the CheckTransaction will fail when trying to add it to a block
        fCheckMempool = false;
        fCheckBlock = true;
        // Turn on the BIP that enforces the block check
        SetEnforcedValues(true);

        fCheck = !CheckTransaction(tx, state, true, fCheckMempool, fCheckBlock);
        BOOST_CHECK(fCheck);
        BOOST_CHECK(state.GetRejectReason() == "bad-txns-asset-reissued-amount-isn't-zero");
    }

#ifdef ENABLE_WALLET
    BOOST_AUTO_TEST_CASE(asset_tx_enforce_coinbase_test)
    {
        BOOST_TEST_MESSAGE("Running Asset TX Enforce Coinbase Test");

        SelectParams(CBaseChainParams::MAIN);

        // Build wallet
        bitdb.MakeMock();
        std::unique_ptr<CWalletDBWrapper> dbw(new CWalletDBWrapper(&bitdb, "wallet_test.dat"));
        CWallet wallet(std::move(dbw));
        bool firstRun;
        wallet.LoadWallet(firstRun);

        // Build coinbasescript
        std::shared_ptr<CReserveScript> coinbaseScript;
        wallet.GetScriptForMining(coinbaseScript);

        // Create coinbase transaction.
        CMutableTransaction coinbaseTx;
        coinbaseTx.vin.resize(1);
        coinbaseTx.vin[0].prevout.SetNull();

        // Resize the coinbase vout to allow for an additional transaction
        coinbaseTx.vout.resize(2);

        // Add in the initial coinbase data
        coinbaseTx.vout[0].scriptPubKey = coinbaseScript->reserveScript;
        coinbaseTx.vout[0].nValue = GetBlockSubsidy(100, GetParams().GetConsensus());
        coinbaseTx.vin[0].scriptSig = CScript() << 100 << OP_0;

        // Create a transfer asset
        CAssetTransfer transferAsset("COINBASE_TEST", 100);
        CScript scriptPubKey = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));
        transferAsset.ConstructTransaction(scriptPubKey);

        // Add the transfer asset script into the coinbase
        coinbaseTx.vout[1].scriptPubKey = scriptPubKey;
        coinbaseTx.vout[1].nValue = 0;

        // Create the transaction and state objects
        CTransaction tx(coinbaseTx);
        CValidationState state;

        // Setting the coinbase check to true
        // This check should now fail on the CheckTransaction call
        SetEnforcedCoinbase(true);
        bool fCheck = CheckTransaction(tx, state, true);
        BOOST_CHECK(!fCheck);
        BOOST_CHECK(state.GetRejectReason() == "bad-txns-coinbase-contains-asset-txes");

        // Setting the coinbase check to false
        // This check should now pass the CheckTransaction call
        SetEnforcedCoinbase(false);
        fCheck = CheckTransaction(tx, state, true);
        BOOST_CHECK(fCheck);

        // Remove wallet used for testing
        bitdb.Flush(true);
        bitdb.Reset();
    }
#endif

    BOOST_AUTO_TEST_CASE(asset_scripts_normalize_pq_destinations_test)
    {
        BOOST_TEST_MESSAGE("Running Asset PQ witness destination test");

        SelectParams(CBaseChainParams::TESTNET);

        uint256 witnessCommitment(uint256S("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"));
        CTxDestination pqDestination = WitnessV1AuthScript(witnessCommitment);

        CNewAsset newAsset("PQASSET", 1000 * COIN, 0, 1, 0, "");
        CScript newAssetScript = GetScriptForDestination(pqDestination);
        newAsset.ConstructTransaction(newAssetScript);

        int type = 0;
        bool isOwner = false;
        int startIndex = 0;
        BOOST_CHECK(newAssetScript.IsAssetScript(type, isOwner, startIndex));
        BOOST_CHECK_EQUAL(type, TX_NEW_ASSET);
        BOOST_CHECK(!isOwner);
        BOOST_CHECK_EQUAL(newAssetScript[0], OP_1);
        BOOST_CHECK_EQUAL(newAssetScript[34], OP_XNA_ASSET);

        int witnessVersion = 0;
        std::vector<unsigned char> witnessProgram;
        BOOST_CHECK(GetAssetScriptWitnessProgram(newAssetScript, witnessVersion, witnessProgram));
        BOOST_CHECK_EQUAL(witnessVersion, 1);
        BOOST_CHECK_EQUAL(witnessProgram.size(), 32U);

        uint160 indexHash;
        int indexType = DEST_INDEX_NONE;
        BOOST_CHECK(GetScriptDestinationIndexKey(newAssetScript, indexHash, indexType));
        BOOST_CHECK_EQUAL(indexType, DEST_INDEX_WITNESS_V1_AUTHSCRIPT);
        BOOST_CHECK(indexHash == Hash160(witnessCommitment.begin(), witnessCommitment.end()));

        CAssetTransfer transferAsset("PQASSET", 1 * COIN);
        CScript transferScript = GetScriptForDestination(pqDestination);
        transferAsset.ConstructTransaction(transferScript);
        BOOST_CHECK(transferScript.IsAssetScript(type, isOwner, startIndex));
        BOOST_CHECK_EQUAL(type, TX_TRANSFER_ASSET);
        BOOST_CHECK(GetAssetScriptWitnessProgram(transferScript, witnessVersion, witnessProgram));
        BOOST_CHECK(GetScriptDestinationIndexKey(transferScript, indexHash, indexType));
        BOOST_CHECK_EQUAL(indexType, DEST_INDEX_WITNESS_V1_AUTHSCRIPT);

        CReissueAsset reissueAsset("PQASSET", 10 * COIN, 0, 1, "");
        CScript reissueScript = GetScriptForDestination(pqDestination);
        reissueAsset.ConstructTransaction(reissueScript);
        BOOST_CHECK(reissueScript.IsAssetScript(type, isOwner, startIndex));
        BOOST_CHECK_EQUAL(type, TX_REISSUE_ASSET);
        BOOST_CHECK(GetAssetScriptWitnessProgram(reissueScript, witnessVersion, witnessProgram));
        BOOST_CHECK(GetScriptDestinationIndexKey(reissueScript, indexHash, indexType));
        BOOST_CHECK_EQUAL(indexType, DEST_INDEX_WITNESS_V1_AUTHSCRIPT);
    }

    BOOST_AUTO_TEST_CASE(asset_transfer_pq_signs_with_standard_flags_test)
    {
        BOOST_TEST_MESSAGE("Running Asset PQ transfer signing test");

        SelectParams(CBaseChainParams::TESTNET);

        CBasicKeyStore keystore;
        CKey key;
        key.MakeNewKeyPQ();
        CPubKey pubkey = key.GetPubKey();
        BOOST_CHECK(pubkey.IsPQ());
        BOOST_CHECK(keystore.AddKeyPubKey(key, pubkey));
        AddDefaultPQAuthScriptSpendData(keystore, pubkey);

        CTxDestination pqDestination = GetDefaultPQAuthScriptDestination(pubkey);
        CAssetTransfer asset("PQASSET", 1 * COIN);
        CScript assetScript = GetScriptForDestination(pqDestination);
        asset.ConstructTransaction(assetScript);

        CMutableTransaction txFrom;
        txFrom.nVersion = 1;
        txFrom.nLockTime = 0;
        txFrom.vin.resize(1);
        txFrom.vout.resize(1);
        txFrom.vin[0].prevout.SetNull();
        txFrom.vin[0].scriptSig = CScript() << CScriptNum(0) << CScriptNum(0);
        txFrom.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
        txFrom.vout[0].scriptPubKey = assetScript;
        txFrom.vout[0].nValue = 0;

        CMutableTransaction txTo;
        txTo.nVersion = 1;
        txTo.nLockTime = 0;
        txTo.vin.resize(1);
        txTo.vout.resize(1);
        txTo.vin[0].prevout.hash = txFrom.GetHash();
        txTo.vin[0].prevout.n = 0;
        txTo.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
        txTo.vout[0].scriptPubKey = CScript();
        txTo.vout[0].nValue = 0;

        const CTransaction fundingTx(txFrom);
        BOOST_CHECK(SignSignature(keystore, fundingTx, txTo, 0, SIGHASH_ALL));

        ScriptError err = SCRIPT_ERR_UNKNOWN_ERROR;
        const unsigned int flags = SCRIPT_VERIFY_P2SH |
                                   SCRIPT_VERIFY_STRICTENC |
                                   SCRIPT_VERIFY_DERSIG |
                                   SCRIPT_VERIFY_LOW_S |
                                   SCRIPT_VERIFY_WITNESS |
                                   SCRIPT_VERIFY_WITNESS_PUBKEYTYPE |
                                   SCRIPT_VERIFY_AUTHSCRIPT;

        BOOST_CHECK(VerifyScript(txTo.vin[0].scriptSig, assetScript, &txTo.vin[0].scriptWitness,
                                 flags, MutableTransactionSignatureChecker(&txTo, 0, 0), &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
        BOOST_CHECK(txTo.vin[0].scriptSig.empty());
        BOOST_CHECK_EQUAL(txTo.vin[0].scriptWitness.stack.size(), 4U);
    }

    BOOST_AUTO_TEST_CASE(asset_owner_pq_signs_with_standard_policy_test)
    {
        BOOST_TEST_MESSAGE("Running Asset PQ owner signing policy test");

        SelectParams(CBaseChainParams::TESTNET);

        CBasicKeyStore keystore;
        CKey key;
        key.MakeNewKeyPQ();
        CPubKey pubkey = key.GetPubKey();
        BOOST_CHECK(pubkey.IsPQ());
        BOOST_CHECK(keystore.AddKeyPubKey(key, pubkey));
        AddDefaultPQAuthScriptSpendData(keystore, pubkey);

        CTxDestination pqDestination = GetDefaultPQAuthScriptDestination(pubkey);
        CNewAsset asset("PQOWNER", 100 * COIN, 0, 1, 0, "");
        CScript ownerScript = GetScriptForDestination(pqDestination);
        asset.ConstructOwnerTransaction(ownerScript);

        CMutableTransaction txFrom;
        txFrom.nVersion = 1;
        txFrom.nLockTime = 0;
        txFrom.vin.resize(1);
        txFrom.vout.resize(1);
        txFrom.vin[0].prevout.SetNull();
        txFrom.vin[0].scriptSig = CScript() << CScriptNum(0) << CScriptNum(0);
        txFrom.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
        txFrom.vout[0].scriptPubKey = ownerScript;
        txFrom.vout[0].nValue = 0;

        CMutableTransaction txTo;
        txTo.nVersion = 1;
        txTo.nLockTime = 0;
        txTo.vin.resize(1);
        txTo.vout.resize(1);
        txTo.vin[0].prevout.hash = txFrom.GetHash();
        txTo.vin[0].prevout.n = 0;
        txTo.vin[0].nSequence = CTxIn::SEQUENCE_FINAL;
        txTo.vout[0].scriptPubKey = GetScriptForDestination(DecodeDestination(GetParams().GlobalBurnAddress()));
        txTo.vout[0].nValue = 1 * COIN;

        const CTransaction fundingTx(txFrom);
        BOOST_CHECK(SignSignature(keystore, fundingTx, txTo, 0, SIGHASH_ALL));
        BOOST_CHECK(txTo.vin[0].scriptSig.empty());
        BOOST_CHECK_EQUAL(txTo.vin[0].scriptWitness.stack.size(), 4U);

        ScriptError err = SCRIPT_ERR_UNKNOWN_ERROR;
        const unsigned int flags = SCRIPT_VERIFY_P2SH |
                                   SCRIPT_VERIFY_STRICTENC |
                                   SCRIPT_VERIFY_DERSIG |
                                   SCRIPT_VERIFY_LOW_S |
                                   SCRIPT_VERIFY_WITNESS |
                                   SCRIPT_VERIFY_WITNESS_PUBKEYTYPE |
                                   SCRIPT_VERIFY_AUTHSCRIPT;

        BOOST_CHECK(VerifyScript(txTo.vin[0].scriptSig, ownerScript, &txTo.vin[0].scriptWitness,
                                 flags, MutableTransactionSignatureChecker(&txTo, 0, 0), &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);

        std::string reason;
        BOOST_CHECK(IsStandardTx(CTransaction(txTo), reason, true));

        CCoinsView view;
        CCoinsViewCache coins(&view);
        coins.AddCoin(COutPoint(txFrom.GetHash(), 0), Coin(CTxOut(0, ownerScript), 1, false), true);
        BOOST_CHECK(IsWitnessStandard(CTransaction(txTo), coins));
    }

    BOOST_AUTO_TEST_CASE(pq_witness_dummy_signature_test)
    {
        BOOST_TEST_MESSAGE("Running PQ witness dummy signature test");

        SelectParams(CBaseChainParams::TESTNET);

        CBasicKeyStore keystore;
        CKey key;
        key.MakeNewKeyPQ();
        CPubKey pubkey = key.GetPubKey();
        BOOST_CHECK(pubkey.IsPQ());
        BOOST_CHECK(keystore.AddKeyPubKey(key, pubkey));
        AddDefaultPQAuthScriptSpendData(keystore, pubkey);

        CScript witnessScript = GetScriptForDestination(GetDefaultPQAuthScriptDestination(pubkey));
        SignatureData sigdata;

        BOOST_CHECK(ProduceSignature(DummySignatureCreator(&keystore), witnessScript, sigdata));
        BOOST_CHECK(sigdata.scriptSig.empty());
        BOOST_CHECK_EQUAL(sigdata.scriptWitness.stack.size(), 4U);
        BOOST_CHECK_EQUAL(sigdata.scriptWitness.stack[0].size(), 1U);
        BOOST_CHECK_EQUAL(sigdata.scriptWitness.stack[1].size(), ML_DSA_44_SIG_SIZE + 1);
        BOOST_CHECK_EQUAL(sigdata.scriptWitness.stack[1].size(), 1U + ML_DSA_44_PUBKEY_SIZE);
    }

BOOST_AUTO_TEST_SUITE_END()
