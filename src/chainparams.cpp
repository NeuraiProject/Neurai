// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2023 The Neurai Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "arith_uint256.h"

#include <assert.h>
#include "chainparamsseeds.h"

//TODO: Take these out
extern double algoHashTotal[16];
extern int algoHashHits[16];


static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << CScriptNum(0) << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Fortune 16/April/2023  Elon Musk agrees A.I. will hit people like an asteroid";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

void CChainParams::TurnOffSegwit() {
	consensus.nSegwitEnabled = false;
}

void CChainParams::TurnOffCSV() {
	consensus.nCSVEnabled = false;
}

void CChainParams::TurnOffBIP34() {
	consensus.nBIP34Enabled = false;
}

void CChainParams::TurnOffBIP65() {
	consensus.nBIP65Enabled = false;
}

void CChainParams::TurnOffBIP66() {
	consensus.nBIP66Enabled = false;
}

bool CChainParams::BIP34() {
	return consensus.nBIP34Enabled;
}

bool CChainParams::BIP65() {
	return consensus.nBIP34Enabled;
}

bool CChainParams::BIP66() {
	return consensus.nBIP34Enabled;
}

bool CChainParams::CSVEnabled() const{
	return consensus.nCSVEnabled;
}


/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
         strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 14400;  // Micro halving every 14400 blocks
        consensus.nBIP34Enabled = true;
        consensus.nBIP65Enabled = true;
        consensus.nBIP66Enabled = true;
        consensus.nSegwitEnabled = true;
        consensus.nCSVEnabled = true;
        consensus.powLimit = uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.kawpowLimit = uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // Estimated starting diff for first 180 kawpow blocks
        consensus.nPowTargetTimespan = 2016 * 60; // 1.4 days
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1000;
        consensus.nMinerConfirmationWindow = 2016;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1684274400;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1704063599; // Sun Dec 31 2023 22:59:59 GMT+0000
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nStartTime = 1684274400;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nTimeout = 1704063599; // Sun Dec 31 2023 22:59:59 GMT+0000
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].bit = 7; 
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nStartTime = 1684274400; 
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nTimeout = 1704063599; // Sun Dec 31 2023 22:59:59 GMT+0000
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].bit = 8;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nStartTime = 1684274400;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nTimeout = 1704063599; // Sun Dec 31 2023 22:59:59 GMT+0000
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideRuleChangeActivationThreshold = 208;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideMinerConfirmationWindow = 288;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nStartTime = 1684274400;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nTimeout = 1704063599; // Sun Dec 31 2023 22:59:59 GMT+0000
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nStartTime = 1684274400;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nTimeout = 1704063599; // Sun Dec 31 2023 22:59:59 GMT+0000
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideRuleChangeActivationThreshold = 400;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideMinerConfirmationWindow = 500;


        uint32_t nGenesisTime = 1681720840;

        // The best chain should have at least this much work
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000bc45d3c25c5f"); // block 58000

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000000155b81afb6ac20009e45eb98c9810fb4dd5501e9f636c7951ae5f768"); // block 58000

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x4e; // N
        pchMessageStart[1] = 0x45; // E
        pchMessageStart[2] = 0x55; // U
        pchMessageStart[3] = 0x52; // R
        nDefaultPort = 19000;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(nGenesisTime, 7131026, 0x1e00ffff, 4, 50000 * COIN);

        consensus.hashGenesisBlock = genesis.GetX16RHash();

        assert(consensus.hashGenesisBlock == uint256S("00000044d33c0c0ba019be5c0249730424a69cb4c222153322f68c6104484806"));
        assert(genesis.hashMerkleRoot == uint256S("4b28bf93d960cd83d1889757381d5a587208464e9075bdc0739151fbe15f5951"));

        vSeeds.emplace_back("dns.neurai.org", false);
        vSeeds.emplace_back("seed1.neuracrypt.org", false);
        vSeeds.emplace_back("seed2.neuracrypt.org", false);
        vSeeds.emplace_back("seed3.neuracrypt.org", false);
        vSeeds.emplace_back("seed4.neuracrypt.org", false);
        vSeeds.emplace_back("neurai.satopool.com", false);
        vSeeds.emplace_back("seed1.neurai.org", false);
        vSeeds.emplace_back("seed2.neurai.org", false);
        vSeeds.emplace_back("seed3.neurai.org", false);
        vSeeds.emplace_back("neurai-ipv6.neuraiexplorer.com", false);
        vSeeds.emplace_back("neurai-ipv4.neuraiexplorer.com", false);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,53); //N
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,117);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        // Neurai BIP44 cointype in mainnet is '0'
        nExtCoinType = 0;

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fMiningRequiresPeers = true;
   
	checkpointData = (CCheckpointData) {
            {
                { 0, genesis.GetHash()},
                { 1000, uint256S("0x000002f94d6d13b28e16b63d31fc1ec8e239c24d984f016832ffd77d1d942be7")},
                { 5000, uint256S("0x00000002c8e014859dcf88659b68bc8e7446f9f768b7ad58345abb0c5728baef")},
                { 10000, uint256S("0x00000001189e35e795f531f86ded4adef83962035e602181355c935734bbf169")},
                { 20000, uint256S("0x00000005883ce924be51c43b617ead2f156c1882c6644e1c3a4f41e7d2c24d3c")},
                { 27000, uint256S("0x00000000ab0d7c1f1e2d8ad3f195474c616e95b7a5d12b20916d0f5a63135cb7")},
                { 37000, uint256S("0x0000000069fcc1a9e0f405afc967ca432271439288d58aa1db7103ef370ca3ff")},
                { 43000, uint256S("0x00000002397ff101430416d3366690b15cf81e9e7ae6d4b44100b24a09f106c8")},
                { 55300, uint256S("0x000000004680b6917faa6c2bb21c5339a1c4b5275aa3e0dd6c19ddfe5e8ec463")},
                { 58150, uint256S("0x00000000155b81afb6ac20009e45eb98c9810fb4dd5501e9f636c7951ae5f768")},
                { 61000, uint256S("0x0000000002441c4a83360da932cfd929048d52ba752464ad793191ef85f956cc")},
                { 70100, uint256S("0x00000000000a431aa2f41657f5b46e3c86fc0489aeba6ea2550054b46ca8c5d1")},
                { 158000, uint256S("0x0000000000024416ff91d4102b2d3b7302929283ad42192e2f09a8539a4cf343")},
                { 190000, uint256S("0x0000000000011d26a3cfdd8cbe23fc223722c82969b86d0a6282bf62558097bd")},
                { 216000, uint256S("0x000000000001d989bfce030064cf3693621922cb2425ac6477ae8779600a4261")}
            }
        };
	    

        chainTxData = ChainTxData{
            nGenesisTime, // * UNIX timestamp of last known number of transactions
            0,    // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0       // * estimated number of transactions per second after that timestamp
        };

        /** XNA Start **/
        // Burn Amounts
        nIssueAssetBurnAmount = 1000 * COIN;
        nReissueAssetBurnAmount = 200 * COIN;
        nIssueSubAssetBurnAmount = 200 * COIN;
        nIssueUniqueAssetBurnAmount = 10 * COIN;
        nIssueMsgChannelAssetBurnAmount = 200 * COIN;
        nIssueQualifierAssetBurnAmount = 2000 * COIN;
        nIssueSubQualifierAssetBurnAmount = 200 * COIN;
        nIssueRestrictedAssetBurnAmount = 3000 * COIN;
        nAddNullQualifierTagBurnAmount = .2 * COIN;
        
        //Global Burn Address
        strGlobalBurnAddress = "NbURNXXXXXXXXXXXXXXXXXXXXXXXT65Gdr";

        // Burn Addresses
        strIssueAssetBurnAddress = "NbURNXXXXXXXXXXXXXXXXXXXXXXXT65Gdr";
        strReissueAssetBurnAddress = "NXReissueAssetXXXXXXXXXXXXXXWLe4Ao";
        strIssueSubAssetBurnAddress = "NXissueSubAssetXXXXXXXXXXXXXX6B2JF";
        strIssueUniqueAssetBurnAddress = "NXissueUniqueAssetXXXXXXXXXXUBzP4Z";
        strIssueMsgChannelAssetBurnAddress = "NXissueMsgChanneLAssetXXXXXXTUzrtJ";
        strIssueQualifierAssetBurnAddress = "NXissueQuaLifierXXXXXXXXXXXXWurNcU";
        strIssueSubQualifierAssetBurnAddress = "NXissueSubQuaLifierXXXXXXXXXV71vM3";
        strIssueRestrictedAssetBurnAddress = "NXissueRestrictedXXXXXXXXXXXWpXx4H";
        strAddNullQualifierTagBurnAddress = "NXaddTagBurnXXXXXXXXXXXXXXXXWucUTr";

        // DGW Activation
        nDGWActivationBlock = 1;

        nMaxReorganizationDepth = 60; // 60 at 1 minute block timespan is +/- 60 minutes.
        nMinReorganizationPeers = 6;
        nMinReorganizationAge = 60 * 60 * 12; // 12 hours

        nAssetActivationHeight = 10; // Asset activated block height
        nMessagingActivationBlock = 10; // Messaging activated block height
        nRestrictedActivationBlock = 10; // Restricted activated block height
	    
        nKAAAWWWPOWActivationTime = nGenesisTime + 1; 
        nKAWPOWActivationTime = nKAAAWWWPOWActivationTime;
    }
};

/**
 * Testnet (v7)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 14400;  // Micro halving every 14400 blocks
        consensus.nBIP34Enabled = true;
        consensus.nBIP65Enabled = true;
        consensus.nBIP66Enabled = true;
        consensus.nSegwitEnabled = true;
        consensus.nCSVEnabled = true;
        consensus.powLimit = uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.kawpowLimit = uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // Estimated starting diff for first 180 kawpow blocks
        consensus.nPowTargetTimespan = 2016 * 60; // 1.4 days
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1000; // Approx 80% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1704063599;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nTimeout = 1704063599;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].bit = 7; 
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nStartTime = 0; 
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nTimeout = 1704063599; // Sun Dec 31 2023 22:59:59 GMT+0000
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].bit = 8;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nTimeout = 1704063599;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideRuleChangeActivationThreshold = 208;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideMinerConfirmationWindow = 288;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nTimeout = 1704063599;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nTimeout = 1704063599;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideRuleChangeActivationThreshold = 400;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideMinerConfirmationWindow = 500;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");


        pchMessageStart[0] = 0x52; // R
        pchMessageStart[1] = 0x55; // U
        pchMessageStart[2] = 0x45; // E
        pchMessageStart[3] = 0x4e; // N
        nDefaultPort = 19100;
        nPruneAfterHeight = 1000;

        uint32_t nGenesisTime = 1681720840; 


        genesis = CreateGenesisBlock(nGenesisTime, 57837983, 0x1e00ffff, 2, 50000 * COIN);
        consensus.hashGenesisBlock = genesis.GetX16RHash();

        //Test MerkleRoot and GenesisBlock
        assert(consensus.hashGenesisBlock == uint256S("0000006af8b8297448605b0283473ec712f9768f81cc7eae6269b875dee3b0cf"));
        assert(genesis.hashMerkleRoot == uint256S("4b28bf93d960cd83d1889757381d5a587208464e9075bdc0739151fbe15f5951"));

        vFixedSeeds.clear();
        vSeeds.clear();

        vSeeds.emplace_back("testnet1.neuracrypt.org", false);
        vSeeds.emplace_back("testnet2.neuracrypt.org", false);
        vSeeds.emplace_back("testnet3.neuracrypt.org", false);
        vSeeds.emplace_back("testnet1.neurai.org", false);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,127); //t
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // Neurai BIP44 cointype in testnet
        nExtCoinType = 0;

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fMiningRequiresPeers = true;

        checkpointData = (CCheckpointData) {
            {
              {0, genesis.GetHash()}
            }
        };

        chainTxData = ChainTxData{
            nGenesisTime, // * UNIX timestamp of last known number of transactions
            0,          // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0           // * estimated number of transactions per second after that timestamp
        };

        /** XNA Start **/
        // Burn Amounts
        nIssueAssetBurnAmount = 1000 * COIN;
        nReissueAssetBurnAmount = 200 * COIN;
        nIssueSubAssetBurnAmount = 200 * COIN;
        nIssueUniqueAssetBurnAmount = 10 * COIN;
        nIssueMsgChannelAssetBurnAmount = 200 * COIN;
        nIssueQualifierAssetBurnAmount = 2000 * COIN;
        nIssueSubQualifierAssetBurnAmount = 200 * COIN;
        nIssueRestrictedAssetBurnAmount = 3000 * COIN;
        nAddNullQualifierTagBurnAmount = .2 * COIN;

        //Global Burn Address
        strGlobalBurnAddress = "tBURNXXXXXXXXXXXXXXXXXXXXXXXVZLroy";

        // Burn Addresses
        strIssueAssetBurnAddress = strGlobalBurnAddress;
        strReissueAssetBurnAddress = "tXReissueAssetXXXXXXXXXXXXXXYmsjpM";
        strIssueSubAssetBurnAddress = "tXissueSubAssetXXXXXXXXXXXXXW53F8Q";
        strIssueUniqueAssetBurnAddress = "tXissueUniqueAssetXXXXXXXXXXSChvqQ";
        strIssueMsgChannelAssetBurnAddress = "tXissueMsgChanneLAssetXXXXXXVFmW2d";
        strIssueQualifierAssetBurnAddress = "tXissueQuaLifierXXXXXXXXXXXXTfjTyH";
        strIssueSubQualifierAssetBurnAddress = "tXissueSubQuaLifierXXXXXXXXXYmbjCh";
        strIssueRestrictedAssetBurnAddress = "tXissueRestrictedXXXXXXXXXXXbvd3Ug";
        strAddNullQualifierTagBurnAddress = "tXaddTagBurnXXXXXXXXXXXXXXXXYXaTg1";

        // DGW Activation
        nDGWActivationBlock = 1;

        nMaxReorganizationDepth = 60; // 60 at 1 minute block timespan is +/- 60 minutes.
        nMinReorganizationPeers = 6;
        nMinReorganizationAge = 60 * 60 * 12; // 12 hours

        nAssetActivationHeight = 10; // Asset activated block height
        nMessagingActivationBlock = 10; // Messaging activated block height
        nRestrictedActivationBlock = 10; // Restricted activated block height
	    
        nKAAAWWWPOWActivationTime = nGenesisTime + 1;
        nKAWPOWActivationTime = nKAAAWWWPOWActivationTime;
        /** XNA End **/
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 14400;  // Micro halving every 14400 blocks
        consensus.nBIP34Enabled = true;
        consensus.nBIP65Enabled = true;
        consensus.nBIP66Enabled = true;
        consensus.nSegwitEnabled = true;
        consensus.nCSVEnabled = true;
        consensus.powLimit = uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.kawpowLimit = uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // Estimated starting diff for first 180 kawpow blocks
        consensus.nPowTargetTimespan = 2016 * 60; // 1.4 days
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1000; 
        consensus.nMinerConfirmationWindow = 2016; 
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1704063599;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nTimeout = 1704063599;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].bit = 7; 
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nStartTime = 0; 
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nTimeout = 1704063599; // Sun Dec 31 2023 22:59:59 GMT+0000
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].bit = 8;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nTimeout = 1704063599;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideRuleChangeActivationThreshold = 208;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideMinerConfirmationWindow = 288;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nTimeout = 1704063599;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nTimeout = 1704063599;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideRuleChangeActivationThreshold = 400;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nOverrideMinerConfirmationWindow = 500;


        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0x52; // R
        pchMessageStart[1] = 0x55; // U
        pchMessageStart[2] = 0x45; // E
        pchMessageStart[3] = 0x4e; // N
        nDefaultPort = 19200;
        nPruneAfterHeight = 1000;

        uint32_t nGenesisTime = 1681720840;


        genesis = CreateGenesisBlock(nGenesisTime, 1, 0x207fffff, 4, 50000 * COIN);
        consensus.hashGenesisBlock = genesis.GetX16RHash();

        assert(consensus.hashGenesisBlock == uint256S("0x0b2c703dc93bb63a36c4e33b85be4855ddbca2ac951a7a0a29b8de0408200a3c "));
        assert(genesis.hashMerkleRoot == uint256S("4b28bf93d960cd83d1889757381d5a587208464e9075bdc0739151fbe15f5951"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = (CCheckpointData) {
            {
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,127); //t
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        // Neurai BIP44 cointype in regtest
        nExtCoinType = 1;

        /** XNA Start **/
        // Burn Amounts
        nIssueAssetBurnAmount = 1000 * COIN;
        nReissueAssetBurnAmount = 200 * COIN;
        nIssueSubAssetBurnAmount = 200 * COIN;
        nIssueUniqueAssetBurnAmount = 10 * COIN;
        nIssueMsgChannelAssetBurnAmount = 200 * COIN;
        nIssueQualifierAssetBurnAmount = 2000 * COIN;
        nIssueSubQualifierAssetBurnAmount = 200 * COIN;
        nIssueRestrictedAssetBurnAmount = 3000 * COIN;
        nAddNullQualifierTagBurnAmount = .2 * COIN;

        //Global Burn Address
        strGlobalBurnAddress = "tBURNXXXXXXXXXXXXXXXXXXXXXXXVZLroy";

        // Burn Addresses
        strIssueAssetBurnAddress = strGlobalBurnAddress;
        strReissueAssetBurnAddress = strGlobalBurnAddress;
        strIssueSubAssetBurnAddress = strGlobalBurnAddress;
        strIssueUniqueAssetBurnAddress = strGlobalBurnAddress;
        strIssueMsgChannelAssetBurnAddress = strGlobalBurnAddress;
        strIssueQualifierAssetBurnAddress = strGlobalBurnAddress;
        strIssueSubQualifierAssetBurnAddress = strGlobalBurnAddress;
        strIssueRestrictedAssetBurnAddress = strGlobalBurnAddress;
        strAddNullQualifierTagBurnAddress = strGlobalBurnAddress;

        // DGW Activation
        nDGWActivationBlock = 200;

        nMaxReorganizationDepth = 60; 
        nMinReorganizationPeers = 4;
        nMinReorganizationAge = 60 * 60 * 12; 

        nAssetActivationHeight = 0; 
        nMessagingActivationBlock = 0; 
        nRestrictedActivationBlock = 0; 


        nKAAAWWWPOWActivationTime = 3582830167;
        nKAWPOWActivationTime = nKAAAWWWPOWActivationTime;
        /** XNA End **/
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &GetParams() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network, bool fForceBlockNetwork)
{
    SelectBaseParams(network);
    if (fForceBlockNetwork) {
        bNetwork.SetNetwork(network);
    }
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}

void TurnOffSegwit(){
	globalChainParams->TurnOffSegwit();
}

void TurnOffCSV() {
	globalChainParams->TurnOffCSV();
}

void TurnOffBIP34() {
	globalChainParams->TurnOffBIP34();
}

void TurnOffBIP65() {
	globalChainParams->TurnOffBIP65();
}

void TurnOffBIP66() {
	globalChainParams->TurnOffBIP66();
}
