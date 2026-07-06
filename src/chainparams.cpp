// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"
#include "arith_uint256.h"

#include <assert.h>
#include <limits>
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
        consensus.nPQWitnessEnabled = false; // PQ not yet active on mainnet
        consensus.nCATEnabled = false;  // OP_CAT (BIP 347) not yet active on mainnet
        consensus.nCTVEnabled = false;  // OP_CTV (BIP 119) not yet active on mainnet
        consensus.nCSFSEnabled = false; // OP_CHECKSIGFROMSTACK not yet active on mainnet
        consensus.nTXHASHEnabled = false;  // OP_TXHASH not yet active on mainnet
        consensus.nTXFIELDEnabled = false; // OP_TXFIELD (NOP7) not yet active on mainnet
        consensus.nSPLITEnabled = false;   // OP_SPLIT (NOP8) not yet active on mainnet
        consensus.nREVERSEBYTESEnabled = false; // OP_REVERSEBYTES not yet active on mainnet
        consensus.nOUTPUTVALUEEnabled = false; // OP_OUTPUTVALUE not yet active on mainnet
        consensus.nOUTPUTSCRIPTEnabled = false; // OP_OUTPUTSCRIPT not yet active on mainnet
        consensus.nOUTPUTASSETFIELDEnabled = false; // OP_OUTPUTASSETFIELD not yet active on mainnet
        consensus.nINPUTASSETFIELDEnabled = false; // OP_INPUTASSETFIELD not yet active on mainnet
        consensus.n64BitIntegersEnabled = false; // 64-bit arithmetic not yet active on mainnet
        consensus.nTXLOCKTIMEEnabled = false; // OP_TXLOCKTIME not yet active on mainnet
        consensus.nINPUTOUTPUTCOUNTEnabled = false; // OP_INPUTCOUNT/OP_OUTPUTCOUNT not yet active on mainnet
        consensus.nREFINPUTSEnabled = false; // NIP-014: tx v3 + vrefin not yet active on mainnet
        consensus.nOUTPUTAUTHCOMMITMENTEnabled = false; // NIP-023: OP_OUTPUTAUTHCOMMITMENT not yet active on mainnet
        consensus.nINPUTVALUEEnabled = false; // NIP-024: OP_INPUTVALUE not yet active on mainnet
        consensus.nCHAINCONTEXTEnabled = false; // NIP-026: OP_CHAINCONTEXT not yet active on mainnet
        consensus.nASSETRBFBlockEnabled = false; // NIP-025: asset-AuthScript RBF ban not yet active on mainnet
        // NIP-028: block-time reduction not active on mainnet
        consensus.nBlockTimeReductionHeight   = std::numeric_limits<int>::max();
        consensus.nPowTargetSpacingPost       = 1 * 60;       // mirror legacy
        consensus.nPowTargetTimespanPost      = 2016 * 60;    // mirror legacy
        consensus.nSubsidyHalvingIntervalPost = 14400;        // mirror legacy
        consensus.nKeccakBlake2bEnabled       = false;        // NIP-030: not active on mainnet
        consensus.nMerkleInclusionEnabled     = false;        // NIP-031: not active on mainnet
        consensus.nModernHashesEnabled        = false;        // NIP-034a: not active on mainnet
        consensus.nPoseidonEnabled            = false;        // NIP-036: not active on mainnet
        consensus.nEd25519Enabled             = false;        // NIP-035: not active on mainnet
        consensus.nCheckSigAddEnabled         = false;        // NIP-039: not active on mainnet
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
        vSeeds.emplace_back("neurai.satopool.com", false);
        vSeeds.emplace_back("seed1.neurai.org", false);
        vSeeds.emplace_back("seed2.neurai.org", false);
        vSeeds.emplace_back("seed3.neurai.org", false);
        vSeeds.emplace_back("neurai-ipv6.neuraiexplorer.com", false);
        vSeeds.emplace_back("neurai-ipv4.neuraiexplorer.com", false);
        vSeeds.emplace_back("main-seed.neurai.top", false);
        vSeeds.emplace_back("node.neurai.org", false);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,53); //N
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,117);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY]    = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY]    = {0x04, 0x88, 0xAD, 0xE4};
        base58Prefixes[EXT_PQ_SECRET_KEY] = {0x04, 0x88, 0xAC, 0x24}; // xpqp... (mainnet)
        strBech32HRP = "nq";

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
                { 216000, uint256S("0x000000000001d989bfce030064cf3693621922cb2425ac6477ae8779600a4261")},
                { 235000, uint256S("0x00000000000148a02dfe4d476bec0e15edb8aba16aa5bbc250d39f9feec94083")},
                { 304000, uint256S("0x000000000001b89a5b02d73f9835199d64e1fac2f276bc7b8783eaa3d8ab2d30")},
                { 432000, uint256S("0x000000000001ce8ae0ee5a9a629ac8434a7e2ed371112a1737dadc5a7ae5b200")},
	            { 1180000, uint256S("0x00000000000b01a49d709ff53ab480765cff9136bbd7237be66fd6ef079faa19")},
                { 1330000, uint256S("0x00000000000e22514b7645a6901c97cf91e227fc9615a536f69ae4e1e53a9785")}
            }
        };

        chainTxData = ChainTxData{
            1762149426, // * UNIX timestamp of last known number of transactions
            1885721,    // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.02      // * estimated number of transactions per second after that timestamp
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
        nMaxReorganizationDepthPost = 60; // mainnet: NIP-028 inactive; mirror legacy
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
        consensus.nPQWitnessEnabled = true; // PQ (ML-DSA-44) active on testnet
        consensus.nCATEnabled = true;  // OP_CAT (BIP 347) active on testnet
        consensus.nCTVEnabled = true;  // OP_CTV (BIP 119) active on testnet
        consensus.nCSFSEnabled = true;  // OP_CHECKSIGFROMSTACK active on testnet
        consensus.nTXHASHEnabled = true;  // OP_TXHASH active on testnet
        consensus.nTXFIELDEnabled = true; // OP_TXFIELD (NOP7) active on testnet
        consensus.nSPLITEnabled = true;   // OP_SPLIT (NOP8) active on testnet
        consensus.nREVERSEBYTESEnabled = true; // OP_REVERSEBYTES active on testnet
        consensus.nOUTPUTVALUEEnabled = true; // OP_OUTPUTVALUE active on testnet
        consensus.nOUTPUTSCRIPTEnabled = true; // OP_OUTPUTSCRIPT active on testnet
        consensus.nOUTPUTASSETFIELDEnabled = true; // OP_OUTPUTASSETFIELD active on testnet
        consensus.nINPUTASSETFIELDEnabled = true; // OP_INPUTASSETFIELD active on testnet
        consensus.n64BitIntegersEnabled = true; // 64-bit arithmetic active on testnet
        consensus.nTXLOCKTIMEEnabled = true; // OP_TXLOCKTIME active on testnet
        consensus.nINPUTOUTPUTCOUNTEnabled = true; // OP_INPUTCOUNT/OP_OUTPUTCOUNT active on testnet
        consensus.nREFINPUTSEnabled = true; // NIP-014: tx v3 + vrefin active on testnet
        consensus.nOUTPUTAUTHCOMMITMENTEnabled = true; // NIP-023: OP_OUTPUTAUTHCOMMITMENT active on testnet
        consensus.nINPUTVALUEEnabled = true; // NIP-024: OP_INPUTVALUE active on testnet
        consensus.nCHAINCONTEXTEnabled = true; // NIP-026: OP_CHAINCONTEXT active on testnet
        consensus.nASSETRBFBlockEnabled = true; // NIP-025: asset-AuthScript RBF ban active on testnet
        // NIP-028: block-time reduction (60s -> 30s) and coupled subsidy halving
        // activate at testnet height 22,700. Halving interval doubled so the
        // wall-clock micro-halving cadence (~10 days) is preserved across the
        // spacing change.
        consensus.nBlockTimeReductionHeight   = 22700;
        consensus.nPowTargetSpacingPost       = 30;
        consensus.nPowTargetTimespanPost      = 2016 * 30;
        consensus.nSubsidyHalvingIntervalPost = 28800;
        consensus.nKeccakBlake2bEnabled       = true;         // NIP-030: active on testnet from genesis
        consensus.nMerkleInclusionEnabled     = true;         // NIP-031: active on testnet from genesis
        consensus.nModernHashesEnabled        = true;         // NIP-034a: active on testnet from genesis
        consensus.nPoseidonEnabled            = true;         // NIP-036: active on testnet from genesis
        consensus.nEd25519Enabled             = true;         // NIP-035: active on testnet from genesis
        consensus.nCheckSigAddEnabled         = true;         // NIP-039: active on testnet from genesis
        consensus.powLimit = uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.kawpowLimit = uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); // Estimated starting diff for first 180 kawpow blocks
        consensus.nPowTargetTimespan = 2016 * 60; // 1.4 days
        consensus.nPowTargetSpacing = 1 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1000; // Approx 80% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1893452400;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].bit = 6;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nTimeout = 1893452400;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_ASSETS].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].bit = 7; 
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nStartTime = 0; 
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nTimeout = 1893452400; //	Mon Dec 31 2029 23:00:00 GMT+0000
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_MSG_REST_ASSETS].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].bit = 8;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nTimeout = 1893452400;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideRuleChangeActivationThreshold = 208;
        consensus.vDeployments[Consensus::DEPLOYMENT_TRANSFER_SCRIPT_SIZE].nOverrideMinerConfirmationWindow = 288;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].bit = 9;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nTimeout = 1893452400;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideRuleChangeActivationThreshold = 108;
        consensus.vDeployments[Consensus::DEPLOYMENT_ENFORCE_VALUE].nOverrideMinerConfirmationWindow = 144;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].bit = 10;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_COINBASE_ASSETS].nTimeout = 1893452400;
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

        // SHA256 testnet: KAWPOW never activates — keeps Bitcoin-style 4-byte nNonce format
        // Must be set BEFORE genesis mining so GetHash() uses the SHA256d path
        nKAAAWWWPOWActivationTime = 0xFFFFFFFF;
        nKAWPOWActivationTime = nKAAAWWWPOWActivationTime;

        // Testnet has a fixed, stable genesis: no automatic epoch reset, no dependency on any
        // local file. The genesis time is a code constant and the block is auto-mined
        // deterministically at startup (same inputs -> same nonce -> same hash), so every node
        // converges on the same genesis. This is the epoch-0 genesis the network has always run
        // (the old auto-reset never fired, so no epoch was ever incremented).
        static const uint32_t TESTNET_BASE_TIME = 1774828800; // 2026-03-30 00:00:00 UTC

        uint32_t nGenesisTime = TESTNET_BASE_TIME;

        // Auto-mine genesis (deterministic). TODO(NIP-hardening): hardcode nonce+hash behind an
        // assert once the genesis hash no longer depends on bNetwork (see finding #17).
        genesis = CreateGenesisBlock(nGenesisTime, 0, 0x1e00ffff, 2, 50000 * COIN);
        {
            arith_uint256 hashTarget = arith_uint256().SetCompact(genesis.nBits);
            while (UintToArith256(genesis.GetHash()) > hashTarget) {
                ++genesis.nNonce;
            }
        }
        consensus.hashGenesisBlock = genesis.GetHash();

        LogPrintf("Testnet genesis — time: %u  nonce: %u  hash: %s\n",
            nGenesisTime, genesis.nNonce,
            consensus.hashGenesisBlock.ToString());

        assert(genesis.hashMerkleRoot == uint256S("4b28bf93d960cd83d1889757381d5a587208464e9075bdc0739151fbe15f5951"));

        vFixedSeeds.clear();
        vSeeds.clear();

        vSeeds.emplace_back("testnet1.neurai.org", false);
        vSeeds.emplace_back("testnet2.neurai.org", false);
        vSeeds.emplace_back("testnet3.neurai.org", false);
        vSeeds.emplace_back("seed-testnet.neurai.org", false);
        vSeeds.emplace_back("testnet.neurai.top", false);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,127); //t
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY]    = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY]    = {0x04, 0x35, 0x83, 0x94};
        base58Prefixes[EXT_PQ_SECRET_KEY] = {0x04, 0x35, 0x81, 0xD5}; // tpqp... (testnet)
        strBech32HRP = "tnq";

        // Neurai BIP44 cointype in testnet
        nExtCoinType = 1;

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
        strReissueAssetBurnAddress = "tAssetXXXXXXXXXXXXXXXXXXXXXXas6pz8";
        strIssueSubAssetBurnAddress = "tSubAssetXXXXXXXXXXXXXXXXXXXXGTvF4";
        strIssueUniqueAssetBurnAddress = "tUniqueAssetXXXXXXXXXXXXXXXXVCgpLs";
        strIssueMsgChannelAssetBurnAddress = "tMsgChanneLAssetXXXXXXXXXXXXVsJoya";
        strIssueQualifierAssetBurnAddress = "tQuaLifierXXXXXXXXXXXXXXXXXXT5czoV";
        strIssueSubQualifierAssetBurnAddress = "tSubQuaLifierXXXXXXXXXXXXXXXW5MmGk";
        strIssueRestrictedAssetBurnAddress = "tRestrictedXXXXXXXXXXXXXXXXXVyPBEK";
        strAddNullQualifierTagBurnAddress = "tTagBurnXXXXXXXXXXXXXXXXXXXXYm6pxA";

        // DGW Activation
        nDGWActivationBlock = 1;

        // NIP-028: pre-22700  60 blocks × 60s = 60 min;
        //          post-22700 120 blocks × 30s = 60 min.
        nMaxReorganizationDepth     = 60;
        nMaxReorganizationDepthPost = 120;
        nMinReorganizationPeers = 6;
        nMinReorganizationAge = 60 * 60 * 12; // 12 hours

        nAssetActivationHeight = 1; // Asset activated block height
        nMessagingActivationBlock = 1; // Messaging activated block height
        nRestrictedActivationBlock = 1; // Restricted activated block height

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
        consensus.nPQWitnessEnabled = true; // PQ (ML-DSA-44) active on regtest
        consensus.nCATEnabled = true;  // OP_CAT (BIP 347) active on regtest
        consensus.nCTVEnabled = true;  // OP_CTV (BIP 119) active on regtest
        consensus.nCSFSEnabled = true;  // OP_CHECKSIGFROMSTACK active on regtest
        consensus.nTXHASHEnabled = true;  // OP_TXHASH active on regtest
        consensus.nTXFIELDEnabled = true; // OP_TXFIELD (NOP7) active on regtest
        consensus.nSPLITEnabled = true;   // OP_SPLIT (NOP8) active on regtest
        consensus.nREVERSEBYTESEnabled = true; // OP_REVERSEBYTES active on regtest
        consensus.nOUTPUTVALUEEnabled = true; // OP_OUTPUTVALUE active on regtest
        consensus.nOUTPUTSCRIPTEnabled = true; // OP_OUTPUTSCRIPT active on regtest
        consensus.nOUTPUTASSETFIELDEnabled = true; // OP_OUTPUTASSETFIELD active on regtest
        consensus.nINPUTASSETFIELDEnabled = true; // OP_INPUTASSETFIELD active on regtest
        consensus.n64BitIntegersEnabled = true; // 64-bit arithmetic active on regtest
        consensus.nTXLOCKTIMEEnabled = true; // OP_TXLOCKTIME active on regtest
        consensus.nINPUTOUTPUTCOUNTEnabled = true; // OP_INPUTCOUNT/OP_OUTPUTCOUNT active on regtest
        consensus.nREFINPUTSEnabled = true; // NIP-014: tx v3 + vrefin active on regtest
        consensus.nOUTPUTAUTHCOMMITMENTEnabled = true; // NIP-023: OP_OUTPUTAUTHCOMMITMENT active on regtest
        consensus.nINPUTVALUEEnabled = true; // NIP-024: OP_INPUTVALUE active on regtest
        consensus.nCHAINCONTEXTEnabled = true; // NIP-026: OP_CHAINCONTEXT active on regtest
        consensus.nASSETRBFBlockEnabled = true; // NIP-025: asset-AuthScript RBF ban active on regtest
        // NIP-028: not active on regtest by default; tests can override via
        // CChainParams::UpdateBlockTimeReduction... if a future opt-in is added.
        consensus.nBlockTimeReductionHeight   = std::numeric_limits<int>::max();
        consensus.nPowTargetSpacingPost       = 1 * 60;
        consensus.nPowTargetTimespanPost      = 2016 * 60;
        consensus.nSubsidyHalvingIntervalPost = 14400;
        consensus.nKeccakBlake2bEnabled       = true;         // NIP-030: active on regtest from genesis
        consensus.nMerkleInclusionEnabled     = true;         // NIP-031: active on regtest from genesis
        consensus.nModernHashesEnabled        = true;         // NIP-034a: active on regtest from genesis
        consensus.nPoseidonEnabled            = true;         // NIP-036: active on regtest from genesis
        consensus.nEd25519Enabled             = true;         // NIP-035: active on regtest from genesis
        consensus.nCheckSigAddEnabled         = true;         // NIP-039: active on regtest from genesis
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

        // SHA256 regtest: KAWPOW never activates — keeps Bitcoin-style 4-byte nNonce format
        // Must be set BEFORE genesis mining so GetHash() uses the SHA256d path
        nKAAAWWWPOWActivationTime = 0xFFFFFFFF;
        nKAWPOWActivationTime = nKAAAWWWPOWActivationTime;

        uint32_t nGenesisTime = 1681720840;

        // Auto-mine genesis with SHA256d (deterministic, instant with 0x207fffff)
        genesis = CreateGenesisBlock(nGenesisTime, 0, 0x207fffff, 2, 50000 * COIN);
        {
            arith_uint256 hashTarget = arith_uint256().SetCompact(genesis.nBits);
            while (UintToArith256(genesis.GetHash()) > hashTarget) {
                ++genesis.nNonce;
            }
        }
        consensus.hashGenesisBlock = genesis.GetHash();

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
        base58Prefixes[EXT_PUBLIC_KEY]    = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY]    = {0x04, 0x35, 0x83, 0x94};
        base58Prefixes[EXT_PQ_SECRET_KEY] = {0x04, 0x35, 0x81, 0xD5}; // tpqp... (regtest)
        strBech32HRP = "rnq";

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
        nMaxReorganizationDepthPost = 60; // regtest: NIP-028 inactive; mirror legacy
        nMinReorganizationPeers = 4;
        nMinReorganizationAge = 60 * 60 * 12;

        nAssetActivationHeight = 0; 
        nMessagingActivationBlock = 0; 
        nRestrictedActivationBlock = 0; 


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
