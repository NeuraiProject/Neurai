// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_CONSENSUS_PARAMS_H
#define NEURAI_CONSENSUS_PARAMS_H

#include "uint256.h"
#include <map>
#include <string>

namespace Consensus {

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_ASSETS, // Deployment of RIP2
    DEPLOYMENT_MSG_REST_ASSETS, // Delpoyment of RIP5 and Restricted assets
    DEPLOYMENT_TRANSFER_SCRIPT_SIZE,
    DEPLOYMENT_ENFORCE_VALUE,
    DEPLOYMENT_COINBASE_ASSETS,
    // DEPLOYMENT_CSV, // Deployment of BIP68, BIP112, and BIP113.
//    DEPLOYMENT_SEGWIT, // Deployment of BIP141, BIP143, and BIP147.
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;
    /** Use to override the confirmation window on a specific BIP */
    uint32_t nOverrideMinerConfirmationWindow;
    /** Use to override the the activation threshold on a specific BIP */
    uint32_t nOverrideRuleChangeActivationThreshold;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /** Block height and hash at which BIP34 becomes active */
    bool nBIP34Enabled;
    bool nBIP65Enabled;
    bool nBIP66Enabled;
    // uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    // int BIP65Height;
    /** Block height at which BIP66 becomes active */
    // int BIP66Height;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    uint256 kawpowLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;
    bool nSegwitEnabled;
    bool nCSVEnabled;
    /** Enable post-quantum (ML-DSA-44) witness v1 verification.
     *  true on testnet/regtest; false on mainnet until future activation. */
    bool nPQWitnessEnabled;
    /** Enable OP_CAT (BIP 347) - stack element concatenation.
     *  true on testnet/regtest; false on mainnet until future activation. */
    bool nCATEnabled;
    /** Enable OP_CHECKTEMPLATEVERIFY (BIP 119) - transaction template verification.
     *  true on testnet/regtest; false on mainnet until future activation. */
    bool nCTVEnabled;
    /** Enable OP_CHECKSIGFROMSTACK - verify signature against arbitrary message.
     *  true on testnet/regtest; false on mainnet until future activation. */
    bool nCSFSEnabled;
    /** Enable OP_TXHASH - push hash of selected transaction fields to stack.
     *  true on testnet/regtest; false on mainnet until future activation. */
    bool nTXHASHEnabled;
    /** Enable OP_TXFIELD (NOP7) - push raw bytes of spent output fields to stack.
     *  Required for recursive DEX covenants. true on testnet/regtest; false on mainnet. */
    bool nTXFIELDEnabled;
    /** Enable OP_SPLIT (NOP8) - split a byte array into two parts at a given position.
     *  Inverse of OP_CAT. true on testnet/regtest; false on mainnet until future activation. */
    bool nSPLITEnabled;
    /** Enable OP_REVERSEBYTES - reverse the top stack item in place.
     *  true on testnet/regtest; false on mainnet until future activation. */
    bool nREVERSEBYTESEnabled;
    /** Enable OP_OUTPUTVALUE - push the amount of a selected output as raw
     *  8-byte little-endian data. true on testnet/regtest; false on mainnet. */
    bool nOUTPUTVALUEEnabled;
    /** Enable OP_OUTPUTSCRIPT - push the scriptPubKey of a selected output
     *  as raw bytes. true on testnet/regtest; false on mainnet. */
    bool nOUTPUTSCRIPTEnabled;
    /** Enable OP_OUTPUTASSETFIELD - read asset payload fields from a selected
     *  output by selector. true on testnet/regtest; false on mainnet. */
    bool nOUTPUTASSETFIELDEnabled;
    /** Enable OP_INPUTASSETFIELD - read asset payload fields from a selected
     *  prevout referenced by an input. true on testnet/regtest; false on mainnet. */
    bool nINPUTASSETFIELDEnabled;
    /** Enable 64-bit arithmetic and OP_MUL/OP_DIV/OP_MOD. true on
     *  testnet/regtest; false on mainnet until future activation. */
    bool n64BitIntegersEnabled;
    /** Enable OP_TXLOCKTIME - push transaction nLockTime as raw 4-byte
     *  little-endian data. true on testnet/regtest; false on mainnet. */
    bool nTXLOCKTIMEEnabled;
    /** Enable OP_INPUTCOUNT / OP_OUTPUTCOUNT - push transaction input/output
     *  count onto the stack. true on testnet/regtest; false on mainnet. */
    bool nINPUTOUTPUTCOUNTEnabled;
    /** NIP-014: Enable transaction v3 with reference inputs (vrefin) and
     *  OP_REFINPUT* opcodes. true on testnet/regtest; false on mainnet. */
    bool nREFINPUTSEnabled;
};
} // namespace Consensus

#endif // NEURAI_CONSENSUS_PARAMS_H
