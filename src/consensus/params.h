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
    /** NIP-023: Enable OP_OUTPUTAUTHCOMMITMENT - push the 32-byte AuthScript v1
     *  commitment of a selected output's scriptPubKey. Symmetric to
     *  TXFIELD_SPENT_AUTHCOMMITMENT for inputs. true on testnet/regtest;
     *  false on mainnet until future activation. */
    bool nOUTPUTAUTHCOMMITMENTEnabled;
    /** NIP-024: Enable OP_INPUTVALUE - push the XNA satoshi value of a selected
     *  input's prevout. Symmetric to OP_OUTPUTVALUE. true on testnet/regtest;
     *  false on mainnet until future activation. */
    bool nINPUTVALUEEnabled;
    /** NIP-026: Enable OP_CHAINCONTEXT (selectors HEIGHT, MTP, CHAIN_ID).
     *  true on testnet/regtest; false on mainnet until future activation.
     *  ApplyConsensusOptIns co-sets SCRIPT_VERIFY_64BIT_INTEGERS whenever
     *  this is true — MTP after 2038 does not fit in a 4-byte CScriptNum. */
    bool nCHAINCONTEXTEnabled;
    /** NIP-025: If a transaction spends at least one asset-wrapped AuthScript v1
     *  UTXO, require nSequence >= 0xfffffffe on every input of that transaction.
     *  Covers DEX partial-fill covenants AND plain asset transfers to PQ
     *  (witness-v1) addresses — the predicate cannot distinguish the two at
     *  consensus level. true on testnet/regtest; false on mainnet until future
     *  activation. */
    bool nASSETRBFBlockEnabled;
    /** Strict rejection of outputs that contain OP_XNA_ASSET but are not a
     *  valid asset/null-asset script. The legacy (origin/main) rule accepts
     *  such an output when its script *starts* with OP_XNA_ASSET; the strict
     *  rule rejects it outright. Enabling this retroactively would fork mainnet
     *  history, so it is false on mainnet (origin/main behaviour) until the
     *  unified fork and true on testnet/regtest, where it is already consensus.
     *  See NIP/revision/010. */
    bool nXNAAssetStrictEnabled;
    /** NIP-040: height at which the asset marker migrates from "rvn" to
     *  "xna". Below this height ordinary asset outputs must carry the legacy
     *  "rvn" marker and "xna" outputs are invalid; at and above it the rule
     *  inverts. Inputs are never affected: legacy UTXOs stay spendable
     *  forever. std::numeric_limits<int>::max() on chains that have not
     *  scheduled the fork (mainnet until the second release). See NIP/040. */
    int nAssetMarkerNip040Height;
    /** Enable the height-based shortcut in AreAssetsDeployed()/IsRip5Active()
     *  (assets/RIP5 active once the tip reaches nAssetActivationHeight /
     *  nMessagingActivationBlock). This is meant for fresh test networks. On
     *  mainnet it must be false so those functions depend solely on VersionBits,
     *  exactly like origin/main — the shortcut with mainnet height 10 would
     *  activate assets on historical blocks that predate the real deployment and
     *  break IBD. true on testnet; true on regtest too but inert there (its
     *  heights are 0, so the shortcut's `> 0` guard skips it → VersionBits).
     *  See NIP/revision/004. */
    bool nAssetRip5ActivationByHeightEnabled;
    /** NIP-028: activation height for the testnet block-time reduction
     *  (60s → 30s) and coupled subsidy halving. Set to
     *  std::numeric_limits<int>::max() to disable on chains that did
     *  not opt in (mainnet, regtest by default). At and after this
     *  height the chain consensus rules use:
     *    - nPowTargetSpacingPost           (= 30 on testnet)
     *    - nPowTargetTimespanPost          (= 2016 * 30 on testnet)
     *    - nSubsidyHalvingIntervalPost     (= 28800, doubled so the
     *      wall-clock halving cadence ~10 days is preserved across the
     *      spacing change)
     *    - GetBlockSubsidy()               halved at this height
     *    - block.nVersion                  must carry VERSIONBITS_FLAG_NIP028 */
    int     nBlockTimeReductionHeight;
    int64_t nPowTargetSpacingPost;
    int64_t nPowTargetTimespanPost;
    int     nSubsidyHalvingIntervalPost;
    /** NIP-030: enable OP_KECCAK256 (0xba) and OP_BLAKE2B (0xbb)
     *  hash opcodes. Both occupy previously unassigned slots
     *  (`bad-opcode` pre-NIP-030); activation is a hard-fork
     *  relative to the pre-NIP-030 rules. true on testnet/regtest
     *  from genesis; false on mainnet until a future activation
     *  NIP. */
    bool nKeccakBlake2bEnabled;
    /** NIP-031: enable OP_CHECKMERKLEINCLUSION (0xc1) — native
     *  Merkle inclusion verification with a tree-scheme selector
     *  (BITCOIN_NEURAI / SHA256_PLAIN / KECCAK256_PLAIN /
     *  BLAKE2B_PLAIN). Slot 0xc1 was previously unassigned
     *  (`bad-opcode`); activation is a hard-fork. Co-extends the
     *  per-element stack cap to MAX_PQ_SCRIPT_ELEMENT_SIZE (3072 B)
     *  and the MAX_STACK_BYTES gate. true on testnet/regtest from
     *  genesis; false on mainnet until a future activation NIP. */
    bool nMerkleInclusionEnabled;
    /** NIP-034a: enable OP_BLAKE3 (0xc8), OP_SHA3_256 (0xca) and
     *  OP_SHA512 (0xcb) hash opcodes. All three slots were
     *  previously unassigned (`bad-opcode`); activation is a
     *  hard-fork. OP_POSEIDON (0xc9) is intentionally NOT covered
     *  by this flag and stays bad-opcode pending its own NIP.
     *  true on testnet/regtest from genesis; false on mainnet
     *  until a future activation NIP. */
    bool nModernHashesEnabled;

    /** NIP-036: enable OP_POSEIDON (0xc9), the SNARK-friendly
     *  Poseidon hash over the BN254 scalar field. Slot was
     *  previously unassigned (`bad-opcode`); activation is a
     *  hard-fork. true on testnet/regtest from genesis; false
     *  on mainnet until a future activation NIP. */
    bool nPoseidonEnabled;

    /** NIP-035: enable OP_CHECKSIG_ED25519 (0xdd), the strict-profile
     *  RFC 8032 PureEd25519 signature verifier. Slot was previously
     *  unassigned (`bad-opcode`); activation is a hard-fork. true on
     *  testnet/regtest from genesis; false on mainnet until a future
     *  activation NIP. Activation also widens the large-witness
     *  standardness gate so messages > 80 B can be relayed. */
    bool nEd25519Enabled;

    /** NIP-039: enable OP_CHECKSIGADD (0xde), a generic signature
     *  accumulator compatible with legacy and PQ CPubKey encodings.
     *  Slot was previously unassigned (`bad-opcode`); activation is
     *  a hard-fork. true on testnet/regtest from genesis; false on
     *  mainnet until a future activation NIP. Activation also widens
     *  the per-element script cap and the large-witness standardness
     *  gate so PQ-sized signatures and pubkeys can flow through. */
    bool nCheckSigAddEnabled;
};
} // namespace Consensus

#endif // NEURAI_CONSENSUS_PARAMS_H
