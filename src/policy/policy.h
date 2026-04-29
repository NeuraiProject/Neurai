// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2021 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_POLICY_POLICY_H
#define NEURAI_POLICY_POLICY_H

#include "consensus/consensus.h"
#include "consensus/params.h"
#include "feerate.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/standard.h"

#include <string>

class CCoinsViewCache;
class CTxOut;

/** Default for -blockmaxweight, which controls the range of block weights the mining code will create **/
// Deprecated with RIP2 implementation
//static const unsigned int DEFAULT_BLOCK_MAX_WEIGHT = MAX_BLOCK_WEIGHT - 4000;
///** Default for -blockmintxfee, which sets the minimum feerate for a transaction in blocks created by mining code **/
static const unsigned int DEFAULT_BLOCK_MIN_TX_FEE = 1000;
/** The maximum weight for transactions we're willing to relay/mine */
static const unsigned int MAX_STANDARD_TX_WEIGHT = 400000;
/** Maximum number of signature check operations in an IsStandard() P2SH script */
static const unsigned int MAX_P2SH_SIGOPS = 15;
/** The maximum number of sigops we're willing to relay/mine in a single tx */
static const unsigned int MAX_STANDARD_TX_SIGOPS_COST = MAX_BLOCK_SIGOPS_COST/5;
/** Default for -maxmempool, maximum megabytes of mempool memory usage */
static const unsigned int DEFAULT_MAX_MEMPOOL_SIZE = 300;
/** Default for -incrementalrelayfee, which sets the minimum feerate increase for mempool limiting or BIP 125 replacement **/
static const unsigned int DEFAULT_INCREMENTAL_RELAY_FEE = 1000;
/** Default for -bytespersigop */
static const unsigned int DEFAULT_BYTES_PER_SIGOP = 20;
/** The maximum number of witness stack items in a standard P2WSH script */
static const unsigned int MAX_STANDARD_P2WSH_STACK_ITEMS = 100;
/** The maximum size of each witness stack item in a standard P2WSH script */
static const unsigned int MAX_STANDARD_P2WSH_STACK_ITEM_SIZE = 80;
/** The maximum size of each witness stack item in a standard P2WSH script
 *  when CSFS is active (NIP-021). Matches EffectiveMaxScriptElementSize
 *  in interpreter.h under SCRIPT_VERIFY_CHECKSIGFROMSTACK. */
static const unsigned int MAX_CSFS_STANDARD_P2WSH_STACK_ITEM_SIZE = MAX_PQ_SCRIPT_ELEMENT_SIZE;
/** The maximum size of a standard witnessScript */
static const unsigned int MAX_STANDARD_P2WSH_SCRIPT_SIZE = 3600;
/** NIP-014: Maximum number of reference inputs in a standard v3 transaction */
static const unsigned int MAX_STANDARD_REFINPUTS = 64;
/** Min feerate for defining dust. Historically this has been based on the
 * minRelayTxFee, however changing the dust limit changes which transactions are
 * standard and should be done with care and ideally rarely. It makes sense to
 * only increase the dust limit after prior releases were already not creating
 * outputs below the new threshold */
static const unsigned int DUST_RELAY_TX_FEE = 3000;
/**
 * Standard script verification flags that standard transactions will comply
 * with. However scripts violating these flags may still be present in valid
 * blocks and we must accept those blocks.
 */
static constexpr script_verify_flags STANDARD_SCRIPT_VERIFY_FLAGS = MANDATORY_SCRIPT_VERIFY_FLAGS |
                                                         SCRIPT_VERIFY_DERSIG |
                                                         SCRIPT_VERIFY_STRICTENC |
                                                         SCRIPT_VERIFY_MINIMALDATA |
                                                         SCRIPT_VERIFY_NULLDUMMY |
                                                         SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS |
                                                         SCRIPT_VERIFY_CLEANSTACK |
                                                         SCRIPT_VERIFY_MINIMALIF |
                                                         SCRIPT_VERIFY_NULLFAIL |
                                                         SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY |
                                                         SCRIPT_VERIFY_CHECKSEQUENCEVERIFY |
                                                         SCRIPT_VERIFY_LOW_S |
                                                         SCRIPT_VERIFY_WITNESS |
                                                         SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM |
                                                         SCRIPT_VERIFY_WITNESS_PUBKEYTYPE;

/** For convenience, standard but not mandatory verify flags. */
static constexpr script_verify_flags STANDARD_NOT_MANDATORY_VERIFY_FLAGS = STANDARD_SCRIPT_VERIFY_FLAGS & ~MANDATORY_SCRIPT_VERIFY_FLAGS;

/**
 * NIP-020: ORs every consensus-activated opt-in flag into `base` and returns
 * the result.  Used directly by validation.cpp (AcceptToMemoryPool,
 * GetBlockScriptFlags) and indirectly through
 * GetStandardScriptVerifyFlagsWithConsensusOptIns by non-consensus paths.
 */
inline script_verify_flags ApplyConsensusOptIns(script_verify_flags base,
                                                const Consensus::Params& consensus)
{
    if (consensus.nPQWitnessEnabled)        base |= SCRIPT_VERIFY_AUTHSCRIPT;
    if (consensus.nCATEnabled)              base |= SCRIPT_VERIFY_CAT;
    if (consensus.nCTVEnabled)              base |= SCRIPT_VERIFY_CHECKTEMPLATEVERIFY;
    if (consensus.nCSFSEnabled)             base |= SCRIPT_VERIFY_CHECKSIGFROMSTACK;
    if (consensus.nTXHASHEnabled)           base |= SCRIPT_VERIFY_TXHASH;
    if (consensus.nTXFIELDEnabled)          base |= SCRIPT_VERIFY_TXFIELD;
    if (consensus.nSPLITEnabled)            base |= SCRIPT_VERIFY_SPLIT;
    if (consensus.nREVERSEBYTESEnabled)     base |= SCRIPT_VERIFY_REVERSEBYTES;
    if (consensus.nOUTPUTVALUEEnabled)      base |= SCRIPT_VERIFY_OUTPUTVALUE;
    if (consensus.nOUTPUTSCRIPTEnabled)     base |= SCRIPT_VERIFY_OUTPUTSCRIPT;
    if (consensus.nOUTPUTASSETFIELDEnabled) base |= SCRIPT_VERIFY_OUTPUTASSETFIELD;
    if (consensus.nINPUTASSETFIELDEnabled)  base |= SCRIPT_VERIFY_INPUTASSETFIELD;
    if (consensus.n64BitIntegersEnabled)    base |= SCRIPT_VERIFY_64BIT_INTEGERS;
    if (consensus.nTXLOCKTIMEEnabled)       base |= SCRIPT_VERIFY_TXLOCKTIME;
    if (consensus.nINPUTOUTPUTCOUNTEnabled) base |= SCRIPT_VERIFY_INPUTOUTPUTCOUNT;
    if (consensus.nREFINPUTSEnabled)        base |= SCRIPT_VERIFY_REFINPUTS;
    if (consensus.nOUTPUTAUTHCOMMITMENTEnabled) base |= SCRIPT_VERIFY_OUTPUTAUTHCOMMITMENT;
    if (consensus.nINPUTVALUEEnabled)        base |= SCRIPT_VERIFY_INPUTVALUE;
    // NIP-026: OP_CHAINCONTEXT pushes up to 8-byte values (MTP exceeds
    // 4 bytes after 2038), so it must be co-set with 64BIT_INTEGERS.
    // The handler re-checks this at runtime as belt-and-braces (§3.7).
    if (consensus.nCHAINCONTEXTEnabled)      base |= SCRIPT_VERIFY_CHAINCONTEXT
                                                   | SCRIPT_VERIFY_64BIT_INTEGERS;
    // NIP-030: OP_KECCAK256 and OP_BLAKE2B hash opcodes.
    if (consensus.nKeccakBlake2bEnabled)     base |= SCRIPT_VERIFY_KECCAK_BLAKE2B;
    // NIP-031: OP_CHECKMERKLEINCLUSION (native Merkle proof verifier).
    if (consensus.nMerkleInclusionEnabled)   base |= SCRIPT_VERIFY_MERKLE_INCLUSION;
    // NIP-034a: OP_BLAKE3 / OP_SHA3_256 / OP_SHA512.
    if (consensus.nModernHashesEnabled)      base |= SCRIPT_VERIFY_MODERN_HASHES;
    return base;
}

/** NIP-020: convenience wrapper — STANDARD_SCRIPT_VERIFY_FLAGS | opt-ins. */
inline script_verify_flags GetStandardScriptVerifyFlagsWithConsensusOptIns(
    const Consensus::Params& consensus)
{
    return ApplyConsensusOptIns(STANDARD_SCRIPT_VERIFY_FLAGS, consensus);
}

/** Used as the flags parameter to sequence and nLocktime checks in non-consensus code. */
static const unsigned int STANDARD_LOCKTIME_VERIFY_FLAGS = LOCKTIME_VERIFY_SEQUENCE |
                                                           LOCKTIME_MEDIAN_TIME_PAST;

CAmount GetDustThreshold(const CTxOut& txout, const CFeeRate& dustRelayFee);

bool IsDust(const CTxOut& txout, const CFeeRate& dustRelayFee);

bool IsStandard(const CScript& scriptPubKey, txnouttype& whichType, const bool witnessEnabled = false);
    /**
     * Check for standard transaction types
     * @return True if all outputs (scriptPubKeys) use only standard transaction forms
     */
bool IsStandardTx(const CTransaction& tx, std::string& reason, const bool witnessEnabled = false);
    /**
     * Check for standard transaction types
     * @param[in] mapInputs    Map of previous transactions that have outputs we're spending
     * @return True if all inputs (scriptSigs) use only standard transaction forms
     */
bool AreInputsStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs);
    /**
     * Check if the transaction is over standard P2WSH resources limit:
     * 3600bytes witnessScript size, 100 witness stack elements.
     * Per-item size: 80 bytes when largeWitnessItemsActive is false;
     * MAX_PQ_SCRIPT_ELEMENT_SIZE (3072 bytes) when true. The wider cap is
     * activated by either NIP-021 (CSFS — PQ pubkeys/signatures exceed 520 B)
     * or NIP-031 (OP_CHECKMERKLEINCLUSION — depth-32 proofs are ~1029 B).
     * Callers pass `nCSFSEnabled || nMerkleInclusionEnabled`.
     * These limits are adequate for multi-signature up to n-of-100 using OP_CHECKSIG, OP_ADD, and OP_EQUAL,
     */
bool IsWitnessStandard(const CTransaction& tx, const CCoinsViewCache& mapInputs,
                        bool largeWitnessItemsActive);

extern CFeeRate incrementalRelayFee;
extern CFeeRate dustRelayFee;
extern unsigned int nBytesPerSigOp;

/** Compute the virtual transaction size (weight reinterpreted as bytes). */
int64_t GetVirtualTransactionSize(int64_t nWeight, int64_t nSigOpCost);
int64_t GetVirtualTransactionSize(const CTransaction& tx, int64_t nSigOpCost = 0);

#endif // NEURAI_POLICY_POLICY_H
