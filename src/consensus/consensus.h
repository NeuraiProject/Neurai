// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2020 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_CONSENSUS_CONSENSUS_H
#define NEURAI_CONSENSUS_CONSENSUS_H

#include <stdlib.h>
#include <stdint.h>

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 4000000;
/** The maximum allowed weight for a block, see BIP 141 (network rule) */
static const unsigned int MAX_BLOCK_WEIGHT = 4000000;

/** The maximum allowed weight for a block, after RIP 2 (network rule) */
static const unsigned int MAX_BLOCK_WEIGHT_RIP2 = 8000000;

/** The maximum allowed size for a serialized block, in bytes after RIP 2(only for buffer size limits) */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE_RIP2 = 8000000;

/** From the NIP-028 height on (30 s blocks), the serialized size of a block,
 *  witness included, may not exceed this (network rule). It bounds what every
 *  node has to relay and store; the weight limit no longer binds below it. */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE_NIP028 = 2000000;

// Deterministic Poseidon permutations, enforced after its height activation.
static constexpr uint64_t MAX_BLOCK_POSEIDON_WORK = 200000;
// NIP-054: OP_CHECKASSETAUTH work units per block (consensus). Sized from the
// worst-case benchmarks so that a full block costs no more to validate than
// the worst OP_POSEIDON block.
static constexpr uint64_t MAX_BLOCK_ASSETAUTH_WORK = 450000;
// From the NIP-028 height on (30 s blocks) both budgets are halved, so that
// the work a node validates per second stays the same and the worst block
// stays within a tenth of the interval (CPU review 16-11-2026, B2-a).
static constexpr uint64_t MAX_BLOCK_POSEIDON_WORK_NIP028 = 100000;
static constexpr uint64_t MAX_BLOCK_ASSETAUTH_WORK_NIP028 = 225000;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const int64_t MAX_BLOCK_SIGOPS_COST = 80000;
/** The maximum number of legacy signature operations a transaction may execute,
 *  counted by GetLegacyExecutedSigOpCount (network rule from the consensus
 *  cleanup height, BIP-54). */
static const unsigned int MAX_TX_LEGACY_SIGOPS = 2500;
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;
static const int COINBASE_MATURITY_TESTNET = 5;

static const int WITNESS_SCALE_FACTOR = 4;

static const size_t MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60; // 60 is the lower bound for the size of a valid serialized CTransaction
static const size_t MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10; // 10 is the lower bound for the size of a serialized CTransaction

#define UNUSED_VAR     __attribute__ ((unused))
//! This variable needs to in this class because undo.h uses it. However because it is in this class
//! it causes unused variable warnings when compiling. This UNUSED_VAR removes the unused warnings
UNUSED_VAR static bool fAssetsIsActive = false;
UNUSED_VAR static bool fRip5IsActive = false;
UNUSED_VAR static bool fTransferScriptIsActive = false;
UNUSED_VAR static bool fEnforcedValuesIsActive = false;
UNUSED_VAR static bool fCheckCoinbaseAssetsIsActive = false;

unsigned int GetMaxBlockWeight();
unsigned int GetMaxBlockSerializedSize();

namespace Consensus { struct Params; }
/** Serialized size limit, witness included, of a block at nHeight. */
unsigned int GetMaxBlockSerializedSizeAtHeight(int nHeight, const Consensus::Params& params);
/** Poseidon permutations a block at nHeight may run (network rule). */
uint64_t GetMaxBlockPoseidonWork(int nHeight, const Consensus::Params& params);
/** OP_CHECKASSETAUTH work units a block at nHeight may run (network rule). */
uint64_t GetMaxBlockAssetAuthWork(int nHeight, const Consensus::Params& params);
int GetCoinbaseMaturity();

/** Flags for nSequence and nLockTime locks */
enum {
    /* Interpret sequence numbers as relative lock-time constraints. */
    LOCKTIME_VERIFY_SEQUENCE = (1 << 0),

    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};

#endif // NEURAI_CONSENSUS_CONSENSUS_H
