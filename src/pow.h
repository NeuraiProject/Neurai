// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_POW_H
#define NEURAI_POW_H

#include "consensus/params.h"

#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class uint256;

/** Number of blocks in the Dark Gravity Wave retarget window. */
static const int DGW_PAST_BLOCKS = 180;

/**
 * Earliest timestamp the consensus cleanup rules allow for the block that
 * follows pindexPrev:
 *  - no more than MAX_BLOCK_TIME_REGRESSION seconds before its parent, and
 *  - not before the first block of the retarget window that will end at it,
 *    so the timespan the next retarget measures is never negative.
 * It does not include the median-time-past rule.
 */
int64_t GetConsensusCleanupMinimumTime(const CBlockIndex* pindexPrev);

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params&);
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params&);

/** Check whether a block hash satisfies the proof-of-work requirement specified by nBits */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params&);

#endif // NEURAI_POW_H
