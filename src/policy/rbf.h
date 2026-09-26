// Copyright (c) 2016 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_POLICY_RBF_H
#define NEURAI_POLICY_RBF_H

#include "txmempool.h"

static const uint32_t MAX_BIP125_RBF_SEQUENCE = 0xfffffffd;

class CCoinsViewCache;

// NIP025-patch1: classify inputs and outputs, including administrative assets.
// Missing prevouts conservatively prevent replacement. Read-only references
// do not count. Call under the candidate block's asset activation context.
bool InvolvesAssets(const CTransaction& tx, const CCoinsViewCache& view);

// Checks the entire bounded eviction set, not just directly conflicting txs.
bool ReplacementInvolvesAssets(const CTransaction& candidate,
                              const CTxMemPool::setEntries& evicted,
                              const CCoinsViewCache& view);

enum RBFTransactionState {
    RBF_TRANSACTIONSTATE_UNKNOWN,
    RBF_TRANSACTIONSTATE_REPLACEABLE_BIP125,
    RBF_TRANSACTIONSTATE_FINAL
};

// Check whether the sequence numbers on this transaction are signaling
// opt-in to replace-by-fee, according to BIP 125
bool SignalsOptInRBF(const CTransaction &tx);

// Determine whether an in-mempool transaction is signaling opt-in to RBF
// according to BIP 125
// This involves checking sequence numbers of the transaction, as well
// as the sequence numbers of all in-mempool ancestors.
RBFTransactionState IsRBFOptIn(const CTransaction &tx, CTxMemPool &pool);

#endif // NEURAI_POLICY_RBF_H
