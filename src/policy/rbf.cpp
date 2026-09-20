// Copyright (c) 2016 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "policy/rbf.h"
#include "coins.h"

bool SignalsOptInRBF(const CTransaction &tx)
{
    for (const CTxIn &txin : tx.vin) {
        if (txin.nSequence < std::numeric_limits<unsigned int>::max()-1) {
            return true;
        }
    }
    return false;
}

RBFTransactionState IsRBFOptIn(const CTransaction &tx, CTxMemPool &pool)
{
    AssertLockHeld(pool.cs);

    CTxMemPool::setEntries setAncestors;

    // First check the transaction itself.
    if (SignalsOptInRBF(tx)) {
        return RBF_TRANSACTIONSTATE_REPLACEABLE_BIP125;
    }

    // If this transaction is not in our mempool, then we can't be sure
    // we will know about all its inputs.
    if (!pool.exists(tx.GetHash())) {
        return RBF_TRANSACTIONSTATE_UNKNOWN;
    }

    // If all the inputs have nSequence >= maxint-1, it still might be
    // signaled for RBF if any unconfirmed parents have signaled.
    uint64_t noLimit = std::numeric_limits<uint64_t>::max();
    std::string dummy;
    CTxMemPoolEntry entry = *pool.mapTx.find(tx.GetHash());
    pool.CalculateMemPoolAncestors(entry, setAncestors, noLimit, noLimit, noLimit, noLimit, dummy, false);

    for (CTxMemPool::txiter it : setAncestors) {
        if (SignalsOptInRBF(it->GetTx())) {
            return RBF_TRANSACTIONSTATE_REPLACEABLE_BIP125;
        }
    }
    return RBF_TRANSACTIONSTATE_FINAL;
}

namespace {
bool AssetOperation(const CScript& script)
{
    return script.IsAssetScript() || script.IsNullAsset();
}
}

bool InvolvesAssets(const CTransaction& tx, const CCoinsViewCache& view)
{
    for (const auto& output : tx.vout) {
        if (AssetOperation(output.scriptPubKey)) return true;
    }
    for (const auto& input : tx.vin) {
        const Coin& coin = view.AccessCoin(input.prevout);
        if (coin.IsSpent() || AssetOperation(coin.out.scriptPubKey)) return true;
    }
    return false;
}

bool ReplacementInvolvesAssets(const CTransaction& candidate,
                              const CTxMemPool::setEntries& evicted,
                              const CCoinsViewCache& view)
{
    if (InvolvesAssets(candidate, view)) return true;
    for (const auto& entry : evicted) {
        if (InvolvesAssets(entry->GetTx(), view)) return true;
    }
    return false;
}
