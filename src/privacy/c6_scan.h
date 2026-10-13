// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_PRIVACY_C6_SCAN_H
#define NEURAI_PRIVACY_C6_SCAN_H

#include "amount.h"
#include "primitives/transaction.h"
#include "privacy/c6_config.h"
#include "privacy/c6_world.h"
#include "uint256.h"

#include <functional>
#include <set>

namespace privacy {

/** A published note record, in note-tree order. */
struct C6Record {
    Bytes32 cm{};
    Bytes record;
    uint32_t index = 0;
    int height = 0;
    uint256 txid;
};

/** Public pool state replayed from the confirmed active chain. */
struct C6PoolState {
    C6World world;
    Bytes opening;
    COutPoint statePoint;
    CAmount reserve = 0;
    COutPoint reservePoint; //!< null when the reserve is empty
    std::vector<C6Record> records;
    std::vector<int> rootHeights; //!< block height of each historical root
    std::set<uint256> transitionTxids;
    int transitions = 0;
    int height = -1; //!< last scanned block
    uint256 hash;
};

/** Reads one state transition from its transaction (witness of input 0). */
bool ParseC6Transition(const C6Config& config, const CTransaction& tx, C6Event& event, Bytes& transcript,
                       std::vector<Bytes>& records, Bytes32& root, std::string& error);

/** Applies a confirmed transition after checking it reproduces exactly. Fails
 *  closed: on error the state must be discarded. */
bool ApplyC6Transition(const C6Config& config, C6PoolState& state, const CTransaction& tx, int height, std::string& error);

/** Follows the pool state thread inside this node, from the pinned birth to the
 *  active tip. Uses the spent index when enabled, otherwise reads the blocks.
 *  Not thread safe: one scanner per thread. */
class C6ChainScanner
{
public:
    explicit C6ChainScanner(const C6Config& config) : m_config(config) {}

    /** Brings the state to the active tip; restarts from birth after a reorg.
     *  progress(height, tip) may return false to cancel. */
    bool Update(std::string& error, const std::function<bool(int, int)>& progress = {});
    const C6PoolState& State() const { return m_state; }
    bool Ready() const { return m_ready; }
    /** Newest historical root with at least two confirmations, or -1. */
    int EligibleRoot() const;

private:
    bool Reset(std::string& error);
    const C6Config& m_config;
    C6PoolState m_state;
    bool m_ready = false;
};

} // namespace privacy

#endif // NEURAI_PRIVACY_C6_SCAN_H
