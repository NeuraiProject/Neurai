// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "privacy/c6_scan.h"

#include "assets/assets.h"
#include "chain.h"
#include "chainparams.h"
#include "spentindex.h"
#include "txdb.h"
#include "util.h"
#include "utiltime.h"
#include "validation.h"

#include <algorithm>

namespace privacy {
namespace {

uint256 ToUint256(const Bytes32& bytes)
{
    return uint256(std::vector<unsigned char>(bytes.begin(), bytes.end()));
}

Bytes ScriptBytes(const CScript& script) { return Bytes(script.begin(), script.end()); }

/** C7 verifiable birth: the transaction spends the UNIQUE emission and sends the
 *  owner token NAME! to the network's global burn address, so the creator keeps
 *  no power over the name. */
bool CheckC7Birth(const C6Config& config, const CTransaction& birth, std::string& error)
{
    const COutPoint emission(ToUint256(config.emissionTxid), config.emissionVout);
    if (std::none_of(birth.vin.begin(), birth.vin.end(), [&](const CTxIn& in) { return in.prevout == emission; })) {
        error = "C7 birth does not spend the pinned emission";
        return false;
    }
    const std::string owner = config.identity.substr(0, config.identity.find('#')) + "!";
    for (const CTxOut& out : birth.vout) {
        CAssetTransfer transfer;
        std::string address;
        if (TransferAssetFromScript(out.scriptPubKey, transfer, address) && transfer.strName == owner &&
            address == GetParams().GlobalBurnAddress()) {
            return true;
        }
    }
    error = "C7 birth does not burn the owner token " + owner;
    return false;
}

} // namespace

bool C6ChainScanner::Reset(std::string& error)
{
    m_ready = false;
    m_state = C6PoolState{};
    const CBlockIndex* index;
    {
        LOCK(cs_main);
        index = chainActive[m_config.anchorHeight];
        if (!index || index->GetBlockHash() != ToUint256(m_config.anchorHash)) {
            error = "pool birth block is not in the active chain";
            return false;
        }
    }
    CBlock block;
    if (!ReadBlockFromDisk(block, index, GetParams().GetConsensus())) {
        error = "cannot read the pool birth block";
        return false;
    }
    const uint256 txid = ToUint256(m_config.anchorTxid);
    const auto found = std::find_if(block.vtx.begin(), block.vtx.end(), [&](const CTransactionRef& tx) { return tx->GetHash() == txid; });
    if (found == block.vtx.end() || m_config.anchorVout >= (*found)->vout.size() ||
        ScriptBytes((*found)->vout[m_config.anchorVout].scriptPubKey) != m_config.anchorScript) {
        error = "pool birth output not found";
        return false;
    }
    if (m_config.c7 && !CheckC7Birth(m_config, **found, error)) return false;
    if (m_state.world.Opening() != m_config.anchorOpening) {
        error = "pool birth must be an empty state";
        return false;
    }
    m_state.opening = m_config.anchorOpening;
    m_state.statePoint = COutPoint(txid, m_config.anchorVout);
    // Transitions may follow the birth in its own block.
    m_state.height = m_config.anchorHeight - 1;
    m_state.hash = index->pprev ? index->pprev->GetBlockHash() : uint256();
    m_ready = true;
    return true;
}

bool C6ChainScanner::Update(std::string& error, const std::function<bool(int, int)>& progress)
{
    int tip;
    bool restart = !m_ready;
    {
        LOCK(cs_main);
        if (!chainActive.Tip() || chainActive.Genesis()->GetBlockHash() != ToUint256(m_config.genesis)) {
            error = "this node is not on the pool's network";
            return false;
        }
        tip = chainActive.Height();
        if (m_ready && (m_state.height > tip || chainActive[m_state.height]->GetBlockHash() != m_state.hash)) restart = true;
    }
    if (tip < m_config.anchorHeight) {
        error = "the node has not synchronised up to the pool birth";
        return false;
    }
    if (restart && !Reset(error)) return false;
    const int64_t started = GetTimeMillis();
    const int fromHeight = m_state.height;

    auto apply = [&](const CBlockIndex* index, const CBlock& block) {
        // Transactions of one block are ordered, so a chain of transitions in the
        // same block is followed in order.
        for (const CTransactionRef& tx : block.vtx) {
            for (size_t n = 0; n < tx->vin.size(); ++n) {
                if (tx->vin[n].prevout != m_state.statePoint) continue;
                if (n != 0 || !ApplyC6Transition(m_config, m_state, *tx, index->nHeight, error)) {
                    if (n != 0) error = "pool state spent outside input zero";
                    m_ready = false;
                    return false;
                }
                break;
            }
        }
        return true;
    };
    auto readBlock = [&](int height, const CBlockIndex*& index, CBlock& block) {
        {
            LOCK(cs_main);
            index = chainActive[height];
        }
        if (!index || !ReadBlockFromDisk(block, index, GetParams().GetConsensus())) {
            error = "block data unavailable (pruned node?)";
            m_ready = false;
            return false;
        }
        return true;
    };

    if (fSpentIndex) {
        // Jump straight to each spending block.
        for (;;) {
            CSpentIndexKey key(m_state.statePoint.hash, m_state.statePoint.n);
            CSpentIndexValue spender;
            {
                LOCK(cs_main);
                // Confirmed spends only: GetSpentIndex would overlay the mempool.
                if (!pblocktree->ReadSpentIndex(key, spender)) break;
            }
            if (spender.blockHeight > tip) break;
            if (spender.blockHeight <= m_state.height && m_state.height >= m_config.anchorHeight) {
                error = "spent index disagrees with the scanned chain";
                m_ready = false;
                return false;
            }
            const CBlockIndex* index;
            CBlock block;
            if (!readBlock(spender.blockHeight, index, block)) return false;
            const uint256 before = m_state.statePoint.hash;
            if (!apply(index, block)) return false;
            if (m_state.statePoint.hash == before) {
                error = "spent index points to a block without the state spend";
                m_ready = false;
                return false;
            }
            m_state.height = index->nHeight - 1; // the next spend may be in the same block
            if (progress && !progress(index->nHeight, tip)) {
                error = "cancelled";
                m_ready = false;
                return false;
            }
        }
        LOCK(cs_main);
        m_state.height = tip;
        m_state.hash = chainActive[tip]->GetBlockHash();
    } else {
        for (int height = m_state.height + 1; height <= tip; ++height) {
            const CBlockIndex* index;
            CBlock block;
            if (!readBlock(height, index, block) || !apply(index, block)) return false;
            m_state.height = height;
            m_state.hash = index->GetBlockHash();
            if (progress && (height % 500 == 0 || height == tip) && !progress(height, tip)) {
                error = "cancelled";
                m_ready = false;
                return false;
            }
        }
    }
    LOCK(cs_main);
    if (m_state.height > chainActive.Height() || chainActive[m_state.height]->GetBlockHash() != m_state.hash) {
        error = "chain changed during the scan; retry";
        m_ready = false;
        return false;
    }
    if (m_state.height != fromHeight) {
        LogPrintf("privacy: pool state %d -> %d (%d transitions, %u notes, %s) in %d ms\n", fromHeight, m_state.height,
                  m_state.transitions, m_state.world.NoteCount(), fSpentIndex ? "spent index" : "block replay",
                  GetTimeMillis() - started);
    }
    return true;
}

int C6ChainScanner::EligibleRoot() const
{
    for (int i = static_cast<int>(m_state.rootHeights.size()) - 1; i >= 0; --i) {
        if (m_state.height - m_state.rootHeights[i] + 1 >= 2) return i;
    }
    return -1;
}

} // namespace privacy
