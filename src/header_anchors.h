// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_HEADER_ANCHORS_H
#define NEURAI_HEADER_ANCHORS_H

#include <primitives/block.h>
#include <uint256.h>

#include <cstddef>
#include <vector>

static constexpr int HEADER_ANCHOR_INTERVAL = 2000;

/** Authenticate a continuous prefix ending at the highest matching anchor in
 * this batch. Anchor i commits to the header at height (i + 1) * interval.
 * A mismatch authenticates nothing; the caller must perform normal PoW checks.
 * No mutable chain state is accessed here.
 */
size_t CountAnchoredHeaders(const std::vector<uint256>& anchors, int start_height,
                           const std::vector<CBlockHeader>& headers);

#endif // NEURAI_HEADER_ANCHORS_H
