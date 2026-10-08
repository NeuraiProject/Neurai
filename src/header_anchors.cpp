// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <header_anchors.h>

#include <algorithm>
#include <cstdint>

size_t CountAnchoredHeaders(const std::vector<uint256>& anchors, int start_height,
                           const std::vector<CBlockHeader>& headers)
{
    if (anchors.empty() || headers.empty() || start_height < 1) return 0;
    const int64_t end = int64_t(start_height) + int64_t(headers.size()) - 1;
    const int64_t number = std::min<int64_t>(end / HEADER_ANCHOR_INTERVAL, anchors.size());
    const int64_t height = number * HEADER_ANCHOR_INTERVAL;
    if (number == 0 || height < start_height) return 0;
    const size_t count = size_t(height - start_height + 1);
    if (headers[count - 1].GetHash() != anchors[number - 1]) return 0;

    // Check the commitment chain here too, rather than relying on every caller
    // to authenticate continuity before trusting this result.
    for (size_t i = 1; i < count; ++i) {
        if (headers[i].hashPrevBlock != headers[i - 1].GetHash()) return 0;
    }
    return count;
}
