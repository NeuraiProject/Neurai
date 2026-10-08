// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_HEADER_VERIFICATION_H
#define NEURAI_HEADER_VERIFICATION_H

#include <crypto/epoch_context_cache.h>
#include <primitives/block.h>

class CBlockIndex;
class CChainParams;
class CValidationState;
namespace Consensus { struct Params; }

/** One epoch, at most 64 headers. The pin lives through acceptance so a failed
 * check retried in series uses exactly the workers' context. */
struct HeaderVerificationWindow {
    std::vector<CBlockHeader> headers;
    std::vector<uint8_t> candidates;
    std::vector<uint8_t> checked;
    int epoch{0};
    bool pow_failed{false};
    EpochContextCache::Pinned context;
};
enum class HeaderWindowStatus { READY, SERIAL, DONE, ERROR };

/** Requires cs_main. Accept cheap/authenticated prefixes before expensive work.
 * offset advances only over accepted prefixes. */
HeaderWindowStatus PrepareHeaderWindow(const std::vector<CBlockHeader>& headers,
    const std::vector<uint8_t>& authenticated, size_t& offset, size_t limit,
    const CChainParams& params, CValidationState& state, const CBlockIndex** last,
    CBlockHeader* first_invalid, HeaderVerificationWindow& window);

/** Requires cs_main NOT held. Allocation/worker failures are local errors. */
bool VerifyHeaderWindow(HeaderVerificationWindow& window, int threads,
                        const Consensus::Params& params, CValidationState& state);

/** Serial acceptance is authoritative, including when pow_failed is true. */
bool AcceptHeaderWindow(const HeaderVerificationWindow& window,
    const CChainParams& params, CValidationState& state, const CBlockIndex** last,
    CBlockHeader* first_invalid);

/** Network batch entry point; small/ineligible batches preserve the serial path.
 * authenticated, when supplied, contains only cryptographically anchored marks. */
bool ProcessHeadersWithParallelPoW(const std::vector<CBlockHeader>& headers,
    CValidationState& state, const CChainParams& params, const CBlockIndex** last,
    CBlockHeader* first_invalid, const std::vector<uint8_t>* authenticated = nullptr);

#endif // NEURAI_HEADER_VERIFICATION_H
