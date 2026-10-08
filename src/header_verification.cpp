// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <header_verification.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <crypto/ethash/helpers.hpp>
#include <util.h>
#include <validation.h>

#include <algorithm>
#include <atomic>
#include <exception>
#include <mutex>
#include <thread>

namespace {
bool CoherentKawpow(const CBlockHeader& header, int64_t height)
{
    return !bNetwork.fSHA256Mining && header.nTime >= nKAWPOWActivationTime &&
           height >= 0 && int64_t(header.nHeight) == height;
}

bool Candidate(const CBlockHeader& header)
{
    AssertLockHeld(cs_main);
    return mapBlockIndex.count(header.GetHash()) == 0 && NeedsFullKAWPOWCheck(header);
}

bool AcceptRange(const std::vector<CBlockHeader>& headers, const std::vector<uint8_t>& checked,
    size_t begin, size_t end, const CChainParams& params, CValidationState& state,
    const CBlockIndex** last, CBlockHeader* first_invalid)
{
    const std::vector<CBlockHeader> range(headers.begin() + begin, headers.begin() + end);
    const std::vector<uint8_t> marks(checked.begin() + begin, checked.begin() + end);
    return ProcessNewBlockHeaders(range, state, params, last, first_invalid, &marks);
}
}

HeaderWindowStatus PrepareHeaderWindow(const std::vector<CBlockHeader>& headers,
    const std::vector<uint8_t>& authenticated, size_t& offset, size_t limit,
    const CChainParams& params, CValidationState& state, const CBlockIndex** last,
    CBlockHeader* first_invalid, HeaderVerificationWindow& window)
{
    AssertLockHeld(cs_main);
    assert(authenticated.size() == headers.size());
    assert(window.headers.empty() && !window.context && limit > 0 && limit <= 64);
    if (offset == headers.size()) return HeaderWindowStatus::DONE;
    const auto prev = mapBlockIndex.find(headers[offset].hashPrevBlock);
    if (prev == mapBlockIndex.end()) return HeaderWindowStatus::SERIAL;
    const int64_t start = int64_t(prev->second->nHeight) + 1 - int64_t(offset);
    while (offset < headers.size()) {
        size_t end = offset;
        while (end < headers.size()) {
            const auto& header = headers[end];
            if (!authenticated[end] && (!CoherentKawpow(header, start + end) || Candidate(header))) break;
            ++end;
        }
        if (end == offset) {
            if (!CoherentKawpow(headers[offset], start + offset)) return HeaderWindowStatus::SERIAL;
            break;
        }
        // Accept the cheap prefix in one call, preserving first-failure order
        // without emitting a tip notification for every known/anchored header.
        const std::vector<CBlockHeader> prefix(headers.begin() + offset, headers.begin() + end);
        const std::vector<uint8_t> marks(authenticated.begin() + offset, authenticated.begin() + end);
        if (!AcceptBlockHeaders(prefix, state, params, last, first_invalid, &marks))
            return HeaderWindowStatus::ERROR;
        offset = end;
    }
    if (offset == headers.size()) return HeaderWindowStatus::DONE;
    window.epoch = ethash::get_epoch_number(headers[offset].nHeight);
    for (size_t i = offset; i < headers.size() && i - offset < limit; ++i) {
        const auto& header = headers[i];
        if (!CoherentKawpow(header, start + i) || ethash::get_epoch_number(header.nHeight) != window.epoch) break;
        window.headers.push_back(header);
        window.checked.push_back(authenticated[i]);
        window.candidates.push_back(!authenticated[i] && Candidate(header));
    }
    assert(!window.headers.empty() && window.candidates.front());
    return HeaderWindowStatus::READY;
}

bool VerifyHeaderWindow(HeaderVerificationWindow& window, int threads,
                        const Consensus::Params& params, CValidationState& state)
{
    AssertLockNotHeld(cs_main);
    assert(threads >= 2 && !window.context && !window.headers.empty());
    assert(window.headers.size() <= 64 && window.checked.size() == window.headers.size() &&
           window.candidates.size() == window.headers.size());
    std::atomic<size_t> next{0};
    std::atomic<bool> stop{false};
    std::exception_ptr worker_error;
    std::mutex error_mutex;
    std::vector<std::thread> workers;
    try {
        window.context = KawpowValidationCache().Pin(window.epoch);
        const size_t count = std::min(size_t(threads), window.headers.size());
        workers.reserve(count);
        for (size_t n = 0; n < count; ++n) {
            workers.emplace_back([&] {
                try {
                    while (!stop.load(std::memory_order_relaxed)) {
                        const size_t i = next.fetch_add(1, std::memory_order_relaxed);
                        if (i >= window.headers.size()) break;
                        if (!window.candidates[i]) continue;
                        CValidationState result;
                        if (CheckBlockHeaderPoWFull(window.headers[i], result, params, *window.context)) {
                            window.checked[i] = 1;
                        } else {
                            stop.store(true, std::memory_order_relaxed);
                        }
                    }
                } catch (...) {
                    std::lock_guard<std::mutex> lock(error_mutex);
                    worker_error = std::current_exception();
                    stop.store(true, std::memory_order_relaxed);
                }
            });
        }
        for (auto& worker : workers) worker.join();
        if (worker_error) std::rethrow_exception(worker_error);
        window.pow_failed = stop.load(std::memory_order_relaxed);
        return true;
    } catch (...) {
        stop.store(true, std::memory_order_relaxed);
        for (auto& worker : workers) if (worker.joinable()) worker.join();
        try {
            throw;
        } catch (const std::exception& e) {
            LogPrintf("Parallel KAWPOW verification unavailable: %s\n", e.what());
        } catch (...) {
            LogPrintf("Parallel KAWPOW verification failed with an unknown local exception\n");
        }
        return state.Error("parallel KAWPOW verification unavailable");
    }
}

bool AcceptHeaderWindow(const HeaderVerificationWindow& window,
    const CChainParams& params, CValidationState& state, const CBlockIndex** last,
    CBlockHeader* first_invalid)
{
    return ProcessNewBlockHeaders(window.headers, state, params, last, first_invalid, &window.checked);
}

bool ProcessHeadersWithParallelPoW(const std::vector<CBlockHeader>& headers,
    CValidationState& state, const CChainParams& params, const CBlockIndex** last,
    CBlockHeader* first_invalid, const std::vector<uint8_t>* authenticated)
{
    AssertLockNotHeld(cs_main);
    if (first_invalid) first_invalid->SetNull();
    if (nScriptCheckThreads < 2 || headers.size() < 16)
        return ProcessNewBlockHeaders(headers, state, params, last, first_invalid, authenticated);
    try {
        const std::vector<uint8_t> checked = authenticated && authenticated->size() == headers.size() ?
            *authenticated : std::vector<uint8_t>(headers.size(), 0);
        size_t candidates = 0;
        {
            LOCK(cs_main);
            const auto prev = mapBlockIndex.find(headers.front().hashPrevBlock);
            if (prev != mapBlockIndex.end()) {
                const int64_t start = int64_t(prev->second->nHeight) + 1;
                for (size_t i = 0; i < headers.size() && candidates < 16; ++i) {
                    if (!checked[i] && !CoherentKawpow(headers[i], start + i)) break;
                    if (!checked[i] && Candidate(headers[i])) ++candidates;
                }
            }
        }
        if (candidates < 16)
            return ProcessNewBlockHeaders(headers, state, params, last, first_invalid, &checked);

        size_t offset = 0;
        const size_t limit = 4 * size_t(std::min(nScriptCheckThreads, 16));
        while (offset < headers.size()) {
            HeaderVerificationWindow window;
            HeaderWindowStatus status;
            {
                LOCK(cs_main);
                status = PrepareHeaderWindow(headers, checked, offset, limit, params, state, last, first_invalid, window);
            }
            if (status == HeaderWindowStatus::ERROR) return false;
            if (status == HeaderWindowStatus::DONE)
                return ProcessNewBlockHeaders({}, state, params, last, first_invalid);
            if (status == HeaderWindowStatus::SERIAL)
                return AcceptRange(headers, checked, offset, headers.size(), params, state, last, first_invalid);
            if (!VerifyHeaderWindow(window, nScriptCheckThreads, params.GetConsensus(), state)) return false;
            if (!AcceptHeaderWindow(window, params, state, last, first_invalid)) return false;
            offset += window.headers.size();
            if (window.pow_failed) {
                LogPrint(BCLog::NET, "Header window accepted after parallel PoW failure; continuing serially\n");
                return AcceptRange(headers, checked, offset, headers.size(), params, state, last, first_invalid);
            }
        }
        return true;
    } catch (const std::exception& e) {
        LogPrintf("Header verification resource failure: %s\n", e.what());
        return state.Error("header verification unavailable");
    }
}
