// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_TEST_EPOCH_CONTEXT_CACHE_TEST_ACCESS_H
#define NEURAI_TEST_EPOCH_CONTEXT_CACHE_TEST_ACCESS_H

#include <crypto/epoch_context_cache.h>
#include <cassert>
#include <chrono>
#include <thread>

struct EpochContextCacheTestAccess {
    static bool WaitForCallers(EpochContextCache& cache, int epoch, long callers)
    {
        const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        do {
            {
                std::unique_lock<std::mutex> lock(cache.m_mutex, std::try_to_lock);
                if (lock.owns_lock()) {
                    const auto it = cache.m_pending.find(epoch);
                    // The registry owns one reference; every Get owns another.
                    if (it != cache.m_pending.end() && it->second.use_count() == callers + 1) return true;
                }
            }
            std::this_thread::yield();
        } while (std::chrono::steady_clock::now() < end);
        return false;
    }

    static size_t Pending(EpochContextCache& cache)
    {
        std::lock_guard<std::mutex> lock(cache.m_mutex);
        return cache.m_pending.size();
    }

    struct FactoryOverride {
        EpochContextCache& cache;
        EpochContextCache::Factory factory;
        std::list<EpochContextCache::Ready> ready;
        FactoryOverride(EpochContextCache& cacheIn, EpochContextCache::Factory replacement)
            : cache(cacheIn), factory(std::move(replacement))
        {
            std::lock_guard<std::mutex> lock(cache.m_mutex);
            assert(cache.m_pending.empty());
            factory.swap(cache.m_create);
            ready.swap(cache.m_ready);
        }
        ~FactoryOverride()
        {
            std::lock_guard<std::mutex> lock(cache.m_mutex);
            assert(cache.m_pending.empty());
            factory.swap(cache.m_create);
            ready.swap(cache.m_ready);
        }
        FactoryOverride(const FactoryOverride&) = delete;
        FactoryOverride& operator=(const FactoryOverride&) = delete;
    };
};

#endif // NEURAI_TEST_EPOCH_CONTEXT_CACHE_TEST_ACCESS_H
