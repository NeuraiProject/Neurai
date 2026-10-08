// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/epoch_context_cache.h>

#include <algorithm>
#include <cassert>
#include <iterator>
#include <new>
#include <stdexcept>

EpochContextCache::EpochContextCache(size_t capacity, Factory create)
    : m_capacity(capacity), m_create(std::move(create))
{
    if (capacity == 0 || !m_create) throw std::invalid_argument("invalid epoch context cache");
}

EpochContextCache::Context EpochContextCache::CreateContext(int epoch)
{
    return Context(ethash::create_epoch_context(epoch));
}

EpochContextCache::Context EpochContextCache::Get(int epoch)
{
    return Acquire(epoch, false);
}

EpochContextCache::Pinned EpochContextCache::Pin(int epoch)
{
    return Pinned(this, epoch, Acquire(epoch, true));
}

size_t EpochContextCache::PendingReservations() const
{
    return std::count_if(m_pending.begin(), m_pending.end(),
                        [](const auto& item) { return item.second->pins != 0; });
}

EpochContextCache::Context EpochContextCache::Acquire(int epoch, bool pin)
{
    std::shared_ptr<Pending> pending;
    std::list<Ready> retired;
    bool build = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const auto ready = std::find_if(m_ready.begin(), m_ready.end(),
            [epoch](const auto& item) { return item.epoch == epoch; });
        if (ready != m_ready.end()) {
            if (pin) ++ready->pins;
            m_ready.splice(m_ready.begin(), m_ready, ready);
            return ready->context;
        }
        const auto it = m_pending.find(epoch);
        if (it != m_pending.end()) {
            pending = it->second;
        } else {
            pending = std::make_shared<Pending>();
            m_pending.emplace(epoch, pending);
            build = true;
        }
        if (pin) {
            if (pending->pins == 0 && m_ready.size() + PendingReservations() == m_capacity) {
                const auto victim = std::find_if(m_ready.rbegin(), m_ready.rend(),
                                                 [](const Ready& item) { return item.pins == 0; });
                if (victim == m_ready.rend()) {
                    // A failed pin must not cancel a build started by Get().
                    if (build) m_pending.erase(epoch);
                    throw std::runtime_error("all epoch context slots are reserved");
                }
                retired.splice(retired.end(), m_ready, std::prev(victim.base()));
            }
            ++pending->pins;
        }
    }
    retired.clear(); // Free evicted memory outside the mutex, before waiting.
    if (!build) return pending->future.get();

    Context context;
    try {
        context = m_create(epoch);
        if (!context) throw std::bad_alloc();
        if (context->epoch_number != epoch) throw std::logic_error("wrong epoch context");
        // Allocate the LRU node before publishing or resolving anything. Failure
        // leaves no half-published context and reaches every joined caller.
        std::list<Ready> entry;
        entry.push_front(Ready{epoch, context, 0});
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            entry.front().pins = pending->pins;
            const size_t other_reservations = PendingReservations() - (pending->pins != 0);
            bool cache = m_ready.size() < m_capacity - other_reservations;
            if (!cache) {
                const auto victim = std::find_if(m_ready.rbegin(), m_ready.rend(),
                                                 [](const Ready& item) { return item.pins == 0; });
                if (victim != m_ready.rend()) {
                    retired.splice(retired.end(), m_ready, std::prev(victim.base()));
                    cache = true;
                }
            }
            assert(pending->pins == 0 || cache);
            pending->promise.set_value(context);
            if (cache) m_ready.splice(m_ready.begin(), entry);
            m_pending.erase(epoch);
        }
    } catch (...) {
        const auto error = std::current_exception();
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            pending->promise.set_exception(error);
            m_pending.erase(epoch);
        }
        std::rethrow_exception(error);
    }
    return context;
}

void EpochContextCache::Unpin(int epoch, const ethash::epoch_context* context) noexcept
{
    std::lock_guard<std::mutex> lock(m_mutex);
    const auto ready = std::find_if(m_ready.begin(), m_ready.end(),
        [epoch, context](const Ready& item) { return item.epoch == epoch && item.context.get() == context; });
    assert(ready != m_ready.end() && ready->pins != 0);
    --ready->pins;
}

EpochContextCache::Pinned::Pinned(Pinned&& other) noexcept
    : m_owner(other.m_owner), m_epoch(other.m_epoch), m_context(std::move(other.m_context))
{
    other.m_owner = nullptr;
}

EpochContextCache::Pinned& EpochContextCache::Pinned::operator=(Pinned&& other) noexcept
{
    if (this != &other) {
        Reset();
        m_owner = other.m_owner;
        m_epoch = other.m_epoch;
        m_context = std::move(other.m_context);
        other.m_owner = nullptr;
    }
    return *this;
}

EpochContextCache::Pinned::~Pinned()
{
    Reset();
}

void EpochContextCache::Pinned::Reset() noexcept
{
    if (m_owner) m_owner->Unpin(m_epoch, m_context.get());
    m_owner = nullptr;
    m_context.reset();
}

EpochContextCache& KawpowValidationCache()
{
    static EpochContextCache cache(2);
    return cache;
}

EpochContextCache& KawpowRpcCache()
{
    static EpochContextCache cache(1);
    return cache;
}
