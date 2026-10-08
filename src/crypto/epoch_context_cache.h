// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_CRYPTO_EPOCH_CONTEXT_CACHE_H
#define NEURAI_CRYPTO_EPOCH_CONTEXT_CACHE_H

#include <crypto/ethash/include/ethash/ethash.hpp>

#include <functional>
#include <cstddef>
#include <future>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <utility>

/** A bounded LRU of completed light contexts. In-flight constructions are
 * tracked separately, so eviction cannot start a second build of the same epoch.
 * Contexts in use remain alive after eviction. Construction and waiting happen
 * outside the mutex. The cache must outlive its callers and pinned handles.
 */
class EpochContextCache
{
public:
    using Context = std::shared_ptr<const ethash::epoch_context>;
    using Factory = std::function<Context(int)>;

    /** Move-only ownership of one eviction reservation. */
    class Pinned {
    public:
        Pinned() = default;
        Pinned(Pinned&& other) noexcept;
        Pinned& operator=(Pinned&& other) noexcept;
        ~Pinned();
        Pinned(const Pinned&) = delete;
        Pinned& operator=(const Pinned&) = delete;
        const ethash::epoch_context& operator*() const { return *m_context; }
        const ethash::epoch_context* operator->() const { return m_context.get(); }
        explicit operator bool() const { return bool(m_context); }
        const Context& SharedContext() const { return m_context; }

    private:
        friend class EpochContextCache;
        Pinned(EpochContextCache* owner, int epoch, Context context)
            : m_owner(owner), m_epoch(epoch), m_context(std::move(context)) {}
        void Reset() noexcept;
        EpochContextCache* m_owner{nullptr};
        int m_epoch{0};
        Context m_context;
    };

    explicit EpochContextCache(size_t capacity, Factory create = CreateContext);
    Context Get(int epoch);
    /** Reserve before building/waiting. Throws locally when every slot is pinned
     * or reserved for another epoch; never waits for another epoch to unpin.
     */
    Pinned Pin(int epoch);

private:
    static Context CreateContext(int epoch);
    Context Acquire(int epoch, bool pin);
    void Unpin(int epoch, const ethash::epoch_context* context) noexcept;
    size_t PendingReservations() const; // Requires m_mutex.
    struct Ready {
        int epoch;
        Context context;
        size_t pins{0};
    };
    struct Pending {
        std::promise<Context> promise;
        std::shared_future<Context> future{promise.get_future().share()};
        size_t pins{0};
    };
    const size_t m_capacity;
    Factory m_create;
    std::mutex m_mutex;
    std::list<Ready> m_ready;
    std::map<int, std::shared_ptr<Pending>> m_pending;

    // Fixtures can inject failures and observe joined requests without sleeps.
    friend struct EpochContextCacheTestAccess;
};

/** Validation/mining and getkawpowhash deliberately use independent caches. */
EpochContextCache& KawpowValidationCache();
EpochContextCache& KawpowRpcCache();

#endif // NEURAI_CRYPTO_EPOCH_CONTEXT_CACHE_H
