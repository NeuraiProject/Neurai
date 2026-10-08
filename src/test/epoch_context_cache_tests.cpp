// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/ethash/helpers.hpp>
#include <crypto/ethash/include/ethash/progpow.hpp>
#include <crypto/ethash/progpow_test_vectors.hpp>
#include <test/epoch_context_cache_test_access.h>

#include <boost/test/unit_test.hpp>
#include <atomic>
#include <vector>

namespace {
using Context = EpochContextCache::Context;

Context FakeContext(int epoch)
{
    return std::make_shared<const ethash::epoch_context>(ethash::epoch_context{epoch, 0, nullptr, nullptr, 0});
}

struct Gate {
    std::promise<void> release;
    std::shared_future<void> future{release.get_future().share()};
    void Wait() { future.get(); }
    void Open() { release.set_value(); }
};

}

BOOST_AUTO_TEST_SUITE(epoch_context_cache_tests)

BOOST_AUTO_TEST_CASE(capacity_and_factory_are_required)
{
    BOOST_CHECK_THROW(EpochContextCache(0), std::invalid_argument);
    BOOST_CHECK_THROW(EpochContextCache(1, {}), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(lru_keeps_contexts_alive_only_while_owned)
{
    std::atomic<int> live{0};
    std::atomic<int> builds{0};
    {
        EpochContextCache cache(2, [&](int epoch) {
            ++live;
            ++builds;
            return Context(new ethash::epoch_context{epoch, 0, nullptr, nullptr, 0},
                [&](const ethash::epoch_context* p) { delete p; --live; });
        });
        Context a = cache.Get(0);
        const auto b = cache.Get(1);
        BOOST_CHECK(cache.Get(0) == a); // A becomes most recently used.
        cache.Get(2); // Evicts B, which is still owned by this scope.
        BOOST_CHECK_EQUAL(live.load(), 3);
        BOOST_CHECK(cache.Get(0) == a);
        BOOST_CHECK_EQUAL(builds.load(), 3);
        BOOST_CHECK(cache.Get(1) != b);
        BOOST_CHECK_EQUAL(builds.load(), 4);
        BOOST_CHECK_EQUAL(EpochContextCacheTestAccess::Pending(cache), 0U);
    }
    BOOST_CHECK_EQUAL(live.load(), 0);
}

BOOST_AUTO_TEST_CASE(concurrent_callers_share_one_build)
{
    Gate gate;
    std::atomic<int> builds{0};
    EpochContextCache cache(2, [&](int epoch) { ++builds; gate.Wait(); return FakeContext(epoch); });
    std::vector<std::future<Context>> callers;
    for (int i = 0; i < 12; ++i) callers.emplace_back(std::async(std::launch::async, [&] { return cache.Get(3); }));
    const bool joined = EpochContextCacheTestAccess::WaitForCallers(cache, 3, 12);
    gate.Open();
    const auto result = callers.front().get();
    for (size_t i = 1; i < callers.size(); ++i) BOOST_CHECK(callers[i].get() == result);
    BOOST_CHECK(joined);
    BOOST_CHECK_EQUAL(builds.load(), 1);
    BOOST_CHECK_EQUAL(EpochContextCacheTestAccess::Pending(cache), 0U);
}

BOOST_AUTO_TEST_CASE(other_epochs_do_not_wait_for_construction)
{
    Gate gate;
    EpochContextCache cache(2, [&](int epoch) { if (epoch == 0) gate.Wait(); return FakeContext(epoch); });
    const auto ready = cache.Get(1);
    auto a = std::async(std::launch::async, [&] { return cache.Get(0); });
    const bool started = EpochContextCacheTestAccess::WaitForCallers(cache, 0, 1);
    auto hit = std::async(std::launch::async, [&] { return cache.Get(1); });
    auto miss = std::async(std::launch::async, [&] { return cache.Get(2); });
    const bool hit_ready = hit.wait_for(std::chrono::seconds(10)) == std::future_status::ready;
    const bool miss_ready = miss.wait_for(std::chrono::seconds(10)) == std::future_status::ready;
    gate.Open();
    BOOST_CHECK(started && hit_ready && miss_ready);
    BOOST_CHECK(hit.get() == ready);
    BOOST_CHECK_EQUAL(miss.get()->epoch_number, 2);
    BOOST_CHECK_EQUAL(a.get()->epoch_number, 0);
}

BOOST_AUTO_TEST_CASE(eviction_does_not_remove_pending_attempts)
{
    Gate gate;
    std::atomic<int> a_builds{0};
    EpochContextCache cache(1, [&](int epoch) {
        if (epoch == 0) { ++a_builds; gate.Wait(); }
        return FakeContext(epoch);
    });
    auto first = std::async(std::launch::async, [&] { return cache.Get(0); });
    const bool started = EpochContextCacheTestAccess::WaitForCallers(cache, 0, 1);
    auto pressure = std::async(std::launch::async, [&] { cache.Get(1); return cache.Get(2); });
    const bool pressure_done = pressure.wait_for(std::chrono::seconds(10)) == std::future_status::ready;
    auto second = std::async(std::launch::async, [&] { return cache.Get(0); });
    const bool joined = EpochContextCacheTestAccess::WaitForCallers(cache, 0, 2);
    gate.Open();
    BOOST_CHECK(started && pressure_done && joined);
    BOOST_CHECK_EQUAL(pressure.get()->epoch_number, 2);
    BOOST_CHECK(first.get() == second.get());
    BOOST_CHECK_EQUAL(a_builds.load(), 1);
}

BOOST_AUTO_TEST_CASE(failure_reaches_all_waiters_and_next_request_retries)
{
    for (const bool return_null : {false, true}) {
        Gate gate;
        std::atomic<int> builds{0};
        EpochContextCache cache(1, [&](int epoch) -> Context {
            if (++builds == 1) {
                gate.Wait();
                if (return_null) return {};
                throw std::runtime_error("test context failure");
            }
            return FakeContext(epoch);
        });
        std::vector<std::future<Context>> callers;
        for (int i = 0; i < 8; ++i) callers.emplace_back(std::async(std::launch::async, [&] { return cache.Get(0); }));
        const bool joined = EpochContextCacheTestAccess::WaitForCallers(cache, 0, 8);
        gate.Open();
        BOOST_CHECK(joined);
        for (auto& caller : callers) {
            if (return_null) { BOOST_CHECK_THROW(caller.get(), std::bad_alloc); }
            else { BOOST_CHECK_EXCEPTION(caller.get(), std::runtime_error,
                [](const std::runtime_error& e) { return std::string(e.what()) == "test context failure"; }); }
        }
        BOOST_CHECK_EQUAL(EpochContextCacheTestAccess::Pending(cache), 0U);
        const auto retried = cache.Get(0);
        BOOST_CHECK_EQUAL(retried->epoch_number, 0);
        BOOST_CHECK(cache.Get(0) == retried);
        BOOST_CHECK_EQUAL(builds.load(), 2);
    }
}

BOOST_AUTO_TEST_CASE(concurrent_evictions_retain_correct_epochs)
{
    EpochContextCache cache(2, FakeContext);
    std::vector<std::future<bool>> callers;
    for (int thread = 0; thread < 12; ++thread) {
        callers.emplace_back(std::async(std::launch::async, [&, thread] {
            for (int i = 0; i < 500; ++i) {
                const int epoch = (i + thread) % 7;
                const auto held = cache.Get(epoch);
                cache.Get((epoch + 1) % 7);
                if (held->epoch_number != epoch) return false;
            }
            return true;
        }));
    }
    for (auto& caller : callers) BOOST_CHECK(caller.get());
    BOOST_CHECK_EQUAL(EpochContextCacheTestAccess::Pending(cache), 0U);
}

BOOST_AUTO_TEST_CASE(cached_contexts_match_progpow_vectors)
{
    EpochContextCache cache(2);
    for (const auto& v : progpow_hash_test_cases) {
        const auto context = cache.Get(ethash::get_epoch_number(v.block_number));
        const auto result = progpow::hash(*context, v.block_number, to_hash256(v.header_hash_hex), std::stoull(v.nonce_hex, nullptr, 16));
        BOOST_CHECK_EQUAL(to_hex(result.mix_hash), v.mix_hash_hex);
        BOOST_CHECK_EQUAL(to_hex(result.final_hash), v.final_hash_hex);
    }
}

BOOST_AUTO_TEST_CASE(shared_real_contexts_hash_concurrently)
{
    EpochContextCache cache(2);
    std::vector<std::future<bool>> callers;
    for (int thread = 0; thread < 12; ++thread) {
        callers.emplace_back(std::async(std::launch::async, [&, thread] {
            for (int i = 0; i < 8; ++i) {
                const auto& v = progpow_hash_test_cases[(i + thread) % 2 ? 0 : 4];
                const auto context = cache.Get(ethash::get_epoch_number(v.block_number));
                const auto result = progpow::hash(*context, v.block_number, to_hash256(v.header_hash_hex), std::stoull(v.nonce_hex, nullptr, 16));
                if (to_hex(result.mix_hash) != v.mix_hash_hex || to_hex(result.final_hash) != v.final_hash_hex) return false;
            }
            return true;
        }));
    }
    for (auto& caller : callers) BOOST_CHECK(caller.get());
}

BOOST_AUTO_TEST_CASE(pin_reserves_before_waiting_and_survives_eviction_pressure)
{
    Gate gate;
    std::atomic<int> a_builds{0};
    EpochContextCache cache(2, [&](int epoch) {
        if (epoch == 0) { ++a_builds; gate.Wait(); }
        return FakeContext(epoch);
    });
    auto pending_pin = std::async(std::launch::async, [&] { return cache.Pin(0); });
    const bool started = EpochContextCacheTestAccess::WaitForCallers(cache, 0, 1);
    auto pressure = std::async(std::launch::async, [&] {
        for (int epoch = 1; epoch < 20; ++epoch) cache.Get(epoch);
    });
    const bool pressure_done = pressure.wait_for(std::chrono::seconds(10)) == std::future_status::ready;
    gate.Open();
    auto pinned = pending_pin.get();
    pressure.get();
    BOOST_CHECK(started && pressure_done);
    for (int epoch = 20; epoch < 40; ++epoch) {
        cache.Get(epoch);
        BOOST_CHECK(cache.Get(0) == pinned.SharedContext());
    }
    BOOST_CHECK_EQUAL(a_builds.load(), 1);
}

BOOST_AUTO_TEST_CASE(pin_moves_release_exactly_one_reservation)
{
    EpochContextCache cache(2, FakeContext);
    auto a = cache.Pin(0);
    auto b = cache.Pin(1);
    const auto b_context = b.SharedContext();
    BOOST_CHECK_THROW(cache.Pin(2), std::runtime_error);
    a = std::move(b); // Releases A; transfers B's reservation.
    BOOST_CHECK(!b);
    {
        auto c = cache.Pin(2);
        BOOST_CHECK_THROW(cache.Pin(3), std::runtime_error);
        auto moved = std::move(c);
        BOOST_CHECK(!c);
        cache.Get(4); // Cannot evict either pinned epoch.
        BOOST_CHECK(cache.Get(1) == b_context);
        BOOST_CHECK(cache.Get(2) == moved.SharedContext());
    }
    BOOST_CHECK_NO_THROW(cache.Pin(3));
    BOOST_CHECK(cache.Get(1) == b_context);
    a = EpochContextCache::Pinned{};
    BOOST_CHECK_NO_THROW(cache.Pin(4));
}

BOOST_AUTO_TEST_CASE(full_pin_capacity_does_not_block_or_cancel_get)
{
    Gate gate;
    std::atomic<int> b_builds{0};
    EpochContextCache cache(1, [&](int epoch) {
        if (epoch == 1) { ++b_builds; gate.Wait(); }
        return FakeContext(epoch);
    });
    auto a = cache.Pin(0);
    BOOST_CHECK_THROW(cache.Pin(1), std::runtime_error);
    BOOST_CHECK_EQUAL(b_builds.load(), 0);
    std::vector<std::future<Context>> callers;
    for (int i = 0; i < 8; ++i) callers.emplace_back(std::async(std::launch::async, [&] { return cache.Get(1); }));
    const bool joined = EpochContextCacheTestAccess::WaitForCallers(cache, 1, 8);
    BOOST_CHECK_THROW(cache.Pin(1), std::runtime_error); // Must leave Get's attempt intact.
    gate.Open();
    const auto b = callers.front().get();
    for (size_t i = 1; i < callers.size(); ++i) BOOST_CHECK(callers[i].get() == b);
    BOOST_CHECK(joined);
    BOOST_CHECK_EQUAL(b_builds.load(), 1);
    BOOST_CHECK(cache.Get(0) == a.SharedContext());
    BOOST_CHECK_EQUAL(EpochContextCacheTestAccess::Pending(cache), 0U);
}

BOOST_AUTO_TEST_CASE(pending_pins_reserve_capacity_and_failed_pins_allow_retry)
{
    Gate gate;
    std::atomic<int> a_builds{0};
    EpochContextCache cache(1, [&](int epoch) -> Context {
        if (epoch == 0 && ++a_builds == 1) { gate.Wait(); return {}; }
        return FakeContext(epoch);
    });
    std::vector<std::future<EpochContextCache::Pinned>> callers;
    for (int i = 0; i < 8; ++i) callers.emplace_back(std::async(std::launch::async, [&] { return cache.Pin(0); }));
    const bool joined = EpochContextCacheTestAccess::WaitForCallers(cache, 0, 8);
    BOOST_CHECK_THROW(cache.Pin(1), std::runtime_error);
    BOOST_CHECK_EQUAL(cache.Get(1)->epoch_number, 1); // A reservation does not block another epoch's build.
    gate.Open();
    BOOST_CHECK_THROW(callers.front().get(), std::bad_alloc);
    auto retried = cache.Pin(0);
    // Consuming old failures must not release the new attempt's reservation.
    for (size_t i = 1; i < callers.size(); ++i) BOOST_CHECK_THROW(callers[i].get(), std::bad_alloc);
    BOOST_CHECK(joined);
    BOOST_CHECK_THROW(cache.Pin(1), std::runtime_error);
    cache.Get(1);
    BOOST_CHECK(cache.Get(0) == retried.SharedContext());
    BOOST_CHECK_EQUAL(a_builds.load(), 2);
}

BOOST_AUTO_TEST_SUITE_END()
