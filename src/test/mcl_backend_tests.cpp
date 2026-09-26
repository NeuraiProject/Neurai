// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#include "crypto/mcl_backend.h"
#include <boost/test/unit_test.hpp>
#include <atomic>
#include <barrier>
#include <thread>
#include <vector>
BOOST_AUTO_TEST_SUITE(mcl_backend_tests)
BOOST_AUTO_TEST_CASE(concurrent_initialization)
{
    constexpr unsigned n = 16;
    std::barrier start(n);
    std::atomic<unsigned> successes{0};
    std::vector<std::thread> workers;
    for (unsigned i = 0; i < n; ++i) workers.emplace_back([&] {
        start.arrive_and_wait();
        if (MCL_InitSanityCheck()) ++successes;
    });
    for (auto& t : workers) t.join();
    BOOST_CHECK_EQUAL(successes.load(), n);
    BOOST_CHECK(MCL_InitSanityCheck());
}
BOOST_AUTO_TEST_SUITE_END()
