// Copyright (c) 2025 The Neurai Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include "depinmcpworker.h"
#include "test/test_neurai.h"
#include "uint256.h"
#include "utiltime.h"

#include <cstring>
#include <string>

// Friend accessor that exposes the worker's private logic to the tests without
// going through Initialize() (which performs network I/O to the MCP server).
struct DepinMCPWorkerTester
{
    static void SetCommandKey(CDepinMCPWorker& w, const std::string& k) { w.commandKey = k; }
    static bool ExtractCommand(CDepinMCPWorker& w, const std::string& msg, std::string& out) { return w.ExtractCommand(msg, out); }

    static void SetRateLimit(CDepinMCPWorker& w, int n) { w.rateLimitPerMinute = n; }
    static bool CheckRateLimit(CDepinMCPWorker& w, const std::string& a) { return w.CheckRateLimit(a); }

    static void SetGlobalRateLimit(CDepinMCPWorker& w, int n) { w.globalRateLimitPerMinute = n; }
    static bool CheckGlobalRateLimit(CDepinMCPWorker& w) { return w.CheckGlobalRateLimit(); }

    static void MarkAsProcessed(CDepinMCPWorker& w, const uint256& h) { w.MarkAsProcessed(h); }
    static bool IsMessageProcessed(CDepinMCPWorker& w, const uint256& h) { return w.IsMessageProcessed(h); }
};

namespace {
uint256 HashFromInt(uint32_t i)
{
    uint256 h;
    memcpy(h.begin(), &i, sizeof(i));
    return h;
}
}

BOOST_FIXTURE_TEST_SUITE(depinmcpworker_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(extract_command)
{
    CDepinMCPWorker w;
    DepinMCPWorkerTester::SetCommandKey(w, "/ai");

    std::string out;

    // Basic prefix stripping
    BOOST_CHECK(DepinMCPWorkerTester::ExtractCommand(w, "/ai hello world", out));
    BOOST_CHECK_EQUAL(out, "hello world");

    // Leading/trailing whitespace is trimmed
    BOOST_CHECK(DepinMCPWorkerTester::ExtractCommand(w, "/ai    spaced text   ", out));
    BOOST_CHECK_EQUAL(out, "spaced text");

    // Just the prefix yields an empty (but valid) command
    BOOST_CHECK(DepinMCPWorkerTester::ExtractCommand(w, "/ai", out));
    BOOST_CHECK_EQUAL(out, "");

    // Missing prefix is rejected
    BOOST_CHECK(!DepinMCPWorkerTester::ExtractCommand(w, "hello", out));

    // Overly long input is capped
    std::string longInput = "/ai " + std::string(MCP_MAX_COMMAND_CHARS + 1000, 'x');
    BOOST_CHECK(DepinMCPWorkerTester::ExtractCommand(w, longInput, out));
    BOOST_CHECK_EQUAL(out.length(), MCP_MAX_COMMAND_CHARS);
}

BOOST_AUTO_TEST_CASE(per_sender_rate_limit)
{
    CDepinMCPWorker w;
    DepinMCPWorkerTester::SetRateLimit(w, 2); // 2 per minute per sender

    SetMockTime(1000000);

    // First two pass, third is rejected
    BOOST_CHECK(DepinMCPWorkerTester::CheckRateLimit(w, "addrA"));
    BOOST_CHECK(DepinMCPWorkerTester::CheckRateLimit(w, "addrA"));
    BOOST_CHECK(!DepinMCPWorkerTester::CheckRateLimit(w, "addrA"));

    // A different sender has an independent budget
    BOOST_CHECK(DepinMCPWorkerTester::CheckRateLimit(w, "addrB"));

    // After the window rolls over, addrA can send again
    SetMockTime(1000000 + 61);
    BOOST_CHECK(DepinMCPWorkerTester::CheckRateLimit(w, "addrA"));

    SetMockTime(0);
}

BOOST_AUTO_TEST_CASE(global_rate_limit)
{
    CDepinMCPWorker w;
    DepinMCPWorkerTester::SetGlobalRateLimit(w, 2); // 2 per minute total

    SetMockTime(2000000);

    BOOST_CHECK(DepinMCPWorkerTester::CheckGlobalRateLimit(w));
    BOOST_CHECK(DepinMCPWorkerTester::CheckGlobalRateLimit(w));
    BOOST_CHECK(!DepinMCPWorkerTester::CheckGlobalRateLimit(w));

    // Disabled (0) always allows
    DepinMCPWorkerTester::SetGlobalRateLimit(w, 0);
    BOOST_CHECK(DepinMCPWorkerTester::CheckGlobalRateLimit(w));

    SetMockTime(0);
}

BOOST_AUTO_TEST_CASE(processed_cache_fifo_eviction)
{
    CDepinMCPWorker w;

    const uint32_t extra = 5;
    const uint32_t total = (uint32_t)MCP_MAX_PROCESSED_CACHE + extra;

    for (uint32_t i = 0; i < total; i++) {
        DepinMCPWorkerTester::MarkAsProcessed(w, HashFromInt(i));
    }

    // Cache is capped at the maximum size
    BOOST_CHECK_EQUAL(w.GetProcessedCacheSize(), MCP_MAX_PROCESSED_CACHE);

    // The oldest entries were evicted (FIFO), the newest are retained
    BOOST_CHECK(!DepinMCPWorkerTester::IsMessageProcessed(w, HashFromInt(0)));
    BOOST_CHECK(!DepinMCPWorkerTester::IsMessageProcessed(w, HashFromInt(extra - 1)));
    BOOST_CHECK(DepinMCPWorkerTester::IsMessageProcessed(w, HashFromInt(extra)));
    BOOST_CHECK(DepinMCPWorkerTester::IsMessageProcessed(w, HashFromInt(total - 1)));

    // Re-marking an existing hash does not grow the cache
    DepinMCPWorkerTester::MarkAsProcessed(w, HashFromInt(total - 1));
    BOOST_CHECK_EQUAL(w.GetProcessedCacheSize(), MCP_MAX_PROCESSED_CACHE);
}

BOOST_AUTO_TEST_SUITE_END()
