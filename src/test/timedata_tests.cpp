// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include "timedata.h"
#include "test/test_neurai.h"

#include <boost/test/unit_test.hpp>
#include <chain.h>
#include <limits>

BOOST_FIXTURE_TEST_SUITE(timedata_tests, BasicTestingSetup)

    BOOST_AUTO_TEST_CASE(util_MedianFilter_test)
    {
        BOOST_TEST_MESSAGE("Running Util MedianFilter Test");

        CMedianFilter<int> filter(5, 15);

        BOOST_CHECK_EQUAL(filter.median(), 15);

        filter.input(20); // [15 20]
        BOOST_CHECK_EQUAL(filter.median(), 17);

        filter.input(30); // [15 20 30]
        BOOST_CHECK_EQUAL(filter.median(), 20);

        filter.input(3); // [3 15 20 30]
        BOOST_CHECK_EQUAL(filter.median(), 17);

        filter.input(7); // [3 7 15 20 30]
        BOOST_CHECK_EQUAL(filter.median(), 15);

        filter.input(18); // [3 7 18 20 30]
        BOOST_CHECK_EQUAL(filter.median(), 18);

        filter.input(0); // [0 3 7 18 30]
        BOOST_CHECK_EQUAL(filter.median(), 7);
    }


namespace {
CNetAddr TimePeer(unsigned int id)
{
    const uint8_t bytes[4] = {10, 1, static_cast<uint8_t>(id >> 8), static_cast<uint8_t>(id)};
    CNetAddr address;
    address.SetRaw(NET_IPV4, bytes);
    return address;
}

int64_t MedianOfPeers(int64_t sample, int64_t limit)
{
    TimeOffsetData data;
    for (unsigned int i = 1; i <= 4; ++i) data.AddSample(TimePeer(i), sample, limit);
    return data.Offset();
}
}

BOOST_AUTO_TEST_CASE(default_adjustment_leaves_room_for_opposite_peer_skews)
{
    BOOST_CHECK_EQUAL(DEFAULT_MAX_TIME_ADJUSTMENT, 300);
    BOOST_CHECK_LT(2 * DEFAULT_MAX_TIME_ADJUSTMENT, MAX_FUTURE_BLOCK_TIME_DGW);
    for (const int64_t offset : {-300, -299, 0, 299, 300})
        BOOST_CHECK_EQUAL(MedianOfPeers(offset, DEFAULT_MAX_TIME_ADJUSTMENT), offset);
    for (const int64_t offset : {-4200, -721, -301, 301, 721, 4200})
        BOOST_CHECK_EQUAL(MedianOfPeers(offset, DEFAULT_MAX_TIME_ADJUSTMENT), 0);
}

BOOST_AUTO_TEST_CASE(disabled_and_custom_adjustment_limits)
{
    for (const int64_t limit : {-1, 0}) {
        for (const int64_t offset : {-300, -1, 0, 1, 300})
            BOOST_CHECK_EQUAL(MedianOfPeers(offset, limit), 0);
    }
    for (const int64_t offset : {-120, 120}) BOOST_CHECK_EQUAL(MedianOfPeers(offset, 120), offset);
    for (const int64_t offset : {-121, 121}) BOOST_CHECK_EQUAL(MedianOfPeers(offset, 120), 0);
    // An explicit operator override remains effective, including the old limit.
    BOOST_CHECK_EQUAL(MedianOfPeers(600, 600), 600);
    BOOST_CHECK_EQUAL(MedianOfPeers(-4200, 4200), -4200);
}

BOOST_AUTO_TEST_CASE(distinct_peers_and_minimum_sample_count)
{
    TimeOffsetData data;
    for (unsigned int i = 1; i <= 3; ++i) {
        data.AddSample(TimePeer(i), 100, 300);
        BOOST_CHECK_EQUAL(data.Offset(), 0);
    }
    for (int i = 0; i < 10; ++i) data.AddSample(TimePeer(1), -200, 300);
    BOOST_CHECK_EQUAL(data.Offset(), 0);
    data.AddSample(TimePeer(4), 100, 300);
    BOOST_CHECK_EQUAL(data.Offset(), 100);
    data.AddSample(TimePeer(5), -200, 300); // Six samples, including the initial zero.
    BOOST_CHECK_EQUAL(data.Offset(), 100);
    data.AddSample(TimePeer(6), -200, 300); // Median of seven is still 100.
    BOOST_CHECK_EQUAL(data.Offset(), 100);
    data.AddSample(TimePeer(7), -200, 300);
    data.AddSample(TimePeer(8), -200, 300);
    BOOST_CHECK_EQUAL(data.Offset(), 0);
}

BOOST_AUTO_TEST_CASE(sample_cap_preserves_the_existing_lifetime_bound)
{
    TimeOffsetData data;
    for (unsigned int i = 1; i <= 200; ++i) data.AddSample(TimePeer(i), 100, 300);
    BOOST_CHECK_EQUAL(data.Offset(), 100);
    for (unsigned int i = 201; i <= 450; ++i) data.AddSample(TimePeer(i), -200, 300);
    BOOST_CHECK_EQUAL(data.Offset(), 100);
}

BOOST_AUTO_TEST_CASE(out_of_range_median_resets_offset_and_warns_once)
{
    TimeOffsetData data;
    for (unsigned int i = 1; i <= 4; ++i) BOOST_CHECK(!data.AddSample(TimePeer(i), 300, 300));
    BOOST_CHECK_EQUAL(data.Offset(), 300);
    unsigned int warnings = 0;
    for (unsigned int i = 5; i <= 20; ++i) warnings += data.AddSample(TimePeer(i), 1000, 300);
    BOOST_CHECK_EQUAL(data.Offset(), 0);
    BOOST_CHECK_EQUAL(warnings, 1U);
    TimeOffsetData near;
    BOOST_CHECK(!near.AddSample(TimePeer(1), 60, 300));
    for (unsigned int i = 2; i <= 8; ++i) BOOST_CHECK(!near.AddSample(TimePeer(i), 1000, 300));
    BOOST_CHECK_EQUAL(near.Offset(), 0);
}

BOOST_AUTO_TEST_CASE(extreme_samples_cannot_overflow_median_bounds)
{
    const auto low = std::numeric_limits<int64_t>::min();
    const auto high = std::numeric_limits<int64_t>::max();
    for (const int64_t offset : {low, low + 1, high}) {
        BOOST_CHECK_EQUAL(MedianOfPeers(offset, 300), 0);
        BOOST_CHECK_EQUAL(MedianOfPeers(offset, 0), 0);
    }
    BOOST_CHECK_EQUAL(MedianOfPeers(low, high), 0);
    BOOST_CHECK_EQUAL(MedianOfPeers(-high, high), -high);
    BOOST_CHECK_EQUAL(MedianOfPeers(high, high), high);
}

BOOST_AUTO_TEST_CASE(peer_timestamp_subtraction_saturates_without_overflow)
{
    const auto low = std::numeric_limits<int64_t>::min();
    const auto high = std::numeric_limits<int64_t>::max();
    BOOST_CHECK_EQUAL(GetTimeOffsetSample(1700000300, 1700000000), 300);
    BOOST_CHECK_EQUAL(GetTimeOffsetSample(1699999700, 1700000000), -300);
    BOOST_CHECK_EQUAL(GetTimeOffsetSample(low, 1700000000), low);
    BOOST_CHECK_EQUAL(GetTimeOffsetSample(high, -1), high);
    BOOST_CHECK_EQUAL(GetTimeOffsetSample(low, high), low);
    BOOST_CHECK_EQUAL(GetTimeOffsetSample(high, low), high);
    BOOST_CHECK_EQUAL(GetTimeOffsetSample(low, low), 0);
    BOOST_CHECK_EQUAL(GetTimeOffsetSample(high, high), 0);
    BOOST_CHECK_EQUAL(GetTimeOffsetSample(-1, high), low);
    BOOST_CHECK_EQUAL(GetTimeOffsetSample(-1, low), high);
    BOOST_CHECK_EQUAL(GetTimeOffsetSample(low, 0), low);
    BOOST_CHECK_EQUAL(GetTimeOffsetSample(high, 0), high);
}

BOOST_AUTO_TEST_SUITE_END()
