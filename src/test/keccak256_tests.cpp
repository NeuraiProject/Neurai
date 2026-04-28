// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/keccak256.h"
#include "utilstrencodings.h"
#include "test/test_neurai.h"

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(keccak256_tests, BasicTestingSetup)

static std::string Keccak256Hex(const std::string& s)
{
    unsigned char hash[32];
    crypto::Keccak256(reinterpret_cast<const unsigned char*>(s.data()),
                      s.size(), hash);
    return HexStr(hash, hash + 32);
}

BOOST_AUTO_TEST_CASE(keccak256_empty)
{
    // Ethereum / Keccak-256 reference: keccak256("") =
    //   c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    BOOST_CHECK_EQUAL(
        Keccak256Hex(""),
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
}

BOOST_AUTO_TEST_CASE(keccak256_abc)
{
    // keccak256("abc") =
    //   4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
    BOOST_CHECK_EQUAL(
        Keccak256Hex("abc"),
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
}

BOOST_AUTO_TEST_CASE(keccak256_hello)
{
    // keccak256("Hello") = (Ethereum reference)
    //   06b3dfaec148fb1bb2b066f10ec285e7c9bf402ab32aa78a5d38e34566810cd2
    BOOST_CHECK_EQUAL(
        Keccak256Hex("Hello"),
        "06b3dfaec148fb1bb2b066f10ec285e7c9bf402ab32aa78a5d38e34566810cd2");
}

BOOST_AUTO_TEST_CASE(keccak256_length_consistency)
{
    // Sanity: distinct inputs of different lengths produce distinct
    // 32-byte outputs (rules out a corrupt wrapper that always
    // returns the same buffer or zeroes it out).
    unsigned char h_a[32], h_b[32], h_c[32];
    crypto::Keccak256(reinterpret_cast<const unsigned char*>("x"),  1, h_a);
    crypto::Keccak256(reinterpret_cast<const unsigned char*>("xy"), 2, h_b);
    crypto::Keccak256(reinterpret_cast<const unsigned char*>(""),   0, h_c);
    BOOST_CHECK(memcmp(h_a, h_b, 32) != 0);
    BOOST_CHECK(memcmp(h_b, h_c, 32) != 0);
    BOOST_CHECK(memcmp(h_a, h_c, 32) != 0);
}

BOOST_AUTO_TEST_SUITE_END()
