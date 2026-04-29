// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/keccak256.h"
#include "crypto/sha3_256.h"
#include "test/test_neurai.h"
#include "utilstrencodings.h"

#include <cstring>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(sha3_256_tests, BasicTestingSetup)

namespace {

std::string SHA3Hex(const std::string& s)
{
    unsigned char hash[32];
    crypto::SHA3_256(reinterpret_cast<const unsigned char*>(s.data()),
                     s.size(), hash);
    return HexStr(hash, hash + 32);
}

} // namespace

// Reference vectors from FIPS 202 / NIST CAVP.

BOOST_AUTO_TEST_CASE(sha3_256_empty)
{
    BOOST_CHECK_EQUAL(
        SHA3Hex(""),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
}

BOOST_AUTO_TEST_CASE(sha3_256_abc)
{
    BOOST_CHECK_EQUAL(
        SHA3Hex("abc"),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
}

BOOST_AUTO_TEST_CASE(sha3_256_long_message)
{
    BOOST_CHECK_EQUAL(
        SHA3Hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376");
}

BOOST_AUTO_TEST_CASE(sha3_256_long_message_2)
{
    BOOST_CHECK_EQUAL(
        SHA3Hex("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
                "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
        "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18");
}

// 1000-byte input of 'a' to cover multiple absorption blocks (rate = 136).
// Cross-checked against Python's hashlib.sha3_256.
BOOST_AUTO_TEST_CASE(sha3_256_1000_a)
{
    std::string s(1000, 'a');
    BOOST_CHECK_EQUAL(
        SHA3Hex(s),
        "8f3934e6f7a15698fe0f396b95d8c4440929a8fa6eae140171c068b4549fbf81");
}

// Sanity: distinct inputs of different lengths produce distinct outputs.
BOOST_AUTO_TEST_CASE(sha3_256_length_consistency)
{
    unsigned char ha[32], hb[32], hc[32];
    crypto::SHA3_256(reinterpret_cast<const unsigned char*>("x"),  1, ha);
    crypto::SHA3_256(reinterpret_cast<const unsigned char*>("xy"), 2, hb);
    crypto::SHA3_256(reinterpret_cast<const unsigned char*>(""),   0, hc);
    BOOST_CHECK(memcmp(ha, hb, 32) != 0);
    BOOST_CHECK(memcmp(ha, hc, 32) != 0);
    BOOST_CHECK(memcmp(hb, hc, 32) != 0);
}

// SHA3-256 must differ from Keccak-256 on the same input.
// The two functions only differ in the padding byte (0x06 vs 0x01),
// but that suffices to produce a different hash for any input.
BOOST_AUTO_TEST_CASE(sha3_256_differs_from_keccak256)
{
    const char* msg = "neurai";
    unsigned char hsha3[32], hkeccak[32];
    crypto::SHA3_256(reinterpret_cast<const unsigned char*>(msg),  6, hsha3);
    crypto::Keccak256(reinterpret_cast<const unsigned char*>(msg), 6, hkeccak);
    BOOST_CHECK(memcmp(hsha3, hkeccak, 32) != 0);
}

BOOST_AUTO_TEST_SUITE_END()
