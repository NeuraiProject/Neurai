// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/blake3_wrap.h"
#include "test/test_neurai.h"
#include "utilstrencodings.h"

#include <cstring>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(blake3_tests, BasicTestingSetup)

namespace {

std::string Blake3Hex(const std::string& s)
{
    unsigned char hash[32];
    crypto::Blake3_256(reinterpret_cast<const unsigned char*>(s.data()),
                       s.size(), hash);
    return HexStr(hash, hash + 32);
}

std::string Blake3HexBytes(const std::vector<unsigned char>& v)
{
    unsigned char hash[32];
    crypto::Blake3_256(v.data(), v.size(), hash);
    return HexStr(hash, hash + 32);
}

} // namespace

// Reference vectors from BLAKE3 official KAT (test_vectors.json):
//   https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
// All inputs use the spec's "byte-pattern" generator (i = 0,1,...,251 mod 251).

BOOST_AUTO_TEST_CASE(blake3_empty)
{
    BOOST_CHECK_EQUAL(
        Blake3Hex(""),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
}

BOOST_AUTO_TEST_CASE(blake3_abc)
{
    BOOST_CHECK_EQUAL(
        Blake3Hex("abc"),
        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");
}

// BLAKE3 KAT for input length 1: byte 0x00.
BOOST_AUTO_TEST_CASE(blake3_kat_len_1)
{
    std::vector<unsigned char> v = {0x00};
    BOOST_CHECK_EQUAL(
        Blake3HexBytes(v),
        "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213");
}

// BLAKE3 KAT for input length 2: bytes (0x00, 0x01).
BOOST_AUTO_TEST_CASE(blake3_kat_len_2)
{
    std::vector<unsigned char> v = {0x00, 0x01};
    BOOST_CHECK_EQUAL(
        Blake3HexBytes(v),
        "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63");
}

// BLAKE3 KAT for input length 1024 (one full chunk).
// Input bytes follow BLAKE3 KAT generator: byte i = i mod 251.
// Expected from upstream test_vectors.json (first 32 bytes of the
// extended 262-byte output).
BOOST_AUTO_TEST_CASE(blake3_kat_len_1024)
{
    std::vector<unsigned char> v(1024);
    for (size_t i = 0; i < v.size(); ++i) v[i] = (unsigned char)(i % 251);
    BOOST_CHECK_EQUAL(
        Blake3HexBytes(v),
        "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7");
}

// BLAKE3 KAT for input length 1025 (one full chunk + 1 byte: triggers tree mode).
BOOST_AUTO_TEST_CASE(blake3_kat_len_1025)
{
    std::vector<unsigned char> v(1025);
    for (size_t i = 0; i < v.size(); ++i) v[i] = (unsigned char)(i % 251);
    BOOST_CHECK_EQUAL(
        Blake3HexBytes(v),
        "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444");
}

// Length sanity: distinct inputs of different lengths produce distinct outputs.
BOOST_AUTO_TEST_CASE(blake3_length_consistency)
{
    unsigned char ha[32], hb[32], hc[32];
    crypto::Blake3_256(reinterpret_cast<const unsigned char*>("x"),  1, ha);
    crypto::Blake3_256(reinterpret_cast<const unsigned char*>("xy"), 2, hb);
    crypto::Blake3_256(reinterpret_cast<const unsigned char*>(""),   0, hc);
    BOOST_CHECK(memcmp(ha, hb, 32) != 0);
    BOOST_CHECK(memcmp(ha, hc, 32) != 0);
    BOOST_CHECK(memcmp(hb, hc, 32) != 0);
}

BOOST_AUTO_TEST_SUITE_END()
