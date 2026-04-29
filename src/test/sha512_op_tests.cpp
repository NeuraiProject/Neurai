// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NIP-034a: tests for the SHA512_Wrap helper. The underlying
// CSHA512 class is already FIPS 180-4 verified by TestSHA512 cases
// in src/test/crypto_tests.cpp; here we only verify that the
// wrapper forwards correctly.

#include "crypto/sha512.h"
#include "crypto/sha512_wrap.h"
#include "test/test_neurai.h"
#include "utilstrencodings.h"

#include <cstring>
#include <string>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(sha512_op_tests, BasicTestingSetup)

namespace {

std::string SHA512WrapHex(const std::string& s)
{
    unsigned char hash[64];
    crypto::SHA512_Wrap(reinterpret_cast<const unsigned char*>(s.data()),
                         s.size(), hash);
    return HexStr(hash, hash + 64);
}

} // namespace

BOOST_AUTO_TEST_CASE(sha512_wrap_empty)
{
    // FIPS 180-4 reference for SHA-512 of empty string.
    BOOST_CHECK_EQUAL(
        SHA512WrapHex(""),
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
}

BOOST_AUTO_TEST_CASE(sha512_wrap_abc)
{
    BOOST_CHECK_EQUAL(
        SHA512WrapHex("abc"),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

// Wrapper forwards correctly: same hash as direct CSHA512 use.
BOOST_AUTO_TEST_CASE(sha512_wrap_matches_csha512_direct)
{
    const char* msg = "the quick brown fox jumps over the lazy dog";
    const size_t len = strlen(msg);

    unsigned char via_wrap[64];
    crypto::SHA512_Wrap(reinterpret_cast<const unsigned char*>(msg), len, via_wrap);

    unsigned char via_direct[64];
    CSHA512().Write(reinterpret_cast<const unsigned char*>(msg), len)
              .Finalize(via_direct);

    BOOST_CHECK(memcmp(via_wrap, via_direct, 64) == 0);
}

BOOST_AUTO_TEST_CASE(sha512_wrap_long_input)
{
    // 1000 bytes of 'a' — covers multiple SHA-512 blocks (block size 128 B).
    std::string s(1000, 'a');
    unsigned char via_wrap[64], via_direct[64];
    crypto::SHA512_Wrap(reinterpret_cast<const unsigned char*>(s.data()),
                         s.size(), via_wrap);
    CSHA512().Write(reinterpret_cast<const unsigned char*>(s.data()), s.size())
              .Finalize(via_direct);
    BOOST_CHECK(memcmp(via_wrap, via_direct, 64) == 0);
}

BOOST_AUTO_TEST_SUITE_END()
