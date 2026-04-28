// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/blake2b.h"
#include "utilstrencodings.h"
#include "test/test_neurai.h"

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(blake2b_tests, BasicTestingSetup)

static std::string Blake2bHex(const std::string& s)
{
    unsigned char hash[32];
    crypto::Blake2b256(reinterpret_cast<const unsigned char*>(s.data()),
                       s.size(), hash);
    return HexStr(hash, hash + 32);
}

BOOST_AUTO_TEST_CASE(blake2b_empty)
{
    // BLAKE2b-256 with default parameters of empty input.
    // Reference:
    //   python3 -c "import hashlib; print(hashlib.blake2b(b'', digest_size=32).hexdigest())"
    //   → 0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8
    BOOST_CHECK_EQUAL(
        Blake2bHex(""),
        "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8");
}

BOOST_AUTO_TEST_CASE(blake2b_abc)
{
    // python3 -c "import hashlib; print(hashlib.blake2b(b'abc', digest_size=32).hexdigest())"
    //   → bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319
    BOOST_CHECK_EQUAL(
        Blake2bHex("abc"),
        "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
}

BOOST_AUTO_TEST_CASE(blake2b_block_boundary)
{
    // 128 bytes is one full block; 129 forces a second block.
    // Verify both transitions don't smear the result.
    // Reference values computed with:
    //   python3 -c "import hashlib; print(hashlib.blake2b(b'a'*N, digest_size=32).hexdigest())"
    std::string b127(127, 'a');
    std::string b128(128, 'a');
    std::string b129(129, 'a');
    BOOST_CHECK_EQUAL(
        Blake2bHex(b127),
        "59e2f1aba240f20aa591016f5ef429990bc9c2131dcd0d30f0ffd75ed18f317d");
    BOOST_CHECK_EQUAL(
        Blake2bHex(b128),
        "ae2aa48507885c4c950fb809b2076f959cde9f8ea6da260d9a3587df33dac450");
    BOOST_CHECK_EQUAL(
        Blake2bHex(b129),
        "2f64744a6de0d2c0b56e64cf6e29a5aaa255010d415d51c75ccc82f73dccd865");
}

BOOST_AUTO_TEST_SUITE_END()
