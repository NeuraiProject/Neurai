// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#include "crypto/groth16_bn254.h"
#include "test/data/groth16_vectors.h"
#include "utilstrencodings.h"
#include <boost/test/unit_test.hpp>
using neurai::zk::Result;
namespace {
struct Fixture {
    std::vector<unsigned char> vk=ParseHex(groth16_vectors::VK);
    std::vector<unsigned char> proof=ParseHex(groth16_vectors::PROOF);
    std::vector<unsigned char> inputs=ParseHex(groth16_vectors::INPUTS);
    Result Verify() const { return neurai::zk::Verify(vk,proof,inputs); }
};
}
BOOST_FIXTURE_TEST_SUITE(groth16_tests, Fixture)
BOOST_AUTO_TEST_CASE(real_proof) { BOOST_CHECK(Verify()==Result::VALID); }
BOOST_AUTO_TEST_CASE(rerandomized_proof) {
    proof=ParseHex(groth16_vectors::RERANDOMIZED);
    BOOST_CHECK(Verify()==Result::VALID);
}
BOOST_AUTO_TEST_CASE(wrong_statement) {
    inputs.back()^=1; BOOST_CHECK(Verify()==Result::INVALID);
}
BOOST_AUTO_TEST_CASE(other_circuit) {
    vk=ParseHex(groth16_vectors::OTHER_VK); BOOST_CHECK(Verify()==Result::INVALID);
}
BOOST_AUTO_TEST_CASE(input_range_and_count) {
    inputs.clear(); BOOST_CHECK(Verify()==Result::INPUT_COUNT);
    inputs.resize(32*17); BOOST_CHECK(Verify()==Result::INPUT_COUNT);
    inputs.resize(33); BOOST_CHECK(Verify()==Result::INPUT_COUNT);
    inputs=ParseHex(groth16_vectors::INPUTS);
    auto r=ParseHex("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001");
    std::copy(r.begin(),r.end(),inputs.begin()); BOOST_CHECK(Verify()==Result::INPUT_RANGE);
}
BOOST_AUTO_TEST_CASE(proof_encoding) {
    proof.pop_back(); BOOST_CHECK(Verify()==Result::PROOF_ENCODING);
    proof=ParseHex(groth16_vectors::PROOF); proof.push_back(0); BOOST_CHECK(Verify()==Result::PROOF_ENCODING);
    proof.clear(); BOOST_CHECK(Verify()==Result::PROOF_ENCODING);
    proof=ParseHex(groth16_vectors::PROOF); proof[31]|=0x40; BOOST_CHECK(Verify()==Result::PROOF_ENCODING);
    proof=ParseHex(groth16_vectors::PROOF);
    auto q=ParseHex(groth16_vectors::G2_NON_SUBGROUP);
    std::copy(q.begin(),q.end(),proof.begin()+32); BOOST_CHECK(Verify()==Result::PROOF_ENCODING);
}
BOOST_AUTO_TEST_CASE(vk_encoding) {
    vk.push_back(0); BOOST_CHECK(Verify()==Result::VK_ENCODING);
    vk=ParseHex(groth16_vectors::VK); vk[225]=1; BOOST_CHECK(Verify()==Result::VK_ENCODING);
    vk=ParseHex(groth16_vectors::VK); vk[95]|=0x40; BOOST_CHECK(Verify()==Result::VK_ENCODING);
    vk=ParseHex(groth16_vectors::VK); std::fill(vk.begin(),vk.begin()+32,0xff); BOOST_CHECK(Verify()==Result::VK_ENCODING);
}
BOOST_AUTO_TEST_CASE(k_mismatch) {
    inputs.resize(32); BOOST_CHECK(Verify()==Result::INPUT_COUNT);
}
BOOST_AUTO_TEST_SUITE_END()
