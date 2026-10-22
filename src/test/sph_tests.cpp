// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#include "data/sph_compat.json.h"
#include "chainparams.h"
#include "hash.h"
#include "test/scoped_block_network.h"
#include "utilstrencodings.h"
#include <boost/test/unit_test.hpp>
#include <univalue.h>
#include <algorithm>
#include <array>
#include <limits>

BOOST_AUTO_TEST_SUITE(sph_tests)

BOOST_AUTO_TEST_CASE(independent_digest_vectors_with_unaligned_input_and_output)
{
    UniValue vectors;
    BOOST_REQUIRE(vectors.read(std::string(json_tests::sph_compat,
        json_tests::sph_compat + sizeof(json_tests::sph_compat))));
    for (const auto& entry : vectors["cases"].getValues()) {
        const int algorithm = entry["algorithm"].get_int();
        const auto bytes = ParseHex(entry["input"].get_str());
        const std::string expected = entry["expected"].get_str();
        for (size_t offset = 0; offset < 16; ++offset) {
            std::vector<unsigned char> input(bytes.size() + 16, 0);
            std::copy(bytes.begin(), bytes.end(), input.begin() + offset);
            const auto* data = input.data() + offset;
            alignas(16) unsigned char output[96];
            std::fill(std::begin(output), std::end(output), 0xa5);
            if (algorithm < 16) {
                if (algorithm == 9) {
                    sph_simd512_context ctx;
                    sph_simd512_init(&ctx);
                    for (size_t i=0;i<bytes.size();++i) sph_simd512(&ctx,data+i,1);
                    sph_simd512_close(&ctx,output+offset);
                } else {
                    BOOST_REQUIRE_EQUAL(algorithm,12);
                    sph_fugue512_context ctx;
                    sph_fugue512_init(&ctx);
                    for (size_t i=0;i<bytes.size();++i) sph_fugue512(&ctx,data+i,1);
                    sph_fugue512_close(&ctx,output+offset);
                }
                BOOST_CHECK_EQUAL(HexStr(output+offset,output+offset+64),expected);
                for (size_t i=0;i<offset;++i) BOOST_CHECK_EQUAL(output[i],0xa5);
                for (size_t i=offset+64;i<sizeof output;++i) BOOST_CHECK_EQUAL(output[i],0xa5);
            } else {
                BOOST_REQUIRE_EQUAL(bytes.size(),80U);
                uint256 previous;
                std::copy(data+4,data+36,previous.begin());
                const auto result=algorithm==16 ? HashX16R(data,data+80,previous) : HashX16RV2(data,data+80,previous);
                BOOST_CHECK_EQUAL(result.GetHex(),expected);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(integer_encoding_preserves_bytes_at_every_alignment)
{
    const uint64_t values[]{0,1,UINT64_C(0x0123456789abcdef),UINT64_C(0x8000000000000000),UINT64_MAX};
    alignas(16) unsigned char buffer[64];
    for (uint64_t value:values) for (size_t offset=0;offset<16;++offset) for (unsigned format=0;format<4;++format) {
        const unsigned width=format<2 ? 4 : 8;
        const bool big=format%2;
        const uint64_t narrowed=width==4 ? uint32_t(value) : value;
        std::fill(std::begin(buffer),std::end(buffer),0xa5);
        auto* data=buffer+16+offset;
        if(width==4) { if(big)sph_enc32be(data,narrowed);else sph_enc32le(data,narrowed); }
        else { if(big)sph_enc64be(data,narrowed);else sph_enc64le(data,narrowed); }
        for(size_t i=0;i<sizeof buffer;++i) {
            const size_t start=16+offset;
            const unsigned char expected=i>=start && i<start+width ?
                static_cast<unsigned char>(narrowed>>(8*(big ? width-1-(i-start) : i-start))) : 0xa5;
            BOOST_CHECK_EQUAL(buffer[i],expected);
        }
        const uint64_t decoded=width==4 ? (big ? sph_dec32be(data) : sph_dec32le(data)) :
            (big ? sph_dec64be(data) : sph_dec64le(data));
        BOOST_CHECK_EQUAL(decoded,narrowed);
    }
}

BOOST_AUTO_TEST_CASE(wallet_network_scope_matches_testnet_and_restores_globals)
{
    const auto saved=bNetwork;
    const auto activation=nKAWPOWActivationTime;
    {
        ScopedTestBlockNetwork main(CBaseChainParams::MAIN);
        BOOST_CHECK(!bNetwork.fSHA256Mining && !bNetwork.fOnTestnet && !bNetwork.fOnRegtest);
        {
            ScopedTestBlockNetwork test(CBaseChainParams::TESTNET);
            BOOST_CHECK(bNetwork.fSHA256Mining && bNetwork.fOnTestnet && !bNetwork.fOnRegtest);
            const auto params=CreateChainParams(CBaseChainParams::TESTNET);
            BOOST_CHECK_EQUAL(params->GenesisBlock().GetHash().GetHex(),
                "0000008b384aeffecdab182575dc4e86c9f07f90318c65088532660ed9a8a021");
            {
                ScopedTestBlockNetwork reg(CBaseChainParams::REGTEST);
                BOOST_CHECK(bNetwork.fSHA256Mining && bNetwork.fOnRegtest && !bNetwork.fOnTestnet);
                nKAWPOWActivationTime=123;
            }
            BOOST_CHECK(bNetwork.fSHA256Mining && bNetwork.fOnTestnet && !bNetwork.fOnRegtest);
            BOOST_CHECK_EQUAL(nKAWPOWActivationTime,UINT32_MAX);
        }
        BOOST_CHECK(!bNetwork.fSHA256Mining && !bNetwork.fOnTestnet && !bNetwork.fOnRegtest);
    }
    BOOST_CHECK_EQUAL(bNetwork.fSHA256Mining,saved.fSHA256Mining);
    BOOST_CHECK_EQUAL(bNetwork.fOnTestnet,saved.fOnTestnet);
    BOOST_CHECK_EQUAL(bNetwork.fOnRegtest,saved.fOnRegtest);
    BOOST_CHECK_EQUAL(nKAWPOWActivationTime,activation);
}
BOOST_AUTO_TEST_SUITE_END()
