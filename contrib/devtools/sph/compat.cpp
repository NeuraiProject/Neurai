// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
// Standalone differential runner: line protocol "algorithm hex", '-' is empty.
// 0..15 are the X16 component hashes; 16=X16R, 17=X16RV2. No network/wallet.
#include "hash.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

static std::vector<unsigned char> Unhex(const std::string& text)
{
    if (text == "-") return {};
    if (text.size() % 2 || text.size() > 2097152) throw std::runtime_error("invalid hex size");
    std::vector<unsigned char> bytes;
    auto digit = [](char c) { if (c >= '0' && c <= '9') return c-'0'; if (c >= 'a' && c <= 'f') return c-'a'+10; if (c >= 'A' && c <= 'F') return c-'A'+10; throw std::runtime_error("invalid hex digit"); };
    for (size_t i = 0; i < text.size(); i += 2) bytes.push_back(digit(text[i])*16+digit(text[i+1]));
    return bytes;
}

static std::vector<unsigned char> Digest(int algorithm, const std::vector<unsigned char>& bytes)
{
    unsigned char out[64];
    const unsigned char empty = 0;
    const auto* data = bytes.empty() ? &empty : bytes.data();
#define COMPONENT(id, name) case id: { sph_##name##_context ctx; sph_##name##_init(&ctx); sph_##name(&ctx, data, bytes.size()); sph_##name##_close(&ctx, out); break; }
    switch (algorithm) {
        COMPONENT(0, blake512) COMPONENT(1, bmw512) COMPONENT(2, groestl512)
        COMPONENT(3, jh512) COMPONENT(4, keccak512) COMPONENT(5, skein512)
        COMPONENT(6, luffa512) COMPONENT(7, cubehash512) COMPONENT(8, shavite512)
        COMPONENT(9, simd512) COMPONENT(10, echo512) COMPONENT(11, hamsi512)
        COMPONENT(12, fugue512) COMPONENT(13, shabal512) COMPONENT(14, whirlpool)
        COMPONENT(15, sha512)
        case 16: case 17: {
            if (bytes.size() != 80) throw std::runtime_error("X16 header must be 80 bytes");
            uint256 previous;
            std::copy(bytes.begin()+4, bytes.begin()+36, previous.begin());
            const auto hash = algorithm == 16 ? HashX16R(data, data+80, previous) : HashX16RV2(data, data+80, previous);
            // The caller reverses these raw bytes for the displayed hash.
            return std::vector<unsigned char>(hash.begin(), hash.end());
        }
        default: throw std::runtime_error("unknown algorithm");
    }
#undef COMPONENT
    return std::vector<unsigned char>(out, out+64);
}

int main(int argc, char** argv)
{
    try {
        if (argc == 2 && std::string(argv[1]) == "--bench") {
            for (int algorithm : {9,12,16,17}) for (size_t size : {size_t(64),size_t(80),size_t(1024)}) {
                if (algorithm >= 16 && size != 80) continue;
                std::vector<unsigned char> bytes(size);
                for (size_t i=0;i<size;++i) bytes[i]=static_cast<unsigned char>(i*37+11);
                // The selectors traverse every X16 component.
                for (size_t i=0;i<8;++i) bytes[4+i]=static_cast<unsigned char>(0xef-i*0x22);
                const unsigned iterations=algorithm>=16 ? 1000 : 20000;
                volatile unsigned guard=0;
                const auto start=std::chrono::steady_clock::now();
                for (unsigned n=0;n<iterations;++n) { bytes.back()=static_cast<unsigned char>(n); auto digest=Digest(algorithm,bytes); guard=guard+digest[n%digest.size()]; }
                const auto us=std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now()-start).count();
                std::cout<<"{\"algorithm\":"<<algorithm<<",\"bytes\":"<<size<<",\"iterations\":"<<iterations<<",\"microseconds\":"<<us<<",\"guard\":"<<guard<<"}\n";
            }
            return 0;
        }
        if (argc != 1) throw std::runtime_error("usage: sph-compat [--bench]");
        std::ios::sync_with_stdio(false);
        int algorithm; std::string hex;
        while (std::cin >> algorithm >> hex) {
            auto digest=Digest(algorithm,Unhex(hex));
            if (algorithm>=16) std::reverse(digest.begin(),digest.end());
            for (auto byte:digest) std::cout<<"0123456789abcdef"[byte>>4]<<"0123456789abcdef"[byte&15];
            std::cout<<'\n';
        }
        return std::cin.eof() ? 0 : 1;
    } catch (const std::exception& e) { std::cerr<<e.what()<<'\n';return 1; }
}
