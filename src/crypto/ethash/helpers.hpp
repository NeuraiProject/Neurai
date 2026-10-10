// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#pragma once

#include <crypto/ethash/include/ethash/ethash.hpp>

#include <string>
#include <stdexcept>

template <typename Hash>
inline std::string to_hex(const Hash& h)
{
    static const auto hex_chars = "0123456789abcdef";
    std::string str;
    str.reserve(sizeof(h) * 2);
    for (auto b : h.bytes)
    {
        str.push_back(hex_chars[uint8_t(b) >> 4]);
        str.push_back(hex_chars[uint8_t(b) & 0xf]);
    }
    return str;
}

inline ethash::hash256 to_hash256(const std::string& hex)
{
    ethash::hash256 hash = {};
    if (hex.size() != sizeof(hash.bytes) * 2)
        throw std::invalid_argument("hash256 requires exactly 64 hexadecimal characters");

    auto parse_digit = [](char d) -> unsigned {
        if (d >= '0' && d <= '9') return d - '0';
        if (d >= 'a' && d <= 'f') return d - 'a' + 10;
        if (d >= 'A' && d <= 'F') return d - 'A' + 10;
        throw std::invalid_argument("invalid hash256 hexadecimal character");
    };
    // Ethash consumes bytes in textual order, not uint256's internal order.
    for (size_t i = 0; i < sizeof(hash.bytes); ++i)
    {
        const unsigned h = parse_digit(hex[2 * i]);
        const unsigned l = parse_digit(hex[2 * i + 1]);
        hash.bytes[i] = uint8_t((h << 4) | l);
    }
    return hash;
}

/// Comparison operator for hash256 to be used in unit tests.
inline bool operator==(const ethash::hash256& a, const ethash::hash256& b) noexcept
{
    return std::memcmp(a.bytes, b.bytes, sizeof(a)) == 0;
}

inline bool operator!=(const ethash::hash256& a, const ethash::hash256& b) noexcept
{
    return !(a == b);
}

inline const ethash::epoch_context& get_ethash_epoch_context_0() noexcept
{
    static ethash::epoch_context_ptr context = ethash::create_epoch_context(0);
    return *context;
}
