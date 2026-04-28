// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/keccak256.h"
#include "crypto/ethash/include/ethash/keccak.hpp"

#include <cstring>

namespace crypto {

void Keccak256(const unsigned char* data, size_t len,
               unsigned char hash[32])
{
    const ethash::hash256 h = ethash::keccak256(data, len);
    std::memcpy(hash, h.bytes, 32);
}

} // namespace crypto
