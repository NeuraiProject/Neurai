// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/blake3_wrap.h"

extern "C" {
#include "crypto/blake3/blake3.h"
}

namespace crypto {

void Blake3_256(const unsigned char* data, size_t len,
                unsigned char hash[32])
{
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, data, len);
    blake3_hasher_finalize(&h, hash, 32);
}

} // namespace crypto
