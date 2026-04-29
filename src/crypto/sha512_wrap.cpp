// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "crypto/sha512_wrap.h"

#include "crypto/sha512.h"

namespace crypto {

void SHA512_Wrap(const unsigned char* data, size_t len,
                  unsigned char hash[64])
{
    CSHA512().Write(data, len).Finalize(hash);
}

} // namespace crypto
