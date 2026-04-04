// Copyright (c) 2017, 2021 Pieter Wuille
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Bech32 and Bech32m are string encoding formats used in newer address types.
// The outputs consist of a human-readable part (e.g. "nq" for mainnet PQ
// addresses), a separator character ('1'), and a base32-encoded part.
// Bech32m (BIP350) uses a different constant for the checksum from Bech32
// (BIP173), making the two encoding formats incompatible.

#ifndef NEURAI_BECH32_H
#define NEURAI_BECH32_H

#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

namespace bech32 {

enum class Encoding {
    INVALID,   ///< Failed decoding
    BECH32,    ///< Bech32 encoding as defined in BIP173
    BECH32M,   ///< Bech32m encoding as defined in BIP350
};

/** Encode a Bech32 or Bech32m string. Returns empty string on failure.
 *  hrp: the human-readable part
 *  values: 5-bit data values
 *  enc: BECH32 or BECH32M
 */
std::string Encode(const std::string& hrp, const std::vector<uint8_t>& values, Encoding enc = Encoding::BECH32);

struct DecodeResult {
    Encoding encoding;         ///< What encoding was detected in the result; INVALID if failed
    std::string hrp;           ///< The human-readable part
    std::vector<uint8_t> data; ///< The payload (excluding checksum)
};

/** Decode a Bech32 or Bech32m string. */
DecodeResult Decode(const std::string& str);

/** Convert between bit sizes.
 *
 *  'frombits' and 'tobits' must be in the range [1,8]. The function takes the
 *  input from 'in', packs it into groups of 'frombits', then unpacks into
 *  groups of 'tobits'. If padding is true (for encoding), any leftover bits
 *  are zero-padded. If padding is false (for decoding), it fails if the result
 *  has non-zero padding or incomplete groups.
 */
template <int frombits, int tobits, bool pad>
bool ConvertBits(const std::vector<uint8_t>& in, std::vector<uint8_t>& out)
{
    int acc = 0;
    int bits = 0;
    const int maxv = (1 << tobits) - 1;
    const int max_acc = (1 << (frombits + tobits - 1)) - 1;
    for (const auto value : in) {
        if (value < 0 || (value >> frombits)) return false;
        acc = ((acc << frombits) | value) & max_acc;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            out.push_back((acc >> bits) & maxv);
        }
    }
    if (pad) {
        if (bits) out.push_back((acc << (tobits - bits)) & maxv);
    } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
        return false;
    }
    return true;
}

} // namespace bech32

#endif // NEURAI_BECH32_H
