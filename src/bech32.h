// Copyright (c) 2017, 2021 Pieter Wuille
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_BECH32_H
#define NEURAI_BECH32_H

#include <stdint.h>
#include <string>
#include <vector>

namespace bech32
{

/**
 * The Bech32 and Bech32m checksums are calculated using the same polynomial
 * logic, but with different encoding constants.
 */
enum class Encoding {
    INVALID,
    BECH32,  // BIP173
    BECH32M, // BIP350
};

/** Encode a Bech32 or Bech32m string.
 *
 *  @param[in] hrp      The human-readable part of the output string.
 *  @param[in] values   The 5-bit symbols for the data part.
 *  @param[in] encoding What encoding encoding to use.
 *  @returns            The encoded string, or an empty string in case of failure.
 */
std::string Encode(const std::string& hrp, const std::vector<uint8_t>& values, Encoding encoding);

/** Decode a Bech32 or Bech32m string.
 *
 *  @param[in] str      The Bech32 or Bech32m string to decode.
 *  @returns            A pair (hrp, data). The hrp will be empty in case of
 *                      failure. The data part will be the 5-bit symbols.
 *                      The encoding will be INVALID if decoding failed.
 */
struct DecodeResult
{
    Encoding encoding;
    std::string hrp;
    std::vector<uint8_t> data;

    DecodeResult() : encoding(Encoding::INVALID) {}
    DecodeResult(Encoding _encoding, std::string _hrp, std::vector<uint8_t> _data) : encoding(_encoding), hrp(_hrp), data(_data) {}
};


DecodeResult Decode(const std::string& str);

/** Convert from one power-of-2 number base to another. */
template<int frombits, int tobits, bool pad, typename O, typename I>
bool ConvertBits(const I& in, O out) {
    int acc = 0;
    int bits = 0;
    int maxv = (1 << tobits) - 1;
    int max_acc = (1 << (frombits + tobits - 1)) - 1;
    for (const auto& byte : in) {
        acc = ((acc << frombits) | byte) & max_acc;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            *out++ = (acc >> bits) & maxv;
        }
    }
    if (pad) {
        if (bits) {
            *out++ = (acc << (tobits - bits)) & maxv;
        }
    } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
        return false;
    }
    return true;
}

} // namespace bech32

#endif // NEURAI_BECH32_H
