// Copyright (c) 2017, 2021 Pieter Wuille
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bech32.h"

#include <assert.h>

namespace bech32 {

namespace {

typedef std::vector<uint8_t> data;

// The Bech32 and Bech32m character set for encoding.
const char* CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// The Bech32 and Bech32m character set for decoding.
// Maps ASCII values to 5-bit values; -1 means invalid character.
const int8_t CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
};

// Bech32m constant as defined in BIP350.
const uint32_t BECH32M_CONST = 0x2bc830a3;

/** This function will compute what 6-byte checksum is appended to the HRP +
 *  data before encoding, using the generator polynomial defined in BIP173 or
 *  BIP350, depending on the encoding.
 */
uint32_t PolyMod(const data& v)
{
    uint32_t c = 1;
    for (const auto& d : v) {
        uint8_t c0 = c >> 25;
        c = ((c & 0x1ffffff) << 5) ^ d;
        if (c0 & 1)  c ^= 0x3b6a57b2;
        if (c0 & 2)  c ^= 0x26508e6d;
        if (c0 & 4)  c ^= 0x1ea119fa;
        if (c0 & 8)  c ^= 0x3d4233dd;
        if (c0 & 16) c ^= 0x2a1462b3;
    }
    return c;
}

/** Expand a HRP for use in checksum computation. */
data HRPExpand(const std::string& hrp)
{
    data ret;
    ret.resize(hrp.size() * 2 + 1);
    for (size_t i = 0; i < hrp.size(); ++i) {
        unsigned char c = hrp[i];
        ret[i] = c >> 5;
        ret[i + hrp.size() + 1] = c & 0x1f;
    }
    ret[hrp.size()] = 0;
    return ret;
}

/** Verify a checksum. Returns INVALID if the checksum is invalid, or the
 *  encoding type if it's valid. */
Encoding VerifyChecksum(const std::string& hrp, const data& values)
{
    // PolyMod computes what value to use for the checksum given HRP+data.
    // If provided, it should equal 1 for BIP173 Bech32 or BECH32M_CONST for BIP350 Bech32m.
    data enc = HRPExpand(hrp);
    enc.insert(enc.end(), values.begin(), values.end());
    const uint32_t check = PolyMod(enc);
    if (check == 1) return Encoding::BECH32;
    if (check == BECH32M_CONST) return Encoding::BECH32M;
    return Encoding::INVALID;
}

/** Create a checksum (6 5-bit values). */
data CreateChecksum(const std::string& hrp, const data& values, Encoding enc)
{
    data enc_hrp = HRPExpand(hrp);
    data enc_data = enc_hrp;
    enc_data.insert(enc_data.end(), values.begin(), values.end());
    enc_data.resize(enc_data.size() + 6);
    uint32_t mod = PolyMod(enc_data) ^ (enc == Encoding::BECH32M ? BECH32M_CONST : 1);
    data ret(6);
    for (size_t i = 0; i < 6; ++i) {
        // Convert the 5-bit groups in mod to checksum values.
        ret[i] = (mod >> (5 * (5 - i))) & 31;
    }
    return ret;
}

} // namespace

/** Encode a Bech32 or Bech32m string. */
std::string Encode(const std::string& hrp, const data& values, Encoding enc)
{
    // Ensure we have valid values in the HRP.
    for (const char& c : hrp) {
        if (c < 33 || c > 126) return "";
        if (c >= 'A' && c <= 'Z') return "";
    }
    data checksum = CreateChecksum(hrp, values, enc);
    data combined = values;
    combined.insert(combined.end(), checksum.begin(), checksum.end());
    std::string ret = hrp + '1';
    ret.reserve(ret.size() + combined.size());
    for (const auto c : combined) {
        ret += CHARSET[c];
    }
    return ret;
}

/** Decode a Bech32 or Bech32m string. */
DecodeResult Decode(const std::string& str)
{
    bool lower = false, upper = false;
    for (size_t i = 0; i < str.size(); ++i) {
        unsigned char c = str[i];
        if (c < 33 || c > 126) return {};
        if (c >= 'a' && c <= 'z') lower = true;
        if (c >= 'A' && c <= 'Z') upper = true;
    }
    if (lower && upper) return {};

    size_t pos = str.rfind('1');
    if (str.size() > 90 || pos == std::string::npos || pos == 0 || pos + 7 > str.size()) {
        return {};
    }

    std::string hrp;
    for (size_t i = 0; i < pos; ++i) {
        unsigned char c = str[i];
        if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
        hrp += c;
    }

    data values;
    values.resize(str.size() - pos - 1);
    for (size_t i = pos + 1; i < str.size(); ++i) {
        unsigned char c = str[i];
        if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
        int8_t v = (c & 0x80) ? -1 : CHARSET_REV[c];
        if (v < 0) return {};
        values[i - pos - 1] = v;
    }

    Encoding result_enc = VerifyChecksum(hrp, values);
    if (result_enc == Encoding::INVALID) return {};

    return {result_enc, hrp, data(values.begin(), values.end() - 6)};
}

} // namespace bech32
