// Copyright (c) 2017, 2021 Pieter Wuille
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bech32.h"
#include "utilstrencodings.h"

namespace bech32
{

namespace
{

typedef std::vector<uint8_t> data;

/** The Bech32 character set for encoding. */
const char* CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/** The Bech32 character set for decoding. */
const int8_t CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

/* Determine the final constant to use for the specified encoding. */
uint32_t EncodingConstant(Encoding encoding) {
    if (encoding == Encoding::BECH32) return 1;
    if (encoding == Encoding::BECH32M) return 0x2bc830a3;
    return 0; // Should never happen
}

/** This function will compute what 8 5-bit values to XOR into the last 6 input values, in order to
 *  make the checksum 0. These 8 values are packed together in a single 40-bit integer. The higher
 *  bits correspond to earlier values. */
uint64_t PolyMod(const data& v)
{
    // The input is interpreted as a list of coefficients of a polynomial over F = GF(32), with an
    // implicit 1 in front. If the input is [v0,v1,v2,v3,v4], that polynomial is v(x) =
    // 1*x^5 + v0*x^4 + v1*x^3 + v2*x^2 + v3*x + v4. The implicit 1 guarantees that
    // [v0,v1,v2,...] has a distinct checksum from [0,v0,v1,v2,...].

    // The output is a 30-bit integer whose 5-bit groups are the coefficients of the
    // remainder of v(x) mod g(x), where g(x) is the Bech32 generator,
    // x^6 + {29}x^5 + {22}x^4 + {20}x^3 + {21}x^2 + {29}x + {18}. g(x) is chosen in such a way
    // that the resulting code is a BCH code, guaranteeing detection of up to 3 errors within a
    // window of 1023 characters. Among the various possible BCH codes, one was selected to in
    // fact guarantee detection of up to 4 errors within a window of 89 characters.

    // Note that the coefficients are elements of GF(32), here represented as decimal numbers
    // between {}. In this finite field, addition is just XOR of the corresponding numbers. For
    // example, {27} + {13} = {27 ^ 13} = {22}. Multiplication is more complicated, and requires
    // treating the bits of values as coefficients of a polynomial over GF(2).

    // Here is a list of the coefficients of g(x):
    // {29}, {22}, {20}, {21}, {29}, {18}

    // This loop implements the polynomial division logic. The variable c is the current value
    // of the remainder. In each step, we shift c left by 5 bits (multiplying the polynomial by x),
    // and XOR it with the generator polynomial's coefficients multiplied by the term that got
    // shifted out (the MSB of c, here corresponding to x^k where k is the degree of the current
    // partial remainder).
    uint32_t c = 1;
    for (const auto v_i : v) {
        uint8_t c0 = c >> 25;
        c = ((c & 0x1ffffff) << 5) ^ v_i;
        if (c0 & 1)  c ^= 0x3b6a57b2; // k(x) = {29}x^5 + {22}x^4 + {20}x^3 + {21}x^2 + {29}x + {18}
        if (c0 & 2)  c ^= 0x26508e6d; // k(x) * {2}
        if (c0 & 4)  c ^= 0x1ea119fa; // k(x) * {4}
        if (c0 & 8)  c ^= 0x3d4233dd; // k(x) * {8}
        if (c0 & 16) c ^= 0x2a1462b3; // k(x) * {16}
    }
    return c;
}

/** Convert to lower case. */
inline unsigned char LowerCase(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') ? (c - 'A') + 'a' : c;
}

/** Expand a HRP for use in checksum computation. */
data ExpandHRP(const std::string& hrp)
{
    data ret;
    ret.reserve(hrp.size() * 2 + 1);
    for (size_t i = 0; i < hrp.size(); ++i) {
        unsigned char c = hrp[i];
        ret.push_back(c >> 5);
    }
    ret.push_back(0);
    for (size_t i = 0; i < hrp.size(); ++i) {
        unsigned char c = hrp[i];
        ret.push_back(c & 0x1f);
    }
    return ret;
}

/** Verify a checksum. */
Encoding VerifyChecksum(const std::string& hrp, const data& values)
{
    // PolyMod computes what value to xor into the final values to make the checksum 0. However,
    // the last 6 values are the checksum itself, so they are already included in the input.
    // Thus, we want to see if PolyMod returns the encoding constant directly.
    data enc = ExpandHRP(hrp);
    enc.insert(enc.end(), values.begin(), values.end());
    uint32_t check = PolyMod(enc);
    if (check == EncodingConstant(Encoding::BECH32)) return Encoding::BECH32;
    if (check == EncodingConstant(Encoding::BECH32M)) return Encoding::BECH32M;
    return Encoding::INVALID;
}

/** Create a checksum. */
data CreateChecksum(const std::string& hrp, const data& values, Encoding encoding)
{
    data enc = ExpandHRP(hrp);
    enc.insert(enc.end(), values.begin(), values.end());
    enc.resize(enc.size() + 6); // Append 6 zeros
    uint32_t mod = PolyMod(enc) ^ EncodingConstant(encoding);
    data ret;
    ret.resize(6);
    for (size_t i = 0; i < 6; ++i) {
        // Convert the 30-bit modulus to 5-bit values.
        ret[i] = (mod >> (5 * (5 - i))) & 31;
    }
    return ret;
}

} // namespace

std::string Encode(const std::string& hrp, const std::vector<uint8_t>& values, Encoding encoding)
{
    data checksum = CreateChecksum(hrp, values, encoding);
    data combined = values;
    combined.insert(combined.end(), checksum.begin(), checksum.end());
    std::string ret = hrp + '1';
    ret.reserve(ret.size() + combined.size());
    for (const auto c : combined) {
        ret += CHARSET[c];
    }
    return ret;
}

DecodeResult Decode(const std::string& str)
{
    bool lower = false, upper = false;
    for (size_t i = 0; i < str.size(); ++i) {
        unsigned char c = str[i];
        if (c >= 'a' && c <= 'z') lower = true;
        else if (c >= 'A' && c <= 'Z') upper = true;
        else if (c < 33 || c > 126) return {};
    }
    if (lower && upper) return {};
    size_t pos = str.rfind('1');
    if (str.size() > 90 || pos == str.npos || pos == 0 || pos + 7 > str.size()) {
        return {};
    }
    data values;
    values.resize(str.size() - 1 - pos);
    for (size_t i = 0; i < str.size() - 1 - pos; ++i) {
        unsigned char c = str[i + pos + 1];
        int8_t rev = CHARSET_REV[c];

        if (rev == -1) {
            return {};
        }
        values[i] = rev;
    }
    std::string hrp;
    for (size_t i = 0; i < pos; ++i) {
        hrp += LowerCase(str[i]);
    }
    Encoding encoding = VerifyChecksum(hrp, values);
    if (encoding == Encoding::INVALID) return {};
    return DecodeResult(encoding, hrp, data(values.begin(), values.end() - 6));
}

} // namespace bech32
