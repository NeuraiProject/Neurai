// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Differential fuzzer: crypto::p256 (NIP-060 strict profile) against OpenSSL.
//
// Every input is either raw bytes cut into public key, signature and message,
// or a valid signature built with OpenSSL from input-derived d and k, then
// mutated. Both sides must agree on the structural result (with the same
// precedence: public key, then signature), on the decompressed point and on
// the verification result. Any disagreement aborts.
//
// Build and run: see README.md in this directory.

#include "crypto/p256.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

using crypto::p256::StructuralResult;

namespace {

struct Ctx {
    EC_GROUP* group;
    BIGNUM* p;
    BIGNUM* n;
    BIGNUM* half_n;
    BN_CTX* bn;
    Ctx()
    {
        group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
        p = BN_new();
        n = BN_new();
        half_n = BN_new();
        bn = BN_CTX_new();
        EC_GROUP_get_curve(group, p, nullptr, nullptr, bn);
        BN_copy(n, EC_GROUP_get0_order(group));
        BN_rshift1(half_n, n);
    }
};

Ctx& ctx()
{
    static Ctx c;
    return c;
}

[[noreturn]] void Fail(const char* what, int a, int b)
{
    fprintf(stderr, "DISAGREEMENT: %s (neurai %d, openssl %d)\n", what, a, b);
    abort();
}

// Reference structural check of the public key; fills y on success.
StructuralResult RefParsePub(const uint8_t* pub, size_t len, uint8_t y[32])
{
    Ctx& c = ctx();
    if (len != 33) return StructuralResult::PUBKEY_SIZE_INVALID;
    if (pub[0] != 0x02 && pub[0] != 0x03) return StructuralResult::PUBKEY_PREFIX_INVALID;
    BIGNUM* x = BN_bin2bn(pub + 1, 32, nullptr);
    bool in_range = BN_cmp(x, c.p) < 0;
    BN_free(x);
    if (!in_range) return StructuralResult::PUBKEY_X_OUT_OF_RANGE;
    EC_POINT* q = EC_POINT_new(c.group);
    bool ok = EC_POINT_oct2point(c.group, q, pub, 33, c.bn) == 1;
    if (ok) {
        BIGNUM* qy = BN_new();
        EC_POINT_get_affine_coordinates(c.group, q, nullptr, qy, c.bn);
        BN_bn2binpad(qy, y, 32);
        BN_free(qy);
    }
    EC_POINT_free(q);
    return ok ? StructuralResult::OK : StructuralResult::PUBKEY_NOT_ON_CURVE;
}

StructuralResult RefParseSig(const uint8_t* sig, size_t len)
{
    Ctx& c = ctx();
    if (len == 0) return StructuralResult::OK;
    if (len != 64) return StructuralResult::SIG_SIZE_INVALID;
    BIGNUM* r = BN_bin2bn(sig, 32, nullptr);
    BIGNUM* s = BN_bin2bn(sig + 32, 32, nullptr);
    StructuralResult res = StructuralResult::OK;
    if (BN_is_zero(r) || BN_cmp(r, c.n) >= 0) res = StructuralResult::SIG_R_OUT_OF_RANGE;
    else if (BN_is_zero(s) || BN_cmp(s, c.n) >= 0) res = StructuralResult::SIG_S_OUT_OF_RANGE;
    else if (BN_cmp(s, c.half_n) > 0) res = StructuralResult::SIG_HIGH_S;
    BN_free(r);
    BN_free(s);
    return res;
}

bool RefVerify(const uint8_t* pub, const uint8_t* sig, size_t siglen, const uint8_t* msg, size_t msglen)
{
    if (siglen == 0) return false;
    Ctx& c = ctx();
    uint8_t digest[32];
    SHA256(msg, msglen, digest);
    EC_KEY* key = EC_KEY_new();
    EC_KEY_set_group(key, c.group);
    EC_POINT* q = EC_POINT_new(c.group);
    EC_POINT_oct2point(c.group, q, pub, 33, c.bn);
    EC_KEY_set_public_key(key, q);
    ECDSA_SIG* es = ECDSA_SIG_new();
    ECDSA_SIG_set0(es, BN_bin2bn(sig, 32, nullptr), BN_bin2bn(sig + 32, 32, nullptr));
    int ok = ECDSA_do_verify(digest, 32, es, key);
    ECDSA_SIG_free(es);
    EC_POINT_free(q);
    EC_KEY_free(key);
    return ok == 1;
}

void Check(const uint8_t* pub, size_t publen, const uint8_t* sig, size_t siglen, const uint8_t* msg, size_t msglen)
{
    // Step by step, as the interpreter calls them.
    crypto::p256::PublicKey pk;
    uint8_t ref_y[32];
    StructuralResult a = crypto::p256::ParsePublicKey(pub, publen, pk);
    StructuralResult b = RefParsePub(pub, publen, ref_y);
    if (a != b) Fail("ParsePublicKey", (int)a, (int)b);
    if (a == StructuralResult::OK) {
        if (memcmp(pk.x, pub + 1, 32) != 0) Fail("decompressed x", 0, 0);
        if (memcmp(pk.y, ref_y, 32) != 0) Fail("decompressed y", 0, 0);
    }
    crypto::p256::Signature sg;
    StructuralResult c = crypto::p256::ParseSignature(sig, siglen, sg);
    StructuralResult d = RefParseSig(sig, siglen);
    if (c != d) Fail("ParseSignature", (int)c, (int)d);

    // The one-call form, with its precedence: public key first.
    bool valid = false;
    StructuralResult e = crypto::p256::VerifyStrict(pub, publen, sig, siglen, msg, msglen, valid);
    StructuralResult expected = b != StructuralResult::OK ? b : d;
    if (e != expected) Fail("VerifyStrict result", (int)e, (int)expected);
    if (e != StructuralResult::OK) return;
    bool ours = crypto::p256::Verify(pk, sg, msg, msglen);
    bool ref = RefVerify(pub, sig, siglen, msg, msglen);
    if (ours != ref) Fail("Verify", ours, ref);
    if (valid != ref) Fail("VerifyStrict valid", valid, ref);
}

// A valid strict-profile signature by d with nonce k over msg; false when the
// derived scalars are unusable.
bool Sign(const uint8_t dbytes[32], const uint8_t kbytes[32], const uint8_t* msg, size_t msglen,
          uint8_t pub[33], uint8_t sig[64])
{
    Ctx& c = ctx();
    bool ok = false;
    BIGNUM* d = BN_bin2bn(dbytes, 32, nullptr);
    BIGNUM* k = BN_bin2bn(kbytes, 32, nullptr);
    BN_mod(d, d, c.n, c.bn);
    BN_mod(k, k, c.n, c.bn);
    EC_KEY* key = EC_KEY_new();
    EC_POINT* q = EC_POINT_new(c.group);
    EC_POINT* kg = EC_POINT_new(c.group);
    BIGNUM* rx = BN_new();
    BIGNUM* kinv = BN_new();
    ECDSA_SIG* es = nullptr;
    if (BN_is_zero(d) || BN_is_zero(k)) goto done;
    EC_KEY_set_group(key, c.group);
    EC_KEY_set_private_key(key, d);
    EC_POINT_mul(c.group, q, d, nullptr, nullptr, c.bn);
    EC_KEY_set_public_key(key, q);
    EC_POINT_point2oct(c.group, q, POINT_CONVERSION_COMPRESSED, pub, 33, c.bn);
    EC_POINT_mul(c.group, kg, k, nullptr, nullptr, c.bn);
    EC_POINT_get_affine_coordinates(c.group, kg, rx, nullptr, c.bn);
    BN_mod(rx, rx, c.n, c.bn);
    BN_mod_inverse(kinv, k, c.n, c.bn);
    {
        uint8_t digest[32];
        SHA256(msg, msglen, digest);
        // ECDSA_do_sign_ex takes ownership of nothing: it copies kinv and rp.
        es = ECDSA_do_sign_ex(digest, 32, kinv, rx, key);
    }
    if (!es) goto done;
    {
        const BIGNUM *r, *s;
        ECDSA_SIG_get0(es, &r, &s);
        BIGNUM* low = BN_dup(s);
        if (BN_cmp(low, c.half_n) > 0) BN_sub(low, c.n, low);
        BN_bn2binpad(r, sig, 32);
        BN_bn2binpad(low, sig + 32, 32);
        BN_free(low);
        ok = true;
    }
done:
    ECDSA_SIG_free(es);
    BN_free(kinv);
    BN_free(rx);
    EC_POINT_free(kg);
    EC_POINT_free(q);
    EC_KEY_free(key);
    BN_free(k);
    BN_free(d);
    return ok;
}

void SetScalar(uint8_t out[32], const BIGNUM* v)
{
    BN_bn2binpad(v, out, 32);
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 2) return 0;
    const uint8_t mode = data[0];
    data++;
    size--;

    if (mode & 1) {
        // Raw: lengths favour the valid sizes, contents are arbitrary.
        size_t publen = data[0] < 224 ? 33 : data[0] % 40;
        size_t siglen = size > 1 ? (data[1] < 200 ? 64 : data[1] < 216 ? 0 : data[1] % 72) : 64;
        size_t off = 2;
        if (size < off + publen + siglen) return 0;
        std::vector<uint8_t> pub(data + off, data + off + publen);
        std::vector<uint8_t> sig(data + off + publen, data + off + publen + siglen);
        const uint8_t* msg = data + off + publen + siglen;
        size_t msglen = size - off - publen - siglen;
        // Bias the prefix towards 02/03 so the curve checks run.
        if (publen == 33 && (mode & 2)) pub[0] = 0x02 | (pub[0] & 1);
        Check(pub.data(), publen, sig.data(), siglen, msg, msglen);
        return 0;
    }

    // Constructed: a valid signature, then one mutation.
    if (size < 66) return 0;
    uint8_t pub[33], sig[64];
    const uint8_t* msg = data + 66;
    size_t msglen = size - 66;
    if (!Sign(data, data + 32, msg, msglen, pub, sig)) return 0;
    const uint8_t op = data[64], pos = data[65];
    std::vector<uint8_t> m(msg, msg + msglen);
    size_t siglen = 64, publen = 33;
    Ctx& c = ctx();
    switch (op % 14) {
    case 0: break;                                           // unchanged: must verify
    case 1: pub[1 + pos % 32] ^= (uint8_t)(1 << (op >> 4) % 8); break;
    case 2: sig[pos % 64] ^= (uint8_t)(1 << (op >> 4) % 8); break;
    case 3: if (!m.empty()) m[pos % m.size()] ^= 1; else m.push_back(0); break;
    case 4: pub[0] ^= 0x01; break;                           // the negated point
    case 5: {                                                // high S
        BIGNUM* s = BN_bin2bn(sig + 32, 32, nullptr);
        BN_sub(s, c.n, s);
        SetScalar(sig + 32, s);
        BN_free(s);
        break;
    }
    case 6: {                                                // r + n, when it fits
        BIGNUM* r = BN_bin2bn(sig, 32, nullptr);
        BN_add(r, r, c.n);
        if (BN_num_bytes(r) <= 32) SetScalar(sig, r);
        BN_free(r);
        break;
    }
    case 7: memset(sig, 0, 32); break;                       // r = 0
    case 8: memset(sig + 32, 0, 32); break;                  // s = 0
    case 9: SetScalar(sig + 32, c.half_n); break;            // s = floor(n/2): in range, wrong
    case 10: {                                               // s = floor(n/2) + 1: high S
        BIGNUM* s = BN_dup(c.half_n);
        BN_add_word(s, 1);
        SetScalar(sig + 32, s);
        BN_free(s);
        break;
    }
    case 11: SetScalar(sig, c.n); break;                     // r = n
    case 12: siglen = pos % 64; break;                       // truncated signature
    case 13: publen = pos % 33; break;                       // truncated key
    }
    Check(pub, publen, sig, siglen, m.data(), m.size());
    if (op % 14 == 0) {
        bool valid = false;
        if (crypto::p256::VerifyStrict(pub, 33, sig, 64, m.data(), m.size(), valid) != StructuralResult::OK || !valid)
            Fail("valid signature rejected", 0, 1);
    }
    return 0;
}
