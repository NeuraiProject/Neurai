// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key.h"

#include "arith_uint256.h"
#include "crypto/common.h"
#include "crypto/hmac_sha512.h"
#include "pubkey.h"
#include "random.h"

#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <oqs/oqs.h>

static secp256k1_context* secp256k1_context_sign = nullptr;

/** These functions are taken from the libsecp256k1 distribution and are very ugly. */
static int ec_privkey_import_der(const secp256k1_context* ctx, unsigned char *out32, const unsigned char *privkey, size_t privkeylen) {
    const unsigned char *end = privkey + privkeylen;
    int lenb = 0;
    int len = 0;
    memset(out32, 0, 32);
    /* sequence header */
    if (end < privkey+1 || *privkey != 0x30) {
        return 0;
    }
    privkey++;
    /* sequence length constructor */
    if (end < privkey+1 || !(*privkey & 0x80)) {
        return 0;
    }
    lenb = *privkey & ~0x80; privkey++;
    if (lenb < 1 || lenb > 2) {
        return 0;
    }
    if (end < privkey+lenb) {
        return 0;
    }
    /* sequence length */
    len = privkey[lenb-1] | (lenb > 1 ? privkey[lenb-2] << 8 : 0);
    privkey += lenb;
    if (end < privkey+len) {
        return 0;
    }
    /* sequence element 0: version number (=1) */
    if (end < privkey+3 || privkey[0] != 0x02 || privkey[1] != 0x01 || privkey[2] != 0x01) {
        return 0;
    }
    privkey += 3;
    /* sequence element 1: octet string, up to 32 bytes */
    if (end < privkey+2 || privkey[0] != 0x04 || privkey[1] > 0x20 || end < privkey+2+privkey[1]) {
        return 0;
    }
    memcpy(out32 + 32 - privkey[1], privkey + 2, privkey[1]);
    if (!secp256k1_ec_seckey_verify(ctx, out32)) {
        memset(out32, 0, 32);
        return 0;
    }
    return 1;
}

static int ec_privkey_export_der(const secp256k1_context *ctx, unsigned char *privkey, size_t *privkeylen, const unsigned char *key32, int compressed) {
    secp256k1_pubkey pubkey;
    size_t pubkeylen = 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, key32)) {
        *privkeylen = 0;
        return 0;
    }
    if (compressed) {
        static const unsigned char begin[] = {
            0x30,0x81,0xD3,0x02,0x01,0x01,0x04,0x20
        };
        static const unsigned char middle[] = {
            0xA0,0x81,0x85,0x30,0x81,0x82,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
            0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
            0x21,0x02,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
            0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
            0x17,0x98,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
            0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x24,0x03,0x22,0x00
        };
        unsigned char *ptr = privkey;
        memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
        memcpy(ptr, key32, 32); ptr += 32;
        memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
        pubkeylen = 33;
        secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED);
        ptr += pubkeylen;
        *privkeylen = ptr - privkey;
    } else {
        static const unsigned char begin[] = {
            0x30,0x82,0x01,0x13,0x02,0x01,0x01,0x04,0x20
        };
        static const unsigned char middle[] = {
            0xA0,0x81,0xA5,0x30,0x81,0xA2,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
            0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
            0x41,0x04,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
            0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
            0x17,0x98,0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,0x5D,0xA4,0xFB,0xFC,0x0E,0x11,
            0x08,0xA8,0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,0x9C,0x47,0xD0,0x8F,0xFB,0x10,
            0xD4,0xB8,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
            0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x44,0x03,0x42,0x00
        };
        unsigned char *ptr = privkey;
        memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
        memcpy(ptr, key32, 32); ptr += 32;
        memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
        pubkeylen = 65;
        secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
        ptr += pubkeylen;
        *privkeylen = ptr - privkey;
    }
    return 1;
}

bool CKey::Check(const unsigned char *vch) {
    return secp256k1_ec_seckey_verify(secp256k1_context_sign, vch);
}

void CKey::MakeNewKey(bool fCompressedIn) {
    do {
        GetStrongRandBytes(keydata.data(), keydata.size());
    } while (!Check(keydata.data()));
    fValid = true;
    fCompressed = fCompressedIn;
}

void CKey::MakeNewKeyPQ() {
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    assert(sig != nullptr);

    keydata.resize(sig->length_secret_key + sig->length_public_key);
    uint8_t* pubkey_buf = keydata.data() + sig->length_secret_key;

    OQS_STATUS rc = OQS_SIG_keypair(sig, pubkey_buf, keydata.data());
    assert(rc == OQS_SUCCESS);

    OQS_SIG_free(sig);
    fValid = true;
    fCompressed = true;
}

// Thread-local seed state for deterministic PQ key generation.
// Only valid during MakeNewKeyPQ(seed) — reset to nullptr afterwards.
static thread_local const std::vector<unsigned char>* g_pq_det_seed = nullptr;
static thread_local size_t g_pq_det_offset = 0;
static thread_local bool g_pq_det_overread = false;

// liboqs ML-DSA key generation consumes external randomness as a 32-byte seed
// which it expands internally. To match the bip39 generator, expose the raw
// BIP32-derived seed bytes directly instead of pre-expanding them here.
static void pq_deterministic_randombytes(uint8_t* out, size_t len)
{
    assert(g_pq_det_seed != nullptr);
    const size_t remaining = g_pq_det_seed->size() - g_pq_det_offset;
    const size_t to_copy = std::min(len, remaining);
    if (to_copy > 0) {
        memcpy(out, g_pq_det_seed->data() + g_pq_det_offset, to_copy);
        g_pq_det_offset += to_copy;
    }
    if (to_copy < len) {
        g_pq_det_overread = true;
        memset(out + to_copy, 0, len - to_copy);
    }
}

void CKey::MakeNewKeyPQ(const std::vector<unsigned char>& seed) {
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    assert(sig != nullptr);

    if (seed.size() != 32) {
        OQS_SIG_free(sig);
        throw std::runtime_error("CKey::MakeNewKeyPQ requires a 32-byte seed");
    }

    // Install deterministic RNG that exposes the raw seed bytes expected by
    // the ML-DSA keygen implementation. This matches the bip39 generator's
    // ml_dsa44.keygen(seed) behavior.
    g_pq_det_seed    = &seed;
    g_pq_det_offset  = 0;
    g_pq_det_overread = false;
    OQS_randombytes_custom_algorithm(pq_deterministic_randombytes);

    keydata.resize(sig->length_secret_key + sig->length_public_key);
    uint8_t* pubkey_buf = keydata.data() + sig->length_secret_key;

    OQS_STATUS rc = OQS_SIG_keypair(sig, pubkey_buf, keydata.data());
    assert(rc == OQS_SUCCESS);

    // Restore system randomness and clear seed pointer
    OQS_randombytes_switch_algorithm(OQS_RAND_alg_system);
    g_pq_det_seed = nullptr;
    g_pq_det_offset = 0;

    OQS_SIG_free(sig);
    if (g_pq_det_overread) {
        g_pq_det_overread = false;
        throw std::runtime_error("CKey::MakeNewKeyPQ seed length mismatch with liboqs ML-DSA keygen");
    }
    g_pq_det_overread = false;
    fValid = true;
    fCompressed = true;
}

CPrivKey CKey::GetPrivKey() const {
    assert(fValid);

    if (IsPQ()) {
        return CPrivKey(keydata.begin(), keydata.end());
    }

    CPrivKey privkey;
    int ret;
    size_t privkeylen;
    privkey.resize(279);
    privkeylen = 279;
    ret = ec_privkey_export_der(secp256k1_context_sign, (unsigned char*) privkey.data(), &privkeylen, begin(), fCompressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    assert(ret);
    privkey.resize(privkeylen);
    return privkey;
}

CPubKey CKey::GetPubKey() const {
    assert(fValid);

    if (IsPQ()) {
        // Public key is stored in keydata after the private key bytes
        OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
        assert(sig != nullptr);
        size_t pubkey_len = sig->length_public_key; // 1312
        OQS_SIG_free(sig);

        // keydata layout: [2560 priv][1312 pub]
        assert(keydata.size() == ML_DSA_44_PRIVKEY_SIZE + pubkey_len);

        std::vector<unsigned char> pubdata(1 + pubkey_len);
        pubdata[0] = 0x05; // ML-DSA-44 header byte
        memcpy(pubdata.data() + 1, keydata.data() + ML_DSA_44_PRIVKEY_SIZE, pubkey_len);

        CPubKey result;
        result.Set(pubdata.begin(), pubdata.end());
        assert(result.IsValid());
        return result;
    }

    secp256k1_pubkey pubkey;
    size_t clen = 65;
    CPubKey result;
    int ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pubkey, begin());
    assert(ret);
    // Use a temporary buffer since result.begin() is now const
    unsigned char pub[65];
    secp256k1_ec_pubkey_serialize(secp256k1_context_sign, pub, &clen, &pubkey, fCompressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
    result.Set(pub, pub + clen);
    assert(result.size() == clen);
    assert(result.IsValid());
    return result;
}

bool CKey::Sign(const uint256 &hash, std::vector<unsigned char>& vchSig, uint32_t test_case) const {
    if (!fValid)
        return false;

    if (IsPQ()) {
        OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
        assert(sig != nullptr);
        vchSig.resize(sig->length_signature);
        size_t sig_len = sig->length_signature;
        // Sign the 32-byte hash directly as the message
        OQS_STATUS rc = OQS_SIG_sign(sig, vchSig.data(), &sig_len,
                                      hash.begin(), 32,
                                      keydata.data()); // first 2560 bytes = private key
        OQS_SIG_free(sig);
        if (rc != OQS_SUCCESS) return false;
        vchSig.resize(sig_len);
        return true;
    }

    vchSig.resize(72);
    size_t nSigLen = 72;
    unsigned char extra_entropy[32] = {0};
    WriteLE32(extra_entropy, test_case);
    secp256k1_ecdsa_signature sig;
    int ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, hash.begin(), begin(), secp256k1_nonce_function_rfc6979, test_case ? extra_entropy : nullptr);
    assert(ret);
    secp256k1_ecdsa_signature_serialize_der(secp256k1_context_sign, (unsigned char*)vchSig.data(), &nSigLen, &sig);
    vchSig.resize(nSigLen);
    return true;
}

bool CKey::VerifyPubKey(const CPubKey& pubkey) const {
    if (!IsPQ() && pubkey.IsCompressed() != fCompressed) {
        return false;
    }
    unsigned char rnd[8];
    std::string str = "Neurai key verification\n";
    GetRandBytes(rnd, sizeof(rnd));
    uint256 hash;
    CHash256().Write((unsigned char*)str.data(), str.size()).Write(rnd, sizeof(rnd)).Finalize(hash.begin());
    std::vector<unsigned char> vchSig;
    Sign(hash, vchSig);
    return pubkey.Verify(hash, vchSig);
}

bool CKey::SignCompact(const uint256 &hash, std::vector<unsigned char>& vchSig) const {
    if (!fValid)
        return false;
    vchSig.resize(65);
    int rec = -1;
    secp256k1_ecdsa_recoverable_signature sig;
    int ret = secp256k1_ecdsa_sign_recoverable(secp256k1_context_sign, &sig, hash.begin(), begin(), secp256k1_nonce_function_rfc6979, nullptr);
    assert(ret);
    secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_context_sign, (unsigned char*)&vchSig[1], &rec, &sig);
    assert(ret);
    assert(rec != -1);
    vchSig[0] = 27 + rec + (fCompressed ? 4 : 0);
    return true;
}

bool CKey::Load(CPrivKey &privkey, CPubKey &vchPubKey, bool fSkipCheck=false) {
    if (vchPubKey.IsPQ()) {
        Set(privkey.begin(), privkey.end(), true);
        if (!fValid || !IsPQ()) {
            return false;
        }
        if (fSkipCheck)
            return true;
        return VerifyPubKey(vchPubKey);
    }
    if (!ec_privkey_import_der(secp256k1_context_sign, (unsigned char*)begin(), privkey.data(), privkey.size()))
        return false;
    fCompressed = vchPubKey.IsCompressed();
    fValid = true;

    if (fSkipCheck)
        return true;

    return VerifyPubKey(vchPubKey);
}

bool CKey::Derive(CKey& keyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const {
    assert(IsValid());
    if (IsPQ())
        return false; // BIP32 derivation not supported for PQ keys; use MakeNewKeyPQ(seed) instead
    assert(IsCompressed());
    std::vector<unsigned char, secure_allocator<unsigned char>> vout(64);
    if ((nChild >> 31) == 0) {
        CPubKey pubkey = GetPubKey();
        assert(pubkey.begin() + 33 == pubkey.end());
        BIP32Hash(cc, nChild, *pubkey.begin(), pubkey.begin()+1, vout.data());
    } else {
        assert(begin() + 32 == end());
        BIP32Hash(cc, nChild, 0, begin(), vout.data());
    }
    memcpy(ccChild.begin(), vout.data()+32, 32);
    memcpy((unsigned char*)keyChild.begin(), begin(), 32);
    bool ret = secp256k1_ec_privkey_tweak_add(secp256k1_context_sign, (unsigned char*)keyChild.begin(), vout.data());
    keyChild.fCompressed = true;
    keyChild.fValid = ret;
    return ret;
}

bool CExtKey::Derive(CExtKey &out, unsigned int _nChild) const {
    out.nDepth = nDepth + 1;
    CKeyID id = key.GetPubKey().GetID();
    memcpy(&out.vchFingerprint[0], &id, 4);
    out.nChild = _nChild;
    return key.Derive(out.key, out.chaincode, _nChild, chaincode);
}

void CExtKey::SetSeed(const unsigned char *seed, unsigned int nSeedLen) {
    static const unsigned char hashkey[] = {'B','i','t','c','o','i','n',' ','s','e','e','d'};
    std::vector<unsigned char, secure_allocator<unsigned char>> vout(64);
    CHMAC_SHA512(hashkey, sizeof(hashkey)).Write(seed, nSeedLen).Finalize(vout.data());
    key.Set(vout.data(), vout.data() + 32, true);
    memcpy(chaincode.begin(), vout.data() + 32, 32);
    nDepth = 0;
    nChild = 0;
    memset(vchFingerprint, 0, sizeof(vchFingerprint));
}

CExtPubKey CExtKey::Neuter() const {
    CExtPubKey ret;
    ret.nDepth = nDepth;
    memcpy(&ret.vchFingerprint[0], &vchFingerprint[0], 4);
    ret.nChild = nChild;
    ret.pubkey = key.GetPubKey();
    ret.chaincode = chaincode;
    return ret;
}

void CExtKey::Encode(unsigned char code[BIP32_EXTKEY_SIZE]) const {
    code[0] = nDepth;
    memcpy(code+1, vchFingerprint, 4);
    code[5] = (nChild >> 24) & 0xFF; code[6] = (nChild >> 16) & 0xFF;
    code[7] = (nChild >>  8) & 0xFF; code[8] = (nChild >>  0) & 0xFF;
    memcpy(code+9, chaincode.begin(), 32);
    code[41] = 0;
    assert(key.size() == 32);
    memcpy(code+42, key.begin(), 32);
}

void CExtKey::Decode(const unsigned char code[BIP32_EXTKEY_SIZE]) {
    nDepth = code[0];
    memcpy(vchFingerprint, code+1, 4);
    nChild = (code[5] << 24) | (code[6] << 16) | (code[7] << 8) | code[8];
    memcpy(chaincode.begin(), code+9, 32);
    key.Set(code+42, code+BIP32_EXTKEY_SIZE, true);
}

bool ECC_InitSanityCheck() {
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    return key.VerifyPubKey(pubkey);
}

void ECC_Start() {
    assert(secp256k1_context_sign == nullptr);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    assert(ctx != nullptr);

    {
        // Pass in a random blinding seed to the secp256k1 context.
        std::vector<unsigned char, secure_allocator<unsigned char>> vseed(32);
        GetRandBytes(vseed.data(), 32);
        bool ret = secp256k1_context_randomize(ctx, vseed.data());
        assert(ret);
    }

    secp256k1_context_sign = ctx;
}

void ECC_Stop() {
    secp256k1_context *ctx = secp256k1_context_sign;
    secp256k1_context_sign = nullptr;

    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
}
