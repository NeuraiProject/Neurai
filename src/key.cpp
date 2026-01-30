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
#include "util.h"  // For LogPrintf

#include <oqs/oqs.h>

#include <secp256k1.h>
#include <secp256k1_recovery.h>

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

bool CKey::Check(const unsigned char *vch, unsigned int len) {
    if (len == 32)
        return secp256k1_ec_seckey_verify(secp256k1_context_sign, vch);
    // ML-DSA-44 (Priv + Pub): 2560 + 1312 = 3872 bytes
    if (len == DILITHIUM2_PRIVKEY_SIZE + DILITHIUM2_PUBKEY_SIZE) return true;
    return false;
}

void CKey::MakeNewKey(bool fCompressedIn) {
    keydata.resize(32);
    do {
        GetStrongRandBytes(keydata.data(), keydata.size());
    } while (!Check(keydata.data(), 32));
    fValid = true;
    fCompressed = fCompressedIn;
}

#include "sync.h"

static CCriticalSection cs_OQS;
static std::vector<unsigned char> g_OQS_Seed;
static size_t g_OQS_SeedPos;

static void OQS_Random_Deterministic(uint8_t *dest, size_t len) {
    size_t to_copy = std::min(len, g_OQS_Seed.size() - g_OQS_SeedPos);
    if (to_copy > 0) {
        memcpy(dest, &g_OQS_Seed[g_OQS_SeedPos], to_copy);
        g_OQS_SeedPos += to_copy;
    }
    if (to_copy < len) {
        memset(dest + to_copy, 0, len - to_copy);
    }
}

void CKey::MakeNewKeyPQ() {
    LOCK(cs_OQS);
    LogPrintf("DEBUG MakeNewKeyPQ: Starting\n");
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (!sig) throw std::runtime_error("OQS_SIG_new failed for ML-DSA-44 - algorithm may not be compiled");
    LogPrintf("DEBUG MakeNewKeyPQ: OQS_SIG_new success, sk_len=%zu pk_len=%zu\n", sig->length_secret_key, sig->length_public_key);

    // Verify sizes match our constants (safety check)
    if (sig->length_secret_key != DILITHIUM2_PRIVKEY_SIZE ||
        sig->length_public_key != DILITHIUM2_PUBKEY_SIZE) {
        OQS_SIG_free(sig);
        throw std::runtime_error("OQS ML-DSA-44 key sizes mismatch - expected sk=" +
            std::to_string(DILITHIUM2_PRIVKEY_SIZE) + " pk=" + std::to_string(DILITHIUM2_PUBKEY_SIZE) +
            " got sk=" + std::to_string(sig->length_secret_key) + " pk=" + std::to_string(sig->length_public_key));
    }

    LogPrintf("DEBUG MakeNewKeyPQ: Resizing keydata to %u\n", DILITHIUM2_PRIVKEY_SIZE + DILITHIUM2_PUBKEY_SIZE);
    keydata.resize(DILITHIUM2_PRIVKEY_SIZE + DILITHIUM2_PUBKEY_SIZE);
    LogPrintf("DEBUG MakeNewKeyPQ: Resize done, calling OQS_SIG_keypair\n");

    // Store generated keys directly in keydata
    if (OQS_SIG_keypair(sig, keydata.data() + DILITHIUM2_PRIVKEY_SIZE, keydata.data()) != OQS_SUCCESS) {
        OQS_SIG_free(sig);
        throw std::runtime_error("OQS_SIG_keypair failed");
    }
    LogPrintf("DEBUG MakeNewKeyPQ: OQS_SIG_keypair success\n");
    OQS_SIG_free(sig);
    fValid = true;
    fCompressed = false;
}

void CKey::MakeNewKeyPQ(const std::vector<unsigned char>& seed) {
    LOCK(cs_OQS);
    g_OQS_Seed = seed;
    g_OQS_SeedPos = 0;

    OQS_randombytes_custom_algorithm(OQS_Random_Deterministic);

    try {
        MakeNewKeyPQ();
    } catch (...) {
        OQS_randombytes_switch_algorithm(OQS_RAND_alg_system);
        g_OQS_Seed.clear();
        throw;
    }

    OQS_randombytes_switch_algorithm(OQS_RAND_alg_system);
    g_OQS_Seed.clear();
}

CPrivKey CKey::GetPrivKey() const {
    assert(fValid);
    CPrivKey privkey;
    if (keydata.size() == 32) {
        int ret;
        size_t privkeylen;
        privkey.resize(279);
        privkeylen = 279;
        ret = ec_privkey_export_der(secp256k1_context_sign, (unsigned char*) privkey.data(), &privkeylen, begin(), fCompressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
        assert(ret);
        privkey.resize(privkeylen);
    } else {
        // PQ Key: Just return the raw keydata (Priv + Pub)
        privkey = keydata;
    }
    return privkey;
}

CPubKey CKey::GetPubKey() const {
    assert(fValid);
    if (keydata.size() == 32) {
        secp256k1_pubkey pubkey;
        size_t clen = 65;
        CPubKey result;
        // Make sure CPubKey internal vector is ready? CPubKey ctor handles it or we resize it.
        // CPubKey default ctor is invalid (empty).
        // We will construct via vector.
        std::vector<unsigned char> vch(65);
        int ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pubkey, begin());
        assert(ret);
        secp256k1_ec_pubkey_serialize(secp256k1_context_sign, vch.data(), &clen, &pubkey, fCompressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
        vch.resize(clen);
        return CPubKey(vch);
    } else {
        // PQ Key (ML-DSA-44)
        if (keydata.size() >= DILITHIUM2_PRIVKEY_SIZE + DILITHIUM2_PUBKEY_SIZE) {
            std::vector<unsigned char> pub(keydata.begin() + DILITHIUM2_PRIVKEY_SIZE, keydata.end());
            pub.insert(pub.begin(), 0x05); // Header for PQ key
            return CPubKey(pub);
        }
        return CPubKey();
    }
}

bool CKey::Sign(const uint256 &hash, std::vector<unsigned char>& vchSig, uint32_t test_case) const {
    if (!fValid)
        return false;
    
    if (keydata.size() == 32) {
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
    } else {
        // PQ Sign
        // Requires full keydata or just privkey part?
        // OQS_SIG_sign takes secret_key.
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
        if (!sig) return false;
        
        vchSig.resize(DILITHIUM2_SIG_SIZE);
        size_t sig_len = DILITHIUM2_SIG_SIZE;
        
        if (OQS_SIG_sign(sig, vchSig.data(), &sig_len, hash.begin(), hash.size(), keydata.data()) != OQS_SUCCESS) {
            OQS_SIG_free(sig);
            return false;
        }
        OQS_SIG_free(sig);
        vchSig.resize(sig_len);
        return true;
    }
}

bool CKey::VerifyPubKey(const CPubKey& pubkey) const {
    if (keydata.size() == 32) {
        if (pubkey.IsCompressed() != fCompressed) {
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
    } else {
        // PQ Verification
        // No "Compressed" check needed.
        // Just sign random data and verify.
        unsigned char rnd[8];
        std::string str = "Neurai key verification\n";
        GetRandBytes(rnd, sizeof(rnd));
        uint256 hash;
        CHash256().Write((unsigned char*)str.data(), str.size()).Write(rnd, sizeof(rnd)).Finalize(hash.begin());
        std::vector<unsigned char> vchSig;
        Sign(hash, vchSig);
        // We assume CPubKey::Verify checks using OQS eventually (need to update CPubKey::Verify too?)
        // Wait, CPubKey::Verify is in pubkey.cpp (likely) or header?
        // It's not in pubkey.h (impl not shown in header, declared? No, I don't see Verify in CPubKey decl in previous view).
        // Let me check pubkey.h again in my memory.
        // It's likely in pubkey.cpp. I missed it.
        // VerifyPubKey uses pubkey.Verify. I must update CPubKey::Verify as well!
        return pubkey.Verify(hash, vchSig);
    }
}

bool CKey::SignCompact(const uint256 &hash, std::vector<unsigned char>& vchSig) const {
    if (!fValid)
        return false;
    if (keydata.size() > 32) return false; // Not supported for PQ
    
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

bool CKey::Load(CPrivKey &privkey, CPubKey &vchPubKey, bool fSkipCheck) {
    if (privkey.size() > 2000) { // PQ Key
        keydata = privkey;
        fCompressed = false;
        fValid = true;
        if (fSkipCheck) return true;
        return VerifyPubKey(vchPubKey);
    }
    
    // Legacy
    keydata.resize(32);
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
    assert(IsCompressed());
    assert(keydata.size() == 32); // Must be secp256k1 key, not PQ
    std::vector<unsigned char, secure_allocator<unsigned char>> vout(64);
    if ((nChild >> 31) == 0) {
        CPubKey pubkey = GetPubKey();
        assert(pubkey.begin() + 33 == pubkey.end());
        BIP32Hash(cc, nChild, *pubkey.begin(), pubkey.begin()+1, vout.data());
    } else {
        BIP32Hash(cc, nChild, 0, begin(), vout.data());
    }
    memcpy(ccChild.begin(), vout.data()+32, 32);
    // Resize child keydata before copying (keydata is a vector, not fixed array)
    keyChild.keydata.resize(32);
    memcpy(keyChild.keydata.data(), begin(), 32);
    bool ret = secp256k1_ec_privkey_tweak_add(secp256k1_context_sign, keyChild.keydata.data(), vout.data());
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
