// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "privacy/primitives.h"

#include "crypto/hmac_sha256.h"
#include "crypto/hmac_sha512.h"
#include "crypto/poseidon_bn254.h"
#include "crypto/sha256.h"
#include "random.h"
#include "support/cleanse.h"

extern "C" {
#include "monocypher/monocypher.h"
}

#include <cstdlib>
#include <memory>

namespace privacy {

Bytes U32LE(uint32_t value)
{
    Bytes out(4);
    for (int i = 0; i < 4; ++i) out[i] = static_cast<uint8_t>(value >> (8 * i));
    return out;
}

Bytes U64LE(uint64_t value)
{
    Bytes out(8);
    for (int i = 0; i < 8; ++i) out[i] = static_cast<uint8_t>(value >> (8 * i));
    return out;
}

std::string Hex(const uint8_t* data, size_t size)
{
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (size_t i = 0; i < size; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 15]);
    }
    return out;
}

bool ParseHex32(const std::string& text, Bytes32& out)
{
    if (text.size() != 64) return false;
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < 32; ++i) {
        const int high = nibble(text[2 * i]), low = nibble(text[2 * i + 1]);
        if (high < 0 || low < 0) return false;
        out[i] = static_cast<uint8_t>(high << 4 | low);
    }
    return true;
}

void Wipe(void* data, size_t size)
{
    memory_cleanse(data, size);
}

Bytes32 Sha256(const Bytes& data)
{
    Bytes32 out;
    CSHA256().Write(data.data(), data.size()).Finalize(out.data());
    return out;
}

Bytes32 HmacSha256(const uint8_t* key, size_t keySize, const Bytes& data)
{
    Bytes32 out;
    CHMAC_SHA256(key, keySize).Write(data.data(), data.size()).Finalize(out.data());
    return out;
}

Bytes HkdfExpand(const Bytes32& prk, const Bytes& info, size_t length)
{
    if (length < 1 || length > 32) return {};
    Bytes block = info;
    block.push_back(1);
    Bytes32 okm = HmacSha256(prk.data(), prk.size(), block);
    Bytes out(okm.begin(), okm.begin() + length);
    Wipe(okm);
    return out;
}

void Pbkdf2Sha512(const Bytes& password, const Bytes& salt, uint32_t iterations, uint8_t out[64])
{
    // One output block: T1 = U1 ^ ... ^ Uc, U1 = HMAC(P, S || INT(1)).
    uint8_t u[64];
    CHMAC_SHA512 first(password.data(), password.size());
    first.Write(salt.data(), salt.size());
    const uint8_t blockIndex[4] = {0, 0, 0, 1};
    first.Write(blockIndex, sizeof(blockIndex)).Finalize(u);
    std::copy(u, u + 64, out);
    for (uint32_t i = 1; i < iterations; ++i) {
        CHMAC_SHA512(password.data(), password.size()).Write(u, sizeof(u)).Finalize(u);
        for (int j = 0; j < 64; ++j) out[j] ^= u[j];
    }
    Wipe(u, sizeof(u));
}

bool Argon2id(const Bytes& password, const Bytes& salt, uint32_t passes, uint32_t memoryKiB,
              uint8_t* out, uint32_t outSize)
{
    if (memoryKiB < 8 || passes < 1) return false;
    struct FreeDeleter {
        size_t size;
        void operator()(void* p) const { memory_cleanse(p, size); std::free(p); }
    };
    const size_t workSize = static_cast<size_t>(memoryKiB) * 1024;
    std::unique_ptr<void, FreeDeleter> work(std::malloc(workSize), FreeDeleter{workSize});
    if (!work) return false;
    crypto_argon2_config config;
    config.algorithm = CRYPTO_ARGON2_ID;
    config.nb_blocks = memoryKiB;
    config.nb_passes = passes;
    config.nb_lanes = 1;
    crypto_argon2_inputs inputs;
    inputs.pass = password.data();
    inputs.pass_size = static_cast<uint32_t>(password.size());
    inputs.salt = salt.data();
    inputs.salt_size = static_cast<uint32_t>(salt.size());
    crypto_argon2(out, outSize, work.get(), config, inputs, crypto_argon2_no_extras);
    return true;
}

bool IsCanonicalField(const Bytes32& value)
{
    return crypto::IsCanonicalPoseidonField(value.data());
}

bool IsZero(const Bytes32& value)
{
    uint8_t any = 0;
    for (uint8_t b : value) any |= b;
    return any == 0;
}

Bytes32 FieldFromU64(uint64_t value)
{
    Bytes32 out{};
    for (int i = 0; i < 8; ++i) out[31 - i] = static_cast<uint8_t>(value >> (8 * i));
    return out;
}

Bytes32 PoseidonBytes(const Bytes& data)
{
    Bytes32 out;
    crypto::PoseidonBN254(data.data(), data.size(), out.data());
    return out;
}

bool PoseidonNode(const Bytes32& left, const Bytes32& right, Bytes32& out)
{
    return crypto::PoseidonMerkleNode(left.data(), right.data(), out.data());
}

void X25519Public(const Bytes32& secret, Bytes32& publicKey)
{
    crypto_x25519_public_key(publicKey.data(), secret.data());
}

bool X25519Shared(const Bytes32& secret, const Bytes32& peer, Bytes32& shared)
{
    crypto_x25519(shared.data(), secret.data(), peer.data());
    return !IsZero(shared);
}

Bytes AeadSeal(const Bytes32& key, const std::array<uint8_t, 12>& nonce, const Bytes& aad, const Bytes& plain)
{
    Bytes out(plain.size() + 16);
    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, key.data(), nonce.data());
    crypto_aead_write(&ctx, out.data(), out.data() + plain.size(), aad.data(), aad.size(), plain.data(), plain.size());
    crypto_wipe(&ctx, sizeof(ctx));
    return out;
}

bool AeadOpen(const Bytes32& key, const std::array<uint8_t, 12>& nonce, const Bytes& aad,
              const uint8_t* sealed, size_t sealedSize, Bytes& plain)
{
    if (sealedSize < 16) return false;
    const size_t size = sealedSize - 16;
    plain.assign(size, 0);
    crypto_aead_ctx ctx;
    crypto_aead_init_ietf(&ctx, key.data(), nonce.data());
    const int result = crypto_aead_read(&ctx, plain.data(), sealed + size, aad.data(), aad.size(), sealed, size);
    crypto_wipe(&ctx, sizeof(ctx));
    if (result != 0) {
        plain.clear();
        return false;
    }
    return true;
}

Bytes32 RandomBytes32()
{
    Bytes32 out;
    GetStrongRandBytes(out.data(), static_cast<int>(out.size()));
    return out;
}

} // namespace privacy
