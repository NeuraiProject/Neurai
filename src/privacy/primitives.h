// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_PRIVACY_PRIMITIVES_H
#define NEURAI_PRIVACY_PRIMITIVES_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace privacy {

using Bytes = std::vector<uint8_t>;
using Bytes32 = std::array<uint8_t, 32>;

/** Concatenation helper for byte strings of any container type. */
inline void Append(Bytes& out, const uint8_t* data, size_t size) { out.insert(out.end(), data, data + size); }
template <typename T>
inline void Append(Bytes& out, const T& data) { Append(out, data.data(), data.size()); }
inline void Append(Bytes& out, const std::string& text) { Append(out, reinterpret_cast<const uint8_t*>(text.data()), text.size()); }

Bytes U32LE(uint32_t value);
Bytes U64LE(uint64_t value);
std::string Hex(const uint8_t* data, size_t size);
template <typename T>
inline std::string Hex(const T& data) { return Hex(data.data(), data.size()); }
/** Parses exactly 32 bytes of lower or upper case hex. */
bool ParseHex32(const std::string& text, Bytes32& out);

/** Overwrites secret material; not optimised away. */
void Wipe(void* data, size_t size);
template <typename T>
inline void Wipe(T& data) { Wipe(data.data(), data.size()); }

Bytes32 Sha256(const Bytes& data);
Bytes32 HmacSha256(const uint8_t* key, size_t keySize, const Bytes& data);
inline Bytes32 HmacSha256(const Bytes& key, const Bytes& data) { return HmacSha256(key.data(), key.size(), data); }
/** RFC 5869 expand for outputs of at most 32 bytes (a single HMAC block). */
Bytes HkdfExpand(const Bytes32& prk, const Bytes& info, size_t length);
/** PBKDF2-HMAC-SHA512 with a 64-byte output (BIP39 seed). */
void Pbkdf2Sha512(const Bytes& password, const Bytes& salt, uint32_t iterations, uint8_t out[64]);
/** Argon2id v1.3, single lane; work memory is memoryKiB KiB. */
bool Argon2id(const Bytes& password, const Bytes& salt, uint32_t passes, uint32_t memoryKiB,
              uint8_t* out, uint32_t outSize);

// --- BN254 scalar field elements, 32 bytes big-endian ---------------------

/** True when the value is below the BN254 scalar field modulus r. */
bool IsCanonicalField(const Bytes32& value);
bool IsZero(const Bytes32& value);
Bytes32 FieldFromU64(uint64_t value);
/** NIP-036 CP1 Poseidon byte sponge. */
Bytes32 PoseidonBytes(const Bytes& data);
/** First element of the t=3 permutation of [0, left, right] (NIP-043 Merkle node). */
bool PoseidonNode(const Bytes32& left, const Bytes32& right, Bytes32& out);

// --- X25519 and ChaCha20-Poly1305 (RFC 7748, RFC 8439) --------------------

void X25519Public(const Bytes32& secret, Bytes32& publicKey);
/** Fails for an all-zero shared secret (small-order peer key). */
bool X25519Shared(const Bytes32& secret, const Bytes32& peer, Bytes32& shared);
/** Returns ciphertext || 16-byte tag. */
Bytes AeadSeal(const Bytes32& key, const std::array<uint8_t, 12>& nonce, const Bytes& aad, const Bytes& plain);
bool AeadOpen(const Bytes32& key, const std::array<uint8_t, 12>& nonce, const Bytes& aad,
              const uint8_t* sealed, size_t sealedSize, Bytes& plain);

/** 32 bytes from the node's strong random source. */
Bytes32 RandomBytes32();

} // namespace privacy

#endif // NEURAI_PRIVACY_PRIMITIVES_H
