// Copyright (c) 2024 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_DEPINECIES_H
#define NEURAI_DEPINECIES_H

#include <string>
#include <vector>
#include "key.h"
#include "pubkey.h"
#include "serialize.h"
#include "depinaddress.h"
#include "depinserialization.h"
#include <map>

/**
 * ECIES (Elliptic Curve Integrated Encryption Scheme) implementation for DePIN Messaging
 *
 * This implements hybrid encryption compatible with the web interface:
 * https://github.com/NeuraiProject/DePIN-Messaging/tree/main/website
 *
 * Encryption scheme:
 * 1. Generate ephemeral key pair (one per message)
 * 2. Encrypt plaintext once with AES-256-GCM using key derived from ephemeral private key
 * 3. For each recipient:
 *    - Compute shared secret: ECDH(ephemeral_privkey, recipient_pubkey)
 *    - Derive encryption key from shared secret (SHA256)
 *    - Encrypt the AES key used in step 2 with AES-256-GCM
 *    - Package: [nonce, encrypted_aes_key, auth_tag]
 * 4. Attach single encrypted message payload to all recipients
 *
 * Decryption:
 * 1. Extract ephemeral public key
 * 2. Compute shared secret: ECDH(recipient_privkey, ephemeral_pubkey)
 * 3. Derive decryption key from shared secret
 * 4. Decrypt AES key (GCM tag verified automatically)
 * 5. Decrypt message with recovered AES key (GCM tag verified automatically)
 *
 * Note: GCM provides authenticated encryption, eliminating the need for separate HMAC
 */

static const size_t DEPIN_GCM_OVERHEAD = 28;
static const size_t DEPIN_WRAPPED_KEY_SIZE = 60;
static const size_t MAX_DEPIN_REPLY_PLAINTEXT = 4 * 1024 * 1024;

// Legacy-only messages keep their original bytes. Mixed/strict messages use
// 00 02 followed by the same key/payload and type-tagged destination ids.
class CECIESEncryptedMessage {
public:
    CPubKey ephemeralPubKey;
    std::vector<unsigned char> encryptedPayload;
    std::map<DepinRecipient, std::vector<unsigned char>> recipientKeys;
    CECIESEncryptedMessage() { SetNull(); }
    void SetNull() { ephemeralPubKey = CPubKey(); encryptedPayload.clear(); recipientKeys.clear(); }

    template <typename Stream> void Serialize(Stream& s) const {
        bool extended = false;
        for (const auto& entry : recipientKeys) if (!entry.first.IsLegacy()) extended = true;
        if (extended) { s << uint8_t(0) << uint8_t(2); }
        s << ephemeralPubKey << encryptedPayload;
        WriteCompactSize(s, recipientKeys.size());
        for (const auto& entry : recipientKeys) {
            if (extended) s << entry.first;
            else s << entry.first.LegacyID();
            s << entry.second;
        }
    }
    template <typename Stream> void Unserialize(Stream& s) { Read(s, MAX_DEPIN_REPLY_PLAINTEXT, 50); }
    template <typename Stream> void Read(Stream& s, size_t maxPlaintext, size_t maxRecipients) {
        SetNull();
        uint8_t marker; s >> marker;
        const bool extended = marker == 0;
        std::vector<unsigned char> key;
        if (extended) {
            uint8_t version; s >> version;
            if (version != 2) throw std::ios_base::failure("unsupported ECIES version");
            key = ReadDepinBytes(s, 33, 33);
        } else {
            if (marker != 33) throw std::ios_base::failure("invalid ephemeral key length");
            key.resize(33); s.read(reinterpret_cast<char*>(key.data()), key.size());
        }
        ephemeralPubKey = CPubKey(key);
        if (!ephemeralPubKey.IsCompressed() || !ephemeralPubKey.IsFullyValid())
            throw std::ios_base::failure("invalid compressed ephemeral key");
        encryptedPayload = ReadDepinBytes(s, maxPlaintext + DEPIN_GCM_OVERHEAD, DEPIN_GCM_OVERHEAD + 1);
        const uint64_t count = ReadCompactSize(s);
        if (!count || count > maxRecipients) throw std::ios_base::failure("number of recipients out of range");
        DepinRecipient previous;
        bool hasStrict = false;
        for (uint64_t i = 0; i < count; ++i) {
            DepinRecipient id;
            if (extended) s >> id;
            else { uint160 legacy; s >> legacy; id = DepinRecipient(legacy); }
            if (i && !(previous < id)) throw std::ios_base::failure("duplicate or unordered recipient");
            hasStrict |= !id.IsLegacy();
            recipientKeys.emplace(id, ReadDepinBytes(s, DEPIN_WRAPPED_KEY_SIZE, DEPIN_WRAPPED_KEY_SIZE));
            previous = id;
        }
        if (extended && !hasStrict) throw std::ios_base::failure("noncanonical Legacy-only ECIES v2");
    }
};

// The outer submission envelope has exactly one entry for the pool; an inner
// message may contain any valid nonempty subset of either destination family.
size_t DepinECIESWireLimit(size_t maxPlaintext, size_t maxRecipients);
bool DecodeDepinECIES(const std::vector<unsigned char>& bytes, size_t maxPlaintext,
                      size_t maxRecipients, CECIESEncryptedMessage& message,
                      std::string& error, const DepinRecipient* requiredRecipient = nullptr);

/**
 * Encrypt a message for multiple recipients using hybrid ECIES
 *
 * @param plaintext The message to encrypt
 * @param recipientPubKeys Map of address -> public key for each recipient
 * @param encryptedMsg Output encrypted message structure
 * @param error Output error message if fails
 * @return true if successful, false otherwise
 */
bool ECIESEncryptMessage(const std::string& plaintext,
                         const std::map<std::string, CPubKey>& recipientPubKeys,
                         CECIESEncryptedMessage& encryptedMsg,
                         std::string& error);

/**
 * Decrypt an ECIES encrypted message for a specific recipient
 *
 * @param encryptedMsg The encrypted message structure
 * @param recipientPrivKey Private key of the recipient
 * @param recipientAddress Address of the recipient (for key lookup)
 * @param plaintext Output decrypted message
 * @param error Output error message if fails
 * @return true if successful, false otherwise
 */
bool ECIESDecryptMessage(const CECIESEncryptedMessage& encryptedMsg,
                         const CKey& recipientPrivKey,
                         const std::string& recipientAddress,
                         std::string& plaintext,
                         std::string& error);

/**
 * Generate HMAC-SHA256 for message authentication
 *
 * @param key Key for HMAC
 * @param data Data to authenticate
 * @return HMAC-SHA256 (32 bytes)
 */
std::vector<unsigned char> HMAC_SHA256(const std::vector<unsigned char>& key,
                                        const std::vector<unsigned char>& data);

/**
 * AES-256-CBC encryption
 *
 * @param plaintext Data to encrypt
 * @param key AES key (32 bytes)
 * @param iv Initialization vector (16 bytes)
 * @param ciphertext Output encrypted data
 * @return true if successful
 */
bool AES256_CBC_Encrypt(const std::vector<unsigned char>& plaintext,
                        const std::vector<unsigned char>& key,
                        const std::vector<unsigned char>& iv,
                        std::vector<unsigned char>& ciphertext);

/**
 * AES-256-CBC decryption
 *
 * @param ciphertext Data to decrypt
 * @param key AES key (32 bytes)
 * @param iv Initialization vector (16 bytes)
 * @param plaintext Output decrypted data
 * @return true if successful
 */
bool AES256_CBC_Decrypt(const std::vector<unsigned char>& ciphertext,
                        const std::vector<unsigned char>& key,
                        const std::vector<unsigned char>& iv,
                        std::vector<unsigned char>& plaintext);

/**
 * AES-256-GCM encryption using OpenSSL EVP API
 *
 * GCM (Galois/Counter Mode) is an AEAD (Authenticated Encryption with Associated Data)
 * mode that provides both confidentiality and authenticity in a single operation.
 *
 * @param plaintext Data to encrypt
 * @param key AES key (must be exactly 32 bytes)
 * @param nonce Nonce/IV (must be exactly 12 bytes for GCM)
 * @param ciphertext Output encrypted data (same size as plaintext, no padding)
 * @param tag Output authentication tag (16 bytes)
 * @param aad Additional Authenticated Data (optional, can be empty)
 * @return true if successful, false otherwise
 */
bool AES256_GCM_Encrypt(const std::vector<unsigned char>& plaintext,
                        const std::vector<unsigned char>& key,
                        const std::vector<unsigned char>& nonce,
                        std::vector<unsigned char>& ciphertext,
                        std::vector<unsigned char>& tag,
                        const std::vector<unsigned char>& aad = std::vector<unsigned char>());

/**
 * AES-256-GCM decryption using OpenSSL EVP API
 *
 * Decrypts data encrypted with AES-256-GCM and verifies the authentication tag.
 * The tag verification is performed automatically during decryption.
 *
 * @param ciphertext Data to decrypt
 * @param key AES key (must be exactly 32 bytes)
 * @param nonce Nonce/IV (must be exactly 12 bytes)
 * @param tag Authentication tag to verify (must be exactly 16 bytes)
 * @param plaintext Output decrypted data
 * @param aad Additional Authenticated Data (must match encryption AAD)
 * @return true if successful AND tag verification passed, false otherwise
 */
bool AES256_GCM_Decrypt(const std::vector<unsigned char>& ciphertext,
                        const std::vector<unsigned char>& key,
                        const std::vector<unsigned char>& nonce,
                        const std::vector<unsigned char>& tag,
                        std::vector<unsigned char>& plaintext,
                        const std::vector<unsigned char>& aad = std::vector<unsigned char>());

/**
 * Compute ECDH shared secret
 *
 * @param privKey Private key (ours)
 * @param pubKey Public key (theirs)
 * @param secret Output shared secret (32 bytes)
 * @return true if successful
 */
bool ECDH_ComputeSecret(const CKey& privKey,
                        const CPubKey& pubKey,
                        std::vector<unsigned char>& secret);

/**
 * Key Derivation Function (KDF) using SHA256
 *
 * @param secret Input secret material
 * @param outputLen Desired output length
 * @return Derived key
 */
std::vector<unsigned char> KDF_SHA256(const std::vector<unsigned char>& secret,
                                       size_t outputLen);

#endif // NEURAI_DEPINECIES_H
