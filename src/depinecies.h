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

/**
 * ECIES (Elliptic Curve Integrated Encryption Scheme) implementation for DePIN Messaging
 *
 * This implements hybrid encryption compatible with the web interface:
 * https://github.com/NeuraiProject/DePIN-Messaging/tree/main/website
 *
 * Encryption scheme:
 * 1. Generate ephemeral key pair (one per message)
 * 2. Encrypt plaintext once with AES-256-CBC using key derived from ephemeral private key
 * 3. For each recipient:
 *    - Compute shared secret: ECDH(ephemeral_privkey, recipient_pubkey)
 *    - Derive encryption key from shared secret (SHA256)
 *    - Encrypt the AES key used in step 2
 *    - Package: [ephemeral_pubkey, encrypted_aes_key, hmac]
 * 4. Attach single encrypted message payload to all recipients
 *
 * Decryption:
 * 1. Extract ephemeral public key
 * 2. Compute shared secret: ECDH(recipient_privkey, ephemeral_pubkey)
 * 3. Derive decryption key from shared secret
 * 4. Decrypt AES key
 * 5. Verify HMAC
 * 6. Decrypt message with recovered AES key
 */

// Estructura del mensaje cifrado con ECIES híbrido
class CECIESEncryptedMessage {
public:
    // Clave pública efímera (33 bytes comprimida)
    CPubKey ephemeralPubKey;

    // Payload cifrado (AES-256-CBC)
    // Contiene: [IV (16 bytes) || encrypted_data || HMAC-SHA256 (32 bytes)]
    std::vector<unsigned char> encryptedPayload;

    // Para cada destinatario: clave AES cifrada con ECDH
    // Map: address_hash160 -> [ephemeral_pubkey_for_recipient (33) || encrypted_aes_key (32) || hmac (32)]
    std::map<uint160, std::vector<unsigned char>> recipientKeys;

    CECIESEncryptedMessage() {
        SetNull();
    }

    void SetNull() {
        ephemeralPubKey = CPubKey();
        encryptedPayload.clear();
        recipientKeys.clear();
    }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(ephemeralPubKey);
        READWRITE(encryptedPayload);
        READWRITE(recipientKeys);
    }
};

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
