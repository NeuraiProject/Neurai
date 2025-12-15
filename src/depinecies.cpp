// Copyright (c) 2024 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "depinecies.h"
#include "hash.h"
#include "random.h"
#include "crypto/aes.h"
#include "crypto/sha256.h"
#include "crypto/hmac_sha256.h"
#include "uint256.h"
#include "util.h"
#include "base58.h"

#include <secp256k1.h>
#include <secp256k1_ecdh.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

// HMAC-SHA256
std::vector<unsigned char> HMAC_SHA256(const std::vector<unsigned char>& key,
                                        const std::vector<unsigned char>& data) {
    std::vector<unsigned char> result(CHMAC_SHA256::OUTPUT_SIZE);
    CHMAC_SHA256 hmac(key.data(), key.size());
    hmac.Write(data.data(), data.size());
    hmac.Finalize(result.data());
    return result;
}

// Key Derivation Function using SHA256
std::vector<unsigned char> KDF_SHA256(const std::vector<unsigned char>& secret,
                                       size_t outputLen) {
    std::vector<unsigned char> output;
    output.reserve(outputLen);

    uint32_t counter = 1;
    while (output.size() < outputLen) {
        CSHA256 sha;
        sha.Write(secret.data(), secret.size());

        // Add counter (big-endian)
        unsigned char counterBytes[4];
        counterBytes[0] = (counter >> 24) & 0xFF;
        counterBytes[1] = (counter >> 16) & 0xFF;
        counterBytes[2] = (counter >> 8) & 0xFF;
        counterBytes[3] = counter & 0xFF;
        sha.Write(counterBytes, 4);

        unsigned char hash[CSHA256::OUTPUT_SIZE];
        sha.Finalize(hash);

        size_t copyLen = std::min(outputLen - output.size(), (size_t)CSHA256::OUTPUT_SIZE);
        output.insert(output.end(), hash, hash + copyLen);

        counter++;
    }

    return output;
}

// ECDH shared secret computation
bool ECDH_ComputeSecret(const CKey& privKey,
                        const CPubKey& pubKey,
                        std::vector<unsigned char>& secret) {
    if (!privKey.IsValid() || !pubKey.IsValid()) {
        return false;
    }

    // Use secp256k1 ECDH
    // Shared secret = privKey * pubKey
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_pubkey secp_pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &secp_pubkey, pubKey.begin(), pubKey.size())) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    unsigned char shared[32];
    if (!secp256k1_ecdh(ctx, shared, &secp_pubkey, privKey.begin(), nullptr, nullptr)) {
        secp256k1_context_destroy(ctx);
        return false;
    }

    secret.assign(shared, shared + 32);
    secp256k1_context_destroy(ctx);

    return true;
}

// AES-256-CBC encryption using OpenSSL
bool AES256_CBC_Encrypt(const std::vector<unsigned char>& plaintext,
                        const std::vector<unsigned char>& key,
                        const std::vector<unsigned char>& iv,
                        std::vector<unsigned char>& ciphertext) {
    if (key.size() != 32 || iv.size() != 16) {
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }

    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Allocate output buffer (plaintext size + block size for padding)
    ciphertext.resize(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len = 0;
    int ciphertext_len = 0;

    // Encrypt
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;

    // Finalize (adds padding)
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

// AES-256-CBC decryption using OpenSSL
bool AES256_CBC_Decrypt(const std::vector<unsigned char>& ciphertext,
                        const std::vector<unsigned char>& key,
                        const std::vector<unsigned char>& iv,
                        std::vector<unsigned char>& plaintext) {
    if (key.size() != 32 || iv.size() != 16) {
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Allocate output buffer
    plaintext.resize(ciphertext.size());
    int len = 0;
    int plaintext_len = 0;

    // Decrypt
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;

    // Finalize (removes padding)
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

// AES-256-GCM encryption using OpenSSL
bool AES256_GCM_Encrypt(const std::vector<unsigned char>& plaintext,
                        const std::vector<unsigned char>& key,
                        const std::vector<unsigned char>& nonce,
                        std::vector<unsigned char>& ciphertext,
                        std::vector<unsigned char>& tag,
                        const std::vector<unsigned char>& aad) {
    // Validate input parameters
    if (key.size() != 32) {
        LogPrintf("AES256_GCM_Encrypt: Invalid key size %d (expected 32)\n", key.size());
        return false;
    }
    if (nonce.size() != 12) {
        LogPrintf("AES256_GCM_Encrypt: Invalid nonce size %d (expected 12)\n", nonce.size());
        return false;
    }
    if (plaintext.empty()) {
        LogPrintf("AES256_GCM_Encrypt: Empty plaintext\n");
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LogPrintf("AES256_GCM_Encrypt: Failed to create cipher context\n");
        return false;
    }

    bool success = false;
    do {
        // Initialize GCM encryption
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            LogPrintf("AES256_GCM_Encrypt: EVP_EncryptInit_ex failed\n");
            break;
        }

        // Set nonce length (12 bytes is standard for GCM)
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
            LogPrintf("AES256_GCM_Encrypt: Failed to set IV length\n");
            break;
        }

        // Set key and nonce
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
            LogPrintf("AES256_GCM_Encrypt: Failed to set key and nonce\n");
            break;
        }

        // Process AAD if present
        if (!aad.empty()) {
            int len;
            if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) != 1) {
                LogPrintf("AES256_GCM_Encrypt: Failed to process AAD\n");
                break;
            }
        }

        // Encrypt data (GCM does not add padding, ciphertext size = plaintext size)
        ciphertext.resize(plaintext.size());
        int len = 0;
        int ciphertext_len = 0;
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
            LogPrintf("AES256_GCM_Encrypt: EVP_EncryptUpdate failed\n");
            break;
        }
        ciphertext_len = len;

        // Finalize encryption
        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
            LogPrintf("AES256_GCM_Encrypt: EVP_EncryptFinal_ex failed\n");
            break;
        }
        ciphertext_len += len;
        ciphertext.resize(ciphertext_len);

        // Get authentication tag (128 bits = 16 bytes)
        tag.resize(16);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
            LogPrintf("AES256_GCM_Encrypt: Failed to get authentication tag\n");
            break;
        }

        success = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return success;
}

// AES-256-GCM decryption using OpenSSL
bool AES256_GCM_Decrypt(const std::vector<unsigned char>& ciphertext,
                        const std::vector<unsigned char>& key,
                        const std::vector<unsigned char>& nonce,
                        const std::vector<unsigned char>& tag,
                        std::vector<unsigned char>& plaintext,
                        const std::vector<unsigned char>& aad) {
    // Validate input parameters
    if (key.size() != 32) {
        LogPrintf("AES256_GCM_Decrypt: Invalid key size %d (expected 32)\n", key.size());
        return false;
    }
    if (nonce.size() != 12) {
        LogPrintf("AES256_GCM_Decrypt: Invalid nonce size %d (expected 12)\n", nonce.size());
        return false;
    }
    if (tag.size() != 16) {
        LogPrintf("AES256_GCM_Decrypt: Invalid tag size %d (expected 16)\n", tag.size());
        return false;
    }
    if (ciphertext.empty()) {
        LogPrintf("AES256_GCM_Decrypt: Empty ciphertext\n");
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LogPrintf("AES256_GCM_Decrypt: Failed to create cipher context\n");
        return false;
    }

    bool success = false;
    do {
        // Initialize GCM decryption
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            LogPrintf("AES256_GCM_Decrypt: EVP_DecryptInit_ex failed\n");
            break;
        }

        // Set nonce length
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) {
            LogPrintf("AES256_GCM_Decrypt: Failed to set IV length\n");
            break;
        }

        // Set key and nonce
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
            LogPrintf("AES256_GCM_Decrypt: Failed to set key and nonce\n");
            break;
        }

        // Process AAD if present
        if (!aad.empty()) {
            int len;
            if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()) != 1) {
                LogPrintf("AES256_GCM_Decrypt: Failed to process AAD\n");
                break;
            }
        }

        // Decrypt data
        plaintext.resize(ciphertext.size());
        int len = 0;
        int plaintext_len = 0;
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
            LogPrintf("AES256_GCM_Decrypt: EVP_DecryptUpdate failed\n");
            break;
        }
        plaintext_len = len;

        // Set expected authentication tag for verification
        // Make a mutable copy of the tag for EVP_CIPHER_CTX_ctrl
        std::vector<unsigned char> tag_copy = tag;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag_copy.data()) != 1) {
            LogPrintf("AES256_GCM_Decrypt: Failed to set authentication tag\n");
            break;
        }

        // Finalize decryption - this verifies the tag automatically
        // If the tag does not match, EVP_DecryptFinal_ex will return an error
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) != 1) {
            LogPrintf("AES256_GCM_Decrypt: Authentication tag verification FAILED\n");
            plaintext.clear(); // Clear potentially corrupted data
            break;
        }
        plaintext_len += len;
        plaintext.resize(plaintext_len);

        success = true;
    } while (false);

    EVP_CIPHER_CTX_free(ctx);
    return success;
}

// Hybrid ECIES encryption for multiple recipients
bool ECIESEncryptMessage(const std::string& plaintext,
                         const std::map<std::string, CPubKey>& recipientPubKeys,
                         CECIESEncryptedMessage& encryptedMsg,
                         std::string& error) {
    if (plaintext.empty()) {
        error = "Plaintext is empty";
        return false;
    }

    if (recipientPubKeys.empty()) {
        error = "No recipients provided";
        return false;
    }

    // Step 1: Generate ephemeral key pair (one per message)
    CKey ephemeralPrivKey;
    ephemeralPrivKey.MakeNewKey(true); // compressed
    CPubKey ephemeralPubKey = ephemeralPrivKey.GetPubKey();

    if (!ephemeralPubKey.IsValid()) {
        error = "Failed to generate ephemeral key pair";
        return false;
    }

    encryptedMsg.ephemeralPubKey = ephemeralPubKey;

    // Step 2: Derive AES key from ephemeral private key
    std::vector<unsigned char> ephemeralSecret(ephemeralPrivKey.begin(), ephemeralPrivKey.end());
    std::vector<unsigned char> aesKey = KDF_SHA256(ephemeralSecret, 32);

    // Generate random nonce for AES-GCM (12 bytes)
    std::vector<unsigned char> nonce(12);
    GetStrongRandBytes(nonce.data(), 12);

    // Step 3: Encrypt plaintext once with AES-256-GCM
    std::vector<unsigned char> plaintextVec(plaintext.begin(), plaintext.end());
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> tag;

    if (!AES256_GCM_Encrypt(plaintextVec, aesKey, nonce, ciphertext, tag)) {
        error = "AES-GCM encryption failed";
        return false;
    }

    // Step 4: Package encrypted payload: [Nonce (12) || ciphertext || Tag (16)]
    // GCM provides authenticated encryption, no separate HMAC needed
    encryptedMsg.encryptedPayload.clear();
    encryptedMsg.encryptedPayload.insert(encryptedMsg.encryptedPayload.end(), nonce.begin(), nonce.end());
    encryptedMsg.encryptedPayload.insert(encryptedMsg.encryptedPayload.end(), ciphertext.begin(), ciphertext.end());
    encryptedMsg.encryptedPayload.insert(encryptedMsg.encryptedPayload.end(), tag.begin(), tag.end());

    // Step 6: For each recipient, encrypt the AES key using ECDH
    for (const auto& recipient : recipientPubKeys) {
        const std::string& address = recipient.first;
        const CPubKey& recipientPubKey = recipient.second;

        if (!recipientPubKey.IsValid()) {
            LogPrintf("Warning: Invalid public key for recipient %s, skipping\n", address);
            continue;
        }

        // Compute shared secret: ECDH(ephemeral_privkey, recipient_pubkey)
        std::vector<unsigned char> sharedSecret;
        if (!ECDH_ComputeSecret(ephemeralPrivKey, recipientPubKey, sharedSecret)) {
            LogPrintf("Warning: ECDH failed for recipient %s, skipping\n", address);
            continue;
        }

        // Derive encryption key from shared secret
        std::vector<unsigned char> encKey = KDF_SHA256(sharedSecret, 32);

        // Generate random nonce for this recipient's key encryption (12 bytes)
        std::vector<unsigned char> recipientNonce(12);
        GetStrongRandBytes(recipientNonce.data(), 12);

        // Encrypt the AES key with GCM
        std::vector<unsigned char> encryptedAESKey;
        std::vector<unsigned char> recipientTag;
        if (!AES256_GCM_Encrypt(aesKey, encKey, recipientNonce, encryptedAESKey, recipientTag)) {
            LogPrintf("Warning: Failed to encrypt AES key for recipient %s, skipping\n", address);
            continue;
        }

        // Package for this recipient: [Nonce (12) || encrypted_aes_key || Tag (16)]
        // GCM provides authenticated encryption, no separate HMAC needed
        std::vector<unsigned char> recipientPackage;
        recipientPackage.insert(recipientPackage.end(), recipientNonce.begin(), recipientNonce.end());
        recipientPackage.insert(recipientPackage.end(), encryptedAESKey.begin(), encryptedAESKey.end());
        recipientPackage.insert(recipientPackage.end(), recipientTag.begin(), recipientTag.end());

        // Get address hash160 for key lookup
        CTxDestination dest = DecodeDestination(address);
        const CKeyID* keyID = boost::get<CKeyID>(&dest);
        if (!keyID) {
            LogPrintf("Warning: Invalid address format for recipient %s, skipping\n", address);
            continue;
        }
        uint160 addressHash(*keyID);

        encryptedMsg.recipientKeys[addressHash] = recipientPackage;
    }

    if (encryptedMsg.recipientKeys.empty()) {
        error = "Failed to encrypt for any recipient";
        return false;
    }

    return true;
}

// Hybrid ECIES decryption
bool ECIESDecryptMessage(const CECIESEncryptedMessage& encryptedMsg,
                         const CKey& recipientPrivKey,
                         const std::string& recipientAddress,
                         std::string& plaintext,
                         std::string& error) {
    if (!recipientPrivKey.IsValid()) {
        error = "Invalid recipient private key";
        return false;
    }

    if (!encryptedMsg.ephemeralPubKey.IsValid()) {
        error = "Invalid ephemeral public key in message";
        return false;
    }

    // Get address hash160
    CTxDestination dest = DecodeDestination(recipientAddress);
    const CKeyID* keyID = boost::get<CKeyID>(&dest);
    if (!keyID) {
        error = "Invalid recipient address format";
        return false;
    }
    uint160 addressHash(*keyID);

    // Find recipient key package
    auto it = encryptedMsg.recipientKeys.find(addressHash);
    if (it == encryptedMsg.recipientKeys.end()) {
        error = "This message is not encrypted for this recipient";
        return false;
    }

    const std::vector<unsigned char>& recipientPackage = it->second;

    // Package format: [Nonce (12) || encrypted_aes_key (32, no padding in GCM) || Tag (16)]
    // Minimum size: 12 + 32 + 16 = 60 bytes
    if (recipientPackage.size() < 60) {
        error = "Recipient key package is too small";
        return false;
    }

    // Extract Nonce (first 12 bytes)
    std::vector<unsigned char> recipientNonce(recipientPackage.begin(), recipientPackage.begin() + 12);

    // Extract Tag (last 16 bytes)
    std::vector<unsigned char> recipientTag(recipientPackage.end() - 16, recipientPackage.end());

    // Extract encrypted AES key (everything between Nonce and Tag)
    std::vector<unsigned char> encryptedAESKey(recipientPackage.begin() + 12, recipientPackage.end() - 16);

    // Step 1: Compute shared secret using recipient's private key and ephemeral public key
    std::vector<unsigned char> sharedSecret;
    if (!ECDH_ComputeSecret(recipientPrivKey, encryptedMsg.ephemeralPubKey, sharedSecret)) {
        error = "ECDH computation failed";
        return false;
    }

    // Step 2: Derive decryption key from shared secret
    std::vector<unsigned char> decKey = KDF_SHA256(sharedSecret, 32);

    // Step 3: Decrypt AES key (GCM tag verified automatically)
    std::vector<unsigned char> aesKey;
    if (!AES256_GCM_Decrypt(encryptedAESKey, decKey, recipientNonce, recipientTag, aesKey)) {
        error = "Failed to decrypt AES key (authentication failed)";
        return false;
    }

    if (aesKey.size() != 32) {
        error = "Decrypted AES key has invalid size";
        return false;
    }

    // Step 4: Extract Nonce, ciphertext, and Tag from encrypted payload
    // Payload format: [Nonce (12) || ciphertext || Tag (16)]
    if (encryptedMsg.encryptedPayload.size() < 28) { // 12 + 0 + 16
        error = "Encrypted payload is too small";
        return false;
    }

    std::vector<unsigned char> payloadNonce(encryptedMsg.encryptedPayload.begin(),
                                             encryptedMsg.encryptedPayload.begin() + 12);
    std::vector<unsigned char> payloadTag(encryptedMsg.encryptedPayload.end() - 16,
                                           encryptedMsg.encryptedPayload.end());
    std::vector<unsigned char> payloadCiphertext(encryptedMsg.encryptedPayload.begin() + 12,
                                                  encryptedMsg.encryptedPayload.end() - 16);

    // Step 5: Decrypt message (GCM tag verified automatically)
    std::vector<unsigned char> plaintextVec;
    if (!AES256_GCM_Decrypt(payloadCiphertext, aesKey, payloadNonce, payloadTag, plaintextVec)) {
        error = "Failed to decrypt message (authentication failed)";
        return false;
    }

    plaintext = std::string(plaintextVec.begin(), plaintextVec.end());
    return true;
}
