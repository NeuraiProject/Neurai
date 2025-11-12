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

    // Generate random IV for AES
    std::vector<unsigned char> iv(16);
    GetStrongRandBytes(iv.data(), 16);

    // Step 3: Encrypt plaintext once with AES-256-CBC
    std::vector<unsigned char> plaintextVec(plaintext.begin(), plaintext.end());
    std::vector<unsigned char> ciphertext;

    if (!AES256_CBC_Encrypt(plaintextVec, aesKey, iv, ciphertext)) {
        error = "AES encryption failed";
        return false;
    }

    // Step 4: Compute HMAC of ciphertext
    std::vector<unsigned char> hmac = HMAC_SHA256(aesKey, ciphertext);

    // Step 5: Package encrypted payload: [IV || ciphertext || HMAC]
    encryptedMsg.encryptedPayload.clear();
    encryptedMsg.encryptedPayload.insert(encryptedMsg.encryptedPayload.end(), iv.begin(), iv.end());
    encryptedMsg.encryptedPayload.insert(encryptedMsg.encryptedPayload.end(), ciphertext.begin(), ciphertext.end());
    encryptedMsg.encryptedPayload.insert(encryptedMsg.encryptedPayload.end(), hmac.begin(), hmac.end());

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

        // Generate random IV for this recipient's key encryption
        std::vector<unsigned char> recipientIV(16);
        GetStrongRandBytes(recipientIV.data(), 16);

        // Encrypt the AES key
        std::vector<unsigned char> encryptedAESKey;
        if (!AES256_CBC_Encrypt(aesKey, encKey, recipientIV, encryptedAESKey)) {
            LogPrintf("Warning: Failed to encrypt AES key for recipient %s, skipping\n", address);
            continue;
        }

        // Compute HMAC of encrypted AES key
        std::vector<unsigned char> recipientHMAC = HMAC_SHA256(encKey, encryptedAESKey);

        // Package for this recipient: [IV || encrypted_aes_key || HMAC]
        std::vector<unsigned char> recipientPackage;
        recipientPackage.insert(recipientPackage.end(), recipientIV.begin(), recipientIV.end());
        recipientPackage.insert(recipientPackage.end(), encryptedAESKey.begin(), encryptedAESKey.end());
        recipientPackage.insert(recipientPackage.end(), recipientHMAC.begin(), recipientHMAC.end());

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

    // Package format: [IV (16) || encrypted_aes_key (32+padding) || HMAC (32)]
    // Minimum size: 16 + 32 + 32 = 80 bytes (but with AES padding, encrypted key will be larger)
    if (recipientPackage.size() < 80) {
        error = "Recipient key package is too small";
        return false;
    }

    // Extract IV (first 16 bytes)
    std::vector<unsigned char> recipientIV(recipientPackage.begin(), recipientPackage.begin() + 16);

    // Extract HMAC (last 32 bytes)
    std::vector<unsigned char> recipientHMAC(recipientPackage.end() - 32, recipientPackage.end());

    // Extract encrypted AES key (everything between IV and HMAC)
    std::vector<unsigned char> encryptedAESKey(recipientPackage.begin() + 16, recipientPackage.end() - 32);

    // Step 1: Compute shared secret using recipient's private key and ephemeral public key
    std::vector<unsigned char> sharedSecret;
    if (!ECDH_ComputeSecret(recipientPrivKey, encryptedMsg.ephemeralPubKey, sharedSecret)) {
        error = "ECDH computation failed";
        return false;
    }

    // Step 2: Derive decryption key from shared secret
    std::vector<unsigned char> decKey = KDF_SHA256(sharedSecret, 32);

    // Step 3: Verify HMAC of encrypted AES key
    std::vector<unsigned char> computedHMAC = HMAC_SHA256(decKey, encryptedAESKey);
    if (computedHMAC != recipientHMAC) {
        error = "HMAC verification failed for recipient key";
        return false;
    }

    // Step 4: Decrypt AES key
    std::vector<unsigned char> aesKey;
    if (!AES256_CBC_Decrypt(encryptedAESKey, decKey, recipientIV, aesKey)) {
        error = "Failed to decrypt AES key";
        return false;
    }

    if (aesKey.size() != 32) {
        error = "Decrypted AES key has invalid size";
        return false;
    }

    // Step 5: Extract IV, ciphertext, and HMAC from encrypted payload
    // Payload format: [IV (16) || ciphertext || HMAC (32)]
    if (encryptedMsg.encryptedPayload.size() < 48) { // 16 + 0 + 32
        error = "Encrypted payload is too small";
        return false;
    }

    std::vector<unsigned char> payloadIV(encryptedMsg.encryptedPayload.begin(),
                                          encryptedMsg.encryptedPayload.begin() + 16);
    std::vector<unsigned char> payloadHMAC(encryptedMsg.encryptedPayload.end() - 32,
                                            encryptedMsg.encryptedPayload.end());
    std::vector<unsigned char> payloadCiphertext(encryptedMsg.encryptedPayload.begin() + 16,
                                                  encryptedMsg.encryptedPayload.end() - 32);

    // Step 6: Verify HMAC of ciphertext
    std::vector<unsigned char> computedPayloadHMAC = HMAC_SHA256(aesKey, payloadCiphertext);
    if (computedPayloadHMAC != payloadHMAC) {
        error = "HMAC verification failed for message payload";
        return false;
    }

    // Step 7: Decrypt message
    std::vector<unsigned char> plaintextVec;
    if (!AES256_CBC_Decrypt(payloadCiphertext, aesKey, payloadIV, plaintextVec)) {
        error = "Failed to decrypt message";
        return false;
    }

    plaintext = std::string(plaintextVec.begin(), plaintextVec.end());
    return true;
}
