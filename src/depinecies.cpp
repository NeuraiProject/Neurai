// Copyright (c) 2024 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "depinecies.h"
#include "chainparams.h"
#include "depinserialization.h"
#include "streams.h"
#include "support/cleanse.h"
#include "version.h"
#include "hash.h"
#include "random.h"
#include "crypto/aes.h"
#include "crypto/sha256.h"
#include "crypto/hmac_sha256.h"
#include "uint256.h"
#include "util.h"
#include "base58.h"

#include <algorithm>
#include <stdexcept>

#include <secp256k1.h>
#include <secp256k1_ecdh.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

size_t DepinECIESWireLimit(size_t maxPlaintext, size_t maxRecipients)
{
    // Prefix, compressed key, commitment, CompactSizes, and largest typed id.
    return 2 + 34 + DEPIN_KEY_COMMITMENT_SIZE + 9 + DEPIN_GCM_OVERHEAD + maxPlaintext + 9 +
           maxRecipients * (33 + 1 + DEPIN_WRAPPED_KEY_SIZE);
}

namespace {
const char* const MESSAGE_CONTEXT_TAG = "Neurai/DePIN/message/v3";
const char* const REPLY_CONTEXT_TAG = "Neurai/DePIN/reply/v3";
const char* const SUBMIT_CONTEXT_TAG = "Neurai/DePIN/submit/v3";
const char* const WRAP_TAG = "Neurai/DePIN/wrap/v3";
const char* const COMMIT_TAG = "Neurai/DePIN/commit/v3";

uint256 Sha256(const CDataStream& data)
{
    const std::vector<unsigned char> bytes(data.begin(), data.end());
    uint256 out;
    CSHA256().Write(bytes.data(), bytes.size()).Finalize(out.begin());
    return out;
}

void WriteNetwork(CDataStream& data, const std::vector<unsigned char>& network)
{
    if (network.size() != 32) throw std::invalid_argument("DePIN network id must be 32 bytes");
    data.write(reinterpret_cast<const char*>(network.data()), network.size());
}

bool SameBytes(const unsigned char* a, const unsigned char* b, size_t size)
{
    unsigned char difference = 0;
    for (size_t i = 0; i < size; ++i) difference |= a[i] ^ b[i];
    return difference == 0;
}
}

std::vector<unsigned char> DepinNetworkId()
{
    const uint256& genesis = GetParams().GetConsensus().hashGenesisBlock;
    std::vector<unsigned char> id(genesis.begin(), genesis.end());
    std::reverse(id.begin(), id.end());
    return id;
}

uint256 DepinMessageContext(const std::vector<unsigned char>& network, const std::string& token,
                            const std::string& sender, int64_t timestamp, uint8_t type)
{
    CDataStream data(SER_NETWORK, PROTOCOL_VERSION);
    data << std::string(MESSAGE_CONTEXT_TAG);
    WriteNetwork(data, network);
    data << token << sender << timestamp << type;
    return Sha256(data);
}

uint256 DepinMessageContext(const std::string& token, const std::string& sender, int64_t timestamp, uint8_t type)
{
    return DepinMessageContext(DepinNetworkId(), token, sender, timestamp, type);
}

uint256 DepinTransportContext(const std::vector<unsigned char>& network, DepinTransport use)
{
    CDataStream data(SER_NETWORK, PROTOCOL_VERSION);
    data << std::string(use == DepinTransport::REPLY ? REPLY_CONTEXT_TAG : SUBMIT_CONTEXT_TAG);
    WriteNetwork(data, network);
    return Sha256(data);
}

uint256 DepinTransportContext(DepinTransport use)
{
    return DepinTransportContext(DepinNetworkId(), use);
}

std::vector<unsigned char> DepinWrapKey(const uint256& context, const std::vector<unsigned char>& sharedSecret,
                                        const CPubKey& ephemeralPubKey, const DepinRecipient& recipient)
{
    // HKDF-Extract: the context is the salt, the shared secret the input
    unsigned char prk[CHMAC_SHA256::OUTPUT_SIZE];
    CHMAC_SHA256(context.begin(), context.size()).Write(sharedSecret.data(), sharedSecret.size()).Finalize(prk);
    // HKDF-Expand, one block: info = tag || var(E) || var(recipient id) || 01
    CDataStream id(SER_NETWORK, PROTOCOL_VERSION);
    id << recipient;
    CDataStream info(SER_NETWORK, PROTOCOL_VERSION);
    info << std::string(WRAP_TAG) << ephemeralPubKey << std::vector<unsigned char>(id.begin(), id.end()) << uint8_t(1);
    const std::vector<unsigned char> infoBytes(info.begin(), info.end());
    std::vector<unsigned char> key(CHMAC_SHA256::OUTPUT_SIZE);
    CHMAC_SHA256(prk, sizeof(prk)).Write(infoBytes.data(), infoBytes.size()).Finalize(key.data());
    memory_cleanse(prk, sizeof(prk));
    return key;
}

uint256 DepinKeyCommitment(const uint256& context, const std::vector<unsigned char>& contentKey)
{
    CDataStream data(SER_NETWORK, PROTOCOL_VERSION);
    data << std::string(COMMIT_TAG) << context;
    data.write(reinterpret_cast<const char*>(contentKey.data()), contentKey.size());
    const uint256 commitment = Sha256(data);
    if (!data.empty()) memory_cleanse(&data[0], data.size());
    return commitment;
}

std::string DepinOpenFailureName(DepinOpenFailure failure)
{
    switch (failure) {
    case DepinOpenFailure::NONE: return "none";
    case DepinOpenFailure::INVALID_KEY: return "invalid_key";
    case DepinOpenFailure::NOT_RECIPIENT: return "not_recipient";
    case DepinOpenFailure::UNWRAP: return "unwrap";
    case DepinOpenFailure::COMMITMENT: return "commitment";
    case DepinOpenFailure::DECRYPT: return "decrypt";
    }
    return "unknown";
}

bool DecodeDepinECIES(const std::vector<unsigned char>& bytes, size_t maxPlaintext,
                      size_t maxRecipients, CECIESEncryptedMessage& message,
                      std::string& error, const DepinRecipient* requiredRecipient)
{
    message.SetNull();
    try {
        if (bytes.size() > DepinECIESWireLimit(maxPlaintext, maxRecipients))
            throw std::ios_base::failure("wire size exceeds budget");
        CDataStream stream(bytes, SER_NETWORK, PROTOCOL_VERSION);
        CECIESEncryptedMessage decoded;
        decoded.Read(stream, maxPlaintext, maxRecipients);
        if (!stream.empty()) throw std::ios_base::failure("trailing bytes");
        if (requiredRecipient && !decoded.recipientKeys.count(*requiredRecipient))
            throw std::ios_base::failure("required recipient missing");
        message = std::move(decoded);
        return true;
    } catch (const std::exception& e) {
        error = std::string("Invalid ECIES message payload: ") + e.what();
        return false;
    }
}

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
// ECDH shared secret computation
bool ECDH_ComputeSecret(const CKey& privKey,
                        const CPubKey& pubKey,
                        std::vector<unsigned char>& secret) {
    if (!privKey.IsValid() || !pubKey.IsValid()) {
        return false;
    }

    // Use secp256k1 ECDH
    // Shared secret = privKey * pubKey
    // One context for the life of the process: building one for each secret
    // costs far more than the secret itself. It is only read here, which any
    // number of threads may do at once.
    static secp256k1_context* const ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_pubkey secp_pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx, &secp_pubkey, pubKey.begin(), pubKey.size())) {
        return false;
    }

    unsigned char shared[32];
    if (!secp256k1_ecdh(ctx, shared, &secp_pubkey, privKey.begin(), nullptr, nullptr)) {
        return false;
    }

    secret.assign(shared, shared + 32);

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

bool ECIESEncryptMessage(const std::string& plaintext,
                         const std::map<std::string, CPubKey>& recipientPubKeys,
                         const uint256& context,
                         CECIESEncryptedMessage& encryptedMsg,
                         std::string& error) {
    encryptedMsg.SetNull();
    if (plaintext.empty()) {
        error = "Plaintext is empty";
        return false;
    }
    if (recipientPubKeys.empty()) {
        error = "No recipients provided";
        return false;
    }
    std::map<DepinRecipient, CPubKey> recipients;
    for (const auto& entry : recipientPubKeys) {
        DepinRecipient id;
        if (!DepinRecipient::FromAddress(entry.first, id) || !DepinPubKeyMatchesAddress(entry.first, entry.second)) {
            error = "Recipient public key does not match a supported address";
            return false;
        }
        recipients.emplace(id, entry.second);
    }

    // One ephemeral key for the envelope, and a content key of its own
    CKey ephemeralPrivKey;
    ephemeralPrivKey.MakeNewKey(true);
    const CPubKey ephemeralPubKey = ephemeralPrivKey.GetPubKey();
    if (!ephemeralPubKey.IsValid()) {
        error = "Failed to generate ephemeral key pair";
        return false;
    }
    std::vector<unsigned char> contentKey(32);
    GetStrongRandBytes(contentKey.data(), contentKey.size());

    // The text, once, with the context as additional authenticated data
    std::vector<unsigned char> nonce(12);
    GetStrongRandBytes(nonce.data(), nonce.size());
    const std::vector<unsigned char> plaintextVec(plaintext.begin(), plaintext.end());
    const std::vector<unsigned char> aad(context.begin(), context.end());
    std::vector<unsigned char> ciphertext, tag;
    if (!AES256_GCM_Encrypt(plaintextVec, contentKey, nonce, ciphertext, tag, aad)) {
        memory_cleanse(contentKey.data(), contentKey.size());
        error = "AES-GCM encryption failed";
        return false;
    }
    encryptedMsg.ephemeralPubKey = ephemeralPubKey;
    encryptedMsg.encryptedPayload = nonce;
    encryptedMsg.encryptedPayload.insert(encryptedMsg.encryptedPayload.end(), ciphertext.begin(), ciphertext.end());
    encryptedMsg.encryptedPayload.insert(encryptedMsg.encryptedPayload.end(), tag.begin(), tag.end());

    // The content key, wrapped for each recipient: nonce || encrypted key || tag
    for (const auto& recipient : recipients) {
        std::vector<unsigned char> sharedSecret;
        if (!ECDH_ComputeSecret(ephemeralPrivKey, recipient.second, sharedSecret)) {
            memory_cleanse(contentKey.data(), contentKey.size());
            encryptedMsg.SetNull();
            error = "ECDH failed for recipient " + recipient.first.Address();
            return false;
        }
        std::vector<unsigned char> wrapKey = DepinWrapKey(context, sharedSecret, ephemeralPubKey, recipient.first);
        memory_cleanse(sharedSecret.data(), sharedSecret.size());
        std::vector<unsigned char> wrapNonce(12), wrapped, wrapTag;
        GetStrongRandBytes(wrapNonce.data(), wrapNonce.size());
        const bool sealed = AES256_GCM_Encrypt(contentKey, wrapKey, wrapNonce, wrapped, wrapTag);
        memory_cleanse(wrapKey.data(), wrapKey.size());
        if (!sealed) {
            memory_cleanse(contentKey.data(), contentKey.size());
            encryptedMsg.SetNull();
            error = "Failed to wrap the content key for recipient " + recipient.first.Address();
            return false;
        }
        std::vector<unsigned char> package = wrapNonce;
        package.insert(package.end(), wrapped.begin(), wrapped.end());
        package.insert(package.end(), wrapTag.begin(), wrapTag.end());
        encryptedMsg.recipientKeys[recipient.first] = package;
    }

    encryptedMsg.commitment = DepinKeyCommitment(context, contentKey);
    memory_cleanse(contentKey.data(), contentKey.size());
    return true;
}

bool ECIESDecryptFor(const CECIESEncryptedMessage& encryptedMsg,
                     const CKey& recipientPrivKey,
                     const DepinRecipient& recipient,
                     const uint256& context,
                     std::string& plaintext,
                     std::string& error,
                     DepinOpenFailure* failure) {
    const auto fail = [&](DepinOpenFailure why, const std::string& reason) {
        if (failure) *failure = why;
        error = reason;
        return false;
    };
    if (failure) *failure = DepinOpenFailure::NONE;
    if (!recipientPrivKey.IsValid()) return fail(DepinOpenFailure::INVALID_KEY, "Invalid recipient private key");
    if (!encryptedMsg.ephemeralPubKey.IsFullyValid())
        return fail(DepinOpenFailure::INVALID_KEY, "Invalid ephemeral public key in message");

    const auto it = encryptedMsg.recipientKeys.find(recipient);
    if (it == encryptedMsg.recipientKeys.end())
        return fail(DepinOpenFailure::NOT_RECIPIENT, "This message is not encrypted for this recipient");
    const std::vector<unsigned char>& package = it->second;
    if (package.size() != DEPIN_WRAPPED_KEY_SIZE)
        return fail(DepinOpenFailure::UNWRAP, "Recipient key package has the wrong size");

    std::vector<unsigned char> sharedSecret;
    if (!ECDH_ComputeSecret(recipientPrivKey, encryptedMsg.ephemeralPubKey, sharedSecret))
        return fail(DepinOpenFailure::INVALID_KEY, "ECDH computation failed");
    std::vector<unsigned char> wrapKey = DepinWrapKey(context, sharedSecret, encryptedMsg.ephemeralPubKey, recipient);
    memory_cleanse(sharedSecret.data(), sharedSecret.size());

    // The content key: it only opens under the context the envelope was made for
    const std::vector<unsigned char> wrapNonce(package.begin(), package.begin() + 12);
    const std::vector<unsigned char> wrapped(package.begin() + 12, package.end() - 16);
    const std::vector<unsigned char> wrapTag(package.end() - 16, package.end());
    std::vector<unsigned char> contentKey;
    const bool unwrapped = AES256_GCM_Decrypt(wrapped, wrapKey, wrapNonce, wrapTag, contentKey);
    memory_cleanse(wrapKey.data(), wrapKey.size());
    if (!unwrapped || contentKey.size() != 32) {
        if (!contentKey.empty()) memory_cleanse(contentKey.data(), contentKey.size());
        return fail(DepinOpenFailure::UNWRAP, "Failed to decrypt the content key (authentication failed)");
    }

    // ...and it is the key every recipient that accepts the envelope gets
    const uint256 commitment = DepinKeyCommitment(context, contentKey);
    if (!SameBytes(commitment.begin(), encryptedMsg.commitment.begin(), DEPIN_KEY_COMMITMENT_SIZE)) {
        memory_cleanse(contentKey.data(), contentKey.size());
        return fail(DepinOpenFailure::COMMITMENT, "The content key is not the one the envelope commits to");
    }

    const std::vector<unsigned char>& payload = encryptedMsg.encryptedPayload;
    if (payload.size() < DEPIN_GCM_OVERHEAD) {
        memory_cleanse(contentKey.data(), contentKey.size());
        return fail(DepinOpenFailure::DECRYPT, "Encrypted payload is too small");
    }
    const std::vector<unsigned char> nonce(payload.begin(), payload.begin() + 12);
    const std::vector<unsigned char> ciphertext(payload.begin() + 12, payload.end() - 16);
    const std::vector<unsigned char> tag(payload.end() - 16, payload.end());
    const std::vector<unsigned char> aad(context.begin(), context.end());
    std::vector<unsigned char> plaintextVec;
    const bool opened = AES256_GCM_Decrypt(ciphertext, contentKey, nonce, tag, plaintextVec, aad);
    memory_cleanse(contentKey.data(), contentKey.size());
    if (!opened) return fail(DepinOpenFailure::DECRYPT, "Failed to decrypt message (authentication failed)");

    plaintext = std::string(plaintextVec.begin(), plaintextVec.end());
    return true;
}

bool ECIESDecryptMessage(const CECIESEncryptedMessage& encryptedMsg,
                         const CKey& recipientPrivKey,
                         const std::string& recipientAddress,
                         const uint256& context,
                         std::string& plaintext,
                         std::string& error,
                         DepinOpenFailure* failure) {
    DepinRecipient recipient;
    if (!recipientPrivKey.IsValid() || !DepinRecipient::FromAddress(recipientAddress, recipient) ||
        !DepinPubKeyMatchesAddress(recipientAddress, recipientPrivKey.GetPubKey())) {
        if (failure) *failure = DepinOpenFailure::INVALID_KEY;
        error = "Private key does not match a supported recipient address";
        return false;
    }
    return ECIESDecryptFor(encryptedMsg, recipientPrivKey, recipient, context, plaintext, error, failure);
}
