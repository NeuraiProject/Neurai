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
#include "uint256.h"
#include "depinaddress.h"
#include "depinserialization.h"
#include <map>

/**
 * Envelope of DePIN messages, replies and submissions: format 3.
 *
 * One envelope carries one text for one or more recipients:
 * 1. A random content key K encrypts the text once with AES-256-GCM. The
 *    context of the envelope is its additional authenticated data.
 * 2. For each recipient, ECDH between a one-time ephemeral key and the
 *    recipient's key gives a shared secret. HKDF-SHA256, salted with the
 *    context, turns it into the key that wraps K for that recipient.
 * 3. A commitment to K under the context tells every recipient which K is the
 *    one: two recipients that accept the same envelope read the same text.
 *
 * The context is a SHA-256 digest of what the envelope belongs to. For a
 * message, its signed header (section, sender, time, type) on one network;
 * for a reply or a submission, that use on one network. An envelope opens only
 * under the context it was made for: copied under another header, it does not.
 *
 * Wire: 00 03 || var(E) || commitment (32) || var(payload) || CompactSize(n)
 *       || n x (recipient id || var(wrapped key))
 * payload = nonce (12) || ciphertext || tag (16)
 * wrapped key = nonce (12) || encrypted K (32) || tag (16)
 * See doc/depin-messaging-protocol.md for the byte-exact contract.
 */

static const size_t DEPIN_GCM_OVERHEAD = 28;
static const size_t DEPIN_WRAPPED_KEY_SIZE = 60;
static const size_t DEPIN_KEY_COMMITMENT_SIZE = 32;
static const size_t MAX_DEPIN_REPLY_PLAINTEXT = 4 * 1024 * 1024;
static const uint8_t DEPIN_ENVELOPE_FORMAT = 3;

class CECIESEncryptedMessage {
public:
    CPubKey ephemeralPubKey;
    uint256 commitment;
    std::vector<unsigned char> encryptedPayload;
    std::map<DepinRecipient, std::vector<unsigned char>> recipientKeys;
    CECIESEncryptedMessage() { SetNull(); }
    void SetNull() { ephemeralPubKey = CPubKey(); commitment.SetNull(); encryptedPayload.clear(); recipientKeys.clear(); }

    template <typename Stream> void Serialize(Stream& s) const {
        s << uint8_t(0) << DEPIN_ENVELOPE_FORMAT << ephemeralPubKey << commitment << encryptedPayload;
        WriteCompactSize(s, recipientKeys.size());
        for (const auto& entry : recipientKeys) s << entry.first << entry.second;
    }
    template <typename Stream> void Unserialize(Stream& s) { Read(s, MAX_DEPIN_REPLY_PLAINTEXT, 50); }
    template <typename Stream> void Read(Stream& s, size_t maxPlaintext, size_t maxRecipients) {
        SetNull();
        uint8_t marker, format;
        s >> marker >> format;
        if (marker != 0 || format != DEPIN_ENVELOPE_FORMAT) throw std::ios_base::failure("unsupported envelope format");
        const auto key = ReadDepinBytes(s, 33, 33);
        ephemeralPubKey = CPubKey(key);
        if (!ephemeralPubKey.IsCompressed() || !ephemeralPubKey.IsFullyValid())
            throw std::ios_base::failure("invalid compressed ephemeral key");
        s >> commitment;
        encryptedPayload = ReadDepinBytes(s, maxPlaintext + DEPIN_GCM_OVERHEAD, DEPIN_GCM_OVERHEAD + 1);
        const uint64_t count = ReadCompactSize(s);
        if (!count || count > maxRecipients) throw std::ios_base::failure("number of recipients out of range");
        DepinRecipient previous;
        for (uint64_t i = 0; i < count; ++i) {
            DepinRecipient id;
            s >> id;
            if (i && !(previous < id)) throw std::ios_base::failure("duplicate or unordered recipient");
            recipientKeys.emplace(id, ReadDepinBytes(s, DEPIN_WRAPPED_KEY_SIZE, DEPIN_WRAPPED_KEY_SIZE));
            previous = id;
        }
    }
};

// The outer submission envelope has exactly one entry for the pool; an inner
// message may contain any valid nonempty subset of either destination family.
size_t DepinECIESWireLimit(size_t maxPlaintext, size_t maxRecipients);
bool DecodeDepinECIES(const std::vector<unsigned char>& bytes, size_t maxPlaintext,
                      size_t maxRecipients, CECIESEncryptedMessage& message,
                      std::string& error, const DepinRecipient* requiredRecipient = nullptr);

/** The network an envelope is bound to: the hash of its genesis block, in the
 *  order it is displayed (as the "network" field of the protocol). */
std::vector<unsigned char> DepinNetworkId();

/** Context of a message envelope: its signed header on one network. */
uint256 DepinMessageContext(const std::vector<unsigned char>& network, const std::string& token,
                            const std::string& sender, int64_t timestamp, uint8_t type);
uint256 DepinMessageContext(const std::string& token, const std::string& sender, int64_t timestamp, uint8_t type);

/** Envelopes that do not carry a message */
enum class DepinTransport {
    REPLY,  //!< an answer of the pool, encrypted for the client
    SUBMIT, //!< a signed message on its way to the pool
};
uint256 DepinTransportContext(const std::vector<unsigned char>& network, DepinTransport use);
uint256 DepinTransportContext(DepinTransport use);

/** The key that wraps the content key for one recipient (HKDF-SHA256, RFC 5869) */
std::vector<unsigned char> DepinWrapKey(const uint256& context, const std::vector<unsigned char>& sharedSecret,
                                        const CPubKey& ephemeralPubKey, const DepinRecipient& recipient);

/** The commitment to the content key under a context */
uint256 DepinKeyCommitment(const uint256& context, const std::vector<unsigned char>& contentKey);

/**
 * Encrypt a text for one or more recipients, under the context of its use.
 *
 * @param plaintext The text
 * @param recipientPubKeys Address -> public key of each recipient
 * @param context What the envelope belongs to (DepinMessageContext, DepinTransportContext)
 * @param encryptedMsg The envelope
 * @param error Why it failed
 */
bool ECIESEncryptMessage(const std::string& plaintext,
                         const std::map<std::string, CPubKey>& recipientPubKeys,
                         const uint256& context,
                         CECIESEncryptedMessage& encryptedMsg,
                         std::string& error);

/** Why an envelope did not open */
enum class DepinOpenFailure {
    NONE,
    INVALID_KEY,   //!< the key does not belong to the address, or the envelope key is invalid
    NOT_RECIPIENT, //!< the envelope is not encrypted for this key: not an error
    UNWRAP,        //!< the wrapped content key does not open under this context
    COMMITMENT,    //!< the content key is not the one the envelope commits to
    DECRYPT,       //!< the text does not open under this context
};
/** The envelope is addressed to this key and is not authentic */
inline bool IsDepinEnvelopeForged(DepinOpenFailure failure)
{
    return failure == DepinOpenFailure::UNWRAP || failure == DepinOpenFailure::COMMITMENT ||
           failure == DepinOpenFailure::DECRYPT;
}
std::string DepinOpenFailureName(DepinOpenFailure failure);

/**
 * Open an envelope for one recipient, under the context it was made for.
 *
 * @param encryptedMsg The envelope
 * @param recipientPrivKey Private key of the recipient
 * @param recipient The recipient id the envelope uses for that key
 * @param context What the envelope belongs to
 * @param plaintext The text
 * @param error Why it failed
 * @param failure Why it failed, for the caller to tell a message that is not
 *                for it from one that is for it and is not authentic
 */
bool ECIESDecryptFor(const CECIESEncryptedMessage& encryptedMsg,
                     const CKey& recipientPrivKey,
                     const DepinRecipient& recipient,
                     const uint256& context,
                     std::string& plaintext,
                     std::string& error,
                     DepinOpenFailure* failure = nullptr);

/** The same, for the recipient at an address that the key must belong to */
bool ECIESDecryptMessage(const CECIESEncryptedMessage& encryptedMsg,
                         const CKey& recipientPrivKey,
                         const std::string& recipientAddress,
                         const uint256& context,
                         std::string& plaintext,
                         std::string& error,
                         DepinOpenFailure* failure = nullptr);

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

#endif // NEURAI_DEPINECIES_H
