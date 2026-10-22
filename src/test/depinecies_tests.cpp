// Copyright (c) 2024 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "depinecies.h"
#include "streams.h"
#include "version.h"
#include "random.h"
#include "utilstrencodings.h"
#include "test/test_neurai.h"
#include "key.h"
#include "pubkey.h"
#include "base58.h"
#include "script/standard.h"
#include "depinchallenge.h"
#include "keystore.h"

#include <boost/test/unit_test.hpp>
#include <string>
#include <vector>
#include <set>

struct DepinECIESSetup : BasicTestingSetup { DepinECIESSetup() : BasicTestingSetup(CBaseChainParams::REGTEST) {} };
BOOST_FIXTURE_TEST_SUITE(depinecies_tests, DepinECIESSetup)

// Test 1: AES-256-GCM basic encryption/decryption
BOOST_AUTO_TEST_CASE(aes256_gcm_basic_test)
{
    // Test data
    std::string plaintext_str = "Hello, DePIN World!";
    std::vector<unsigned char> plaintext(plaintext_str.begin(), plaintext_str.end());

    // Generate random key and nonce
    std::vector<unsigned char> key(32);
    std::vector<unsigned char> nonce(12);
    GetStrongRandBytes(key.data(), 32);
    GetStrongRandBytes(nonce.data(), 12);

    // Encrypt
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> tag;
    BOOST_CHECK(AES256_GCM_Encrypt(plaintext, key, nonce, ciphertext, tag));

    // Verify ciphertext size equals plaintext (no padding in GCM)
    BOOST_CHECK_EQUAL(ciphertext.size(), plaintext.size());

    // Verify tag size is 16 bytes
    BOOST_CHECK_EQUAL(tag.size(), 16);

    // Verify ciphertext is different from plaintext
    BOOST_CHECK(ciphertext != plaintext);

    // Decrypt
    std::vector<unsigned char> decrypted;
    BOOST_CHECK(AES256_GCM_Decrypt(ciphertext, key, nonce, tag, decrypted));

    // Verify decrypted matches original
    BOOST_CHECK(decrypted == plaintext);
}

// Test 2: NIST test vector for AES-256-GCM
// From NIST SP 800-38D, Appendix B
BOOST_AUTO_TEST_CASE(aes256_gcm_nist_vector_test)
{
    // NIST Test Case 13: GCM-AES-256, 128 bit tag
    // Key: 32 bytes of zeros
    std::vector<unsigned char> key = ParseHex(
        "0000000000000000000000000000000000000000000000000000000000000000");

    // IV: 12 bytes of zeros
    std::vector<unsigned char> nonce = ParseHex("000000000000000000000000");

    // Plaintext: 16 bytes of zeros
    std::vector<unsigned char> plaintext = ParseHex("00000000000000000000000000000000");

    // Expected ciphertext
    std::vector<unsigned char> expected_ciphertext = ParseHex(
        "cea7403d4d606b6e074ec5d3baf39d18");

    // Expected tag
    std::vector<unsigned char> expected_tag = ParseHex(
        "d0d1c8a799996bf0265b98b5d48ab919");

    // Encrypt
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> tag;
    BOOST_CHECK(AES256_GCM_Encrypt(plaintext, key, nonce, ciphertext, tag));

    // Verify ciphertext matches NIST expected value
    BOOST_CHECK(ciphertext == expected_ciphertext);

    // Verify tag matches NIST expected value
    BOOST_CHECK(tag == expected_tag);

    // Decrypt and verify
    std::vector<unsigned char> decrypted;
    BOOST_CHECK(AES256_GCM_Decrypt(ciphertext, key, nonce, tag, decrypted));
    BOOST_CHECK(decrypted == plaintext);
}

// Test 3: NIST test vector with non-zero values
BOOST_AUTO_TEST_CASE(aes256_gcm_nist_vector_nonzero_test)
{
    // NIST Test Case 14: GCM-AES-256
    std::vector<unsigned char> key = ParseHex(
        "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");

    std::vector<unsigned char> nonce = ParseHex("cafebabefacedbaddecaf888");

    std::vector<unsigned char> plaintext = ParseHex(
        "d9313225f88406e5a55909c5aff5269a"
        "86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b39");

    // Expected outputs (from NIST)
    std::vector<unsigned char> expected_ciphertext = ParseHex(
        "522dc1f099567d07f47f37a32a84427d"
        "643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838"
        "c5f61e6393ba7a0abcc9f662");

    // Tag computed for the exact plaintext above (which is the NIST Test Case 14
    // input truncated to 60 bytes — the original NIST vector's 64-byte plaintext
    // and its associated tag do not apply here).
    std::vector<unsigned char> expected_tag = ParseHex(
        "eb9f796c8d356fc31a8433884b696f4f");

    // Encrypt
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> tag;
    BOOST_CHECK(AES256_GCM_Encrypt(plaintext, key, nonce, ciphertext, tag));

    BOOST_CHECK(ciphertext == expected_ciphertext);
    BOOST_CHECK(tag == expected_tag);

    // Decrypt
    std::vector<unsigned char> decrypted;
    BOOST_CHECK(AES256_GCM_Decrypt(ciphertext, key, nonce, tag, decrypted));
    BOOST_CHECK(decrypted == plaintext);
}

// Test 4: Authentication tag verification (tamper detection)
BOOST_AUTO_TEST_CASE(aes256_gcm_auth_tag_test)
{
    std::vector<unsigned char> plaintext = ParseHex("48656c6c6f20576f726c64"); // "Hello World"
    std::vector<unsigned char> key(32);
    std::vector<unsigned char> nonce(12);
    GetStrongRandBytes(key.data(), 32);
    GetStrongRandBytes(nonce.data(), 12);

    // Encrypt
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> tag;
    BOOST_CHECK(AES256_GCM_Encrypt(plaintext, key, nonce, ciphertext, tag));

    // Test 1: Valid tag should decrypt successfully
    std::vector<unsigned char> decrypted;
    BOOST_CHECK(AES256_GCM_Decrypt(ciphertext, key, nonce, tag, decrypted));
    BOOST_CHECK(decrypted == plaintext);

    // Test 2: Modified ciphertext should fail authentication
    std::vector<unsigned char> tampered_ciphertext = ciphertext;
    if (!tampered_ciphertext.empty()) {
        tampered_ciphertext[0] ^= 0x01; // Flip one bit
    }
    std::vector<unsigned char> decrypted2;
    BOOST_CHECK(!AES256_GCM_Decrypt(tampered_ciphertext, key, nonce, tag, decrypted2));

    // Test 3: Modified tag should fail authentication
    std::vector<unsigned char> tampered_tag = tag;
    tampered_tag[0] ^= 0x01; // Flip one bit
    std::vector<unsigned char> decrypted3;
    BOOST_CHECK(!AES256_GCM_Decrypt(ciphertext, key, nonce, tampered_tag, decrypted3));

    // Test 4: Wrong key should fail
    std::vector<unsigned char> wrong_key(32);
    GetStrongRandBytes(wrong_key.data(), 32);
    std::vector<unsigned char> decrypted4;
    BOOST_CHECK(!AES256_GCM_Decrypt(ciphertext, wrong_key, nonce, tag, decrypted4));
}

// Test 5: Empty plaintext handling
BOOST_AUTO_TEST_CASE(aes256_gcm_empty_plaintext_test)
{
    std::vector<unsigned char> plaintext; // Empty
    std::vector<unsigned char> key(32);
    std::vector<unsigned char> nonce(12);
    GetStrongRandBytes(key.data(), 32);
    GetStrongRandBytes(nonce.data(), 12);

    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> tag;

    // Empty plaintext should fail
    BOOST_CHECK(!AES256_GCM_Encrypt(plaintext, key, nonce, ciphertext, tag));
}

// Test 6: Invalid parameter sizes
BOOST_AUTO_TEST_CASE(aes256_gcm_invalid_params_test)
{
    std::vector<unsigned char> plaintext = ParseHex("48656c6c6f");
    std::vector<unsigned char> key(32);
    std::vector<unsigned char> nonce(12);
    GetStrongRandBytes(key.data(), 32);
    GetStrongRandBytes(nonce.data(), 12);

    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> tag;

    // Test invalid key size (16 instead of 32)
    std::vector<unsigned char> short_key(16);
    BOOST_CHECK(!AES256_GCM_Encrypt(plaintext, short_key, nonce, ciphertext, tag));

    // Test invalid nonce size (16 instead of 12)
    std::vector<unsigned char> long_nonce(16);
    GetStrongRandBytes(long_nonce.data(), 16);
    BOOST_CHECK(!AES256_GCM_Encrypt(plaintext, key, long_nonce, ciphertext, tag));

    // Encrypt valid data first
    BOOST_CHECK(AES256_GCM_Encrypt(plaintext, key, nonce, ciphertext, tag));

    // Test invalid tag size during decryption
    std::vector<unsigned char> short_tag(8);
    std::vector<unsigned char> decrypted;
    BOOST_CHECK(!AES256_GCM_Decrypt(ciphertext, key, nonce, short_tag, decrypted));
}

// Test 7: Large message encryption
BOOST_AUTO_TEST_CASE(aes256_gcm_large_message_test)
{
    // Create 10KB message
    std::vector<unsigned char> plaintext(10240);
    for (size_t i = 0; i < plaintext.size(); i++) {
        plaintext[i] = (unsigned char)(i % 256);
    }

    std::vector<unsigned char> key(32);
    std::vector<unsigned char> nonce(12);
    GetStrongRandBytes(key.data(), 32);
    GetStrongRandBytes(nonce.data(), 12);

    // Encrypt
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> tag;
    BOOST_CHECK(AES256_GCM_Encrypt(plaintext, key, nonce, ciphertext, tag));

    // GCM: ciphertext size = plaintext size (no padding)
    BOOST_CHECK_EQUAL(ciphertext.size(), plaintext.size());

    // Decrypt
    std::vector<unsigned char> decrypted;
    BOOST_CHECK(AES256_GCM_Decrypt(ciphertext, key, nonce, tag, decrypted));
    BOOST_CHECK(decrypted == plaintext);
}

// Test 8: Nonce uniqueness (statistical test)
BOOST_AUTO_TEST_CASE(aes256_gcm_nonce_uniqueness_test)
{
    std::set<std::vector<unsigned char>> nonces;
    const int NUM_NONCES = 1000;

    for (int i = 0; i < NUM_NONCES; i++) {
        std::vector<unsigned char> nonce(12);
        GetStrongRandBytes(nonce.data(), 12);

        // Check for collision
        BOOST_CHECK(nonces.find(nonce) == nonces.end());
        nonces.insert(nonce);
    }

    // Verify all nonces are unique
    BOOST_CHECK_EQUAL(nonces.size(), NUM_NONCES);
}

// Test 9: ECIES end-to-end with GCM (single recipient)
BOOST_AUTO_TEST_CASE(ecies_gcm_basic_test)
{
    // Create recipient keys
    CKey recipientPrivKey;
    recipientPrivKey.MakeNewKey(true);
    CPubKey recipientPubKey = recipientPrivKey.GetPubKey();

    // Create a valid Neurai address from the public key
    CKeyID keyID = recipientPubKey.GetID();
    std::string recipientAddress = EncodeDestination(keyID);

    std::map<std::string, CPubKey> recipients;
    recipients[recipientAddress] = recipientPubKey;

    // Encrypt message
    std::string plaintext = "Secret DePIN message!";
    CECIESEncryptedMessage encryptedMsg;
    std::string error;

    BOOST_CHECK(ECIESEncryptMessage(plaintext, recipients, encryptedMsg, error));

    // Verify structure
    BOOST_CHECK(encryptedMsg.ephemeralPubKey.IsValid());
    BOOST_CHECK(!encryptedMsg.encryptedPayload.empty());
    BOOST_CHECK_EQUAL(encryptedMsg.recipientKeys.size(), 1);

    // Verify payload size (nonce 12 + ciphertext + tag 16)
    BOOST_CHECK(encryptedMsg.encryptedPayload.size() >= 28);

    // Decrypt message
    std::string decrypted;
    BOOST_CHECK(ECIESDecryptMessage(encryptedMsg, recipientPrivKey, recipientAddress, decrypted, error));

    // Verify decrypted matches original
    BOOST_CHECK_EQUAL(decrypted, plaintext);
}

// Test 10: ECIES with multiple recipients
BOOST_AUTO_TEST_CASE(ecies_gcm_multiple_recipients_test)
{
    // Create 5 recipients
    std::map<std::string, CPubKey> recipients;
    std::vector<CKey> recipientPrivKeys;
    std::vector<std::string> recipientAddresses;

    for (int i = 0; i < 5; i++) {
        CKey privKey;
        privKey.MakeNewKey(true);
        CPubKey pubKey = privKey.GetPubKey();

        CKeyID keyID = pubKey.GetID();
        std::string address = EncodeDestination(keyID);

        recipients[address] = pubKey;
        recipientPrivKeys.push_back(privKey);
        recipientAddresses.push_back(address);
    }

    // Encrypt message
    std::string plaintext = "Message for all 5 recipients!";
    CECIESEncryptedMessage encryptedMsg;
    std::string error;

    BOOST_CHECK(ECIESEncryptMessage(plaintext, recipients, encryptedMsg, error));
    BOOST_CHECK_EQUAL(encryptedMsg.recipientKeys.size(), 5);

    // Each recipient should be able to decrypt
    for (size_t i = 0; i < recipientPrivKeys.size(); i++) {
        std::string decrypted;
        BOOST_CHECK(ECIESDecryptMessage(encryptedMsg, recipientPrivKeys[i],
                                        recipientAddresses[i], decrypted, error));
        BOOST_CHECK_EQUAL(decrypted, plaintext);
    }
}

// Test 11: ECIES wrong recipient cannot decrypt
BOOST_AUTO_TEST_CASE(ecies_gcm_wrong_recipient_test)
{
    // Encrypt for recipient 1
    CKey recipient1PrivKey;
    recipient1PrivKey.MakeNewKey(true);
    CPubKey recipient1PubKey = recipient1PrivKey.GetPubKey();

    CKeyID keyID1 = recipient1PubKey.GetID();
    std::string recipient1Address = EncodeDestination(keyID1);

    std::map<std::string, CPubKey> recipients;
    recipients[recipient1Address] = recipient1PubKey;

    std::string plaintext = "Secret message";
    CECIESEncryptedMessage encryptedMsg;
    std::string error;

    BOOST_CHECK(ECIESEncryptMessage(plaintext, recipients, encryptedMsg, error));

    // Try to decrypt with recipient 2's key (not in recipients list)
    CKey recipient2PrivKey;
    recipient2PrivKey.MakeNewKey(true);

    CKeyID keyID2 = recipient2PrivKey.GetPubKey().GetID();
    std::string recipient2Address = EncodeDestination(keyID2);

    std::string decrypted;
    BOOST_CHECK(!ECIESDecryptMessage(encryptedMsg, recipient2PrivKey,
                                     recipient2Address, decrypted, error));
    BOOST_CHECK(!error.empty());
}

BOOST_AUTO_TEST_CASE(strict_wire_decoder_bounds_and_canonical_form)
{
    CKey key;
    key.MakeNewKey(true);
    const auto pubkey = key.GetPubKey();
    const std::string address = EncodeDestination(pubkey.GetID());
    std::string error;
    CECIESEncryptedMessage valid, decoded;
    BOOST_REQUIRE(ECIESEncryptMessage("hello", {{address, pubkey}}, valid, error));
    auto wire = [](const CECIESEncryptedMessage& value) {
        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << value;
        return std::vector<unsigned char>(stream.begin(), stream.end());
    };
    const auto bytes = wire(valid);
    const DepinRecipient id(pubkey.GetID());
    BOOST_REQUIRE(DecodeDepinECIES(bytes, 5, 1, decoded, error, &id));
    BOOST_CHECK(!DecodeDepinECIES(bytes, 4, 1, decoded, error));
    for (size_t length = 0; length < bytes.size(); ++length) {
        BOOST_CHECK(!DecodeDepinECIES(std::vector<unsigned char>(bytes.begin(), bytes.begin() + length),
                                      5, 1, decoded, error));
    }
    auto changed = bytes;
    changed.push_back(0);
    BOOST_CHECK(!DecodeDepinECIES(changed, 5, 1, decoded, error));
    CDataStream duplicate(SER_NETWORK, PROTOCOL_VERSION);
    duplicate << valid.ephemeralPubKey << valid.encryptedPayload;
    WriteCompactSize(duplicate, 2);
    duplicate << id.LegacyID() << valid.recipientKeys.at(id) << id.LegacyID() << valid.recipientKeys.at(id);
    BOOST_CHECK(!DecodeDepinECIES(std::vector<unsigned char>(duplicate.begin(), duplicate.end()), 5, 2, decoded, error));
    // A declared huge payload cannot trigger a huge vector allocation.
    CDataStream oversized(SER_NETWORK, PROTOCOL_VERSION);
    oversized << valid.ephemeralPubKey;
    WriteCompactSize(oversized, uint64_t(32) * 1024 * 1024);
    BOOST_CHECK(!DecodeDepinECIES(std::vector<unsigned char>(oversized.begin(), oversized.end()), 5, 1, decoded, error));
    CECIESEncryptedMessage malformed = valid;
    malformed.recipientKeys[id].resize(59);
    BOOST_CHECK(!DecodeDepinECIES(wire(malformed), 5, 1, decoded, error));
    malformed = valid;
    malformed.recipientKeys.clear();
    BOOST_CHECK(!DecodeDepinECIES(wire(malformed), 5, 1, decoded, error));
    malformed = valid;
    malformed.encryptedPayload.resize(28);
    BOOST_CHECK(!DecodeDepinECIES(wire(malformed), 5, 1, decoded, error));
    malformed = valid;
    std::vector<unsigned char> invalidKey(33, 0xff);
    invalidKey[0] = 2; // compressed, but x is outside the field
    malformed.ephemeralPubKey = CPubKey(invalidKey.begin(), invalidKey.end());
    BOOST_CHECK(!DecodeDepinECIES(wire(malformed), 5, 1, decoded, error));
    changed = bytes;
    changed.erase(changed.begin());
    changed.insert(changed.begin(), {253, 33, 0}); // nonminimal CompactSize
    BOOST_CHECK(!DecodeDepinECIES(changed, 5, 1, decoded, error));
    CKey other;
    other.MakeNewKey(true);
    const DepinRecipient otherId(other.GetPubKey().GetID());
    malformed = valid;
    malformed.recipientKeys[otherId] = valid.recipientKeys.at(id);
    BOOST_REQUIRE(DecodeDepinECIES(wire(malformed), 5, 2, decoded, error));
    BOOST_CHECK(!DecodeDepinECIES(wire(malformed), 5, 1, decoded, error));
    CDataStream unordered(SER_NETWORK, PROTOCOL_VERSION);
    unordered << valid.ephemeralPubKey << valid.encryptedPayload;
    WriteCompactSize(unordered, 2);
    for (auto it = malformed.recipientKeys.rbegin(); it != malformed.recipientKeys.rend(); ++it)
        unordered << it->first.LegacyID() << it->second;
    BOOST_CHECK(!DecodeDepinECIES(std::vector<unsigned char>(unordered.begin(), unordered.end()), 5, 2, decoded, error));
    BOOST_CHECK(!DecodeDepinECIES(bytes, 5, 1, decoded, error, &otherId));
    // Structurally sound authentication corruption remains the recipient's check.
    malformed = valid;
    malformed.encryptedPayload.back() ^= 1;
    BOOST_REQUIRE(DecodeDepinECIES(wire(malformed), 5, 1, decoded, error));
    std::string plaintext;
    BOOST_CHECK(!ECIESDecryptMessage(decoded, key, address, plaintext, error));
    for (unsigned int n = 0; n < 256; ++n) {
        std::vector<unsigned char> noise(n, static_cast<unsigned char>(n));
        BOOST_CHECK(!DecodeDepinECIES(noise, 1024, 50, decoded, error));
    }
}


BOOST_AUTO_TEST_CASE(strict_ecdsa_identity_and_wallet_key_resolution)
{
    CKey key, other; key.MakeNewKey(true); other.MakeNewKey(true);
    WitnessStrictAuthScript strict;
    BOOST_REQUIRE(GetStrictAuthScriptDestinationForPubKey(key.GetPubKey(), strict));
    const auto legacy = EncodeDestination(key.GetPubKey().GetID());
    const auto address = EncodeDestination(strict);
    DepinRecipient a, b;
    BOOST_REQUIRE(DepinRecipient::FromAddress(legacy, a));
    BOOST_REQUIRE(DepinRecipient::FromAddress(address, b));
    BOOST_CHECK(!(a == b));
    BOOST_CHECK_EQUAL(a.Address(), legacy);
    BOOST_CHECK_EQUAL(b.Address(), address);
    BOOST_CHECK(DepinPubKeyMatchesAddress(address, key.GetPubKey()));
    BOOST_CHECK(!DepinPubKeyMatchesAddress(address, other.GetPubKey()));
    BOOST_CHECK(!DepinRecipient::FromAddress(EncodeDestination(CScriptID(uint160())), a));
    BOOST_CHECK(!DepinRecipient::FromAddress(EncodeDestination(WitnessV1AuthScript(uint256())), a));
    BOOST_CHECK(!DepinRecipient::FromAddress(EncodeDestination(WitnessStrictAuthScript(STRICT_AUTHSCRIPT_WITNESS_V2_PQ, uint256())), a));
    std::string upper = address; std::transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
    BOOST_CHECK(!DepinRecipient::FromAddress(upper, a));

    std::string signature, error;
    BOOST_REQUIRE(SignDepinChallengePreimage(key, "a complete request", signature, error, address));
    BOOST_CHECK(VerifyDepinChallengeSignature(address, signature, "a complete request", error));
    BOOST_CHECK(!VerifyDepinChallengeSignature(address, signature, "a changed request", error));
    BOOST_CHECK(!VerifyDepinChallengeSignature(legacy, signature, "a complete request", error));
    BOOST_REQUIRE(SignDepinChallengePreimage(key, "a complete request", signature, error));
    BOOST_CHECK(!VerifyDepinChallengeSignature(address, signature, "a complete request", error));
    CBasicKeyStore store; CKeyID id;
    BOOST_REQUIRE(store.AddKeyPubKey(key, key.GetPubKey()));
    BOOST_CHECK(!GetDepinKeyID(store, address, id));
    AuthScriptSpendData spend; spend.key_id = key.GetPubKey().GetID();
    const CScript witnessScript = GetStrictAuthScriptTemplate();
    spend.witnessScript = witnessScript;
    BOOST_REQUIRE(store.AddAuthScriptSpendData(strict.version, strict.commitment, spend));
    BOOST_REQUIRE(GetDepinKeyID(store, address, id));
    BOOST_CHECK(id == key.GetPubKey().GetID());
    spend.key_id = other.GetPubKey().GetID();
    BOOST_REQUIRE(store.AddKeyPubKey(other, other.GetPubKey()));
    BOOST_REQUIRE(store.AddAuthScriptSpendData(strict.version, strict.commitment, spend));
    BOOST_CHECK(!GetDepinKeyID(store, address, id));
}

BOOST_AUTO_TEST_CASE(mixed_ecdsa_ecies_preserves_exact_destinations_and_legacy_bytes)
{
    CKey key; key.MakeNewKey(true);
    WitnessStrictAuthScript strict;
    BOOST_REQUIRE(GetStrictAuthScriptDestinationForPubKey(key.GetPubKey(), strict));
    const auto legacy = EncodeDestination(key.GetPubKey().GetID()), address = EncodeDestination(strict);
    DepinRecipient id; BOOST_REQUIRE(DepinRecipient::FromAddress(address, id));
    CECIESEncryptedMessage message, decoded; std::string error, plain;
    BOOST_REQUIRE(ECIESEncryptMessage("hello", {{legacy, key.GetPubKey()}}, message, error));
    CDataStream v1(SER_NETWORK, PROTOCOL_VERSION); v1 << message;
    CDataStream original(SER_NETWORK, PROTOCOL_VERSION);
    original << message.ephemeralPubKey << message.encryptedPayload;
    WriteCompactSize(original, 1); original << key.GetPubKey().GetID() << message.recipientKeys.begin()->second;
    BOOST_CHECK(std::vector<unsigned char>(v1.begin(), v1.end()) == std::vector<unsigned char>(original.begin(), original.end()));
    BOOST_CHECK(!ECIESDecryptMessage(message, key, address, plain, error));
    BOOST_REQUIRE(ECIESEncryptMessage("hello", {{address, key.GetPubKey()}, {legacy, key.GetPubKey()}}, message, error));
    BOOST_REQUIRE_EQUAL(message.recipientKeys.size(), 2U);
    CDataStream v2(SER_NETWORK, PROTOCOL_VERSION); v2 << message;
    const std::vector<unsigned char> bytes(v2.begin(), v2.end());
    BOOST_CHECK_EQUAL(bytes[0], 0); BOOST_CHECK_EQUAL(bytes[1], 2);
    BOOST_REQUIRE(DecodeDepinECIES(bytes, 5, 2, decoded, error, &id));
    for (const auto& recipient : {legacy, address}) {
        BOOST_REQUIRE(ECIESDecryptMessage(decoded, key, recipient, plain, error));
        BOOST_CHECK_EQUAL(plain, "hello");
    }
    CDataStream stream(bytes, SER_NETWORK, PROTOCOL_VERSION); CECIESEncryptedMessage direct; stream >> direct;
    BOOST_CHECK(direct.recipientKeys == decoded.recipientKeys);
    BOOST_CHECK(!DecodeDepinECIES(bytes, 5, 1, decoded, error));
    for (size_t n = 0; n < bytes.size(); ++n)
        BOOST_CHECK(!DecodeDepinECIES({bytes.begin(), bytes.begin() + n}, 5, 2, decoded, error));
    auto bad = bytes; bad[1] = 3;
    BOOST_CHECK(!DecodeDepinECIES(bad, 5, 2, decoded, error));
    bad = bytes; bad.push_back(0);
    BOOST_CHECK(!DecodeDepinECIES(bad, 5, 2, decoded, error));
    CDataStream unordered(SER_NETWORK, PROTOCOL_VERSION);
    unordered << uint8_t(0) << uint8_t(2) << message.ephemeralPubKey << message.encryptedPayload;
    WriteCompactSize(unordered, 2);
    for (auto it = message.recipientKeys.rbegin(); it != message.recipientKeys.rend(); ++it) unordered << it->first << it->second;
    BOOST_CHECK(!DecodeDepinECIES({unordered.begin(), unordered.end()}, 5, 2, decoded, error));
    CDataStream duplicate(SER_NETWORK, PROTOCOL_VERSION);
    duplicate << uint8_t(0) << uint8_t(2) << message.ephemeralPubKey << message.encryptedPayload;
    WriteCompactSize(duplicate, 2);
    duplicate << id << message.recipientKeys.at(id) << id << message.recipientKeys.at(id);
    BOOST_CHECK(!DecodeDepinECIES({duplicate.begin(), duplicate.end()}, 5, 2, decoded, error));
    CDataStream invalid(SER_NETWORK, PROTOCOL_VERSION);
    invalid << uint8_t(0) << uint8_t(2) << message.ephemeralPubKey << message.encryptedPayload;
    WriteCompactSize(invalid, 1); invalid << uint8_t(2); // unsupported destination tag
    BOOST_CHECK(!DecodeDepinECIES({invalid.begin(), invalid.end()}, 5, 2, decoded, error));
    CDataStream noncanonical(SER_NETWORK, PROTOCOL_VERSION);
    noncanonical << uint8_t(0) << uint8_t(2) << message.ephemeralPubKey << message.encryptedPayload;
    WriteCompactSize(noncanonical, 1); noncanonical << DepinRecipient(key.GetPubKey().GetID()) << message.recipientKeys.begin()->second;
    BOOST_CHECK(!DecodeDepinECIES({noncanonical.begin(), noncanonical.end()}, 5, 2, decoded, error));
    CKey wrong; wrong.MakeNewKey(true);
    BOOST_CHECK(!ECIESEncryptMessage("hello", {{address, wrong.GetPubKey()}}, message, error));
    BOOST_CHECK(message.recipientKeys.empty());
}


BOOST_AUTO_TEST_CASE(strict_ecdsa_recipient_and_plaintext_limits)
{
    std::map<std::string, CPubKey> recipients;
    for (size_t i = 0; i < 51; ++i) {
        CKey key; key.MakeNewKey(true);
        WitnessStrictAuthScript strict;
        BOOST_REQUIRE(GetStrictAuthScriptDestinationForPubKey(key.GetPubKey(), strict));
        recipients.emplace(EncodeDestination(strict), key.GetPubKey());
    }
    CECIESEncryptedMessage message, decoded; std::string error;
    const std::string plain(10240, 'x');
    BOOST_REQUIRE(ECIESEncryptMessage(plain, recipients, message, error));
    CDataStream tooMany(SER_NETWORK, PROTOCOL_VERSION); tooMany << message;
    BOOST_CHECK(!DecodeDepinECIES({tooMany.begin(), tooMany.end()}, plain.size(), 50, decoded, error));
    message.recipientKeys.erase(message.recipientKeys.begin());
    CDataStream allowed(SER_NETWORK, PROTOCOL_VERSION); allowed << message;
    const std::vector<unsigned char> bytes(allowed.begin(), allowed.end());
    BOOST_CHECK(bytes.size() <= DepinECIESWireLimit(plain.size(), 50));
    BOOST_REQUIRE(DecodeDepinECIES(bytes, plain.size(), 50, decoded, error));
    BOOST_CHECK(!DecodeDepinECIES(bytes, plain.size() - 1, 50, decoded, error));
    BOOST_CHECK(!DecodeDepinECIES(bytes, plain.size(), 49, decoded, error));
}

BOOST_AUTO_TEST_SUITE_END()
