// Copyright (c) 2024 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "depinecies.h"
#include "random.h"
#include "utilstrencodings.h"
#include "test/test_neurai.h"
#include "key.h"
#include "pubkey.h"
#include "base58.h"

#include <boost/test/unit_test.hpp>
#include <string>
#include <vector>
#include <set>

BOOST_FIXTURE_TEST_SUITE(depinecies_tests, BasicTestingSetup)

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

    std::vector<unsigned char> expected_tag = ParseHex(
        "76fc6ece0f4e1768cddf8853bb2d551b");

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

BOOST_AUTO_TEST_SUITE_END()
