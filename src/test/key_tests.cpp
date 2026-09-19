// Copyright (c) 2012-2015 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key.h"

#include "base58.h"
#include "crypto/sha256.h"
#include "script/script.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
#include "test/test_neurai.h"

#include <atomic>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <boost/test/unit_test.hpp>
#include <oqs/oqs.h>

namespace {
std::atomic<unsigned int> pq_rng_calls{0};

void ProbePQRng(uint8_t* out, size_t len)
{
    ++pq_rng_calls;
    std::memset(out, 0xa5, len);
}

struct ScopedPQRngProbe {
    ScopedPQRngProbe() { pq_rng_calls = 0; OQS_randombytes_custom_algorithm(ProbePQRng); }
    ~ScopedPQRngProbe() { OQS_randombytes_switch_algorithm(OQS_RAND_alg_system); }
};
} // namespace

static const std::string strSecret1 = "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj";
static const std::string strSecret2 = "5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3";
static const std::string strSecret1C = "Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw";
static const std::string strSecret2C = "L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g";

// A Bitcoin mainnet address, intentionally invalid for Neurai
static const std::string strAddressBad = "1HV9Lc3sNHZxwj4Zk6fB38tEmBryq2cBiF";


BOOST_FIXTURE_TEST_SUITE(key_tests, BasicTestingSetup)

    BOOST_AUTO_TEST_CASE(key_test)
    {
        BOOST_TEST_MESSAGE("Running Key Test");

        CNeuraiSecret bsecret1, bsecret2, bsecret1C, bsecret2C, baddress1;
        BOOST_CHECK(bsecret1.SetString(strSecret1));
        BOOST_CHECK(bsecret2.SetString(strSecret2));
        BOOST_CHECK(bsecret1C.SetString(strSecret1C));
        BOOST_CHECK(bsecret2C.SetString(strSecret2C));
        BOOST_CHECK(!baddress1.SetString(strAddressBad));

        CKey key1 = bsecret1.GetKey();
        BOOST_CHECK(key1.IsCompressed() == false);
        CKey key2 = bsecret2.GetKey();
        BOOST_CHECK(key2.IsCompressed() == false);
        CKey key1C = bsecret1C.GetKey();
        BOOST_CHECK(key1C.IsCompressed() == true);
        CKey key2C = bsecret2C.GetKey();
        BOOST_CHECK(key2C.IsCompressed() == true);

        CPubKey pubkey1 = key1.GetPubKey();
        CPubKey pubkey2 = key2.GetPubKey();
        CPubKey pubkey1C = key1C.GetPubKey();
        CPubKey pubkey2C = key2C.GetPubKey();

        BOOST_CHECK(key1.VerifyPubKey(pubkey1));
        BOOST_CHECK(!key1.VerifyPubKey(pubkey1C));
        BOOST_CHECK(!key1.VerifyPubKey(pubkey2));
        BOOST_CHECK(!key1.VerifyPubKey(pubkey2C));

        BOOST_CHECK(!key1C.VerifyPubKey(pubkey1));
        BOOST_CHECK(key1C.VerifyPubKey(pubkey1C));
        BOOST_CHECK(!key1C.VerifyPubKey(pubkey2));
        BOOST_CHECK(!key1C.VerifyPubKey(pubkey2C));

        BOOST_CHECK(!key2.VerifyPubKey(pubkey1));
        BOOST_CHECK(!key2.VerifyPubKey(pubkey1C));
        BOOST_CHECK(key2.VerifyPubKey(pubkey2));
        BOOST_CHECK(!key2.VerifyPubKey(pubkey2C));

        BOOST_CHECK(!key2C.VerifyPubKey(pubkey1));
        BOOST_CHECK(!key2C.VerifyPubKey(pubkey1C));
        BOOST_CHECK(!key2C.VerifyPubKey(pubkey2));
        BOOST_CHECK(key2C.VerifyPubKey(pubkey2C));

        // Derive addresses from pubkeys and verify round-trip encoding
        std::string addr1 = EncodeDestination(CTxDestination(pubkey1.GetID()));
        std::string addr2 = EncodeDestination(CTxDestination(pubkey2.GetID()));
        std::string addr1C = EncodeDestination(CTxDestination(pubkey1C.GetID()));
        std::string addr2C = EncodeDestination(CTxDestination(pubkey2C.GetID()));

        BOOST_CHECK(DecodeDestination(addr1) == CTxDestination(pubkey1.GetID()));
        BOOST_CHECK(DecodeDestination(addr2) == CTxDestination(pubkey2.GetID()));
        BOOST_CHECK(DecodeDestination(addr1C) == CTxDestination(pubkey1C.GetID()));
        BOOST_CHECK(DecodeDestination(addr2C) == CTxDestination(pubkey2C.GetID()));

        // Compressed and uncompressed keys produce different addresses
        BOOST_CHECK(addr1 != addr1C);
        BOOST_CHECK(addr2 != addr2C);

        for (int n = 0; n < 16; n++)
        {
            std::string strMsg = strprintf("Very secret message %i: 11", n);
            uint256 hashMsg = Hash(strMsg.begin(), strMsg.end());

            // normal signatures

            std::vector<unsigned char> sign1, sign2, sign1C, sign2C;

            BOOST_CHECK(key1.Sign(hashMsg, sign1));
            BOOST_CHECK(key2.Sign(hashMsg, sign2));
            BOOST_CHECK(key1C.Sign(hashMsg, sign1C));
            BOOST_CHECK(key2C.Sign(hashMsg, sign2C));

            BOOST_CHECK(pubkey1.Verify(hashMsg, sign1));
            BOOST_CHECK(!pubkey1.Verify(hashMsg, sign2));
            BOOST_CHECK(pubkey1.Verify(hashMsg, sign1C));
            BOOST_CHECK(!pubkey1.Verify(hashMsg, sign2C));

            BOOST_CHECK(!pubkey2.Verify(hashMsg, sign1));
            BOOST_CHECK(pubkey2.Verify(hashMsg, sign2));
            BOOST_CHECK(!pubkey2.Verify(hashMsg, sign1C));
            BOOST_CHECK(pubkey2.Verify(hashMsg, sign2C));

            BOOST_CHECK(pubkey1C.Verify(hashMsg, sign1));
            BOOST_CHECK(!pubkey1C.Verify(hashMsg, sign2));
            BOOST_CHECK(pubkey1C.Verify(hashMsg, sign1C));
            BOOST_CHECK(!pubkey1C.Verify(hashMsg, sign2C));

            BOOST_CHECK(!pubkey2C.Verify(hashMsg, sign1));
            BOOST_CHECK(pubkey2C.Verify(hashMsg, sign2));
            BOOST_CHECK(!pubkey2C.Verify(hashMsg, sign1C));
            BOOST_CHECK(pubkey2C.Verify(hashMsg, sign2C));

            // compact signatures (with key recovery)

            std::vector<unsigned char> csign1, csign2, csign1C, csign2C;

            BOOST_CHECK(key1.SignCompact(hashMsg, csign1));
            BOOST_CHECK(key2.SignCompact(hashMsg, csign2));
            BOOST_CHECK(key1C.SignCompact(hashMsg, csign1C));
            BOOST_CHECK(key2C.SignCompact(hashMsg, csign2C));

            CPubKey rkey1, rkey2, rkey1C, rkey2C;

            BOOST_CHECK(rkey1.RecoverCompact(hashMsg, csign1));
            BOOST_CHECK(rkey2.RecoverCompact(hashMsg, csign2));
            BOOST_CHECK(rkey1C.RecoverCompact(hashMsg, csign1C));
            BOOST_CHECK(rkey2C.RecoverCompact(hashMsg, csign2C));

            BOOST_CHECK(rkey1 == pubkey1);
            BOOST_CHECK(rkey2 == pubkey2);
            BOOST_CHECK(rkey1C == pubkey1C);
            BOOST_CHECK(rkey2C == pubkey2C);
        }

        // test deterministic signing

        std::vector<unsigned char> detsig, detsigc;
        std::string strMsg = "Very deterministic message";
        uint256 hashMsg = Hash(strMsg.begin(), strMsg.end());
        BOOST_CHECK(key1.Sign(hashMsg, detsig));
        BOOST_CHECK(key1C.Sign(hashMsg, detsigc));
        BOOST_CHECK(detsig == detsigc);
        BOOST_CHECK(detsig == ParseHex("304402205dbbddda71772d95ce91cd2d14b592cfbc1dd0aabd6a394b6c2d377bbe59d31d022014ddda21494a4e221f0824f0b8b924c43fa43c0ad57dccdaa11f81a6bd4582f6"));
        BOOST_CHECK(key2.Sign(hashMsg, detsig));
        BOOST_CHECK(key2C.Sign(hashMsg, detsigc));
        BOOST_CHECK(detsig == detsigc);
        BOOST_CHECK(detsig == ParseHex("3044022052d8a32079c11e79db95af63bb9600c5b04f21a9ca33dc129c2bfa8ac9dc1cd5022061d8ae5e0f6c1a16bde3719c64c2fd70e404b6428ab9a69566962e8771b5944d"));
        BOOST_CHECK(key1.SignCompact(hashMsg, detsig));
        BOOST_CHECK(key1C.SignCompact(hashMsg, detsigc));
        BOOST_CHECK(detsig == ParseHex("1c5dbbddda71772d95ce91cd2d14b592cfbc1dd0aabd6a394b6c2d377bbe59d31d14ddda21494a4e221f0824f0b8b924c43fa43c0ad57dccdaa11f81a6bd4582f6"));
        BOOST_CHECK(detsigc == ParseHex("205dbbddda71772d95ce91cd2d14b592cfbc1dd0aabd6a394b6c2d377bbe59d31d14ddda21494a4e221f0824f0b8b924c43fa43c0ad57dccdaa11f81a6bd4582f6"));
        BOOST_CHECK(key2.SignCompact(hashMsg, detsig));
        BOOST_CHECK(key2C.SignCompact(hashMsg, detsigc));
        BOOST_CHECK(detsig == ParseHex("1c52d8a32079c11e79db95af63bb9600c5b04f21a9ca33dc129c2bfa8ac9dc1cd561d8ae5e0f6c1a16bde3719c64c2fd70e404b6428ab9a69566962e8771b5944d"));
        BOOST_CHECK(detsigc == ParseHex("2052d8a32079c11e79db95af63bb9600c5b04f21a9ca33dc129c2bfa8ac9dc1cd561d8ae5e0f6c1a16bde3719c64c2fd70e404b6428ab9a69566962e8771b5944d"));
    }

    BOOST_AUTO_TEST_CASE(pq_keygen_matches_bip39_generator)
    {
        const std::vector<unsigned char> pqSeed = ParseHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        CKey pqKey1;
        CKey pqKey2;

        pqKey1.MakeNewKeyPQ(pqSeed);
        pqKey2.MakeNewKeyPQ(pqSeed);

        const CPubKey pubkey1 = pqKey1.GetPubKey();
        const CPubKey pubkey2 = pqKey2.GetPubKey();

        BOOST_CHECK(pubkey1.IsPQ());
        BOOST_CHECK(pubkey1 == pubkey2);
        BOOST_CHECK_EQUAL(HexStr(pubkey1.begin(), pubkey1.end()),
            "05d7b2b47254aae0db45e7930d4a98d2c97d8f1397d1789dafa17024b316e9bec94fc9946d42f19b79a7413bbaa33e7149cb42ed5115693ac041facb988adeb5fe0e1d8631184995b592c397d2294e2e14f90aa414ba3826899ac43f4cccacbc26e9a832b95118d5cb433cbef9660b00138e0817f61e762ca274c36ad554eb22aac1162e4ab01acba1e38c4efd8f80b65b333d0f72e55dfe71ce9c1ebb9889e7c56106c0fd73803a2aecfeafded7aa3cb2ceda54d12bd8cd36a78cf975943b47abd25e880ac452e5742ed1e8d1a82afa86e590c758c15ae4d2840d92bca1a5090f40496597fca7d8b9513f1a1bda6e950aaa98de467507d4a4f5a4f0599216582c3572f62eda8905ab3581670c4a02777a33e0ca7295fd8f4ff6d1a0a3a7683d65f5f5f7fc60da023e826c5f92144c02f7d1ba1075987553ea9367fcd76d990b7fa99cd45afdb8836d43e459f5187df058479709a01ea6835935fa70460990cd3dc1ba401ba94bab1dde41ac67ab3319dcaca06048d4c4eef27ee13a9c17d0538f430f2d642dc2415660de78877d8d8abc72523978c042e4285f4319846c44126242976844c10e556ba215b5a719e59d0c6b2a96d39859071fdcc2cde7524a7bedae54e85b318e854e8fe2b2f3edfac9719128270aafd1e5044c3a4fdafd9ff31f90784b8e8e4596144a0daf586511d3d9962b9ea95af197b4e5fc60f2b1ed15de3a5bef5f89bdc79d91051d9b2816e74fa54531efdc1cbe74d448857f476bcd58f21c0b653b3b76a4e076a6559a302718555cc63f74859aabab925f023861ca8cd0f7badb2871f67d55326d7451135ad45f4a1ba69118fbb2c8a30eec9392ef3f977066c9add5c710cc647b1514d217d958c7017c3e90fd20c04e674b90486e9370a31a001d32f473979e4906749e7e477fa0b74508f8a5f2378312b83c25bd388ca0b0fff7478baf42b71667edaac97c46b129643e586e5b055a0c211946d4f36e675bed5860fa042a315d9826164d6a9237c35a5fbf495490a5bd4df248b95c4aae7784b605673166ac4245b5b4b082a09e9323e62f2078c5b76783446defd736ad3a3702d49b089844900a61833397bc4419b30d7a97a0b387c1911474c4d41b53e32a977acb6f0ea75db65bb39e59e701e76957def6f2d44559c31a77122b5204e3b5c219f1688b14ed0bc0b801b3e6e82dcd43e9c0e9f41744cd9815bd1bc8820d8bb123f04facd1b1b685dd5a2b1b8dbbf3ed933670f095a180b4f192d08b10b8fabbdfcc2b24518e32eea0a5e0c904ca844780083f3b0cd2d0b8b6af67bc355b9494025dc7b0a78fa80e3a2dbfeb51328851d6078198e9493651ae787ec0251f922ba30e9f51df62a6d72784cf3dd205393176dfa324a512bd94970a36dd34a514a86791f0eb36f0145b09ab64651b4a0313b299611a2a1c48891627598768a3114060ba4443486df51522a1ce88b30985c216f8e6ed178dd567b304a0d4cafba882a28342f17a9aa26ae58db630083d2c358fdf566c3f5d62a428567bc9ea8ce95caa0f35474b0bfa8f339a250ab4dfcf2083be8eefbc1055e18fe15370eecb260566d83ff06b211aaec43ca29b54ccd00f8815a2465ef0b46515cc7e41f3124f09efff739309ab58b29a1459a00bce5038e938c9678f72eb0e4ee5fdaae66d9f8573fc97fc42b4959f4bf8b61d78433e86b0335d6e9191c4d8bf487b3905c108cfd6ac24b0ceb7dcb7cf51f84d0ed687b95eaeb1c533c06f0d97023d92a70825837b59ba6cb7d4e56b0a87c203862ae8f315ba5925e8edefa679369a2202766151f16a965f9f81ece76cc070b55869e4db9784cf05c830b3242c8312");
        CScript witnessScript;
        witnessScript << OP_TRUE;
        const CTxDestination authScriptDest = CTxDestination(WitnessV1AuthScript(GetAuthScriptCommitment(0x01, &pubkey1, witnessScript)));
        const std::string encoded = EncodeDestination(authScriptDest);
        // Mainnet PQ witness-v1 addresses use HRP "nc" (bech32m). Testnet and
        // regtest = "tnc". BasicTestingSetup defaults to MAIN.
        BOOST_CHECK(encoded.rfind("nc1p", 0) == 0);
        BOOST_CHECK(DecodeDestination(encoded) == authScriptDest);
    }

    BOOST_AUTO_TEST_CASE(pq_seeded_keygen_compatibility_vectors)
    {
        // SHA256 of the complete raw keys captured using the previous RNG-based
        // keygen (liboqs 0.15.0/0.16.0). Seeds are public test data, not wallet secrets.
        struct Vector { const char* seed; const char* secret_hash; const char* public_hash; };
        const Vector vectors[] = {
            {"0000000000000000000000000000000000000000000000000000000000000000",
             "0f9086044d77b6d610c7e92418d9f70a398c69febc7e99f8254aaea98dcfbe77",
             "eb4e7302842153b0fa19e8620739ad258af4929c26dd89079a7ec7d4282208e1"},
            {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
             "04bf6b9f579166a627961dfc5c3bf9717df868db88863856356c4668c8b56b0b",
             "9f107644c1084526af3bc8098680b05499a2325a644e388fb4f970e058d19d46"},
            {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
             "6433074c5ffc9e0f2b1d68bb3fda84e439da0a2d93f508a101e9b44835f0b22c",
             "62c4f1b3164db7fa896a3343e900eb3e13c9f76de122020feba37ee063d49ef0"},
        };
        for (const auto& v : vectors) {
            CKey key;
            key.MakeNewKeyPQ(ParseHex(v.seed));
            BOOST_REQUIRE(key.IsValid());
            BOOST_REQUIRE_EQUAL(key.size(), ML_DSA_44_KEYDATA_SIZE);
            unsigned char digest[CSHA256::OUTPUT_SIZE];
            CSHA256().Write(key.begin(), ML_DSA_44_PRIVKEY_SIZE).Finalize(digest);
            BOOST_CHECK_EQUAL(HexStr(digest, digest + sizeof(digest)), v.secret_hash);
            const CPubKey pubkey = key.GetPubKey();
            CSHA256().Write(pubkey.begin() + 1, ML_DSA_44_PUBKEY_SIZE).Finalize(digest);
            BOOST_CHECK_EQUAL(HexStr(digest, digest + sizeof(digest)), v.public_hash);
        }
    }

    BOOST_AUTO_TEST_CASE(pq_seeded_keygen_preserves_rng)
    {
        ScopedPQRngProbe probe;
        CKey key;
        key.MakeNewKeyPQ(std::vector<unsigned char>(32, 0));
        BOOST_CHECK(key.IsValid());
        BOOST_CHECK_EQUAL(pq_rng_calls.load(), 0U);
        unsigned char bytes[16];
        OQS_randombytes(bytes, sizeof(bytes));
        BOOST_CHECK_EQUAL(pq_rng_calls.load(), 1U);
        for (unsigned char byte : bytes) BOOST_CHECK_EQUAL(byte, 0xa5);
    }

    BOOST_AUTO_TEST_CASE(pq_seeded_keygen_rejects_invalid_seed)
    {
        CKey key;
        key.MakeNewKeyPQ(std::vector<unsigned char>(32, 0));
        const CKey original = key;
        for (size_t size : {0U, 1U, 31U, 33U, 64U}) {
            const std::vector<unsigned char> seed(size, 0);
            BOOST_CHECK_THROW(key.MakeNewKeyPQ(seed), std::runtime_error);
            BOOST_CHECK(key == original);
            CKey empty;
            BOOST_CHECK_THROW(empty.MakeNewKeyPQ(seed), std::runtime_error);
            BOOST_CHECK(!empty.IsValid());
        }
    }

    BOOST_AUTO_TEST_CASE(pq_seeded_keygen_concurrent_with_signing)
    {
        std::vector<CKey> expected(4);
        for (size_t i = 0; i < expected.size(); ++i) {
            expected[i].MakeNewKeyPQ(std::vector<unsigned char>(32, i));
        }
        std::atomic<bool> passed{true};
        std::vector<std::thread> workers;
        for (size_t i = 0; i < expected.size(); ++i) {
            workers.emplace_back([&, i] {
                try {
                    const uint256 hash = uint256S("01");
                    for (int repeat = 0; repeat < 16; ++repeat) {
                        CKey key;
                        key.MakeNewKeyPQ(std::vector<unsigned char>(32, i));
                        if (!(key == expected[i])) passed = false;
                        std::vector<unsigned char> signature;
                        if (!key.Sign(hash, signature) || !key.GetPubKey().Verify(hash, signature)) passed = false;
                        CKey random;
                        random.MakeNewKeyPQ();
                        if (!random.Sign(hash, signature) || !random.GetPubKey().Verify(hash, signature)) passed = false;
                    }
                } catch (...) {
                    passed = false;
                }
            });
        }
        for (auto& worker : workers) worker.join();
        BOOST_CHECK(passed.load());
    }

    BOOST_AUTO_TEST_CASE(pq_privkey_wallet_roundtrip)
    {
        const std::vector<unsigned char> pqSeed = ParseHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        CKey originalKey;
        originalKey.MakeNewKeyPQ(pqSeed);

        const CPubKey originalPubKey = originalKey.GetPubKey();
        const CPrivKey serializedPrivKey = originalKey.GetPrivKey();

        BOOST_CHECK(originalPubKey.IsPQ());
        BOOST_CHECK_EQUAL(serializedPrivKey.size(), (size_t)ML_DSA_44_KEYDATA_SIZE);

        CKey loadedKey;
        CPubKey mutablePubKey = originalPubKey;
        CPrivKey mutablePrivKey = serializedPrivKey;
        BOOST_CHECK(loadedKey.Load(mutablePrivKey, mutablePubKey, false));
        BOOST_CHECK(loadedKey.IsValid());
        BOOST_CHECK(loadedKey.IsPQ());
        BOOST_CHECK(loadedKey.GetPubKey() == originalPubKey);
    }

BOOST_AUTO_TEST_SUITE_END()
