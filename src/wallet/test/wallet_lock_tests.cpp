// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.

#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "wallet/test/wallet_test_fixture.h"
#include "hash.h"

#include <boost/test/unit_test.hpp>
#include <array>
#include <memory>

namespace {
const SecureString WORDS = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const SecureString MNEMONIC_PASSPHRASE = "synthetic mnemonic passphrase";
const SecureString WALLET_PASSPHRASE = "synthetic wallet encryption passphrase";

using LockTestWallet = CWallet;
// Deduce the API's buffer type so the same regression compiles before the fix.
template <typename Buffer>
Buffer SecretBufferType(void (CWallet::*)(uint256&, Buffer&, Buffer&, Buffer&));
using SecretBuffer = decltype(SecretBufferType(&CWallet::GetBip39Data));

struct Secrets {
    uint256 hash;
    SecretBuffer words, passphrase, seed;
    explicit Secrets(LockTestWallet& wallet)
    {
        wallet.GetBip39Data(hash, words, passphrase, seed);
    }
};

CPubKey InitializeWallet(LockTestWallet& wallet, bool pq = false)
{
    LOCK(wallet.cs_wallet);
    bool firstRun;
    BOOST_REQUIRE_EQUAL(wallet.LoadWallet(firstRun), DB_LOAD_OK);
    CHDChain chain(&wallet);
    chain.UseBip44();
    chain.UsePQ(pq);
    BOOST_REQUIRE(chain.SetMnemonic(WORDS, MNEMONIC_PASSPHRASE, chain.vchSeed));
    CKey seedId;
    seedId.MakeNewKey(true);
    chain.seed_id = seedId.GetPubKey().GetID();
    BOOST_REQUIRE(wallet.SetHDChain(chain, false));
    const std::vector<unsigned char> words(WORDS.begin(), WORDS.end());
    const std::vector<unsigned char> passphrase(MNEMONIC_PASSPHRASE.begin(), MNEMONIC_PASSPHRASE.end());
    const std::vector<unsigned char> seed(chain.vchSeed.begin(), chain.vchSeed.end());
    const uint256 hash = Hash(words.begin(), words.end());
    BOOST_REQUIRE(wallet.AddWords(hash, words));
    BOOST_REQUIRE(wallet.AddPassphrase(passphrase));
    BOOST_REQUIRE(wallet.AddVchSeed(seed));
    CWalletDB db(wallet.GetDBHandle());
    BOOST_REQUIRE(db.WriteBip39Words(hash, words, false));
    BOOST_REQUIRE(db.WriteBip39Passphrase(passphrase, false));
    BOOST_REQUIRE(db.WriteBip39VchSeed(seed, false));
    return wallet.GenerateNewKey(db, false);
}

void CheckLockedSecrets(LockTestWallet& wallet)
{
    BOOST_CHECK(wallet.IsLocked());
    Secrets secrets(wallet);
    BOOST_CHECK(secrets.words.empty());
    BOOST_CHECK(secrets.passphrase.empty());
    BOOST_CHECK(secrets.seed.empty());
    const CHDChain& chain = wallet.GetHDChain();
    BOOST_CHECK(chain.vchMnemonic.empty());
    BOOST_CHECK(chain.vchMnemonicPassphrase.empty());
    BOOST_CHECK(chain.vchSeed.empty());
    BOOST_CHECK_EQUAL(chain.vchMnemonic.capacity(), 0U);
    BOOST_CHECK_EQUAL(chain.vchMnemonicPassphrase.capacity(), 0U);
    BOOST_CHECK_EQUAL(chain.vchSeed.capacity(), 0U);
}

void CheckSameSecrets(LockTestWallet& wallet, const Secrets& expected)
{
    Secrets actual(wallet);
    BOOST_CHECK(actual.hash == expected.hash);
    BOOST_CHECK(actual.words == expected.words);
    BOOST_CHECK(actual.passphrase == expected.passphrase);
    BOOST_CHECK(actual.seed == expected.seed);
}

class AtomicDecryptStore : public CCryptoKeyStore
{
public:
    using CCryptoKeyStore::EncryptBip39;
    using CCryptoKeyStore::EncryptKeys;
    using CCryptoKeyStore::DecryptBip39;
    std::array<size_t, 3> SecretCapacities() const
    {
        LOCK(cs_KeyStore);
        return {vchWords.capacity(), vchPassphrase.capacity(), g_vchSeed.capacity()};
    }
    void ClearTestPlaintext()
    {
        vchWords.clear();
        vchPassphrase.clear();
        g_vchSeed.clear();
    }
    void CorruptSeed() { vchCryptedBip39VchSeed.assign(1, 0); }
    bool HasPlaintext() const { return !vchWords.empty() || !vchPassphrase.empty() || !g_vchSeed.empty(); }
};
}

BOOST_FIXTURE_TEST_SUITE(wallet_lock_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(encryption_and_relock_clear_bip39_secrets)
{
    for (bool pq : {false, true}) {
        LockTestWallet wallet(std::make_unique<CWalletDBWrapper>(&bitdb, pq ? "lock-pq.dat" : "lock-legacy.dat"));
        const CPubKey pubkey = InitializeWallet(wallet, pq);
        const Secrets expected(wallet);
        const CPubKey expectedMaster = wallet.GetMasterExtKeyPQ().GetKey().GetPubKey();
        BOOST_REQUIRE_EQUAL(expected.seed.size(), 64U);
        BOOST_REQUIRE(wallet.EncryptWallet(WALLET_PASSPHRASE));
        CheckLockedSecrets(wallet);
        BOOST_CHECK_THROW(wallet.GetMasterExtKeyPQ(), std::runtime_error);
        CKey key;
        BOOST_CHECK(!wallet.GetKey(pubkey.GetID(), key));

        CWalletDB db(wallet.GetDBHandle());
        std::vector<unsigned char> encryptedSeed, plaintextSeed;
        BOOST_REQUIRE(db.ReadBip39VchSeed(encryptedSeed, true));
        BOOST_CHECK(!db.ReadBip39VchSeed(plaintextSeed, false));
        for (int cycle = 0; cycle < 3; ++cycle) {
            BOOST_REQUIRE(wallet.Unlock(WALLET_PASSPHRASE));
            CheckSameSecrets(wallet, expected);
            BOOST_REQUIRE(wallet.GetKey(pubkey.GetID(), key));
            BOOST_CHECK(key.GetPubKey() == pubkey);
            BOOST_CHECK(wallet.GetMasterExtKeyPQ().GetKey().GetPubKey() == expectedMaster);
            // A caller holding a base reference must also clear the HD-chain copy.
            CCryptoKeyStore& base = wallet;
            BOOST_REQUIRE(base.Lock());
            CheckLockedSecrets(wallet);
            std::vector<unsigned char> storedSeed;
            BOOST_REQUIRE(db.ReadBip39VchSeed(storedSeed, true));
            BOOST_CHECK(storedSeed == encryptedSeed);
        }
        BOOST_CHECK(!wallet.Unlock(SecureString("wrong synthetic password")));
        CheckLockedSecrets(wallet);
    }
}

BOOST_AUTO_TEST_CASE(lock_notification_observes_scrubbed_state)
{
    LockTestWallet wallet(std::make_unique<CWalletDBWrapper>(&bitdb, "lock-notify.dat"));
    InitializeWallet(wallet);
    BOOST_REQUIRE(wallet.EncryptWallet(WALLET_PASSPHRASE));
    BOOST_REQUIRE(wallet.Unlock(WALLET_PASSPHRASE));
    // Simulate the additional creation-time copy still owned by the HD chain.
    CHDChain chain = wallet.GetHDChain();
    chain.vchSeed.assign(64, 0x42);
    chain.vchMnemonic.assign(32, 0x43);
    chain.vchMnemonicPassphrase.assign(16, 0x44);
    BOOST_REQUIRE(wallet.SetHDChain(chain, true));
    unsigned notifications = 0;
    auto connection = wallet.NotifyStatusChanged.connect([&](CCryptoKeyStore*) {
        ++notifications;
        CheckLockedSecrets(wallet);
    });
    CCryptoKeyStore& base = wallet;
    BOOST_REQUIRE(base.Lock());
    BOOST_CHECK_EQUAL(notifications, 1U);
    connection.disconnect();
}

BOOST_AUTO_TEST_CASE(failed_lock_preserves_unencrypted_wallet)
{
    LockTestWallet wallet(std::make_unique<CWalletDBWrapper>(&bitdb, "lock-unencrypted.dat"));
    const CPubKey pubkey = InitializeWallet(wallet);
    const Secrets expected(wallet);
    BOOST_CHECK(!wallet.Lock());
    BOOST_CHECK(!wallet.IsCrypted());
    CheckSameSecrets(wallet, expected);
    BOOST_CHECK(!wallet.GetHDChain().vchSeed.empty());
    CKey key;
    BOOST_CHECK(wallet.GetKey(pubkey.GetID(), key));
}

BOOST_AUTO_TEST_CASE(reused_secret_outputs_release_previous_plaintext)
{
    LockTestWallet wallet(std::make_unique<CWalletDBWrapper>(&bitdb, "lock-outputs.dat"));
    InitializeWallet(wallet);
    BOOST_REQUIRE(wallet.EncryptWallet(WALLET_PASSPHRASE));
    BOOST_REQUIRE(wallet.Unlock(WALLET_PASSPHRASE));
    Secrets outputs(wallet);
    BOOST_REQUIRE(!outputs.seed.empty());
    BOOST_REQUIRE(wallet.Lock());
    wallet.GetBip39Data(outputs.hash, outputs.words, outputs.passphrase, outputs.seed);
    BOOST_CHECK(outputs.words.empty());
    BOOST_CHECK(outputs.passphrase.empty());
    BOOST_CHECK(outputs.seed.empty());
    BOOST_CHECK_EQUAL(outputs.words.capacity(), 0U);
    BOOST_CHECK_EQUAL(outputs.passphrase.capacity(), 0U);
    BOOST_CHECK_EQUAL(outputs.seed.capacity(), 0U);
}

BOOST_AUTO_TEST_CASE(passphrase_change_preserves_lock_state_and_seed)
{
    LockTestWallet wallet(std::make_unique<CWalletDBWrapper>(&bitdb, "lock-change.dat"));
    InitializeWallet(wallet, true);
    const Secrets expected(wallet);
    const SecureString replacement = "replacement synthetic wallet password";
    BOOST_REQUIRE(wallet.EncryptWallet(WALLET_PASSPHRASE));
    BOOST_REQUIRE(wallet.ChangeWalletPassphrase(WALLET_PASSPHRASE, replacement));
    CheckLockedSecrets(wallet);
    BOOST_CHECK(!wallet.Unlock(WALLET_PASSPHRASE));
    CheckLockedSecrets(wallet);
    BOOST_REQUIRE(wallet.Unlock(replacement));
    CheckSameSecrets(wallet, expected);
    BOOST_REQUIRE(wallet.ChangeWalletPassphrase(replacement, WALLET_PASSPHRASE));
    BOOST_CHECK(!wallet.IsLocked());
    CheckSameSecrets(wallet, expected);
    BOOST_REQUIRE(wallet.Lock());
    CheckLockedSecrets(wallet);
}

BOOST_AUTO_TEST_CASE(reload_encrypted_wallet_restores_seed_only_after_unlock)
{
    const char* filename = "lock-reload.dat";
    SecretBuffer expectedSeed;
    CPubKey pubkey;
    {
        LockTestWallet wallet(std::make_unique<CWalletDBWrapper>(&bitdb, filename));
        pubkey = InitializeWallet(wallet);
        expectedSeed = Secrets(wallet).seed;
        BOOST_REQUIRE(wallet.EncryptWallet(WALLET_PASSPHRASE));
        CheckLockedSecrets(wallet);
    }
    LockTestWallet reloaded(std::make_unique<CWalletDBWrapper>(&bitdb, filename));
    bool firstRun;
    BOOST_REQUIRE_EQUAL(reloaded.LoadWallet(firstRun), DB_LOAD_OK);
    BOOST_CHECK(!firstRun);
    CheckLockedSecrets(reloaded);
    BOOST_REQUIRE(reloaded.Unlock(WALLET_PASSPHRASE));
    BOOST_CHECK(Secrets(reloaded).seed == expectedSeed);
    CKey key;
    BOOST_CHECK(reloaded.GetKey(pubkey.GetID(), key));
    BOOST_REQUIRE(reloaded.Lock());
    CheckLockedSecrets(reloaded);
}

BOOST_AUTO_TEST_CASE(keystore_lock_releases_plaintext_allocations)
{
    AtomicDecryptStore store;
    const std::vector<unsigned char> words(WORDS.begin(), WORDS.end());
    BOOST_REQUIRE(store.AddWords(Hash(words.begin(), words.end()), words));
    BOOST_REQUIRE(store.AddPassphrase(std::vector<unsigned char>{1, 2, 3}));
    BOOST_REQUIRE(store.AddVchSeed(std::vector<unsigned char>(64, 0x46)));
    BOOST_REQUIRE(store.Lock());
    BOOST_CHECK(!store.HasPlaintext());
    for (size_t capacity : store.SecretCapacities()) BOOST_CHECK_EQUAL(capacity, 0U);
}

BOOST_AUTO_TEST_CASE(failed_bip39_decryption_does_not_publish_partial_plaintext)
{
    AtomicDecryptStore store;
    CKeyingMaterial master(32, 0x45);
    const std::vector<unsigned char> words(WORDS.begin(), WORDS.end());
    BOOST_REQUIRE(store.AddWords(Hash(words.begin(), words.end()), words));
    BOOST_REQUIRE(store.AddPassphrase(std::vector<unsigned char>{1, 2, 3}));
    BOOST_REQUIRE(store.AddVchSeed(std::vector<unsigned char>(64, 0x46)));
    BOOST_REQUIRE(store.EncryptKeys(master));
    BOOST_REQUIRE(store.EncryptBip39(master));
    store.ClearTestPlaintext();
    store.CorruptSeed();
    BOOST_CHECK(!store.DecryptBip39(master));
    BOOST_CHECK(!store.HasPlaintext());
}

BOOST_AUTO_TEST_SUITE_END()
