// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Loading the DePIN pool key from the service wallet
// (wallet/depinpoolkeyload.{h,cpp}): which wallet, which kind of wallet, and
// every refusal names its condition.

#include "wallet/depinpoolkeyload.h"

// amount.h first: assets/assetdb.h declares CAmount parameters without
// including it, so it only compiles when the includer got there first.
#include "amount.h"
#include "assets/assetdb.h"
#include "assets/assets.h"
#include "assets/restricteddb.h"
#include "base58.h"
#include "depinpoolkey.h"
#include "key.h"
#include "test/test_neurai.h"
#include "validation.h"
#include "wallet/db.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"

#include <boost/test/unit_test.hpp>

#include <memory>
#include <string>
#include <vector>

namespace {

const std::string TOKEN = "&TEST";

struct DepinPoolKeyWalletSetup : public TestingSetup {
    bool prevAssetIndex;
    bool prevPubKeyIndex;
    CAssetsDB* prevAssetsDb;
    CLRUCache<std::string, CDatabasedAssetData>* prevAssetsCache;
    CRestrictedDB* prevRestrictedDb;
    std::vector<CWalletRef> prevWallets;

    DepinPoolKeyWalletSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        prevAssetIndex = fAssetIndex;
        prevPubKeyIndex = fPubKeyIndex;
        prevAssetsDb = passetsdb;
        prevAssetsCache = passetsCache;
        prevRestrictedDb = prestricteddb;
        prevWallets = vpwallets;
        fAssetIndex = true;
        fPubKeyIndex = true;
        passetsdb = new CAssetsDB(1 << 20, true, true);
        passetsCache = new CLRUCache<std::string, CDatabasedAssetData>(MAX_CACHE_ASSETS_SIZE);
        prestricteddb = new CRestrictedDB(1 << 20, true, true);
        ::bitdb.MakeMock();
        ClearDepinPoolKey();
    }

    ~DepinPoolKeyWalletSetup()
    {
        ClearDepinPoolKey();
        vpwallets = prevWallets;
        ::bitdb.Flush(true);
        ::bitdb.Reset();
        delete prestricteddb;
        delete passetsCache;
        delete passetsdb;
        prestricteddb = prevRestrictedDb;
        passetsCache = prevAssetsCache;
        passetsdb = prevAssetsDb;
        fPubKeyIndex = prevPubKeyIndex;
        fAssetIndex = prevAssetIndex;
    }

    std::unique_ptr<CWallet> MakeWallet(const std::string& file, bool bip44, bool pq)
    {
        std::unique_ptr<CWallet> wallet(new CWallet(std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, file))));
        bool firstRun = false;
        wallet->LoadWallet(firstRun);

        CKey seedKey;
        seedKey.MakeNewKey(true);
        CHDChain chain(wallet.get());
        chain.seed_id = seedKey.GetPubKey().GetID();
        chain.UseBip44(bip44);
        chain.UsePQ(pq);
        {
            LOCK(wallet->cs_wallet);
            wallet->SetHDChain(chain, true);
        }
        std::vector<unsigned char> seed(64);
        for (size_t i = 0; i < seed.size(); ++i) seed[i] = (unsigned char)(i * 7 + file.size());
        wallet->LoadVchSeed(seed);
        return wallet;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(depinpoolkey_wallet_tests, DepinPoolKeyWalletSetup)

// (12) Only a legacy, unencrypted BIP44 wallet loads, and the key is a pure
// function of its seed.
BOOST_AUTO_TEST_CASE(pool_key_requires_legacy_wallet)
{
    std::string error;

    // No wallet at all (-disablewallet).
    BOOST_CHECK(!LoadDepinPoolKey(nullptr, error));
    BOOST_CHECK_NE(error.find("requires a wallet"), std::string::npos);

    // Not BIP44.
    std::unique_ptr<CWallet> legacyNoBip44 = MakeWallet("nobip44.dat", /*bip44=*/false, /*pq=*/false);
    BOOST_CHECK(!LoadDepinPoolKey(legacyNoBip44.get(), error));
    BOOST_CHECK_MESSAGE(error.find("BIP44") != std::string::npos, error);
    BOOST_CHECK(!HaveDepinPoolKey());

    // Post-quantum.
    std::unique_ptr<CWallet> pqWallet = MakeWallet("pq.dat", true, true);
    BOOST_CHECK(!LoadDepinPoolKey(pqWallet.get(), error));
    BOOST_CHECK_MESSAGE(error.find("non-PQ") != std::string::npos, error);
    BOOST_CHECK(!HaveDepinPoolKey());

    // The right kind of wallet: the loaded key is what depinpoolpkey reports.
    std::unique_ptr<CWallet> service = MakeWallet("service.dat", true, false);
    CKey derived;
    CPubKey derivedPub;
    std::string path;
    BOOST_REQUIRE_MESSAGE(DeriveDepinPoolKeys(service.get(), derived, derivedPub, path, error), error);
    BOOST_CHECK_EQUAL(path, "m/44'/0'/200'/0/0"); // regtest is not testnet: change = 0

    BOOST_REQUIRE_MESSAGE(LoadDepinPoolKey(service.get(), error), error);
    CKey loaded;
    CPubKey loadedPub;
    BOOST_REQUIRE(GetDepinPoolKey(loaded, loadedPub));
    BOOST_CHECK(loaded == derived);
    BOOST_CHECK(loadedPub == derivedPub);
    BOOST_CHECK_EQUAL(GetDepinPoolKeyWalletName(), "service.dat");

    // Another wallet, another key.
    std::unique_ptr<CWallet> other = MakeWallet("other.dat", true, false);
    CKey otherKey;
    CPubKey otherPub;
    BOOST_REQUIRE(DeriveDepinPoolKeys(other.get(), otherKey, otherPub, path, error));
    BOOST_CHECK(!(otherPub == derivedPub));

    // The encrypted-wallet refusal (IsCrypted) is not exercised here: a mock
    // wallet built from a bare CHDChain cannot go through EncryptWallet()
    // (CCryptoKeyStore::Unlock asserts on the synthetic seed state). It is a
    // one-line guard in LoadDepinPoolKey and is covered by the regtest
    // walkthrough with a real encrypted wallet.
}

// The service wallet is never picked by position.
BOOST_AUTO_TEST_CASE(service_wallet_selection)
{
    std::unique_ptr<CWallet> a = MakeWallet("a.dat", true, false);
    std::unique_ptr<CWallet> b = MakeWallet("b.dat", true, false);
    std::string error;

    vpwallets.clear();
    BOOST_CHECK(SelectDepinServiceWallet("", error) == nullptr);
    BOOST_CHECK_MESSAGE(error.find("requires a wallet") != std::string::npos, error);

    vpwallets = {a.get()};
    BOOST_CHECK(SelectDepinServiceWallet("", error) == a.get());
    BOOST_CHECK(SelectDepinServiceWallet("a.dat", error) == a.get());
    BOOST_CHECK(SelectDepinServiceWallet("b.dat", error) == nullptr);

    vpwallets = {a.get(), b.get()};
    BOOST_CHECK(SelectDepinServiceWallet("", error) == nullptr);
    BOOST_CHECK_MESSAGE(error.find("ambiguous") != std::string::npos, error);
    BOOST_CHECK(SelectDepinServiceWallet("b.dat", error) == b.get());
    BOOST_CHECK(SelectDepinServiceWallet("c.dat", error) == nullptr);
    BOOST_CHECK_MESSAGE(error.find("not a loaded wallet") != std::string::npos, error);

    // Load order does not matter once the wallet is named.
    vpwallets = {b.get(), a.get()};
    BOOST_CHECK(SelectDepinServiceWallet("b.dat", error) == b.get());
    BOOST_CHECK(SelectDepinServiceWallet("a.dat", error) == a.get());
    vpwallets.clear();
}

BOOST_AUTO_TEST_SUITE_END()
