// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Guards against PQ key derivation from an empty/short BIP44 seed, parameter
// validation of GenerateXpqpub, the runtime gate for the legacy
// PQ-without-BIP44 wallet state, and the wallet address type (-addresstype).

#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "wallet/test/wallet_test_fixture.h"
#include "base58.h"
#include "script/ismine.h"
#include "script/script.h"
#include "script/standard.h"
#include "validation.h"
#include "ui_interface.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validationinterface.h"

#include <stdexcept>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

// The known 64-byte BIP39 seed for "abandon x11 about" + passphrase ""
std::vector<unsigned char> AbandonSeed64()
{
    return ParseHex(
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
        "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4");
}

// Gives the wallet a BIP44 HD chain backed by the known seed, so the strict
// ECDSA (m/84') branch can be derived.
void MakeBip44Wallet(CWallet& wallet)
{
    CKey key;
    key.MakeNewKey(true);
    CHDChain chain(&wallet);
    chain.seed_id = key.GetPubKey().GetID();
    chain.UseBip44(true);
    wallet.SetHDChain(chain, true);
    wallet.AddVchSeed(AbandonSeed64());
}

struct RegtestWalletSetup : public WalletTestingSetup {
    RegtestWalletSetup() : WalletTestingSetup(CBaseChainParams::REGTEST) {}
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(pqwallet_guard_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(pq_derivation_requires_seed)
{
    CWallet wallet;
    LOCK(wallet.cs_wallet);

    // No BIP44 seed loaded: every PQ derivation entry point must fail closed
    BOOST_CHECK_THROW(wallet.GetMasterExtKeyPQ(), std::runtime_error);
    BOOST_CHECK_THROW(wallet.GenerateXpqpub(0, 1, 0), std::runtime_error);

    // A truncated seed is equally a corrupt state
    wallet.AddVchSeed(std::vector<unsigned char>(16, 0x42));
    BOOST_CHECK_THROW(wallet.GetMasterExtKeyPQ(), std::runtime_error);

    // With the real 64-byte seed, derivation works
    wallet.AddVchSeed(AbandonSeed64());
    BOOST_CHECK_NO_THROW(wallet.GetMasterExtKeyPQ());
}

BOOST_AUTO_TEST_CASE(generatexpqpub_validates_parameters)
{
    CWallet wallet;
    LOCK(wallet.cs_wallet);
    wallet.AddVchSeed(AbandonSeed64());

    // chain must be 0 (external) or 1 (change)
    BOOST_CHECK_THROW(wallet.GenerateXpqpub(2, 1, 0), std::runtime_error);

    // offset + count beyond the hardened index space would alias low indices
    // (i | HARDENED is idempotent on the high bit) or wrap uint32_t
    BOOST_CHECK_THROW(wallet.GenerateXpqpub(0, 2, 0x7FFFFFFF), std::runtime_error);
    BOOST_CHECK_THROW(wallet.GenerateXpqpub(0, 1, 0x80000000), std::runtime_error);

    // Exact boundary offset + count == 2^31: last derivable index, allowed
    CXpqpub xpub;
    BOOST_CHECK_NO_THROW(xpub = wallet.GenerateXpqpub(0, 1, 0x7FFFFFFF));
    BOOST_CHECK_EQUAL(xpub.pubkeys.size(), 1u);
}

BOOST_AUTO_TEST_CASE(ispqenabled_requires_bip44)
{
    CWallet wallet;
    LOCK(wallet.cs_wallet);

    CKey key;
    key.MakeNewKey(true);

    // Legacy corrupt state: PQ flag without BIP44 → gated off at runtime
    CHDChain chain(&wallet);
    chain.seed_id = key.GetPubKey().GetID();
    chain.UsePQ(true);
    chain.UseBip44(false);
    wallet.SetHDChain(chain, true);
    BOOST_CHECK(!wallet.IsPQEnabled());
    // The raw persisted flag keeps the historical state for reporting
    BOOST_CHECK(wallet.GetHDChain().IsPQEnabled());

    // Proper PQ wallet: PQ + BIP44 → enabled
    chain.UseBip44(true);
    wallet.SetHDChain(chain, true);
    BOOST_CHECK(wallet.IsPQEnabled());
}

BOOST_AUTO_TEST_CASE(address_type_names)
{
    for (WalletAddressType type : {WalletAddressType::LEGACY, WalletAddressType::PQ, WalletAddressType::ECDSA}) {
        WalletAddressType parsed;
        BOOST_REQUIRE(ParseWalletAddressType(WalletAddressTypeName(type), parsed));
        BOOST_CHECK(parsed == type);
    }
    BOOST_CHECK(DEFAULT_WALLET_ADDRESS_TYPE == WalletAddressType::LEGACY);
    // Persisted values
    BOOST_CHECK_EQUAL(static_cast<int>(WalletAddressType::LEGACY), 1);
    BOOST_CHECK_EQUAL(static_cast<int>(WalletAddressType::PQ), 2);
    BOOST_CHECK_EQUAL(static_cast<int>(WalletAddressType::ECDSA), 3);
    // Generic AuthScript v1 is a contract family, never a wallet type.
    WalletAddressType parsed;
    for (const std::string& name : {"authscript", "1", "", "ECDSA", "bech32"}) {
        BOOST_CHECK(!ParseWalletAddressType(name, parsed));
    }
}

BOOST_AUTO_TEST_CASE(address_type_inferred_and_persisted)
{
    {
        CWallet wallet(std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, "addresstype.dat")));
        bool firstRun;
        BOOST_REQUIRE_EQUAL(wallet.LoadWallet(firstRun), DB_LOAD_OK);
        // No record: a wallet file from before -addresstype is legacy or PQ,
        // told apart by its HD chain.
        BOOST_CHECK_EQUAL(wallet.GetStoredAddressType(), 0);
        BOOST_CHECK(wallet.GetAddressType() == WalletAddressType::LEGACY);
        CKey key;
        key.MakeNewKey(true);
        CHDChain chain(&wallet);
        chain.seed_id = key.GetPubKey().GetID();
        chain.UseBip44(true);
        chain.UsePQ(true);
        wallet.SetHDChain(chain, true);
        BOOST_CHECK(wallet.GetAddressType() == WalletAddressType::PQ);
        chain.UsePQ(false);
        wallet.SetHDChain(chain, true);
        BOOST_REQUIRE(wallet.SetAddressType(WalletAddressType::ECDSA));
        BOOST_CHECK(wallet.GetAddressType() == WalletAddressType::ECDSA);
    }
    // The record survives a reload.
    CWallet loaded(std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, "addresstype.dat")));
    bool firstRun;
    BOOST_REQUIRE_EQUAL(loaded.LoadWallet(firstRun), DB_LOAD_OK);
    BOOST_CHECK_EQUAL(loaded.GetStoredAddressType(), static_cast<uint8_t>(WalletAddressType::ECDSA));
    BOOST_CHECK(loaded.GetAddressType() == WalletAddressType::ECDSA);
}

BOOST_FIXTURE_TEST_CASE(ecdsa_wallet_hands_out_only_v3, RegtestWalletSetup)
{
    CWallet wallet(std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, "ecdsa_type.dat")));
    bool firstRun;
    BOOST_REQUIRE_EQUAL(wallet.LoadWallet(firstRun), DB_LOAD_OK);
    LOCK2(cs_main, wallet.cs_wallet);
    MakeBip44Wallet(wallet);
    BOOST_REQUIRE(wallet.SetAddressType(WalletAddressType::ECDSA));

    CTxDestination dest;
    std::string error;
    {
        // Before activation an ecdsa wallet hands out v3 addresses (never
        // Legacy), but creates no output to them: no change, no mining.
        CStrictAuthScriptContext inactive(false);
        BOOST_REQUIRE(wallet.GetNewDestination(false, dest, error));
        const WitnessStrictAuthScript* early = boost::get<WitnessStrictAuthScript>(&dest);
        BOOST_REQUIRE(early);
        BOOST_CHECK_EQUAL(early->version, 3);
        BOOST_CHECK(IsMine(wallet, GetScriptForDestination(dest)) == ISMINE_SPENDABLE);
        CTxDestination refused;
        BOOST_CHECK(!wallet.GetNewDestinationOfType("legacy", false, refused, error));
        CReserveKey reservekey(&wallet);
        BOOST_CHECK(!wallet.CreateNewChangeAddress(reservekey, refused, error));
        BOOST_CHECK(error.find("not active yet") != std::string::npos);
        std::shared_ptr<CReserveScript> mining;
        wallet.GetScriptForMining(mining);
        BOOST_CHECK(!mining || mining->reserveScript.empty());
    }

    CStrictAuthScriptContext active(true);
    BOOST_REQUIRE(wallet.GetNewDestination(false, dest, error));
    const WitnessStrictAuthScript* strict = boost::get<WitnessStrictAuthScript>(&dest);
    BOOST_REQUIRE(strict);
    BOOST_CHECK_EQUAL(strict->version, 3);
    BOOST_CHECK(IsMine(wallet, GetScriptForDestination(dest)) == ISMINE_SPENDABLE);

    // Only v3: the ecdsa wallet refuses Legacy, and has no PQ keys.
    BOOST_CHECK(!wallet.GetNewDestinationOfType("legacy", false, dest, error));
    BOOST_CHECK(error.find("strict ECDSA wallet") != std::string::npos);
    BOOST_CHECK(!wallet.GetNewDestinationOfType("pq", false, dest, error));

    // Change and mining follow the wallet type.
    CTxDestination change;
    CReserveKey reservekey(&wallet);
    BOOST_REQUIRE(wallet.CreateNewChangeAddress(reservekey, change, error));
    strict = boost::get<WitnessStrictAuthScript>(&change);
    BOOST_REQUIRE(strict);
    BOOST_CHECK_EQUAL(strict->version, 3);
    reservekey.ReturnKey();

    std::shared_ptr<CReserveScript> mining;
    wallet.GetScriptForMining(mining);
    BOOST_REQUIRE(mining);
    CTxDestination mined;
    BOOST_REQUIRE(ExtractDestination(mining->reserveScript, mined));
    strict = boost::get<WitnessStrictAuthScript>(&mined);
    BOOST_REQUIRE(strict);
    BOOST_CHECK_EQUAL(strict->version, 3);

    // Account addresses too.
    CPubKey accountKey;
    BOOST_REQUIRE(wallet.GetAccountPubkey(accountKey, "acct"));
    CTxDestination account;
    BOOST_REQUIRE(wallet.GetDestinationForOwnKey(accountKey, account));
    strict = boost::get<WitnessStrictAuthScript>(&account);
    BOOST_REQUIRE(strict);
    BOOST_CHECK_EQUAL(strict->version, 3);
    BOOST_CHECK(wallet.mapAddressBook.count(account) == 1);
}

BOOST_FIXTURE_TEST_CASE(legacy_wallet_keeps_legacy_default, RegtestWalletSetup)
{
    CWallet wallet(std::unique_ptr<CWalletDBWrapper>(new CWalletDBWrapper(&bitdb, "legacy_type.dat")));
    bool firstRun;
    BOOST_REQUIRE_EQUAL(wallet.LoadWallet(firstRun), DB_LOAD_OK);
    LOCK2(cs_main, wallet.cs_wallet);
    MakeBip44Wallet(wallet);
    BOOST_REQUIRE(wallet.SetAddressType(WalletAddressType::LEGACY));
    CStrictAuthScriptContext active(true);

    CTxDestination dest;
    std::string error;
    BOOST_REQUIRE(wallet.GetNewDestination(false, dest, error));
    BOOST_CHECK(boost::get<CKeyID>(&dest));
    // A legacy wallet still hands out strict ECDSA on explicit request.
    BOOST_REQUIRE(wallet.GetNewDestinationOfType("ecdsa", false, dest, error));
    BOOST_CHECK(boost::get<WitnessStrictAuthScript>(&dest));
    BOOST_CHECK(!wallet.GetNewDestinationOfType("pq", false, dest, error));
    BOOST_CHECK(error.find("-addresstype=pq") != std::string::npos);
}

// The first-run GUI dialog picks the address type after the wallet file is
// opened: the type and the HD chain's PQ flag must both follow that choice, so
// the wallet loads again, and -addresstype must then match it.
BOOST_AUTO_TEST_CASE(first_run_dialog_address_type)
{
    gArgs.ForceSetArg("-keypool", "2");
    struct ResetArgs {
        ~ResetArgs() { gArgs.ForceSetArg("-keypool", std::to_string(DEFAULT_KEYPOOL_SIZE)); gArgs.ForceSetArg("-addresstype", ""); }
    } reset;
    for (WalletAddressType chosen : {WalletAddressType::PQ, WalletAddressType::ECDSA, WalletAddressType::LEGACY}) {
        const std::string file = "dialog_" + WalletAddressTypeName(chosen) + ".dat";
        // The dialog is the only ShowMnemonic listener, as in the GUI.
        boost::signals2::scoped_connection dialog(uiInterface.ShowMnemonic.connect([chosen](int) { my_address_type = chosen; }));
        gArgs.ForceSetArg("-addresstype", "");
        CWallet* created = CWallet::CreateWalletFromFile(file);
        BOOST_REQUIRE(created);
        BOOST_CHECK(created->GetAddressType() == chosen);
        BOOST_CHECK_EQUAL(created->GetStoredAddressType(), static_cast<uint8_t>(chosen));
        BOOST_CHECK_EQUAL(created->GetHDChain().IsPQEnabled(), chosen == WalletAddressType::PQ);
        BOOST_CHECK(!my_address_type);
        UnregisterValidationInterface(created);
        delete created;
        dialog.disconnect();

        CWallet* reloaded = CWallet::CreateWalletFromFile(file);
        BOOST_REQUIRE_MESSAGE(reloaded, "wallet created from the dialog choice must load again");
        BOOST_CHECK(reloaded->GetAddressType() == chosen);
        UnregisterValidationInterface(reloaded);
        delete reloaded;

        // Opening it with another -addresstype is refused.
        gArgs.ForceSetArg("-addresstype", chosen == WalletAddressType::LEGACY ? "ecdsa" : "legacy");
        CWallet* mismatched = CWallet::CreateWalletFromFile(file);
        BOOST_CHECK(!mismatched);
        if (mismatched) {
            UnregisterValidationInterface(mismatched);
            delete mismatched;
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
