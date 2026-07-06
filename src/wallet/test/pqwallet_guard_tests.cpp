// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Guards against PQ key derivation from an empty/short BIP44 seed, parameter
// validation of GenerateXpqpub, and the runtime gate for the legacy
// PQ-without-BIP44 wallet state.

#include "wallet/wallet.h"
#include "wallet/test/wallet_test_fixture.h"
#include "utilstrencodings.h"

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

BOOST_AUTO_TEST_SUITE_END()
