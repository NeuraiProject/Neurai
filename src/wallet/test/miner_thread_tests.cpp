// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The internal miner keeps mining when it does not get a block template.

#include "chainparams.h"
#include "key.h"
#include "miner.h"
#include "util.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "validation.h"
#include "wallet/wallet.h"
#include "wallet/test/wallet_test_fixture.h"

#include <boost/test/unit_test.hpp>

extern CWallet* pwalletMain;

namespace {

struct RegtestMinerSetup : public WalletTestingSetup {
    RegtestMinerSetup() : WalletTestingSetup(CBaseChainParams::REGTEST) {}
};

// A BIP44 HD chain on a known seed, so that the wallet has a key to mine to
void GiveKeys(CWallet& wallet)
{
    CKey key;
    key.MakeNewKey(true);
    CHDChain chain(&wallet);
    chain.seed_id = key.GetPubKey().GetID();
    chain.UseBip44(true);
    wallet.SetHDChain(chain, true);
    wallet.AddVchSeed(ParseHex(
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
        "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"));
}

int TipHeight()
{
    LOCK(cs_main);
    return chainActive.Height();
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(miner_thread_tests, RegtestMinerSetup)

BOOST_AUTO_TEST_CASE(internal_miner_mines_after_rejected_templates)
{
    // The first two templates the miner asks for are refused, the way a
    // template that fails TestBlockValidity is. The miner thread must survive
    // both and mine the next one. On regtest it stops after one block.
    GiveKeys(*pwalletMain);
    vpwallets.push_back(pwalletMain);

    const int start = TipHeight();
    const uint64_t rejected = nMinerTemplatesRejected.load();
    gArgs.ForceSetArg("-minertemplatefailures", "2");

    GenerateNeurais(true, 1, GetParams());
    const int64_t deadline = GetTimeMillis() + 60 * 1000;
    while (TipHeight() == start && GetTimeMillis() < deadline)
        MilliSleep(50);
    GenerateNeurais(false, 0, GetParams());

    BOOST_CHECK_EQUAL(nMinerTemplatesRejected.load(), rejected + 2);
    BOOST_CHECK_EQUAL(TipHeight(), start + 1);

    gArgs.ForceSetArg("-minertemplatefailures", "0");
    vpwallets.clear();
}

BOOST_AUTO_TEST_SUITE_END()
