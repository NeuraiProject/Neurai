// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-021: IsWitnessStandard per-item size cap under nCSFSEnabled.
// Tests the conditional 80 B / 3072 B limit for P2WSH witness stack items.

#include "policy/policy.h"
#include "coins.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "uint256.h"
#include "amount.h"
#include "test/test_neurai.h"

#include <boost/test/unit_test.hpp>

#include <vector>

namespace {

// 32-byte witness program (content irrelevant for standardness tests).
static const std::vector<unsigned char> kWitnessProgram(32, 0);

// Build a P2WSH scriptPubKey: OP_0 <32-byte-program>
static CScript P2WSHScript()
{
    CScript s;
    s << OP_0 << kWitnessProgram;
    return s;
}

// 1-byte witnessScript appended as the last witness stack item.
// Well under MAX_STANDARD_P2WSH_SCRIPT_SIZE (3600 B); does not affect
// the per-item checks which only cover items before the last.
static const std::vector<unsigned char> kMinimalWitnessScript = {0x51}; // OP_1

// Build a spending transaction. `items` are the non-script witness stack
// items; kMinimalWitnessScript is appended as the final (witnessScript) item.
static CTransaction MakeWitnessTx(const uint256& prevHash,
                                   std::vector<std::vector<unsigned char>> items)
{
    CMutableTransaction tx;
    tx.nVersion = 1;
    tx.vin.resize(1);
    tx.vout.resize(1);
    tx.vin[0].prevout = COutPoint(prevHash, 0);
    for (auto& item : items)
        tx.vin[0].scriptWitness.stack.push_back(std::move(item));
    tx.vin[0].scriptWitness.stack.push_back(kMinimalWitnessScript);
    tx.vout[0].nValue = 0;
    return CTransaction(tx);
}

// Populate a CCoinsViewCache with a single P2WSH coin at (prevHash, 0).
static void AddP2WSHCoin(CCoinsViewCache& coins, const uint256& prevHash)
{
    coins.AddCoin(COutPoint(prevHash, 0),
                  Coin(CTxOut(1 * COIN, P2WSHScript()), 1, false),
                  false);
}

// Stable fake prevout hash shared across all tests.
static const uint256 kPrevHash = uint256S(
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(witness_standard_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// csfsActive = false: legacy 80-byte cap preserved
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(csfs_inactive_keeps_80_byte_limit)
{
    CCoinsView base;
    CCoinsViewCache coins(&base);
    AddP2WSHCoin(coins, kPrevHash);

    // 80 B: exactly at the legacy limit — accepted
    CTransaction ok = MakeWitnessTx(kPrevHash,
        {std::vector<unsigned char>(80, 0xab)});
    BOOST_CHECK(IsWitnessStandard(ok, coins, false));

    // 81 B: one byte over — rejected
    CTransaction ng = MakeWitnessTx(kPrevHash,
        {std::vector<unsigned char>(81, 0xab)});
    BOOST_CHECK(!IsWitnessStandard(ng, coins, false));
}

// ---------------------------------------------------------------------------
// csfsActive = true: raised cap (MAX_CSFS_STANDARD_P2WSH_STACK_ITEM_SIZE)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(csfs_active_allows_pq_sig_size)
{
    CCoinsView base;
    CCoinsViewCache coins(&base);
    AddP2WSHCoin(coins, kPrevHash);

    // 2421 B — ML-DSA-44 signature size; must be accepted under CSFS
    CTransaction tx = MakeWitnessTx(kPrevHash,
        {std::vector<unsigned char>(2421, 0xab)});
    BOOST_CHECK(IsWitnessStandard(tx, coins, true));
}

BOOST_AUTO_TEST_CASE(csfs_active_allows_pq_pubkey_size)
{
    CCoinsView base;
    CCoinsViewCache coins(&base);
    AddP2WSHCoin(coins, kPrevHash);

    // 1313 B — ML-DSA-44 pubkey size; must be accepted under CSFS
    CTransaction tx = MakeWitnessTx(kPrevHash,
        {std::vector<unsigned char>(1313, 0xab)});
    BOOST_CHECK(IsWitnessStandard(tx, coins, true));
}

BOOST_AUTO_TEST_CASE(csfs_active_allows_up_to_cap_and_rejects_over)
{
    CCoinsView base;
    CCoinsViewCache coins(&base);
    AddP2WSHCoin(coins, kPrevHash);

    // Exactly MAX_CSFS_STANDARD_P2WSH_STACK_ITEM_SIZE (3072 B): accepted
    CTransaction ok = MakeWitnessTx(kPrevHash,
        {std::vector<unsigned char>(MAX_CSFS_STANDARD_P2WSH_STACK_ITEM_SIZE, 0xab)});
    BOOST_CHECK(IsWitnessStandard(ok, coins, true));

    // One byte over the cap: rejected
    CTransaction ng = MakeWitnessTx(kPrevHash,
        {std::vector<unsigned char>(MAX_CSFS_STANDARD_P2WSH_STACK_ITEM_SIZE + 1, 0xab)});
    BOOST_CHECK(!IsWitnessStandard(ng, coins, true));
}

// ---------------------------------------------------------------------------
// Limits unchanged by NIP-021
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(witnessscript_size_limit_unchanged)
{
    // The witnessScript (last item) is capped at MAX_STANDARD_P2WSH_SCRIPT_SIZE
    // (3600 B) regardless of csfsActive. NIP-021 does not touch that check.
    CCoinsView base;
    CCoinsViewCache coins(&base);
    AddP2WSHCoin(coins, kPrevHash);

    // 3600 B witnessScript (no other items): accepted
    {
        CMutableTransaction tx;
        tx.nVersion = 1;
        tx.vin.resize(1);
        tx.vout.resize(1);
        tx.vin[0].prevout = COutPoint(kPrevHash, 0);
        tx.vin[0].scriptWitness.stack.push_back(
            std::vector<unsigned char>(3600, 0xab));
        tx.vout[0].nValue = 0;
        BOOST_CHECK(IsWitnessStandard(CTransaction(tx), coins, true));
    }
    // 3601 B witnessScript: rejected regardless of csfsActive
    {
        CMutableTransaction tx;
        tx.nVersion = 1;
        tx.vin.resize(1);
        tx.vout.resize(1);
        tx.vin[0].prevout = COutPoint(kPrevHash, 0);
        tx.vin[0].scriptWitness.stack.push_back(
            std::vector<unsigned char>(3601, 0xab));
        tx.vout[0].nValue = 0;
        BOOST_CHECK(!IsWitnessStandard(CTransaction(tx), coins, true));
    }
}

BOOST_AUTO_TEST_CASE(item_count_limit_unchanged)
{
    // MAX_STANDARD_P2WSH_STACK_ITEMS (100) is not touched by NIP-021.
    // sizeWitnessStack = stack.size() - 1 (excluding the witnessScript).
    CCoinsView base;
    CCoinsViewCache coins(&base);
    AddP2WSHCoin(coins, kPrevHash);

    // 100 non-script items + witnessScript: sizeWitnessStack == 100 (not > 100) — accepted
    {
        std::vector<std::vector<unsigned char>> items(
            MAX_STANDARD_P2WSH_STACK_ITEMS, std::vector<unsigned char>(1, 0xab));
        CTransaction tx = MakeWitnessTx(kPrevHash, items);
        BOOST_CHECK(IsWitnessStandard(tx, coins, true));
    }
    // 101 non-script items + witnessScript: sizeWitnessStack == 101 (> 100) — rejected
    {
        std::vector<std::vector<unsigned char>> items(
            MAX_STANDARD_P2WSH_STACK_ITEMS + 1, std::vector<unsigned char>(1, 0xab));
        CTransaction tx = MakeWitnessTx(kPrevHash, items);
        BOOST_CHECK(!IsWitnessStandard(tx, coins, true));
    }
}

BOOST_AUTO_TEST_SUITE_END()
