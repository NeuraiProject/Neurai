// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NIP revision 010: the strict OP_XNA_ASSET rejection must be gated by
// nXNAAssetStrictEnabled. On mainnet (strict off) CheckTransaction must
// reproduce origin/main byte-for-byte; on testnet/regtest (strict on) the
// strict rule stays in force.

#include "chainparams.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "test/test_neurai.h"

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

// RAII guard: SelectParams mutates the global CChainParams; restore it so the
// switch does not leak into later test cases.
struct NetworkGuard {
    std::string previous;
    explicit NetworkGuard(const std::string& net) : previous(GetParams().NetworkIDString()) {
        SelectParams(net);
    }
    ~NetworkGuard() {
        // NetworkIDString() returns "main"/"test"/"regtest"; map back.
        if (previous == "main") SelectParams(CBaseChainParams::MAIN);
        else if (previous == "test") SelectParams(CBaseChainParams::TESTNET);
        else SelectParams(CBaseChainParams::REGTEST);
    }
};

// Build a minimal plain (non-coinbase, non-asset-issuance) tx carrying a
// single output whose scriptPubKey is exactly `spk`. It reaches the generic
// OP_XNA_ASSET check in CheckTransaction.
CMutableTransaction MakeTxWithOutput(const CScript& spk)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    CTxIn vin;
    vin.prevout.hash = uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    vin.prevout.n = 0; // non-null prevout
    mtx.vin.push_back(vin);
    mtx.vout.emplace_back(0, spk);
    return mtx;
}

// script that starts with OP_XNA_ASSET but is not a valid asset/null-asset
// script: OP_XNA_ASSET OP_TRUE (>= 2 bytes, avoids the standard.cpp OOB edge).
CScript XnaFirstUnparseable()
{
    return CScript() << OP_XNA_ASSET << OP_TRUE;
}

// P2PKH (25 bytes) followed by OP_XNA_ASSET at byte 25 + trailing byte: the
// opcode is in an "expected" position for the strict helper but NOT at byte 0,
// so origin/main (lenient) rejects it.
CScript P2pkhThenXnaAt25()
{
    std::vector<unsigned char> hash20(20, 0x11);
    CScript s;
    s << OP_DUP << OP_HASH160 << hash20 << OP_EQUALVERIFY << OP_CHECKSIG
      << OP_XNA_ASSET << OP_TRUE;
    return s;
}

std::string RejectReason(const CScript& spk)
{
    const CTransaction tx(MakeTxWithOutput(spk));
    CValidationState state;
    bool ok = CheckTransaction(tx, state);
    return ok ? std::string() : state.GetRejectReason();
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(xna_asset_gating_tests, BasicTestingSetup)

// Test 1: the core regression — 0xc0-first, unparseable.
BOOST_AUTO_TEST_CASE(xna_first_unparseable_gated_by_network)
{
    const CScript spk = XnaFirstUnparseable();
    // Sanity: the vector actually exercises the differential branch.
    BOOST_REQUIRE(!spk.IsAssetScript());
    BOOST_REQUIRE(!spk.IsNullAsset());

    {
        NetworkGuard g(CBaseChainParams::REGTEST); // strict on
        BOOST_CHECK_EQUAL(RejectReason(spk), "bad-txns-bad-asset-script");
    }
    {
        NetworkGuard g(CBaseChainParams::MAIN); // strict off → origin/main accepts
        BOOST_CHECK_EQUAL(RejectReason(spk), std::string());
    }
}

// Test 2: 0xc0 out of position — rejected in BOTH modes (gating must not
// loosen this).
BOOST_AUTO_TEST_CASE(xna_out_of_position_rejected_both_modes)
{
    const CScript spk = CScript() << OP_TRUE << OP_XNA_ASSET;
    BOOST_REQUIRE(!spk.IsAssetScript());
    BOOST_REQUIRE(!spk.IsNullAsset());

    {
        NetworkGuard g(CBaseChainParams::REGTEST);
        BOOST_CHECK_EQUAL(RejectReason(spk), "bad-txns-op-xna-asset-not-in-right-script-location");
    }
    {
        NetworkGuard g(CBaseChainParams::MAIN);
        BOOST_CHECK_EQUAL(RejectReason(spk), "bad-txns-op-xna-asset-not-in-right-script-location");
    }
}

// Test 3: the loosening trap — P2PKH + 0xc0 at byte 25. origin/main rejects it
// (script[0] != OP_XNA_ASSET); the lenient path must NOT accept it (which it
// would if it used HasAssetOpcodeInExpectedPosition).
BOOST_AUTO_TEST_CASE(xna_p2pkh_at_byte25_not_loosened_on_mainnet)
{
    const CScript spk = P2pkhThenXnaAt25();
    BOOST_REQUIRE(!spk.IsAssetScript());
    BOOST_REQUIRE(!spk.IsNullAsset());

    {
        NetworkGuard g(CBaseChainParams::MAIN); // lenient — must still reject
        BOOST_CHECK_EQUAL(RejectReason(spk), "bad-txns-op-xna-asset-not-in-right-script-location");
    }
    {
        NetworkGuard g(CBaseChainParams::REGTEST); // strict — rejects as bad script
        BOOST_CHECK_EQUAL(RejectReason(spk), "bad-txns-bad-asset-script");
    }
}

// Test 4: a plain P2PKH output without OP_XNA_ASSET is accepted in both modes.
BOOST_AUTO_TEST_CASE(plain_output_accepted_both_modes)
{
    std::vector<unsigned char> hash20(20, 0x22);
    const CScript spk = CScript() << OP_DUP << OP_HASH160 << hash20 << OP_EQUALVERIFY << OP_CHECKSIG;
    BOOST_REQUIRE(!spk.IsAssetScript());

    {
        NetworkGuard g(CBaseChainParams::REGTEST);
        BOOST_CHECK_EQUAL(RejectReason(spk), std::string());
    }
    {
        NetworkGuard g(CBaseChainParams::MAIN);
        BOOST_CHECK_EQUAL(RejectReason(spk), std::string());
    }
}

BOOST_AUTO_TEST_SUITE_END()
