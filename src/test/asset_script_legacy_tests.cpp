// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NIP revision 011: IsAssetScript must recognize the legacy asset script
// formats present in mainnet history exactly like origin/main — including the
// doubled-OP_XNA_ASSET variant (c0 c0) that stalled IBD at block 1615824 —
// while keeping the new AuthScript route intact.

#include "amount.h"
#include "assets/assets.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/standard.h"
#include "test/test_neurai.h"
#include "utilstrencodings.h"

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

// The real mainnet scriptPubKey from tx 1074...f580 (block 1615824), output 0:
// P2PKH + doubled OP_XNA_ASSET + push17("rvnt" + "RCNF" transfer of 5 XNA-units) + OP_DROP
const char* RCNF_SCRIPT_HEX =
    "76a914cea85af9eb3b5db01239cf97ef1cc1786469be1988ac"
    "c0c01172766e740452434e460065cd1d0000000075";

CScript ScriptFromHex(const std::string& hex)
{
    std::vector<unsigned char> data = ParseHex(hex);
    return CScript(data.begin(), data.end());
}

CScript P2pkhPrefix()
{
    return CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x11)
                     << OP_EQUALVERIFY << OP_CHECKSIG;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(asset_script_legacy_tests, BasicTestingSetup)

// Test 1: the exact mainnet regression vector (doubled c0).
BOOST_AUTO_TEST_CASE(doubled_op_xna_asset_recognized)
{
    const CScript spk = ScriptFromHex(RCNF_SCRIPT_HEX);

    int nType = 0;
    bool fIsOwner = true;
    int nStartingIndex = 0;
    BOOST_REQUIRE(spk.IsAssetScript(nType, fIsOwner, nStartingIndex));
    BOOST_CHECK_EQUAL(nType, (int)TX_TRANSFER_ASSET);
    BOOST_CHECK(!fIsOwner);
    // "rvn" at byte 28 -> type marker at 31 -> serialized data starts at 32
    BOOST_CHECK_EQUAL(nStartingIndex, 32);

    CAssetTransfer transfer;
    std::string strAddress;
    BOOST_REQUIRE(TransferAssetFromScript(spk, transfer, strAddress));
    BOOST_CHECK_EQUAL(transfer.strName, "RCNF");
    BOOST_CHECK_EQUAL(transfer.nAmount, 5 * COIN);
}

// Test 1b: CheckTransaction no longer rejects a tx carrying that output.
BOOST_AUTO_TEST_CASE(doubled_op_xna_asset_passes_checktransaction)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    CTxIn vin;
    vin.prevout.hash = uint256S("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    vin.prevout.n = 0;
    mtx.vin.push_back(vin);
    mtx.vout.emplace_back(0, ScriptFromHex(RCNF_SCRIPT_HEX));
    mtx.vout.emplace_back(39674225, P2pkhPrefix());

    const CTransaction tx(mtx);
    CValidationState state;
    const bool ok = CheckTransaction(tx, state);
    BOOST_CHECK_MESSAGE(ok, "CheckTransaction rejected the historical tx: " + state.GetRejectReason());
    // The specific NIP-011 failure must be gone even if something else fails
    BOOST_CHECK(state.GetRejectReason() != "bad-txns-op-xna-asset-not-in-right-script-location");
    BOOST_CHECK(state.GetRejectReason() != "bad-txns-bad-asset-script");
}

// Test 2: standard single-c0 transfer (what our own code constructs) still works.
BOOST_AUTO_TEST_CASE(single_op_xna_asset_still_recognized)
{
    CScript spk = P2pkhPrefix();
    CAssetTransfer transfer("GOLD", 25 * COIN);
    transfer.ConstructTransaction(spk);

    int nType = 0;
    bool fIsOwner = true;
    int nStartingIndex = 0;
    BOOST_REQUIRE(spk.IsAssetScript(nType, fIsOwner, nStartingIndex));
    BOOST_CHECK_EQUAL(nType, (int)TX_TRANSFER_ASSET);
    // "rvn" at byte 27 -> type marker at 30 -> serialized data starts at 31
    BOOST_CHECK_EQUAL(nStartingIndex, 31);

    CAssetTransfer out;
    std::string strAddress;
    BOOST_REQUIRE(TransferAssetFromScript(spk, out, strAddress));
    BOOST_CHECK_EQUAL(out.strName, "GOLD");
    BOOST_CHECK_EQUAL(out.nAmount, 25 * COIN);
}

// Test 3: the new AuthScript route (OP_1 <32B> prefix) is intact.
BOOST_AUTO_TEST_CASE(authscript_asset_still_recognized)
{
    CScript spk = CScript() << OP_1 << std::vector<unsigned char>(32, 0xab);
    CAssetTransfer transfer("GOLD", 25 * COIN);
    transfer.ConstructTransaction(spk);

    int nType = 0;
    bool fIsOwner = true;
    int nStartingIndex = 0;
    BOOST_REQUIRE(spk.IsAssetScript(nType, fIsOwner, nStartingIndex));
    BOOST_CHECK_EQUAL(nType, (int)TX_TRANSFER_ASSET);

    CAssetTransfer out;
    std::string strAddress;
    BOOST_REQUIRE(TransferAssetFromScript(spk, out, strAddress));
    BOOST_CHECK_EQUAL(out.strName, "GOLD");
    BOOST_CHECK_EQUAL(out.nAmount, 25 * COIN);
}

// Test 4: nesting fidelity with origin/main — when byte 27 is XNA_R ('r') but
// 28/29 do not complete "rvn", the script is REJECTED without trying the
// byte-28 offset (a condensed if/else-if would wrongly accept "r r v n").
BOOST_AUTO_TEST_CASE(origin_main_nesting_fidelity)
{
    // P2PKH + c0 + bytes 26..: c0 'r' 'r' 'v' 'n' 't' ... — [27]='r' enters the
    // first branch, [28]='r' != 'v' -> reject (origin/main behavior).
    std::vector<unsigned char> raw = ParseHex(
        "76a914cea85af9eb3b5db01239cf97ef1cc1786469be1988ac"
        "c0c07272766e74000000000000000075");
    const CScript spk(raw.begin(), raw.end());

    int nType = 0;
    bool fIsOwner = false;
    int nStartingIndex = 0;
    BOOST_CHECK(!spk.IsAssetScript(nType, fIsOwner, nStartingIndex));
}

BOOST_AUTO_TEST_SUITE_END()
