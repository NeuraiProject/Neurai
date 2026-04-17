// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-019: non-consensus RPC/wallet/keystore plumbing for PQ-sized scripts.
// Verifies that structural validators (HasValidOps) and the keystore
// (CBasicKeyStore::AddCScript) accept scripts up to
// MAX_PQ_SCRIPT_ELEMENT_SIZE and reject anything larger.
//
// Full RPC-level verification (sendrawtransaction, signrawtransactionwithkey,
// importaddress/importmulti round-trip, LoadCScript restart) belongs to the
// functional test suite; those scenarios cannot be exercised from a
// stand-alone Boost unit test without wiring up a full node + wallet.

#include "keystore.h"
#include "script/script.h"
#include "test/test_neurai.h"

#include <boost/test/unit_test.hpp>

#include <vector>

namespace {

CScript ScriptWithPush(size_t n)
{
    std::vector<unsigned char> data(n, 0x5a);
    CScript s;
    s << data;
    return s;
}

// A CScript whose serialized size is exactly `n` bytes. Useful to exercise
// CBasicKeyStore::AddCScript, which caps the redeemScript's total size, not
// the size of any push within it.
CScript RawScriptOfSize(size_t n)
{
    std::vector<unsigned char> raw(n, 0x51); // OP_1 padding — any valid opcode
    return CScript(raw.begin(), raw.end());
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(pq_rpc_wallet_support_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// HasValidOps — structural decoder cap (Class A)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(hasvalidops_accepts_legacy_max)
{
    CScript s = ScriptWithPush(MAX_SCRIPT_ELEMENT_SIZE);
    BOOST_CHECK(s.HasValidOps());
}

BOOST_AUTO_TEST_CASE(hasvalidops_accepts_pq_max)
{
    CScript s = ScriptWithPush(MAX_PQ_SCRIPT_ELEMENT_SIZE);
    BOOST_CHECK(s.HasValidOps());
}

BOOST_AUTO_TEST_CASE(hasvalidops_accepts_intermediate_2000)
{
    // 2000 B push: would be rejected pre-NIP-019 (>520), now accepted.
    CScript s = ScriptWithPush(2000);
    BOOST_CHECK(s.HasValidOps());
}

BOOST_AUTO_TEST_CASE(hasvalidops_rejects_above_pq_max)
{
    CScript s = ScriptWithPush(MAX_PQ_SCRIPT_ELEMENT_SIZE + 1);
    BOOST_CHECK(!s.HasValidOps());
}

BOOST_AUTO_TEST_CASE(hasvalidops_rejects_truncated_push)
{
    // Build a PUSHDATA2 header that claims 1000 bytes of payload, but
    // supply no data. Regression guard: structural validator must still
    // reject malformed scripts unrelated to the size bump.
    CScript s;
    s.resize(3);
    s[0] = OP_PUSHDATA2;
    s[1] = 0xe8; // 1000 LSB
    s[2] = 0x03; // 1000 MSB
    BOOST_CHECK(!s.HasValidOps());
}

// ---------------------------------------------------------------------------
// CBasicKeyStore::AddCScript — wallet keystore cap (Class B)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(keystore_accepts_legacy_max_script)
{
    // Use a raw script of exactly MAX_SCRIPT_ELEMENT_SIZE bytes. AddCScript
    // caps the redeemScript's total serialized size, not the size of any
    // inner push, so constructing via ScriptWithPush would overshoot by the
    // push-prefix bytes.
    CBasicKeyStore keystore;
    CScript s = RawScriptOfSize(MAX_SCRIPT_ELEMENT_SIZE);
    BOOST_CHECK(keystore.AddCScript(s));
    BOOST_CHECK(keystore.HaveCScript(CScriptID(s)));
}

BOOST_AUTO_TEST_CASE(keystore_accepts_pq_sized_script)
{
    // 3000 B — a representative "PQ-multisig-like" redeemScript size.
    // Pre-NIP-019 this would have been rejected at the 520 B cap.
    CBasicKeyStore keystore;
    CScript s = ScriptWithPush(3000);
    BOOST_CHECK(keystore.AddCScript(s));
    BOOST_CHECK(keystore.HaveCScript(CScriptID(s)));

    CScript roundtrip;
    BOOST_CHECK(keystore.GetCScript(CScriptID(s), roundtrip));
    BOOST_CHECK(roundtrip == s);
}

BOOST_AUTO_TEST_CASE(keystore_accepts_pq_max_script)
{
    CBasicKeyStore keystore;
    CScript s = RawScriptOfSize(MAX_PQ_SCRIPT_ELEMENT_SIZE);
    BOOST_CHECK(keystore.AddCScript(s));
}

BOOST_AUTO_TEST_CASE(keystore_rejects_above_pq_max_script)
{
    CBasicKeyStore keystore;
    CScript s = RawScriptOfSize(MAX_PQ_SCRIPT_ELEMENT_SIZE + 1);
    BOOST_CHECK(!keystore.AddCScript(s));
    BOOST_CHECK(!keystore.HaveCScript(CScriptID(s)));
}

BOOST_AUTO_TEST_CASE(keystore_multiple_pq_scripts_roundtrip)
{
    // Store two distinct PQ-sized scripts and confirm both round-trip.
    CBasicKeyStore keystore;
    std::vector<unsigned char> blob1(3000, 0xaa);
    std::vector<unsigned char> blob2(2800, 0xbb);
    CScript s1; s1 << blob1;
    CScript s2; s2 << blob2;

    BOOST_CHECK(keystore.AddCScript(s1));
    BOOST_CHECK(keystore.AddCScript(s2));

    CScript out1, out2;
    BOOST_CHECK(keystore.GetCScript(CScriptID(s1), out1));
    BOOST_CHECK(keystore.GetCScript(CScriptID(s2), out2));
    BOOST_CHECK(out1 == s1);
    BOOST_CHECK(out2 == s2);
}

BOOST_AUTO_TEST_SUITE_END()
