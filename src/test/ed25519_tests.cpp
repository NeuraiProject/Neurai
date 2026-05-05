// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-035: tests for crypto/ed25519.{h,cpp} strict-profile verifier.
//
// The hex values below MUST stay byte-exactly in sync with
// src/test/data/ed25519_vectors.json (NIP-035 §8). The JSON file is
// the human-readable single source of truth; these inline values are
// the machine-checkable mirror — same convention as poseidon_vectors.
//
// Test scope today:
//   - structural / canonical-encoding rejections that DO NOT need the
//     vendored ref10 backend run as ordinary BOOST_CHECK_EQUAL asserts.
//   - PureEd25519 verification asserts are wired with the canonical
//     RFC 8032 §7.1 KAT but tagged BOOST_AUTO_TEST_CASE_EXPECTED_FAILURES
//     because crypto/ed25519.cpp::VerifyStrict() is currently a stub.
//     When the ref10 backend lands, drop those decorators in a single
//     diff and the same tests start passing for real.

#include "crypto/ed25519.h"
#include "data/wycheproof_ed25519.json.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "test/test_neurai.h"
#include "utilstrencodings.h"

#include <cstring>
#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>
#include <univalue.h>

using crypto::ed25519::PUBKEY_SIZE;
using crypto::ed25519::SIG_SIZE;
using crypto::ed25519::StructuralResult;
using crypto::ed25519::ValidatePubkey;
using crypto::ed25519::ValidateSignature;
using crypto::ed25519::VerifyStrict;

namespace {

std::vector<unsigned char> H(const std::string& hex)
{
    return ParseHex(hex);
}

bool VerifyHex(const std::string& pk_hex,
               const std::string& sig_hex,
               const std::string& msg_hex)
{
    auto pk  = H(pk_hex);
    auto sig = H(sig_hex);
    auto msg = H(msg_hex);
    return VerifyStrict(pk.data(), pk.size(),
                        sig.data(), sig.size(),
                        msg.data(), msg.size());
}

} // namespace

// =====================================================================
// Suite 1: structural / canonical-encoding rejections.
//
// These assertions are true for the strict NIP-035 §4.4 profile and do
// not depend on the curve-arithmetic backend. They must always pass.
// =====================================================================

BOOST_FIXTURE_TEST_SUITE(ed25519_structural_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(pubkey_size_rejects)
{
    auto short_pk = H("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f70751");
    auto long_pk  = H("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a00");
    BOOST_CHECK(short_pk.size() == 31);
    BOOST_CHECK(long_pk.size()  == 33);

    BOOST_CHECK(ValidatePubkey(short_pk.data(), short_pk.size())
                    == StructuralResult::PUBKEY_SIZE_INVALID);
    BOOST_CHECK(ValidatePubkey(long_pk.data(),  long_pk.size())
                    == StructuralResult::PUBKEY_SIZE_INVALID);
}

BOOST_AUTO_TEST_CASE(signature_size_rejects)
{
    auto short_sig = H("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a10");
    auto long_sig  = H("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b00");
    BOOST_CHECK(short_sig.size() == 63);
    BOOST_CHECK(long_sig.size()  == 65);

    BOOST_CHECK(ValidateSignature(short_sig.data(), short_sig.size())
                    == StructuralResult::SIG_SIZE_INVALID);
    BOOST_CHECK(ValidateSignature(long_sig.data(),  long_sig.size())
                    == StructuralResult::SIG_SIZE_INVALID);
}

BOOST_AUTO_TEST_CASE(pubkey_y_geq_p_rejects)
{
    // y == 2^255 - 1 (top byte 0x7f, sign bit clear, all other bytes 0xff).
    auto pk_2255m1 = H("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    // y == p exactly (low byte 0xed, middle 0xff..0xff, top byte 0x7f).
    auto pk_eq_p   = H("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");

    BOOST_CHECK(ValidatePubkey(pk_2255m1.data(), pk_2255m1.size())
                    == StructuralResult::PUBKEY_NON_CANONICAL);
    BOOST_CHECK(ValidatePubkey(pk_eq_p.data(),   pk_eq_p.size())
                    == StructuralResult::PUBKEY_NON_CANONICAL);
}

BOOST_AUTO_TEST_CASE(pubkey_y_eq_p_minus_1_is_order_2_torsion)
{
    // y == p - 1 == -1 mod p (top byte 0x7f, low byte 0xec, rest 0xff).
    // Canonical-y passes (y < p), the encoding decompresses to the
    // unique x = 0 root, and (0, -1) is the order-2 torsion generator.
    // The strict NIP-035 §4.4 profile MUST reject it as non-subgroup.
    auto pk = H("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    BOOST_CHECK(ValidatePubkey(pk.data(), pk.size())
                    == StructuralResult::PUBKEY_NON_SUBGROUP);
}

BOOST_AUTO_TEST_CASE(pubkey_identity_is_order_1_torsion)
{
    // Encoded identity point: (0, 1). Decompresses, but is the
    // order-1 small-torsion point. Strict profile must reject.
    auto pk = H("0100000000000000000000000000000000000000000000000000000000000000");
    BOOST_CHECK(ValidatePubkey(pk.data(), pk.size())
                    == StructuralResult::PUBKEY_NON_SUBGROUP);
}

BOOST_AUTO_TEST_CASE(signature_S_geq_l_rejects)
{
    // l in little-endian is
    //   ed d3 f5 5c 1a 63 12 58 d6 9c f7 a2 de f9 de 14
    //   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10
    // so S = l exactly is the lower-bound non-canonical case (the
    // strict NIP-035 §4.4 rule is S < l, not S <= l). R is taken from
    // RFC 8032 §7.1 test 1 so the R byte half stays canonical and the
    // failure attributes to S.
    auto sig_S_eq_l = H("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
    BOOST_CHECK_EQUAL(sig_S_eq_l.size(), SIG_SIZE);
    BOOST_CHECK(ValidateSignature(sig_S_eq_l.data(), sig_S_eq_l.size())
                    == StructuralResult::SIG_S_NON_CANONICAL);

    // S = all-ones, far above l.
    auto sig_S_ff = H("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    BOOST_CHECK(ValidateSignature(sig_S_ff.data(), sig_S_ff.size())
                    == StructuralResult::SIG_S_NON_CANONICAL);
}

BOOST_AUTO_TEST_CASE(signature_R_y_geq_p_rejects)
{
    // R.y == 2^255 - 1. S irrelevant for this branch (taken from test 1).
    auto sig_R_2255m1 = H("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    BOOST_CHECK(ValidateSignature(sig_R_2255m1.data(), sig_R_2255m1.size())
                    == StructuralResult::SIG_R_NON_CANONICAL);
}

BOOST_AUTO_TEST_CASE(rfc8032_kat_pubkeys_pass_structural)
{
    // The four RFC 8032 §7.1 PureEd25519 vectors. Every pubkey is a
    // canonical small-coordinate Edwards25519 point — structural
    // validation accepts them without needing curve arithmetic.
    const char* pks[] = {
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
    };
    for (const char* hex : pks) {
        auto pk = H(hex);
        BOOST_CHECK_EQUAL(static_cast<int>(ValidatePubkey(pk.data(), pk.size())),
                          static_cast<int>(StructuralResult::OK));
    }
}

BOOST_AUTO_TEST_CASE(rfc8032_kat_signatures_pass_structural)
{
    const char* sigs[] = {
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    };
    for (const char* hex : sigs) {
        auto sig = H(hex);
        BOOST_CHECK_EQUAL(static_cast<int>(ValidateSignature(sig.data(), sig.size())),
                          static_cast<int>(StructuralResult::OK));
    }
}

BOOST_AUTO_TEST_SUITE_END()

// =====================================================================
// Suite 2: PureEd25519 verification (RFC 8032 §7.1 KATs).
//
// VerifyStrict() must accept the canonical KAT bit-exactly.
// =====================================================================

BOOST_FIXTURE_TEST_SUITE(ed25519_verify_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(rfc8032_test_1_empty_message)
{
    BOOST_CHECK(VerifyHex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ""));
}

BOOST_AUTO_TEST_CASE(rfc8032_test_2_one_byte)
{
    BOOST_CHECK(VerifyHex(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        "72"));
}

BOOST_AUTO_TEST_CASE(rfc8032_test_3_two_bytes)
{
    BOOST_CHECK(VerifyHex(
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        "af82"));
}

BOOST_AUTO_TEST_CASE(rfc8032_test_sha_abc_64_bytes)
{
    BOOST_CHECK(VerifyHex(
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
}

BOOST_AUTO_TEST_CASE(verify_rejects_bit_flip_in_signature_R)
{
    // Test 1 vector with a single bit flipped in R[0]. Must fail.
    BOOST_CHECK(!VerifyHex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "e4564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ""));
}

BOOST_AUTO_TEST_CASE(verify_rejects_wrong_message)
{
    // Test 2 vector but message is "73" instead of "72". Must fail.
    BOOST_CHECK(!VerifyHex(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        "73"));
}

BOOST_AUTO_TEST_CASE(verify_rejects_wrong_pubkey)
{
    // Test 1 R/S/msg with a different (canonical) pubkey. Must fail.
    BOOST_CHECK(!VerifyHex(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ""));
}

BOOST_AUTO_TEST_SUITE_END()

// =====================================================================
// Suite 2.5: Project Wycheproof EDDSA verify vectors (NIP-035 §8).
//
// Wycheproof's v1 schema has just two outcomes per vector:
//   - "valid"   → strict verify must accept
//   - "invalid" → strict verify must reject
//
// The ZIP-215-leniency cases (which used to be tagged "acceptable" in
// the v0 schema) are now folded into "invalid" in v1: Google's stance
// is that strict-rejection is the correct behavior, so a backend that
// silently relaxes to ZIP-215 would fail those. That is exactly the
// regression net we want — see NIP-035 §4.4.
//
// Test buckets exercised: InvalidEncoding, SignatureMalleability
// (S >= l), InvalidSignature (R/S edge cases), TruncatedSignature,
// SignatureWithGarbage, CompressedSignature, InvalidKtv. All must
// reject. We expect 88 valid / 62 invalid in the current vector set
// (numberOfTests = 150).
// =====================================================================

namespace {

UniValue ReadEd25519WycheproofJson()
{
    UniValue v;
    std::string s(json_tests::wycheproof_ed25519,
                  json_tests::wycheproof_ed25519 + sizeof(json_tests::wycheproof_ed25519));
    BOOST_REQUIRE(v.read(s));
    return v;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(ed25519_wycheproof_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(every_vector_matches_strict_profile)
{
    UniValue root = ReadEd25519WycheproofJson();
    BOOST_REQUIRE(root.isObject());

    // Sanity-check the schema and the headline counts. If Google bumps
    // the schema, the parser below may need to follow.
    BOOST_CHECK_EQUAL(root["algorithm"].get_str(), "EDDSA");
    BOOST_CHECK_EQUAL(root["schema"].get_str(), "eddsa_verify_schema_v1.json");

    const UniValue& groups = root["testGroups"].get_array();
    BOOST_CHECK_GT(groups.size(), 0U);

    size_t total = 0;
    size_t valid_seen = 0;
    size_t invalid_seen = 0;

    for (size_t gi = 0; gi < groups.size(); ++gi) {
        const UniValue& g = groups[gi];
        const std::string pk_hex = g["publicKey"]["pk"].get_str();
        const auto pk = ParseHex(pk_hex);

        const UniValue& tests = g["tests"].get_array();
        for (size_t ti = 0; ti < tests.size(); ++ti) {
            const UniValue& t = tests[ti];
            const int tcId = t["tcId"].get_int();
            const std::string result = t["result"].get_str();
            const auto msg = ParseHex(t["msg"].get_str());
            const auto sig = ParseHex(t["sig"].get_str());

            const bool got = crypto::ed25519::VerifyStrict(
                pk.data(),  pk.size(),
                sig.data(), sig.size(),
                msg.data(), msg.size());

            const bool want = (result == "valid");
            if (got != want) {
                BOOST_ERROR("Wycheproof tcId " << tcId
                            << " (" << result << ", flags="
                            << t["flags"].write() << ", comment=\""
                            << t["comment"].get_str() << "\"): expected "
                            << (want ? "accept" : "reject")
                            << ", got "
                            << (got ? "accept" : "reject"));
            }
            ++total;
            if (want) ++valid_seen; else ++invalid_seen;
        }
    }

    // Headline counts pinned for the May 2026 vector set. If Google
    // adds new vectors, bump these constants and review the new cases.
    BOOST_CHECK_EQUAL(total, 150U);
    BOOST_CHECK_EQUAL(valid_seen, 88U);
    BOOST_CHECK_EQUAL(invalid_seen, 62U);
}

BOOST_AUTO_TEST_SUITE_END()

// =====================================================================
// Suite 3: OP_CHECKSIG_ED25519 in EvalScript (NIP-035 §4.6 gating +
// §4.4 strict acceptance + §4.5 error mapping). Mirrors the pattern
// of poseidon_tests' "Suite 4" gating block.
// =====================================================================

BOOST_FIXTURE_TEST_SUITE(ed25519_script_tests, BasicTestingSetup)

namespace {

bool RunEd25519Script(const CScript& script, script_verify_flags flags,
                     ScriptError& err)
{
    std::vector<std::vector<unsigned char>> stack;
    return EvalScript(stack, script, flags, BaseSignatureChecker(),
                      SIGVERSION_BASE, &err);
}

bool RunEd25519ScriptWithStackTop(const CScript& script,
                                  script_verify_flags flags,
                                  ScriptError& err,
                                  std::vector<unsigned char>& top_out)
{
    std::vector<std::vector<unsigned char>> stack;
    bool ok = EvalScript(stack, script, flags, BaseSignatureChecker(),
                         SIGVERSION_BASE, &err);
    if (ok && !stack.empty()) top_out = stack.back();
    return ok;
}

// Builds <sig> <msg> <pubkey> OP_CHECKSIG_ED25519 from hex inputs.
CScript Ed25519CheckSigScript(const std::string& sig_hex,
                              const std::string& msg_hex,
                              const std::string& pk_hex)
{
    CScript s;
    s << ParseHex(sig_hex) << ParseHex(msg_hex) << ParseHex(pk_hex)
      << OP_CHECKSIG_ED25519;
    return s;
}

// RFC 8032 §7.1 test 1 (empty message) inputs reused throughout the suite.
const std::string KAT1_PK =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const std::string KAT1_SIG =
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

} // namespace

// --- Activation gate (§4.6 / §4.7). ----------------------------------

BOOST_AUTO_TEST_CASE(gating_flag_off_returns_bad_opcode)
{
    // Empty stack + OP_CHECKSIG_ED25519, flag off → BAD_OPCODE
    // (must fire before the stack-underflow check, mirroring NIP-036).
    CScript s;
    s << OP_CHECKSIG_ED25519;
    ScriptError err;
    BOOST_CHECK(!RunEd25519Script(s, SCRIPT_VERIFY_NONE, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(gating_flag_off_is_not_nop)
{
    // Even with all 3 stack items present, flag-off must reject as
    // BAD_OPCODE — confirming the slot is NOT a discouraged-NOP.
    CScript s = Ed25519CheckSigScript(KAT1_SIG, /*msg=*/ "", KAT1_PK);
    ScriptError err;
    BOOST_CHECK(!RunEd25519Script(s, SCRIPT_VERIFY_NONE, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(gating_underflow_flag_on)
{
    // Flag on, empty stack → INVALID_STACK_OPERATION.
    CScript s;
    s << OP_CHECKSIG_ED25519;
    ScriptError err;
    BOOST_CHECK(!RunEd25519Script(s, SCRIPT_VERIFY_ED25519, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(gating_underflow_only_two_items)
{
    // Flag on, only 2 of 3 stack items → INVALID_STACK_OPERATION.
    CScript s;
    s << ParseHex(KAT1_SIG) << ParseHex("") << OP_CHECKSIG_ED25519;
    ScriptError err;
    BOOST_CHECK(!RunEd25519Script(s, SCRIPT_VERIFY_ED25519, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_INVALID_STACK_OPERATION);
}

// --- Successful KAT verify pushes 1. --------------------------------

BOOST_AUTO_TEST_CASE(script_kat_pushes_one)
{
    CScript s = Ed25519CheckSigScript(KAT1_SIG, /*msg=*/ "", KAT1_PK);
    std::vector<unsigned char> top;
    ScriptError err;
    BOOST_CHECK(RunEd25519ScriptWithStackTop(s, SCRIPT_VERIFY_ED25519, err, top));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(top.size(), 1U);
    BOOST_CHECK_EQUAL(top[0], 1U);
}

// --- Well-formed-but-invalid signature pushes 0 (no script error). --

BOOST_AUTO_TEST_CASE(script_wrong_message_pushes_zero)
{
    // KAT1 sig+pk but message is "ff" instead of empty.
    CScript s = Ed25519CheckSigScript(KAT1_SIG, /*msg=*/ "ff", KAT1_PK);
    std::vector<unsigned char> top;
    ScriptError err;
    BOOST_CHECK(RunEd25519ScriptWithStackTop(s, SCRIPT_VERIFY_ED25519, err, top));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    BOOST_CHECK(top.empty()); // CScriptNum 0 is encoded as empty.
}

// --- Malformed inputs are hard SCRIPT_ERR_* (consensus errors). -----

BOOST_AUTO_TEST_CASE(script_pubkey_size_invalid)
{
    // 31-byte pubkey.
    CScript s = Ed25519CheckSigScript(
        KAT1_SIG, "",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f70751");
    ScriptError err;
    BOOST_CHECK(!RunEd25519Script(s, SCRIPT_VERIFY_ED25519, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_ED25519_PUBKEY_SIZE);
}

BOOST_AUTO_TEST_CASE(script_signature_size_invalid)
{
    // 63-byte signature.
    CScript s = Ed25519CheckSigScript(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a10",
        "", KAT1_PK);
    ScriptError err;
    BOOST_CHECK(!RunEd25519Script(s, SCRIPT_VERIFY_ED25519, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_ED25519_SIG_SIZE);
}

BOOST_AUTO_TEST_CASE(script_pubkey_non_canonical)
{
    // y == 2^255 - 1, fails ge25519_is_canonical.
    CScript s = Ed25519CheckSigScript(
        KAT1_SIG, "",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    ScriptError err;
    BOOST_CHECK(!RunEd25519Script(s, SCRIPT_VERIFY_ED25519, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_ED25519_PUBKEY_ENCODING);
}

BOOST_AUTO_TEST_CASE(script_signature_S_eq_l)
{
    // R = test 1 R, S = l (boundary, must reject).
    CScript s = Ed25519CheckSigScript(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010",
        "", KAT1_PK);
    ScriptError err;
    BOOST_CHECK(!RunEd25519Script(s, SCRIPT_VERIFY_ED25519, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_ED25519_SIG_ENCODING);
}

// --- OP_VERIFY composition (§5.1 fail-fast pattern). ----------------

BOOST_AUTO_TEST_CASE(script_op_verify_after_success)
{
    CScript s;
    s << ParseHex(KAT1_SIG) << ParseHex("") << ParseHex(KAT1_PK)
      << OP_CHECKSIG_ED25519 << OP_VERIFY << OP_1;
    std::vector<unsigned char> top;
    ScriptError err;
    BOOST_CHECK(RunEd25519ScriptWithStackTop(s, SCRIPT_VERIFY_ED25519, err, top));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
    BOOST_REQUIRE_EQUAL(top.size(), 1U);
    BOOST_CHECK_EQUAL(top[0], 1U);
}

BOOST_AUTO_TEST_CASE(script_op_verify_after_failure)
{
    // KAT1 with wrong message → push 0 → OP_VERIFY fails through
    // SCRIPT_ERR_VERIFY (the standard verify-failure path).
    CScript s;
    s << ParseHex(KAT1_SIG) << ParseHex("ff") << ParseHex(KAT1_PK)
      << OP_CHECKSIG_ED25519 << OP_VERIFY;
    ScriptError err;
    BOOST_CHECK(!RunEd25519Script(s, SCRIPT_VERIFY_ED25519, err));
    BOOST_CHECK_EQUAL(err, SCRIPT_ERR_VERIFY);
}

BOOST_AUTO_TEST_SUITE_END()
