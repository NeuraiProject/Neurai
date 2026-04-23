// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for NIP-012: script_verify_flags type-safe wrapper migration.

#include "script/interpreter.h"
#include "policy/policy.h"
#include "test/test_neurai.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(verify_flags_tests, BasicTestingSetup)

// --- Width tests ---

BOOST_AUTO_TEST_CASE(low_bit_flags_survive)
{
    // Verify that all currently assigned flags (bits 0-33) produce the
    // expected bitmask values through the wrapper.
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_P2SH}.as_int(),              uint64_t{1} << 0);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_STRICTENC}.as_int(),          uint64_t{1} << 1);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_DERSIG}.as_int(),             uint64_t{1} << 2);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_LOW_S}.as_int(),              uint64_t{1} << 3);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_NULLDUMMY}.as_int(),          uint64_t{1} << 4);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_SIGPUSHONLY}.as_int(),         uint64_t{1} << 5);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_MINIMALDATA}.as_int(),         uint64_t{1} << 6);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS}.as_int(), uint64_t{1} << 7);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_CLEANSTACK}.as_int(),          uint64_t{1} << 8);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY}.as_int(), uint64_t{1} << 9);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_CHECKSEQUENCEVERIFY}.as_int(), uint64_t{1} << 10);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_WITNESS}.as_int(),             uint64_t{1} << 11);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM}.as_int(), uint64_t{1} << 12);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_MINIMALIF}.as_int(),           uint64_t{1} << 13);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_NULLFAIL}.as_int(),            uint64_t{1} << 14);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_WITNESS_PUBKEYTYPE}.as_int(),  uint64_t{1} << 15);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_AUTHSCRIPT}.as_int(),          uint64_t{1} << 16);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_CAT}.as_int(),                 uint64_t{1} << 17);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_CHECKTEMPLATEVERIFY}.as_int(),  uint64_t{1} << 18);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_CHECKSIGFROMSTACK}.as_int(),   uint64_t{1} << 19);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_TXHASH}.as_int(),              uint64_t{1} << 20);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_TXFIELD}.as_int(),             uint64_t{1} << 21);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_SPLIT}.as_int(),               uint64_t{1} << 22);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_REVERSEBYTES}.as_int(),        uint64_t{1} << 23);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_OUTPUTVALUE}.as_int(),         uint64_t{1} << 24);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_TXLOCKTIME}.as_int(),          uint64_t{1} << 25);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_OUTPUTSCRIPT}.as_int(),        uint64_t{1} << 26);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_OUTPUTASSETFIELD}.as_int(),    uint64_t{1} << 27);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_64BIT_INTEGERS}.as_int(),      uint64_t{1} << 28);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_INPUTASSETFIELD}.as_int(),     uint64_t{1} << 29);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_INPUTOUTPUTCOUNT}.as_int(),    uint64_t{1} << 30);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_REFINPUTS}.as_int(),           uint64_t{1} << 31);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_OUTPUTAUTHCOMMITMENT}.as_int(), uint64_t{1} << 32);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_INPUTVALUE}.as_int(),          uint64_t{1} << 33);
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_CHAINCONTEXT}.as_int(),        uint64_t{1} << 34);
}

BOOST_AUTO_TEST_CASE(none_is_zero)
{
    BOOST_CHECK_EQUAL(SCRIPT_VERIFY_NONE.as_int(), 0ULL);
    BOOST_CHECK(!(SCRIPT_VERIFY_NONE));
    BOOST_CHECK(SCRIPT_VERIFY_NONE == 0);
}

BOOST_AUTO_TEST_CASE(end_marker_matches_flag_count)
{
    // 35 flags (bits 0-34) means END_MARKER should be 35.
    // Last added: SCRIPT_VERIFY_CHAINCONTEXT at bit 34 (NIP-026).
    BOOST_CHECK_EQUAL(MAX_SCRIPT_VERIFY_FLAGS_BITS, 35);
}

// --- No internal truncation ---

BOOST_AUTO_TEST_CASE(no_truncation)
{
    // Combine all known flags and verify no bits are lost.
    script_verify_flags all = script_verify_flags::from_int(MAX_SCRIPT_VERIFY_FLAGS);
    BOOST_CHECK_EQUAL(all.as_int(), (uint64_t{1} << 35) - 1);
}

BOOST_AUTO_TEST_CASE(chaincontext_is_bit_34)
{
    // NIP-026: OP_CHAINCONTEXT's verify flag must live at bit 34.
    // Pinned because covenants compiled against this bit will break if
    // the enum order ever changes.
    BOOST_CHECK_EQUAL(script_verify_flags{SCRIPT_VERIFY_CHAINCONTEXT}.as_int(),
                      uint64_t{1} << 34);
}

// --- Synthetic high-bit plumbing test ---

BOOST_AUTO_TEST_CASE(high_bit_survives_wrapper)
{
    // Define a temporary high bit above 31 — proves the migration is real.
    constexpr auto high_bit = script_verify_flags::from_int(uint64_t{1} << 40);
    BOOST_CHECK_EQUAL(high_bit.as_int(), uint64_t{1} << 40);

    // Combine with existing flags.
    script_verify_flags combined = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_CAT | high_bit;
    BOOST_CHECK(combined & SCRIPT_VERIFY_P2SH);
    BOOST_CHECK(combined & SCRIPT_VERIFY_CAT);
    BOOST_CHECK(combined & high_bit);

    // Remove a low flag.
    combined &= ~SCRIPT_VERIFY_CAT;
    BOOST_CHECK(!(combined & SCRIPT_VERIFY_CAT));
    BOOST_CHECK(combined & high_bit);

    // Round-trip through from_int / as_int.
    auto rt = script_verify_flags::from_int(combined.as_int());
    BOOST_CHECK(rt == combined);
}

// --- Bitwise operation tests ---

BOOST_AUTO_TEST_CASE(bitwise_operations)
{
    script_verify_flags a = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS;
    script_verify_flags b = SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CAT;

    // OR
    auto c = a | b;
    BOOST_CHECK(c & SCRIPT_VERIFY_P2SH);
    BOOST_CHECK(c & SCRIPT_VERIFY_WITNESS);
    BOOST_CHECK(c & SCRIPT_VERIFY_CAT);

    // AND
    auto d = a & b;
    BOOST_CHECK(!(d & SCRIPT_VERIFY_P2SH));
    BOOST_CHECK(d & SCRIPT_VERIFY_WITNESS);
    BOOST_CHECK(!(d & SCRIPT_VERIFY_CAT));

    // XOR
    auto e = a ^ b;
    BOOST_CHECK(e & SCRIPT_VERIFY_P2SH);
    BOOST_CHECK(!(e & SCRIPT_VERIFY_WITNESS));
    BOOST_CHECK(e & SCRIPT_VERIFY_CAT);

    // NOT
    auto f = ~SCRIPT_VERIFY_P2SH;
    BOOST_CHECK(!(f & SCRIPT_VERIFY_P2SH));
    BOOST_CHECK(f & SCRIPT_VERIFY_WITNESS);
}

// --- Comparison operators ---

BOOST_AUTO_TEST_CASE(comparison_operators)
{
    BOOST_CHECK(SCRIPT_VERIFY_P2SH == SCRIPT_VERIFY_P2SH);
    BOOST_CHECK(SCRIPT_VERIFY_P2SH != SCRIPT_VERIFY_CAT);
    BOOST_CHECK(SCRIPT_VERIFY_NONE == 0);
    BOOST_CHECK(SCRIPT_VERIFY_P2SH != SCRIPT_VERIFY_NONE);
}

// --- Policy masks match expected low bits ---

BOOST_AUTO_TEST_CASE(policy_masks_consistency)
{
    // MANDATORY is just P2SH.
    BOOST_CHECK(MANDATORY_SCRIPT_VERIFY_FLAGS == SCRIPT_VERIFY_P2SH);

    // STANDARD includes MANDATORY.
    BOOST_CHECK(STANDARD_SCRIPT_VERIFY_FLAGS & MANDATORY_SCRIPT_VERIFY_FLAGS);

    // NOT_MANDATORY = STANDARD & ~MANDATORY — should not contain P2SH.
    BOOST_CHECK(!(STANDARD_NOT_MANDATORY_VERIFY_FLAGS & SCRIPT_VERIFY_P2SH));
}

// --- sizeof(script_verify_flags) ---

BOOST_AUTO_TEST_CASE(wrapper_size)
{
    static_assert(sizeof(script_verify_flags) == sizeof(uint64_t),
                  "script_verify_flags must be 64-bit");
}

// --- from_int / as_int round-trip ---

BOOST_AUTO_TEST_CASE(from_int_as_int_roundtrip)
{
    constexpr uint64_t val = 0xDEADBEEF12345678ULL;
    auto flags = script_verify_flags::from_int(val);
    BOOST_CHECK_EQUAL(flags.as_int(), val);
}

BOOST_AUTO_TEST_SUITE_END()
