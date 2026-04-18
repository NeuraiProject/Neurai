// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-020: verify GetStandardScriptVerifyFlagsWithConsensusOptIns behavior.
//
// The helper is a pure function of a Consensus::Params value, so we can
// exercise every combination directly — no chain setup needed. The
// functional signrawtransactionwithkey round-trip belongs to the docker/
// regtest test path, not here.

#include "consensus/params.h"
#include "policy/policy.h"
#include "script/interpreter.h"
#include "test/test_neurai.h"

#include <boost/test/unit_test.hpp>

namespace {

// Build a Consensus::Params with every opt-in flag set to `on`.
Consensus::Params AllOptInsSetTo(bool on)
{
    Consensus::Params p{};
    p.nPQWitnessEnabled        = on;
    p.nCATEnabled              = on;
    p.nCTVEnabled              = on;
    p.nCSFSEnabled             = on;
    p.nTXHASHEnabled           = on;
    p.nTXFIELDEnabled          = on;
    p.nSPLITEnabled            = on;
    p.nREVERSEBYTESEnabled     = on;
    p.nOUTPUTVALUEEnabled      = on;
    p.nOUTPUTSCRIPTEnabled     = on;
    p.nOUTPUTASSETFIELDEnabled = on;
    p.nINPUTASSETFIELDEnabled  = on;
    p.n64BitIntegersEnabled    = on;
    p.nTXLOCKTIMEEnabled       = on;
    p.nINPUTOUTPUTCOUNTEnabled = on;
    p.nREFINPUTSEnabled        = on;
    return p;
}

} // anonymous namespace

BOOST_FIXTURE_TEST_SUITE(policy_pq_flags_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// Baseline: all opt-ins off ⇒ helper == STANDARD_SCRIPT_VERIFY_FLAGS.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(all_opt_ins_off_equals_standard)
{
    Consensus::Params p = AllOptInsSetTo(false);
    script_verify_flags flags = GetStandardScriptVerifyFlagsWithConsensusOptIns(p);
    BOOST_CHECK(flags == STANDARD_SCRIPT_VERIFY_FLAGS);
}

// ---------------------------------------------------------------------------
// Spot-check each opt-in: toggle a single bit on and confirm the helper
// adds exactly that flag to the standard baseline.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(csfs_only_adds_checksigfromstack)
{
    Consensus::Params p = AllOptInsSetTo(false);
    p.nCSFSEnabled = true;
    script_verify_flags flags = GetStandardScriptVerifyFlagsWithConsensusOptIns(p);
    BOOST_CHECK(flags == (STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_CHECKSIGFROMSTACK));
}

BOOST_AUTO_TEST_CASE(authscript_only_adds_authscript)
{
    Consensus::Params p = AllOptInsSetTo(false);
    p.nPQWitnessEnabled = true;
    script_verify_flags flags = GetStandardScriptVerifyFlagsWithConsensusOptIns(p);
    BOOST_CHECK(flags == (STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_AUTHSCRIPT));
}

BOOST_AUTO_TEST_CASE(refinputs_only_adds_refinputs)
{
    Consensus::Params p = AllOptInsSetTo(false);
    p.nREFINPUTSEnabled = true;
    script_verify_flags flags = GetStandardScriptVerifyFlagsWithConsensusOptIns(p);
    BOOST_CHECK(flags == (STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_REFINPUTS));
}

// ---------------------------------------------------------------------------
// All 16 opt-ins on: helper returns STANDARD plus the full opt-in union.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(all_opt_ins_on_sets_every_flag)
{
    Consensus::Params p = AllOptInsSetTo(true);
    script_verify_flags flags = GetStandardScriptVerifyFlagsWithConsensusOptIns(p);

    script_verify_flags expected = STANDARD_SCRIPT_VERIFY_FLAGS
        | SCRIPT_VERIFY_AUTHSCRIPT
        | SCRIPT_VERIFY_CAT
        | SCRIPT_VERIFY_CHECKTEMPLATEVERIFY
        | SCRIPT_VERIFY_CHECKSIGFROMSTACK
        | SCRIPT_VERIFY_TXHASH
        | SCRIPT_VERIFY_TXFIELD
        | SCRIPT_VERIFY_SPLIT
        | SCRIPT_VERIFY_REVERSEBYTES
        | SCRIPT_VERIFY_OUTPUTVALUE
        | SCRIPT_VERIFY_OUTPUTSCRIPT
        | SCRIPT_VERIFY_OUTPUTASSETFIELD
        | SCRIPT_VERIFY_INPUTASSETFIELD
        | SCRIPT_VERIFY_64BIT_INTEGERS
        | SCRIPT_VERIFY_TXLOCKTIME
        | SCRIPT_VERIFY_INPUTOUTPUTCOUNT
        | SCRIPT_VERIFY_REFINPUTS;

    BOOST_CHECK(flags == expected);
}

// ---------------------------------------------------------------------------
// Regression guard: the helper must never remove a bit from the baseline.
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(helper_never_clears_baseline_bits)
{
    for (int mask = 0; mask < 4; ++mask) {
        Consensus::Params p = AllOptInsSetTo(false);
        p.nCSFSEnabled      = (mask & 1) != 0;
        p.nPQWitnessEnabled = (mask & 2) != 0;
        script_verify_flags flags = GetStandardScriptVerifyFlagsWithConsensusOptIns(p);
        BOOST_CHECK((flags & STANDARD_SCRIPT_VERIFY_FLAGS) == STANDARD_SCRIPT_VERIFY_FLAGS);
    }
}

BOOST_AUTO_TEST_SUITE_END()
