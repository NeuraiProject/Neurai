// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The DEPIN self-revocation exception to the soulbound rule.
//
// A holder without the owner token could never self-revoke: CheckTransaction
// demands a transfer of &X or &X! next to the null data, transferring &X!
// is impossible without holding it, and transferring &X tripped the soulbound
// rule, which demanded spending AND transferring &X!. Every exit was closed,
// so VerifySelfRestrictionChange and the whole 'S' flag were dead code on
// chain.
//
// The exception (IsDepinSelfRevocationTransaction): a self-relocation. Every
// input of &X from one address A, every output of &X back to that same A, and
// exactly one flag-1 null data for (X, A). Spending the asset's own UTXO is
// the authorisation -- key control and tenure proved in one act, no
// address->asset index involved. Amount conservation is NOT re-checked by the
// exception: the existing inputs/outputs balance rule already enforces it.
//
// The dangerous direction is the exception being WIDER than written: it is a
// hole in the only rule that makes a soulbound token non-transferable. Most
// cases below are rejections.

#include "amount.h"

#include "assets/assets.h"
#include "assets/assettypes.h"
#include "base58.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "key.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "test/test_neurai.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <string>
#include <vector>

// Regression instrumentation defined in assets.cpp. Deliberately declared here
// rather than in assets.h: it is a test seam, not part of the assets API.
extern std::atomic<uint64_t> gDepinSelfRevocationEvaluations;

namespace {

const std::string ASSET = "&DEVICE";

// REGTEST + a global asset cache (the restriction checks fall through to
// passets). fAssetIndex off, as on a default node; individual cases flip it to
// prove the verdict does not move.
struct DepinSelfRevokeSetup : public BasicTestingSetup {
    CAssetsCache globalAssetsCache;
    CAssetsCache* prevAssets;
    bool prevAssetIndex;

    DepinSelfRevokeSetup() : BasicTestingSetup(CBaseChainParams::REGTEST)
    {
        prevAssets = passets;
        prevAssetIndex = fAssetIndex;
        passets = &globalAssetsCache;
        fAssetIndex = false;
    }

    ~DepinSelfRevokeSetup()
    {
        passets = prevAssets;
        fAssetIndex = prevAssetIndex;
    }
};

std::string NewAddress()
{
    CKey key;
    key.MakeNewKey(true);
    return EncodeDestination(key.GetPubKey().GetID());
}

CScript TransferScript(const std::string& name, CAmount amount, const std::string& address)
{
    CAssetTransfer transfer(name, amount);
    CScript script = GetScriptForDestination(DecodeDestination(address));
    transfer.ConstructTransaction(script);
    return script;
}

// The asset as it leaves issuance (TX_NEW_ASSET, non-owner): the shape a
// soulbound token's UTXO usually has, because it has never moved.
CScript IssuanceScript(const std::string& name, CAmount amount, const std::string& address)
{
    CNewAsset asset(name, amount, DEPIN_ASSET_UNITS, 0, 0, "");
    CScript script = GetScriptForDestination(DecodeDestination(address));
    asset.ConstructTransaction(script);
    return script;
}

CScript OwnerTransferScript(const std::string& address)
{
    CAssetTransfer transfer(ASSET + OWNER_TAG, OWNER_ASSET_AMOUNT);
    CScript script = GetScriptForDestination(DecodeDestination(address));
    transfer.ConstructTransaction(script);
    return script;
}

CScript NullDataScript(const std::string& name, int flag, const std::string& address)
{
    CNullAssetTxData data(name, flag);
    CScript script = GetScriptForNullAssetDataDestination(DecodeDestination(address));
    data.ConstructTransaction(script);
    return script;
}

// A transaction plus the coins view holding its inputs. Outputs and inputs are
// appended by the tests, so every case states its whole shape at the call site.
struct TxFixture {
    CCoinsView base;
    CCoinsViewCache view;
    CMutableTransaction mut;
    unsigned int nNextInput = 0;

    TxFixture() : view(&base) {}

    void AddInput(const CScript& prevoutScript)
    {
        // Distinct fake txids so several inputs never collide.
        std::vector<unsigned char> bytes(32, 0x11);
        bytes[0] = (unsigned char)(0xA0 + nNextInput);
        const COutPoint prevout(uint256(bytes), 0);
        mut.vin.emplace_back(prevout);
        view.AddCoin(prevout, Coin(CTxOut(0, prevoutScript), 1, false), false);
        nNextInput++;
    }

    void AddOutput(const CScript& script) { mut.vout.emplace_back(0, script); }

    CTransaction Tx() const { return CTransaction(mut); }
};

// Full consensus verdict, via Consensus::CheckTxAssets -- the function mempool
// and block connection actually call.
bool CheckAssets(const TxFixture& fixture, std::string& reason)
{
    const CTransaction tx = fixture.Tx();
    CValidationState state;
    std::vector<std::pair<std::string, uint256>> vReissue;
    // assetCache = nullptr, the same convention asset_tx_tests uses: the
    // activation gate and the null-data contextual checks live under
    // `if (assetCache)`, while the soulbound rule -- the subject here -- and
    // the inputs/outputs balance rule run regardless. The null-data STATE
    // checks are exercised separately through ContextualCheckNullAssetTxOut.
    const bool ok = Consensus::CheckTxAssets(tx, state, fixture.view, nullptr,
                                             /*fCheckMempool=*/false, vReissue,
                                             /*fRunningUnitTests=*/true,
                                             /*setMessages=*/nullptr, /*nBlocktime=*/0,
                                             /*myNullAssetData=*/nullptr);
    reason = state.GetRejectReason();
    return ok;
}

// The null-data state transition, judged as consensus judges it, with the
// index on and off.
bool ContextualBothWays(const TxFixture& fixture, unsigned int nullDataOut, std::string& error)
{
    const CTransaction tx = fixture.Tx();
    const bool saved = fAssetIndex;

    fAssetIndex = false;
    CAssetsCache cacheWithout;
    std::string errorWithout;
    const bool without = ContextualCheckNullAssetTxOut(tx.vout[nullDataOut], &tx, fixture.view,
                                                       &cacheWithout, errorWithout);

    fAssetIndex = true;
    CAssetsCache cacheWith;
    std::string errorWith;
    const bool with = ContextualCheckNullAssetTxOut(tx.vout[nullDataOut], &tx, fixture.view,
                                                    &cacheWith, errorWith);

    fAssetIndex = saved;

    BOOST_CHECK_MESSAGE(without == with && errorWithout == errorWith,
                        "verdict differs by -assetindex: without=" +
                            std::string(without ? "accept" : "reject(" + errorWithout + ")") +
                            " with=" + std::string(with ? "accept" : "reject(" + errorWith + ")"));
    error = errorWithout;
    return without;
}

// The same verdict with the index on and off. Any difference is the
// -assetindex divergence coming back through the new path.
bool CheckAssetsBothWays(const TxFixture& fixture, std::string& reason)
{
    const bool saved = fAssetIndex;

    fAssetIndex = false;
    std::string reasonWithout;
    const bool without = CheckAssets(fixture, reasonWithout);

    fAssetIndex = true;
    std::string reasonWith;
    const bool with = CheckAssets(fixture, reasonWith);

    fAssetIndex = saved;

    BOOST_CHECK_MESSAGE(without == with && reasonWithout == reasonWith,
                        "verdict differs by -assetindex: without=" +
                            std::string(without ? "accept" : "reject(" + reasonWithout + ")") +
                            " with=" + std::string(with ? "accept" : "reject(" + reasonWith + ")"));
    reason = reasonWithout;
    return without;
}

const char* kSoulboundRejection = "bad-txns-depin-transfer-not-by-owner";

} // namespace

BOOST_FIXTURE_TEST_SUITE(depin_selfrevoke_tests, DepinSelfRevokeSetup)

// (1)(13)(17) The case that was impossible: spend &X from A, return it to A,
// carry the flag-1 null data for (X, A). Accepted, and accepted identically
// with and without the index. The input coin living in the view is also what a
// same-block receive-then-revoke chain looks like at validation level.
BOOST_AUTO_TEST_CASE(valid_self_revocation_is_accepted)
{
    const std::string holder = NewAddress();

    TxFixture fixture;
    fixture.AddInput(TransferScript(ASSET, 100, holder));
    fixture.AddOutput(TransferScript(ASSET, 100, holder));
    fixture.AddOutput(NullDataScript(ASSET, 1, holder));

    std::string reason;
    BOOST_CHECK_MESSAGE(CheckAssetsBothWays(fixture, reason),
                        "self-revocation must be accepted, got: " + reason);
}

// (2) The null-data-only form stays rejected, by CheckTransaction, exactly as
// today. That rejection is what stops revoking a third party.
BOOST_AUTO_TEST_CASE(null_data_without_transfer_still_rejected)
{
    const std::string holder = NewAddress();

    CMutableTransaction mut;
    std::vector<unsigned char> bytes(32, 0x22);
    mut.vin.emplace_back(COutPoint(uint256(bytes), 0));
    mut.vout.emplace_back(0, NullDataScript(ASSET, 1, holder));
    const CTransaction tx(mut);

    CValidationState state;
    BOOST_CHECK(!CheckTransaction(tx, state, true, false, true));
    BOOST_CHECK_EQUAL(state.GetRejectReason(),
                      "bad-txns-tx-contains-depin-asset-null-tx-without-asset-transfer");
}

// (3) Spending your own &X does not let you revoke someone else: the null data
// must name the same address the asset moves through.
BOOST_AUTO_TEST_CASE(null_data_for_another_address_is_rejected)
{
    const std::string holder = NewAddress();
    const std::string victim = NewAddress();

    TxFixture fixture;
    fixture.AddInput(TransferScript(ASSET, 100, holder));
    fixture.AddOutput(TransferScript(ASSET, 100, holder));
    fixture.AddOutput(NullDataScript(ASSET, 1, victim));

    std::string reason;
    BOOST_CHECK(!CheckAssetsBothWays(fixture, reason));
    BOOST_CHECK_MESSAGE(reason.find(kSoulboundRejection) == 0, "unexpected reason: " + reason);
}

// (4) The exception must not be a back door for moving the token: a transfer to
// any other address, with the null data along for the ride, stays soulbound.
BOOST_AUTO_TEST_CASE(transfer_to_another_address_is_rejected)
{
    const std::string holder = NewAddress();
    const std::string other = NewAddress();

    TxFixture fixture;
    fixture.AddInput(TransferScript(ASSET, 100, holder));
    fixture.AddOutput(TransferScript(ASSET, 100, other));
    fixture.AddOutput(NullDataScript(ASSET, 1, holder));

    std::string reason;
    BOOST_CHECK(!CheckAssetsBothWays(fixture, reason));
    BOOST_CHECK_MESSAGE(reason.find(kSoulboundRejection) == 0, "unexpected reason: " + reason);
}

// (5) Burning or inflating under cover of the exception is caught by the
// balance rule, which the exception deliberately does not duplicate.
BOOST_AUTO_TEST_CASE(amount_mismatch_is_rejected_by_the_balance_rule)
{
    const std::string holder = NewAddress();

    TxFixture fixture;
    fixture.AddInput(TransferScript(ASSET, 100, holder));
    fixture.AddOutput(TransferScript(ASSET, 60, holder));  // 40 would vanish
    fixture.AddOutput(NullDataScript(ASSET, 1, holder));

    std::string reason;
    BOOST_CHECK(!CheckAssetsBothWays(fixture, reason));
    BOOST_CHECK_MESSAGE(reason.find("bad-tx-inputs-outputs-mismatch") == 0,
                        "expected the balance rule, got: " + reason);
}

// (6) A correct self-transfer PLUS a second &X output elsewhere: rejected. The
// condition is over ALL outputs of the asset, not "some output matches".
BOOST_AUTO_TEST_CASE(second_output_to_another_address_is_rejected)
{
    const std::string holder = NewAddress();
    const std::string other = NewAddress();

    TxFixture fixture;
    fixture.AddInput(TransferScript(ASSET, 100, holder));
    fixture.AddOutput(TransferScript(ASSET, 60, holder));   // looks fine alone
    fixture.AddOutput(TransferScript(ASSET, 40, other));    // the smuggle
    fixture.AddOutput(NullDataScript(ASSET, 1, holder));

    std::string reason;
    BOOST_CHECK(!CheckAssetsBothWays(fixture, reason));
    BOOST_CHECK_MESSAGE(reason.find(kSoulboundRejection) == 0, "unexpected reason: " + reason);
}

// (6b) The verdict must not depend on vout order. The null data usually sits
// AFTER the transfer (the wallet appends it last); an implementation written
// inside the per-output loop would see a partial vout and accept one order
// while rejecting the other.
BOOST_AUTO_TEST_CASE(output_order_is_irrelevant)
{
    const std::string holder = NewAddress();

    // Null data first.
    {
        TxFixture fixture;
        fixture.AddInput(TransferScript(ASSET, 100, holder));
        fixture.AddOutput(NullDataScript(ASSET, 1, holder));
        fixture.AddOutput(TransferScript(ASSET, 100, holder));

        std::string reason;
        BOOST_CHECK_MESSAGE(CheckAssetsBothWays(fixture, reason),
                            "null-data-first order rejected: " + reason);
    }

    // Null data last.
    {
        TxFixture fixture;
        fixture.AddInput(TransferScript(ASSET, 100, holder));
        fixture.AddOutput(TransferScript(ASSET, 100, holder));
        fixture.AddOutput(NullDataScript(ASSET, 1, holder));

        std::string reason;
        BOOST_CHECK_MESSAGE(CheckAssetsBothWays(fixture, reason),
                            "null-data-last order rejected: " + reason);
    }
}

// (6c) The self-transfer may be split across several outputs to the same
// address. The aggregation is per asset, not per output, and does not depend on
// the wallet building a single output.
BOOST_AUTO_TEST_CASE(split_self_transfer_is_accepted)
{
    const std::string holder = NewAddress();

    TxFixture fixture;
    fixture.AddInput(TransferScript(ASSET, 100, holder));
    fixture.AddOutput(TransferScript(ASSET, 60, holder));
    fixture.AddOutput(NullDataScript(ASSET, 1, holder));
    fixture.AddOutput(TransferScript(ASSET, 40, holder));

    std::string reason;
    BOOST_CHECK_MESSAGE(CheckAssetsBothWays(fixture, reason),
                        "split self-transfer rejected: " + reason);
}

// (6d) The input is usually the ISSUANCE output, not a transfer: a soulbound
// token has normally never moved, so the UTXO the holder spends is the
// TX_NEW_ASSET the owner distributed. An implementation that only recognises
// the transfer shape passes a transfer-built test and rejects almost every
// real self-revocation.
BOOST_AUTO_TEST_CASE(issuance_shaped_input_is_accepted)
{
    const std::string holder = NewAddress();

    TxFixture fixture;
    fixture.AddInput(IssuanceScript(ASSET, 100 * COIN, holder));
    fixture.AddOutput(TransferScript(ASSET, 100 * COIN, holder));
    fixture.AddOutput(NullDataScript(ASSET, 1, holder));

    std::string reason;
    BOOST_CHECK_MESSAGE(CheckAssetsBothWays(fixture, reason),
                        "issuance-shaped input rejected: " + reason);
}

// (6e) Fail closed. An asset output that classifies as an asset script but
// whose payload cannot be parsed must deny the exception: "all outputs at one
// address" cannot be claimed over a set that was not read in full.
//
// The classification check reads fixed byte offsets (script.cpp,
// IsAssetScript), the parse deserialises the pushed payload; truncating the
// payload keeps the first and breaks the second. CheckTxAssets itself also
// rejects such an output earlier ("bad-tx-asset-transfer-bad-deserialize"), so
// the fail-closed property is asserted on the helper, where it is observable.
BOOST_AUTO_TEST_CASE(unparseable_asset_output_denies_the_exception)
{
    const std::string holder = NewAddress();

    const CScript valid = TransferScript(ASSET, 40, holder);
    std::vector<unsigned char> raw(valid.begin(), valid.end());
    BOOST_REQUIRE(raw.size() > 12);
    raw.resize(raw.size() - 11);          // amputate payload tail + OP_DROP
    raw.push_back(OP_DROP);
    const CScript corrupted(raw.begin(), raw.end());
    BOOST_REQUIRE_MESSAGE(corrupted.IsAssetScript(),
                          "fixture: the truncated script must still classify as an asset script");
    CAssetOutputEntry parsed;
    BOOST_REQUIRE_MESSAGE(!GetAssetData(corrupted, parsed),
                          "fixture: the truncated script must fail to parse");

    TxFixture fixture;
    fixture.AddInput(TransferScript(ASSET, 100, holder));
    fixture.AddOutput(TransferScript(ASSET, 60, holder));
    fixture.AddOutput(corrupted);
    fixture.AddOutput(NullDataScript(ASSET, 1, holder));

    std::string error;
    BOOST_CHECK(!IsDepinSelfRevocationTransaction(fixture.Tx(), fixture.view, ASSET, error));
    BOOST_CHECK_MESSAGE(error.find("unreadable asset output") != std::string::npos,
                        "expected the fail-closed denial, got: " + error);
}

// Two null datas for the same asset -- the holder's and one aimed at another
// address -- deny the exception, IN BOTH ORDERS. CheckTransaction only rejects
// the exact duplicate pair; the cross-address conflict is this rule's to
// reject.
//
// The order matters more than it looks: if the count check degraded to "at
// least one", the last null data seen would win. With the victim's FIRST and
// the holder's second, every other condition would then match and the accepted
// block would write the victim's 'S' flag with no authorisation at all -- the
// exact denial-of-service this design exists to prevent. The first sweep of
// mutations proved the single-order version of this test blind to that.
BOOST_AUTO_TEST_CASE(two_null_datas_for_the_asset_are_rejected)
{
    const std::string holder = NewAddress();
    const std::string victim = NewAddress();

    // Holder's null data first.
    {
        TxFixture fixture;
        fixture.AddInput(TransferScript(ASSET, 100, holder));
        fixture.AddOutput(TransferScript(ASSET, 100, holder));
        fixture.AddOutput(NullDataScript(ASSET, 1, holder));
        fixture.AddOutput(NullDataScript(ASSET, 1, victim));

        std::string reason;
        BOOST_CHECK(!CheckAssetsBothWays(fixture, reason));
        BOOST_CHECK_MESSAGE(reason.find(kSoulboundRejection) == 0, "unexpected reason: " + reason);
    }

    // Victim's null data first -- the order that a weakened count check turns
    // into an unauthorised revocation of the victim.
    {
        TxFixture fixture;
        fixture.AddInput(TransferScript(ASSET, 100, holder));
        fixture.AddOutput(TransferScript(ASSET, 100, holder));
        fixture.AddOutput(NullDataScript(ASSET, 1, victim));
        fixture.AddOutput(NullDataScript(ASSET, 1, holder));

        std::string reason;
        BOOST_CHECK(!CheckAssetsBothWays(fixture, reason));
        BOOST_CHECK_MESSAGE(reason.find(kSoulboundRejection) == 0, "unexpected reason: " + reason);
    }
}

// Every &X input must come from the revoked address itself. A wallet holding
// addresses A and B could otherwise sign a transaction that spends B's tokens,
// pays them to A, and self-revokes A: a real movement of a soulbound token
// between addresses, dressed as a self-revocation. The output and null-data
// conditions are all satisfied in that shape -- only the input-address
// comparison rejects it.
BOOST_AUTO_TEST_CASE(cross_address_input_is_rejected)
{
    const std::string addressA = NewAddress();
    const std::string addressB = NewAddress();

    TxFixture fixture;
    fixture.AddInput(TransferScript(ASSET, 100, addressB));   // B's tokens...
    fixture.AddOutput(TransferScript(ASSET, 100, addressA));  // ...moving to A
    fixture.AddOutput(NullDataScript(ASSET, 1, addressA));

    std::string reason;
    BOOST_CHECK(!CheckAssetsBothWays(fixture, reason));
    BOOST_CHECK_MESSAGE(reason.find(kSoulboundRejection) == 0, "unexpected reason: " + reason);
}

// (7)(8) The owner's form and the plain soulbound rule are untouched: moving
// &X with the owner token still works, moving it without the owner token and
// without the self-revocation pattern still fails.
BOOST_AUTO_TEST_CASE(owner_form_and_plain_soulbound_are_unchanged)
{
    const std::string holder = NewAddress();
    const std::string other = NewAddress();
    const std::string ownerHome = NewAddress();

    // Owner moves tokens: owner token spent and re-transferred -> accepted.
    {
        TxFixture fixture;
        fixture.AddInput(TransferScript(ASSET, 100, ownerHome));
        fixture.AddInput(OwnerTransferScript(ownerHome));
        fixture.AddOutput(TransferScript(ASSET, 100, other));
        fixture.AddOutput(OwnerTransferScript(ownerHome));

        std::string reason;
        BOOST_CHECK_MESSAGE(CheckAssetsBothWays(fixture, reason),
                            "owner move rejected: " + reason);
    }

    // No owner token, no null data -> plain soulbound violation, as today.
    {
        TxFixture fixture;
        fixture.AddInput(TransferScript(ASSET, 100, holder));
        fixture.AddOutput(TransferScript(ASSET, 100, other));

        std::string reason;
        BOOST_CHECK(!CheckAssetsBothWays(fixture, reason));
        BOOST_CHECK_MESSAGE(reason.find(kSoulboundRejection) == 0, "unexpected reason: " + reason);
    }
}

// (10)(17) An address that holds the owner token CAN self-revoke. The old
// guard proved a negative ("does not hold an unspent &X!") through the local
// index, which no transaction can demonstrate; it is gone, and the verdict is
// identical with and without the index. The seeded balance is exactly what the
// old guard used to read -- with it back, this test turns red.
BOOST_AUTO_TEST_CASE(owner_holder_can_self_revoke)
{
    const std::string holder = NewAddress();
    // Exactly what the old guard used to read: the owner-token balance in the
    // asset cache. With the guard restored, this test turns red.
    passets->mapAssetsAddressAmount[std::make_pair(ASSET + OWNER_TAG, holder)] = OWNER_ASSET_AMOUNT;

    TxFixture fixture;
    fixture.AddInput(TransferScript(ASSET, 100, holder));
    fixture.AddOutput(TransferScript(ASSET, 100, holder));
    fixture.AddOutput(NullDataScript(ASSET, 1, holder));

    // The transfer side accepts...
    std::string reason;
    BOOST_CHECK_MESSAGE(CheckAssetsBothWays(fixture, reason),
                        "owner-holder self-revocation rejected by the transfer rule: " + reason);

    // ...and the state transition, where the guard used to live, accepts too --
    // identically with and without the index.
    std::string error;
    BOOST_CHECK_MESSAGE(ContextualBothWays(fixture, /*nullDataOut=*/1, error),
                        "owner-holder self-revocation rejected by the state check: " + error);
}

// (11)(12) The state checks stay: an address already self-revoked, or already
// frozen by the owner, cannot self-revoke again.
BOOST_AUTO_TEST_CASE(already_restricted_states_are_rejected)
{
    const std::string revoked = NewAddress();
    passets->setNewSelfRestrictionToAdd.insert(CAssetCacheSelfRestriction(ASSET, revoked, true));
    {
        TxFixture fixture;
        fixture.AddInput(TransferScript(ASSET, 100, revoked));
        fixture.AddOutput(TransferScript(ASSET, 100, revoked));
        fixture.AddOutput(NullDataScript(ASSET, 1, revoked));

        std::string error;
        BOOST_CHECK(!ContextualBothWays(fixture, /*nullDataOut=*/1, error));
        BOOST_CHECK_EQUAL(error, "bad-txns-depin-already-self-revoked");
    }

    const std::string frozen = NewAddress();
    passets->setNewRestrictedAddressToAdd.insert(
        CAssetCacheRestrictedAddress(ASSET, frozen, RestrictedType::FREEZE_ADDRESS));
    {
        TxFixture fixture;
        fixture.AddInput(TransferScript(ASSET, 100, frozen));
        fixture.AddOutput(TransferScript(ASSET, 100, frozen));
        fixture.AddOutput(NullDataScript(ASSET, 1, frozen));

        std::string error;
        BOOST_CHECK(!ContextualBothWays(fixture, /*nullDataOut=*/1, error));
        BOOST_CHECK_EQUAL(error, "bad-txns-depin-cannot-self-revoke-when-owner-freezed");
    }
}

// (14) The helper alone: no &X input means no proof, whatever the outputs say.
// Also the reverse same-block order -- revoke before receiving -- reduces to
// this: there is no UTXO to spend, so the transaction cannot exist.
BOOST_AUTO_TEST_CASE(no_asset_input_is_denied)
{
    const std::string holder = NewAddress();

    TxFixture fixture;
    // A plain XNA input proves nothing about the asset.
    fixture.AddInput(GetScriptForDestination(DecodeDestination(holder)));
    fixture.AddOutput(TransferScript(ASSET, 100, holder));
    fixture.AddOutput(NullDataScript(ASSET, 1, holder));

    std::string error;
    BOOST_CHECK(!IsDepinSelfRevocationTransaction(fixture.Tx(), fixture.view, ASSET, error));
    BOOST_CHECK_MESSAGE(error.find("does not spend the asset") != std::string::npos,
                        "unexpected denial reason: " + error);
}

// The exception is evaluated ONCE per (transaction, asset), however many
// outputs the self-transfer is split into. The helper scans every vin and
// vout, and the soulbound rule fires once per &X output; without the memo in
// CheckTxAssets the cost is quadratic in a shape the transaction author
// controls -- a split self-revocation, the very form test 6c allows. The
// answer stays correct either way, so only the evaluation counter can see it.
BOOST_AUTO_TEST_CASE(split_self_revocation_is_evaluated_once)
{
    const std::string holder = NewAddress();
    const unsigned int kOutputs = 60;

    TxFixture fixture;
    fixture.AddInput(TransferScript(ASSET, 100 * kOutputs, holder));
    for (unsigned int n = 0; n < kOutputs; ++n) {
        fixture.AddOutput(TransferScript(ASSET, 100, holder));
    }
    fixture.AddOutput(NullDataScript(ASSET, 1, holder));

    gDepinSelfRevocationEvaluations = 0;
    std::string reason;
    BOOST_CHECK_MESSAGE(CheckAssets(fixture, reason),
                        "split self-revocation rejected: " + reason);
    BOOST_CHECK_EQUAL(gDepinSelfRevocationEvaluations.load(), 1U);

    // A rejection is cached across that asset's outputs too: the denied shape
    // is evaluated once, not once per output.
    TxFixture bad;
    const std::string other = NewAddress();
    bad.AddInput(TransferScript(ASSET, 300, holder));
    bad.AddOutput(TransferScript(ASSET, 100, holder));
    bad.AddOutput(TransferScript(ASSET, 100, holder));
    bad.AddOutput(TransferScript(ASSET, 100, other));   // breaks the pattern
    bad.AddOutput(NullDataScript(ASSET, 1, holder));

    gDepinSelfRevocationEvaluations = 0;
    BOOST_CHECK(!CheckAssets(bad, reason));
    BOOST_CHECK_EQUAL(gDepinSelfRevocationEvaluations.load(), 1U);
}

// The memo key is the ASSET, not the transaction: two DEPIN assets self-revoked
// in one transaction get one evaluation each, and each verdict stands on its
// own. A memo collapsed to a single per-transaction flag would report one
// evaluation here -- and worse, reuse the first asset's verdict for the second.
BOOST_AUTO_TEST_CASE(two_assets_in_one_transaction_are_evaluated_separately)
{
    const std::string OTHER_ASSET = "&GADGET";
    const std::string holderA = NewAddress();
    const std::string holderB = NewAddress();

    TxFixture fixture;
    fixture.AddInput(TransferScript(ASSET, 100, holderA));
    fixture.AddInput(TransferScript(OTHER_ASSET, 40, holderB));
    fixture.AddOutput(TransferScript(ASSET, 60, holderA));
    fixture.AddOutput(TransferScript(OTHER_ASSET, 40, holderB));
    fixture.AddOutput(NullDataScript(ASSET, 1, holderA));
    fixture.AddOutput(TransferScript(ASSET, 40, holderA));
    {
        CNullAssetTxData data(OTHER_ASSET, 1);
        CScript script = GetScriptForNullAssetDataDestination(DecodeDestination(holderB));
        data.ConstructTransaction(script);
        fixture.AddOutput(script);
    }

    gDepinSelfRevocationEvaluations = 0;
    std::string reason;
    BOOST_CHECK_MESSAGE(CheckAssets(fixture, reason),
                        "double self-revocation rejected: " + reason);
    BOOST_CHECK_EQUAL(gDepinSelfRevocationEvaluations.load(), 2U);
}

BOOST_AUTO_TEST_SUITE_END()
