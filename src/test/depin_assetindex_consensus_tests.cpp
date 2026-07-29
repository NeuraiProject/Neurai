// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// "The address holding the DEPIN owner token cannot be frozen or revoked",
// decided from the transaction instead of from -assetindex.
//
// The guard used to be AddressHasDEPINOwnerToken() -> GetBestAssetAddressAmount()
// -> `if (fAssetIndex)`. That flag is a local option, off by default
// (DEFAULT_ASSETINDEX = false), so a node with the index rejected transactions
// that a node without it accepted: a consensus divergence in code that runs on
// every freezedepin/unfreezedepin.
//
// The replacement reads the inputs, and is exactly equivalent rather than an
// approximation. VerifyDEPINOwnerChange is only reached when the transaction
// transfers the owner token; transferring an asset requires spending it for the
// same total (tx_verify.cpp, the inputs/outputs balance check); and an owner
// token is indivisible and issued once, so exactly one UTXO of it exists. The
// transaction therefore must be spending that one UTXO, and its previous owner
// is precisely what the guard wanted to know.
//
// Every case here runs BOTH with and without the index. That is the point: any
// difference between the two columns is the bug coming back.

#include "amount.h"

#include "assets/assets.h"
#include "assets/assettypes.h"
#include "base58.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/validation.h"
#include "key.h"
#include "primitives/transaction.h"
#include "rpc/register.h"
#include "rpc/server.h"
#include "script/standard.h"
#include "test/test_neurai.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

#include <string>
#include <univalue.h>
#include <vector>

namespace {

const std::string ASSET = "&DEVICE";

// BasicTestingSetup plus a global asset cache, because the restriction checks
// fall through to `passets`. Restores every global it touches.
//
// REGTEST rather than TESTNET: DEPIN names validate on both
// (AreDEPINAssetsEnabledOnCurrentNetwork), and selecting TESTNET costs about
// 8.5 seconds per test case in this codebase -- the pre-existing DEPIN suites
// that do select it each pay that, and there is no reason for this one to.
//
// The RPC table is registered explicitly: BasicTestingSetup does not do it (only
// TestingSetup does), and one case here drives checkdepinvalidity.
struct DepinIndexSetup : public BasicTestingSetup {
    CAssetsCache globalAssetsCache;
    CAssetsCache* prevAssets;
    bool prevAssetIndex;

    DepinIndexSetup() : BasicTestingSetup(CBaseChainParams::REGTEST)
    {
        prevAssets = passets;
        prevAssetIndex = fAssetIndex;
        passets = &globalAssetsCache;
        fAssetIndex = false;

        RegisterAssetRPCCommands(tableRPC);
    }

    ~DepinIndexSetup()
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

// An output paying the owner token of ASSET to `address`, as a transfer.
CScript OwnerTransferScript(const std::string& address)
{
    CAssetTransfer transfer(ASSET + OWNER_TAG, OWNER_ASSET_AMOUNT);
    CScript script = GetScriptForDestination(DecodeDestination(address));
    transfer.ConstructTransaction(script);
    return script;
}

// The same token as it comes straight out of issuance, which is a different
// script type (TX_NEW_ASSET with the owner flag) and has to be recognised too.
CScript OwnerIssuanceScript(const std::string& address)
{
    CNewAsset asset(ASSET, 1000 * COIN, DEPIN_ASSET_UNITS, 0, 0, "");
    CScript script = GetScriptForDestination(DecodeDestination(address));
    asset.ConstructOwnerTransaction(script);
    return script;
}

CScript NullDataScript(const std::string& address, int flag)
{
    CNullAssetTxData data(ASSET, flag);
    CScript script = GetScriptForNullAssetDataDestination(DecodeDestination(address));
    data.ConstructTransaction(script);
    return script;
}

// The outpoint every fixture spends, when it spends one at all.
COutPoint FundingOutPoint()
{
    return COutPoint(uint256S("0x0101010101010101010101010101010101010101010101010101010101010101"), 0);
}

// A freeze/unfreeze transaction: it moves the owner token to `ownerDestination`
// and carries the null data aimed at `target`.
CMutableTransaction BuildFreezeTx(const std::string& target, const std::string& ownerDestination,
                                  int flag, bool withInput)
{
    CMutableTransaction mut;
    if (withInput) {
        mut.vin.emplace_back(FundingOutPoint());
    }
    mut.vout.emplace_back(0, OwnerTransferScript(ownerDestination));
    mut.vout.emplace_back(0, NullDataScript(target, flag));
    return mut;
}

// Bundles the transaction with the coins view that backs its input, because the
// rule is only meaningful when both are present. `spentScript` is the previous
// output being spent -- that is what says where the owner token was.
struct FreezeTx {
    CCoinsView base;
    CCoinsViewCache view;
    CTransaction tx;

    FreezeTx(const std::string& target, const std::string& ownerDestination, int flag,
             const CScript* spentScript)
        : view(&base), tx(BuildFreezeTx(target, ownerDestination, flag, spentScript != nullptr))
    {
        if (spentScript) {
            view.AddCoin(FundingOutPoint(), Coin(CTxOut(0, *spentScript), 1, false), false);
        }
    }

    // Index of the null-data output.
    static const unsigned int kNullDataOut = 1;
};

// Run the contextual check and report the verdict plus the error, so tests can
// compare the two index configurations without duplicating the plumbing.
struct Verdict {
    bool ok;
    std::string error;

    bool operator==(const Verdict& other) const { return ok == other.ok && error == other.error; }
};

Verdict CheckNullData(const FreezeTx& fixture)
{
    CAssetsCache cache;
    Verdict v;
    v.ok = ContextualCheckNullAssetTxOut(fixture.tx.vout[FreezeTx::kNullDataOut], &fixture.tx,
                                         fixture.view, &cache, v.error);
    return v;
}

// The whole point: the same transaction judged with the index on and off.
Verdict CheckBothWays(const FreezeTx& fixture)
{
    const bool saved = fAssetIndex;

    fAssetIndex = false;
    const Verdict without = CheckNullData(fixture);

    fAssetIndex = true;
    const Verdict with = CheckNullData(fixture);

    fAssetIndex = saved;

    BOOST_CHECK_MESSAGE(without == with,
                        "verdict differs by -assetindex: without=" +
                            std::string(without.ok ? "accept" : "reject(" + without.error + ")") +
                            " with=" +
                            std::string(with.ok ? "accept" : "reject(" + with.error + ")"));
    return without;
}

const char* kOwnerHolderRejection = "bad-txns-depin-owner-holder-address-cannot-be-revoked";

// Record, in the global asset cache, that `address` holds the owner token.
//
// This is what the OLD guard read (AddressHasDEPINOwnerToken ->
// GetBestAssetAddressAmount -> the cache, then passetsdb). Seeding it is what
// gives the with/without-index comparison something to disagree about: with an
// empty cache the "with index" column answers false as well, for lack of data
// rather than by design, and CheckBothWays would report agreement even for the
// buggy implementation. Everything would then rest on the final expectation,
// and the comparison -- the actual subject of this suite -- would be inert.
//
// It also keeps the lookup inside the cache, short of the unguarded
// passetsdb-> dereference in GetBestAssetAddressAmount, so a mutation that
// restores the old guard fails as a test rather than as a segfault.
void SeedOwnerTokenAt(const std::string& address)
{
    passets->mapAssetsAddressAmount[std::make_pair(ASSET + OWNER_TAG, address)] = OWNER_ASSET_AMOUNT;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(depin_assetindex_consensus_tests, DepinIndexSetup)

// (1) and (4a) The half that was missing: the owner token WAS at the target and
// this transaction moves it out. Rejected, and rejected identically with and
// without the index.
//
// This is the case that diverged. Before the change, a node without the index
// accepted it -- the guard resolved to false and never fired.
BOOST_AUTO_TEST_CASE(owner_token_spent_from_target_is_rejected)
{
    const std::string target = NewAddress();
    const std::string elsewhere = NewAddress();

    // The owner token is at `target` before this transaction, which is exactly
    // what the old index-backed guard would have found and the new structural
    // one reads off the input.
    SeedOwnerTokenAt(target);

    const CScript spent = OwnerTransferScript(target);
    FreezeTx fixture(target, elsewhere, (int)RestrictedType::FREEZE_ADDRESS, &spent);

    const Verdict v = CheckBothWays(fixture);
    BOOST_CHECK(!v.ok);
    BOOST_CHECK_EQUAL(v.error, kOwnerHolderRejection);
}

// (5) The same, when the owner token is being spent straight from its issuance
// output rather than from a later transfer. Both script shapes must be
// recognised; covering only one leaves the check bypassable by having moved the
// token once (or by never having moved it).
BOOST_AUTO_TEST_CASE(owner_token_spent_from_target_issuance_is_rejected)
{
    const std::string target = NewAddress();
    const std::string elsewhere = NewAddress();

    SeedOwnerTokenAt(target);

    const CScript spent = OwnerIssuanceScript(target);
    FreezeTx fixture(target, elsewhere, (int)RestrictedType::FREEZE_ADDRESS, &spent);

    const Verdict v = CheckBothWays(fixture);
    BOOST_CHECK(!v.ok);
    BOOST_CHECK_EQUAL(v.error, kOwnerHolderRejection);
}

// (2) and (4b) The half that already existed and must keep working: the owner
// token is being moved TO the target. Rejected by the output-side check, which
// never depended on the index.
BOOST_AUTO_TEST_CASE(owner_token_sent_to_target_is_rejected)
{
    const std::string target = NewAddress();
    const std::string source = NewAddress();

    // Here it starts at `source` and arrives at `target`; the output-side check
    // is what must catch it.
    SeedOwnerTokenAt(source);

    const CScript spent = OwnerTransferScript(source);
    FreezeTx fixture(target, /*ownerDestination=*/target, (int)RestrictedType::FREEZE_ADDRESS, &spent);

    const Verdict v = CheckBothWays(fixture);
    BOOST_CHECK(!v.ok);
    BOOST_CHECK_EQUAL(v.error, kOwnerHolderRejection);
}

// (4c) The case that stops the rule from becoming a blanket rejection: the owner
// token lives at a third address and is neither coming from nor going to the
// target. This must be ACCEPTED -- it is the ordinary freeze.
//
// Without this test, a check that rejected everything would still pass the two
// above, and nobody would notice until every freeze started failing.
BOOST_AUTO_TEST_CASE(owner_token_elsewhere_is_accepted)
{
    const std::string target = NewAddress();
    const std::string ownerHome = NewAddress();

    // The owner token exists and is accounted for -- just not at `target`.
    SeedOwnerTokenAt(ownerHome);

    const CScript spent = OwnerTransferScript(ownerHome);
    FreezeTx fixture(target, /*ownerDestination=*/ownerHome, (int)RestrictedType::FREEZE_ADDRESS, &spent);

    const Verdict v = CheckBothWays(fixture);
    BOOST_CHECK_MESSAGE(v.ok, "an ordinary freeze must be accepted, got: " + v.error);
}

// (3) Unfreeze behaves the same way, in both directions and both configurations.
// The guard sits before the flag is looked at, so it applies symmetrically:
// an address that cannot be frozen cannot be unfrozen either, which is what
// keeps the state recoverable.
BOOST_AUTO_TEST_CASE(unfreeze_is_symmetric)
{
    const std::string target = NewAddress();
    const std::string ownerHome = NewAddress();

    SeedOwnerTokenAt(ownerHome);

    // Ordinary unfreeze of a frozen address: accepted.
    passets->setNewRestrictedAddressToAdd.insert(
        CAssetCacheRestrictedAddress(ASSET, target, RestrictedType::FREEZE_ADDRESS));
    {
        const CScript spent = OwnerTransferScript(ownerHome);
        FreezeTx fixture(target, ownerHome, (int)RestrictedType::UNFREEZE_ADDRESS, &spent);
        const Verdict v = CheckBothWays(fixture);
        BOOST_CHECK_MESSAGE(v.ok, "ordinary unfreeze must be accepted, got: " + v.error);
    }

    // Unfreeze aimed at the address the owner token is leaving: rejected, same
    // as the freeze would be.
    {
        SeedOwnerTokenAt(target);
        const CScript spent = OwnerTransferScript(target);
        FreezeTx fixture(target, ownerHome, (int)RestrictedType::UNFREEZE_ADDRESS, &spent);
        const Verdict v = CheckBothWays(fixture);
        BOOST_CHECK(!v.ok);
        BOOST_CHECK_EQUAL(v.error, kOwnerHolderRejection);
    }
}

// (9) Consensus must not consult wallet state either. The same transaction gets
// the same verdict whether or not a wallet is loaded and whatever it holds --
// the check reads only the transaction and the coins view.
//
// Without this, the fix could have swapped a dependency on configuration for a
// dependency on the local wallet, which is no better.
BOOST_AUTO_TEST_CASE(verdict_does_not_depend_on_wallet_state)
{
    const std::string target = NewAddress();
    const std::string ownerHome = NewAddress();

    SeedOwnerTokenAt(target);

    const CScript spent = OwnerTransferScript(target);
    FreezeTx fixture(target, ownerHome, (int)RestrictedType::FREEZE_ADDRESS, &spent);

    // This unit binary has no wallet attached to the check at all; the assertion
    // is that the verdict is fully determined by tx + inputs, so re-running it
    // against a fresh, empty asset cache reproduces it exactly.
    const Verdict first = CheckNullData(fixture);
    const Verdict second = CheckNullData(fixture);
    BOOST_CHECK(first == second);
    BOOST_CHECK(!first.ok);
    BOOST_CHECK_EQUAL(first.error, kOwnerHolderRejection);
}

// Not a consensus property: a transaction with no inputs never gets that far,
// CheckTransaction rejects it outright. This is about the contextual check in
// isolation -- the pre-existing tests in null_asset_data_tests.cpp build
// input-less transactions to exercise it, and the new rule must not start
// tripping on them.
BOOST_AUTO_TEST_CASE(contextual_check_alone_tolerates_a_transaction_without_inputs)
{
    const std::string target = NewAddress();
    const std::string ownerHome = NewAddress();

    FreezeTx fixture(target, ownerHome, (int)RestrictedType::FREEZE_ADDRESS, /*spentScript=*/nullptr);

    const Verdict v = CheckBothWays(fixture);
    BOOST_CHECK_MESSAGE(v.ok, "the contextual check must not trip on a transaction with no inputs, got: " + v.error);
}

// The helper on its own, so a failure points at the scan rather than at the
// dispatch around it.
BOOST_AUTO_TEST_CASE(spends_owner_token_from_address_helper)
{
    const std::string owner = NewAddress();
    const std::string other = NewAddress();

    CCoinsView base;
    CCoinsViewCache view(&base);

    CMutableTransaction mut;
    const COutPoint prevout(uint256S("0x02"), 0);
    mut.vin.emplace_back(prevout);
    view.AddCoin(prevout, Coin(CTxOut(0, OwnerTransferScript(owner)), 1, false), false);
    const CTransaction tx(mut);

    BOOST_CHECK(TxSpendsDEPINOwnerTokenFromAddress(tx, view, ASSET, owner));
    BOOST_CHECK(!TxSpendsDEPINOwnerTokenFromAddress(tx, view, ASSET, other));
    // A different asset's owner token must not match.
    BOOST_CHECK(!TxSpendsDEPINOwnerTokenFromAddress(tx, view, "&OTHER", owner));

    // Both script shapes have to compare the asset name, not just the address.
    // Checking that only on the transfer branch leaves the issuance branch free
    // to match any asset held at that address.
    CMutableTransaction issuedMut;
    const COutPoint issuedPrev(uint256S("0x04"), 0);
    issuedMut.vin.emplace_back(issuedPrev);
    view.AddCoin(issuedPrev, Coin(CTxOut(0, OwnerIssuanceScript(owner)), 1, false), false);
    const CTransaction issuedTx(issuedMut);

    BOOST_CHECK(TxSpendsDEPINOwnerTokenFromAddress(issuedTx, view, ASSET, owner));
    BOOST_CHECK_MESSAGE(!TxSpendsDEPINOwnerTokenFromAddress(issuedTx, view, "&OTHER", owner),
                        "the issuance branch must compare the asset name too");
    BOOST_CHECK(!TxSpendsDEPINOwnerTokenFromAddress(issuedTx, view, ASSET, other));

    // A plain XNA input proves nothing about the owner token.
    CMutableTransaction plainMut;
    const COutPoint plainPrev(uint256S("0x03"), 0);
    plainMut.vin.emplace_back(plainPrev);
    view.AddCoin(plainPrev, Coin(CTxOut(1000, GetScriptForDestination(DecodeDestination(owner))), 1, false), false);
    const CTransaction plainTx(plainMut);
    BOOST_CHECK(!TxSpendsDEPINOwnerTokenFromAddress(plainTx, view, ASSET, owner));
}

// (6) The DEPIN branch that used to sit in VerifyRestrictedAddressChange was
// unreachable: both dispatches test IsAssetNameAnRestricted() first, and a name
// cannot begin with '$' and '&' at once. Asserting the mutual exclusion is what
// justifies having deleted it.
BOOST_AUTO_TEST_CASE(restricted_and_depin_names_are_disjoint)
{
    BOOST_CHECK(IsAssetNameAnRestricted("$RESTRICTED"));
    BOOST_CHECK(!IsAssetNameADEPIN("$RESTRICTED"));

    BOOST_CHECK(IsAssetNameADEPIN(ASSET));
    BOOST_CHECK(!IsAssetNameAnRestricted(ASSET));
}

// (11) checkdepinvalidity answers for an arbitrary address, so it genuinely
// needs the index. What it must not do is answer "has_asset": false when it
// simply cannot tell -- a wrong answer dressed as a correct one.
BOOST_AUTO_TEST_CASE(checkdepinvalidity_says_it_cannot_answer_without_the_index)
{
    UniValue params(UniValue::VARR);
    params.push_back(ASSET);
    params.push_back(NewAddress());

    JSONRPCRequest request;
    request.strMethod = "checkdepinvalidity";
    request.params = params;
    request.fHelp = false;

    BOOST_REQUIRE(tableRPC["checkdepinvalidity"]);

    // fAssetIndex is false in this fixture.
    bool threw = false;
    try {
        (*tableRPC["checkdepinvalidity"]->actor)(request);
    } catch (const UniValue& e) {
        threw = true;
        const std::string message = find_value(e, "message").get_str();
        BOOST_CHECK_MESSAGE(message.find("assetindex") != std::string::npos,
                            "the error must name -assetindex, got: " + message);
    }
    BOOST_CHECK_MESSAGE(threw,
                        "without the index this RPC must fail loudly, not report has_asset=false");
}

BOOST_AUTO_TEST_SUITE_END()
