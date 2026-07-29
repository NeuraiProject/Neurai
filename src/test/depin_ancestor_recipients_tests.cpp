// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// GetDepinAncestorRecipients(): active holders of a DEPIN branch -- the token
// plus every one of its '/'-separated ancestors, deduplicated.
//
// The tests drive the query through its real seams (passetsdb, prestricteddb
// and the pubkey index) rather than through issuance transactions: those three
// databases are exactly what the function reads, so writing them directly
// exercises the code under test without a wallet, a miner or a chain.
//
// Several cases assert the ACCESS PATTERN, not just the answer, using the
// counters in CDepinAncestorRecipientsStats. Those are the regressions that are
// easy to introduce and invisible to a functional test: one flush per address
// instead of one per query, or one restriction read per (asset, address) pair
// instead of one per address. The result stays correct while the cost explodes.
//
// Runs on REGTEST: DEPIN names only validate on testnet/regtest, and regtest
// needs no asset-activation height for these reads.

#include "depinmsgpool.h"

#include "assets/assetdb.h"
#include "assets/assets.h"
#include "assets/assettypes.h"
#include "assets/restricteddb.h"
#include "base58.h"
#include "chainparams.h"
#include "key.h"
#include "pubkey.h"
#include "pubkeyindex.h"
#include "rpc/client.h"
#include "rpc/server.h"
#include "script/standard.h"
#include "test/test_neurai.h"
#include "txdb.h"
#include "utilstrencodings.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <univalue.h>
#include <vector>

namespace {

const std::string ROOT_TOKEN = "&TEST";
const std::string MID_TOKEN = "&TEST/APPLE";
const std::string LEAF_TOKEN = "&TEST/APPLE/GOLDEN";

// One holder: address plus the key that would have revealed its public key.
struct Holder {
    CKey key;
    CPubKey pubkey;
    std::string address;
};

struct DepinAncestorSetup : public TestingSetup {
    // Everything global this fixture touches is saved and put back, including
    // the database pointers: restoring them to nullptr would be right only as
    // long as nothing else in the binary ever leaves them set.
    bool prevAssetIndex;
    bool prevPubKeyIndex;
    CAssetsDB* prevAssetsDb;
    CLRUCache<std::string, CDatabasedAssetData>* prevAssetsCache;
    CRestrictedDB* prevRestrictedDb;

    DepinAncestorSetup() : TestingSetup(CBaseChainParams::REGTEST)
    {
        prevAssetIndex = fAssetIndex;
        prevPubKeyIndex = fPubKeyIndex;
        prevAssetsDb = passetsdb;
        prevAssetsCache = passetsCache;
        prevRestrictedDb = prestricteddb;

        fAssetIndex = true;
        fPubKeyIndex = true;

        // TestingSetup builds pblocktree/pcoinsTip/passets but none of the
        // asset-side databases. In-memory and wiped, one set per test case.
        passetsdb = new CAssetsDB(1 << 20, true, true);
        passetsCache = new CLRUCache<std::string, CDatabasedAssetData>(MAX_CACHE_ASSETS_SIZE);
        prestricteddb = new CRestrictedDB(1 << 20, true, true);

        gDepinAncestorRecipientsStats.Reset();
    }

    ~DepinAncestorSetup()
    {
        delete prestricteddb;
        delete passetsCache;
        delete passetsdb;

        prestricteddb = prevRestrictedDb;
        passetsCache = prevAssetsCache;
        passetsdb = prevAssetsDb;

        fPubKeyIndex = prevPubKeyIndex;
        fAssetIndex = prevAssetIndex;
    }

    // Make `name` exist as far as ReadAssetData() is concerned.
    void CreateAsset(const std::string& name)
    {
        CNewAsset asset(name, 1000 * COIN, DEPIN_ASSET_UNITS, 0, 0, "");
        BOOST_REQUIRE(passetsdb->WriteAssetData(asset, 1, uint256()));
    }

    void SetBalance(const std::string& assetName, const std::string& address, CAmount amount)
    {
        BOOST_REQUIRE(passetsdb->WriteAssetAddressQuantity(assetName, address, amount));
    }

    // Put `pubkey` in -pubkeyindex under `address`, the way a spend from that
    // address would have.
    void RevealPubKey(const std::string& address, const CPubKey& pubkey)
    {
        CTxDestination dest = DecodeDestination(address);
        CDestinationIndexData addressData;
        BOOST_REQUIRE(GetDestinationIndexData(dest, addressData));

        std::vector<std::pair<CPubKeyIndexKey, CPubKeyIndexValue> > entries;
        entries.emplace_back(CPubKeyIndexKey(addressData), CPubKeyIndexValue(pubkey, 1, uint256()));
        BOOST_REQUIRE(pblocktree->WritePubKeyIndex(entries));
    }

    // A holder whose public key is already revealed.
    Holder NewHolder(bool revealPubKey = true)
    {
        Holder holder;
        holder.key.MakeNewKey(true);
        holder.pubkey = holder.key.GetPubKey();
        holder.address = EncodeDestination(holder.pubkey.GetID());
        if (revealPubKey) {
            RevealPubKey(holder.address, holder.pubkey);
        }
        return holder;
    }

    // A plain address string with no key behind it, for filling the index
    // cheaply: generating 100k real CKeys would cost seconds of secp256k1 work.
    static std::string SyntheticAddress(uint32_t n)
    {
        std::vector<unsigned char> bytes(20, 0);
        bytes[0] = (unsigned char)(n & 0xff);
        bytes[1] = (unsigned char)((n >> 8) & 0xff);
        bytes[2] = (unsigned char)((n >> 16) & 0xff);
        bytes[3] = (unsigned char)((n >> 24) & 0xff);
        return EncodeDestination(CKeyID(uint160(bytes)));
    }

    // The three-level branch used by most cases.
    void CreateBranch()
    {
        CreateAsset(ROOT_TOKEN);
        CreateAsset(MID_TOKEN);
        CreateAsset(LEAF_TOKEN);
    }
};

std::vector<std::string> AddressesOf(const CDepinAncestorRecipients& result)
{
    std::vector<std::string> addresses;
    for (const CDepinRecipient& recipient : result.recipients) {
        addresses.push_back(recipient.address);
    }
    return addresses;
}

bool Contains(const CDepinAncestorRecipients& result, const std::string& address)
{
    const std::vector<std::string> addresses = AddressesOf(result);
    return std::find(addresses.begin(), addresses.end(), address) != addresses.end();
}

// RAII: null a global for the duration of a check and put it back afterwards,
// so a failing BOOST_CHECK cannot leave the rest of the suite broken.
template <typename T>
struct NullGuard {
    T*& slot;
    T* saved;
    explicit NullGuard(T*& slotIn) : slot(slotIn), saved(slotIn) { slot = nullptr; }
    ~NullGuard() { slot = saved; }
};

struct FlagGuard {
    bool& slot;
    bool saved;
    FlagGuard(bool& slotIn, bool value) : slot(slotIn), saved(slotIn) { slot = value; }
    ~FlagGuard() { slot = saved; }
};

UniValue CallAncestorRecipientsRPC(const UniValue& params)
{
    JSONRPCRequest request;
    request.strMethod = "depingetancestorrecipients";
    request.params = params;
    request.fHelp = false;

    BOOST_REQUIRE(tableRPC["depingetancestorrecipients"]);
    return (*tableRPC["depingetancestorrecipients"]->actor)(request);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(depin_ancestor_recipients_tests, DepinAncestorSetup)

// (1) The union of the three levels, and the ancestor chain reported in order.
BOOST_AUTO_TEST_CASE(returns_holders_of_token_and_every_ancestor)
{
    CreateBranch();

    const Holder leafHolder = NewHolder();
    const Holder midHolder = NewHolder();
    const Holder rootHolder = NewHolder();

    SetBalance(LEAF_TOKEN, leafHolder.address, 1);
    SetBalance(MID_TOKEN, midHolder.address, 1);
    SetBalance(ROOT_TOKEN, rootHolder.address, 1);

    CDepinAncestorRecipients result;
    std::string error;
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error), error);

    const std::vector<std::string> expectedAncestors = {LEAF_TOKEN, MID_TOKEN, ROOT_TOKEN};
    BOOST_CHECK_EQUAL_COLLECTIONS(result.ancestors.begin(), result.ancestors.end(),
                                  expectedAncestors.begin(), expectedAncestors.end());

    BOOST_CHECK_EQUAL(result.recipients.size(), 3U);
    BOOST_CHECK(Contains(result, leafHolder.address));
    BOOST_CHECK(Contains(result, midHolder.address));
    BOOST_CHECK(Contains(result, rootHolder.address));
    BOOST_CHECK(!result.truncated);

    // The returned key must be the one that can actually decrypt for it.
    for (const CDepinRecipient& recipient : result.recipients) {
        BOOST_CHECK(recipient.pubkey.IsValid());
        BOOST_CHECK(EncodeDestination(recipient.pubkey.GetID()) == recipient.address);
    }
}

// (2) Querying the root reaches the root only. Descendants and lookalikes stay
// out: the query is by exact name, never by prefix.
BOOST_AUTO_TEST_CASE(root_query_is_exact_never_a_prefix_scan)
{
    CreateBranch();
    CreateAsset("&TESTING");
    CreateAsset("&TEST.FOO");

    const Holder rootHolder = NewHolder();
    const Holder leafHolder = NewHolder();
    const Holder testingHolder = NewHolder();
    const Holder dottedHolder = NewHolder();

    SetBalance(ROOT_TOKEN, rootHolder.address, 1);
    SetBalance(LEAF_TOKEN, leafHolder.address, 1);
    SetBalance("&TESTING", testingHolder.address, 1);
    SetBalance("&TEST.FOO", dottedHolder.address, 1);

    CDepinAncestorRecipients result;
    std::string error;
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(ROOT_TOKEN, 100, result, error), error);

    BOOST_CHECK_EQUAL(result.ancestors.size(), 1U);
    BOOST_CHECK_EQUAL(result.ancestors[0], ROOT_TOKEN);

    BOOST_CHECK_EQUAL(result.recipients.size(), 1U);
    BOOST_CHECK(Contains(result, rootHolder.address));
    BOOST_CHECK(!Contains(result, leafHolder.address));
    BOOST_CHECK(!Contains(result, testingHolder.address));
    BOOST_CHECK(!Contains(result, dottedHolder.address));
}

// (3) Holding several levels of the branch does not multiply the address.
BOOST_AUTO_TEST_CASE(address_present_in_several_ancestors_appears_once)
{
    CreateBranch();

    const Holder holder = NewHolder();
    SetBalance(LEAF_TOKEN, holder.address, 1);
    SetBalance(MID_TOKEN, holder.address, 1);
    SetBalance(ROOT_TOKEN, holder.address, 1);

    CDepinAncestorRecipients result;
    std::string error;
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error), error);

    BOOST_CHECK_EQUAL(result.recipients.size(), 1U);
    BOOST_CHECK_EQUAL(result.recipients[0].address, holder.address);
}

// (4) A row with a zero (or negative) balance is not a holder.
BOOST_AUTO_TEST_CASE(zero_balance_rows_are_ignored)
{
    CreateBranch();

    const Holder active = NewHolder();
    const Holder empty = NewHolder();
    SetBalance(LEAF_TOKEN, active.address, 1);
    SetBalance(LEAF_TOKEN, empty.address, 0);

    CDepinAncestorRecipients result;
    std::string error;
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error), error);

    BOOST_CHECK_EQUAL(result.recipients.size(), 1U);
    BOOST_CHECK(Contains(result, active.address));
    BOOST_CHECK(!Contains(result, empty.address));
    // A zero balance is not a candidate at all, so it is not a skipped one.
    BOOST_CHECK_EQUAL(result.skippedNoPubKey, 0U);
    BOOST_CHECK_EQUAL(result.skippedRestricted, 0U);
}

// (5) No revealed public key means no way to encrypt for it: counted, not returned.
BOOST_AUTO_TEST_CASE(address_without_revealed_pubkey_is_skipped_and_counted)
{
    CreateBranch();

    const Holder revealed = NewHolder();
    const Holder hidden = NewHolder(/*revealPubKey=*/false);
    SetBalance(LEAF_TOKEN, revealed.address, 1);
    SetBalance(LEAF_TOKEN, hidden.address, 1);

    CDepinAncestorRecipients result;
    std::string error;
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error), error);

    BOOST_CHECK_EQUAL(result.recipients.size(), 1U);
    BOOST_CHECK(Contains(result, revealed.address));
    BOOST_CHECK_EQUAL(result.skippedNoPubKey, 1U);
    BOOST_CHECK(result.skippedNoPubKeyComplete);
}

// (6) An index entry whose key hashes to a different address is rejected:
// encrypting for it would produce a payload the holder cannot open.
BOOST_AUTO_TEST_CASE(pubkey_not_matching_the_address_is_rejected)
{
    CreateBranch();

    const Holder holder = NewHolder(/*revealPubKey=*/false);
    const Holder stranger = NewHolder(/*revealPubKey=*/false);

    // A perfectly valid public key -- just not this address's.
    RevealPubKey(holder.address, stranger.pubkey);
    SetBalance(LEAF_TOKEN, holder.address, 1);

    CDepinAncestorRecipients result;
    std::string error;
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error), error);

    BOOST_CHECK(result.recipients.empty());
    BOOST_CHECK_EQUAL(result.skippedNoPubKey, 1U);
}

// (7) Malformed, non-DEPIN and non-existent tokens all fail with a message that
// names the problem rather than returning an empty set.
BOOST_AUTO_TEST_CASE(invalid_non_depin_or_missing_token_errors)
{
    CreateBranch();

    CDepinAncestorRecipients result;
    std::string error;

    BOOST_CHECK(!GetDepinAncestorRecipients("", 100, result, error));
    BOOST_CHECK(!error.empty());

    // Valid asset name, but a ROOT asset rather than a DEPIN one.
    error.clear();
    BOOST_CHECK(!GetDepinAncestorRecipients("PLAINASSET", 100, result, error));
    BOOST_CHECK(error.find("DEPIN") != std::string::npos);

    // Well-formed DEPIN name that was never issued.
    error.clear();
    BOOST_CHECK(!GetDepinAncestorRecipients("&NOSUCH", 100, result, error));
    BOOST_CHECK(error.find("&NOSUCH") != std::string::npos);

    // max_results out of range.
    error.clear();
    BOOST_CHECK(!GetDepinAncestorRecipients(LEAF_TOKEN, 0, result, error));
    error.clear();
    BOOST_CHECK(!GetDepinAncestorRecipients(LEAF_TOKEN, MAX_DEPIN_ANCESTOR_RECIPIENTS_HARD_CAP + 1,
                                            result, error));
}

// (8) A hole in the chain is an error. Skipping the missing level and carrying
// on to the root would answer a different question than the one asked.
BOOST_AUTO_TEST_CASE(missing_intermediate_ancestor_is_an_error)
{
    CreateAsset(ROOT_TOKEN);
    CreateAsset(LEAF_TOKEN);  // deliberately no MID_TOKEN

    const Holder rootHolder = NewHolder();
    SetBalance(ROOT_TOKEN, rootHolder.address, 1);

    CDepinAncestorRecipients result;
    std::string error;
    BOOST_CHECK(!GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error));
    BOOST_CHECK_MESSAGE(error.find(MID_TOKEN) != std::string::npos,
                        "error should name the missing ancestor, got: " + error);
    BOOST_CHECK(result.recipients.empty());
}

// (9) Every precondition is checked, by name, BEFORE the flush.
//
// For pblocktree and pcoinsTip that ordering is not an efficiency preference:
// FlushStateToDisk() dereferences both without checking them, so validating
// after the flush would not produce an error, it would crash. Hence the
// flush-counter assertion in each case -- reaching the error means the flush
// never happened.
//
// prestricteddb is the delicate one: its absence fails OPEN elsewhere in the
// codebase (restriction checks return false when it is null), so the query has
// to FAIL rather than return a set in which everyone merely looks unrestricted.
BOOST_AUTO_TEST_CASE(missing_preconditions_error_before_flushing)
{
    CreateBranch();
    const Holder holder = NewHolder();
    SetBalance(LEAF_TOKEN, holder.address, 1);

    CDepinAncestorRecipients result;
    std::string error;

    {
        FlagGuard guard(fAssetIndex, false);
        gDepinAncestorRecipientsStats.Reset();
        BOOST_CHECK(!GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error));
        BOOST_CHECK(error.find("Asset index") != std::string::npos);
        BOOST_CHECK_EQUAL(gDepinAncestorRecipientsStats.flushCalls.load(), 0U);
    }
    {
        FlagGuard guard(fPubKeyIndex, false);
        gDepinAncestorRecipientsStats.Reset();
        BOOST_CHECK(!GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error));
        BOOST_CHECK(error.find("Public key index") != std::string::npos);
        BOOST_CHECK_EQUAL(gDepinAncestorRecipientsStats.flushCalls.load(), 0U);
    }
    {
        NullGuard<CAssetsDB> guard(passetsdb);
        gDepinAncestorRecipientsStats.Reset();
        BOOST_CHECK(!GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error));
        BOOST_CHECK(error.find("Asset database") != std::string::npos);
        BOOST_CHECK_EQUAL(gDepinAncestorRecipientsStats.flushCalls.load(), 0U);
    }
    {
        NullGuard<CBlockTreeDB> guard(pblocktree);
        gDepinAncestorRecipientsStats.Reset();
        BOOST_CHECK(!GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error));
        BOOST_CHECK(error.find("Block tree") != std::string::npos);
        BOOST_CHECK_EQUAL(gDepinAncestorRecipientsStats.flushCalls.load(), 0U);
    }
    {
        // The one that is easy to forget, because the function never uses it
        // directly -- FlushStateToDisk() does, in its main path.
        NullGuard<CCoinsViewCache> guard(pcoinsTip);
        gDepinAncestorRecipientsStats.Reset();
        BOOST_CHECK(!GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error));
        BOOST_CHECK(error.find("Coins view") != std::string::npos);
        BOOST_CHECK_EQUAL(gDepinAncestorRecipientsStats.flushCalls.load(), 0U);
    }
    {
        NullGuard<CRestrictedDB> guard(prestricteddb);
        gDepinAncestorRecipientsStats.Reset();
        BOOST_CHECK(!GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error));
        BOOST_CHECK_MESSAGE(error.find("Restricted asset database") != std::string::npos,
                            "prestricteddb must fail explicitly, got: " + error);
        BOOST_CHECK(result.recipients.empty());
        BOOST_CHECK_EQUAL(gDepinAncestorRecipientsStats.flushCalls.load(), 0U);
    }

    // Everything restored: the same query now succeeds.
    gDepinAncestorRecipientsStats.Reset();
    BOOST_CHECK_MESSAGE(GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error), error);
    BOOST_CHECK_EQUAL(result.recipients.size(), 1U);
}

// (10) and (11): the boundary between "exactly the limit" and "there are more".
BOOST_AUTO_TEST_CASE(truncation_boundary)
{
    CreateBranch();

    std::vector<std::string> eligible;
    for (int i = 0; i < 5; ++i) {
        const Holder holder = NewHolder();
        SetBalance(LEAF_TOKEN, holder.address, 1);
        eligible.push_back(holder.address);
    }
    std::sort(eligible.begin(), eligible.end());

    CDepinAncestorRecipients result;
    std::string error;

    // Fewer recipients than the limit: nothing is cut.
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(LEAF_TOKEN, 10, result, error), error);
    BOOST_CHECK_EQUAL(result.recipients.size(), 5U);
    BOOST_CHECK(!result.truncated);

    // Exactly the limit: still not truncated. This is what the extra probe
    // beyond maxResults is for -- without it, "5 of 5" and "5 of many" would be
    // indistinguishable.
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(LEAF_TOKEN, 5, result, error), error);
    BOOST_CHECK_EQUAL(result.recipients.size(), 5U);
    BOOST_CHECK(!result.truncated);

    // One less than available: exactly maxResults entries, flagged.
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(LEAF_TOKEN, 3, result, error), error);
    BOOST_CHECK_EQUAL(result.recipients.size(), 3U);
    BOOST_CHECK(result.truncated);

    // ...and they are the first three in address order, not whatever LevelDB
    // handed back first.
    const std::vector<std::string> returned = AddressesOf(result);
    const std::vector<std::string> expected(eligible.begin(), eligible.begin() + 3);
    BOOST_CHECK_EQUAL_COLLECTIONS(returned.begin(), returned.end(),
                                  expected.begin(), expected.end());
}

// (12) The order is fixed before anything is cut, so an ineligible address is
// dropped from the ordering rather than consuming a slot in it. Cutting the
// candidate list first and only then testing eligibility would return fewer
// than maxResults recipients while more were available.
BOOST_AUTO_TEST_CASE(skipped_addresses_do_not_displace_later_valid_ones)
{
    CreateBranch();

    // Six candidates; the two that sort first are made ineligible after the
    // fact, so a naive "take the first N addresses, then filter" would return
    // one recipient instead of three.
    std::vector<Holder> holders;
    for (int i = 0; i < 6; ++i) {
        holders.push_back(NewHolder(/*revealPubKey=*/false));
    }
    std::sort(holders.begin(), holders.end(),
              [](const Holder& a, const Holder& b) { return a.address < b.address; });

    for (size_t i = 0; i < holders.size(); ++i) {
        SetBalance(LEAF_TOKEN, holders[i].address, 1);
        // Leave the first two without a revealed key.
        if (i >= 2) {
            RevealPubKey(holders[i].address, holders[i].pubkey);
        }
    }

    CDepinAncestorRecipients result;
    std::string error;
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(LEAF_TOKEN, 3, result, error), error);

    BOOST_CHECK_EQUAL(result.recipients.size(), 3U);
    BOOST_CHECK(result.truncated);

    const std::vector<std::string> returned = AddressesOf(result);
    const std::vector<std::string> expected = {holders[2].address, holders[3].address,
                                               holders[4].address};
    BOOST_CHECK_EQUAL_COLLECTIONS(returned.begin(), returned.end(),
                                  expected.begin(), expected.end());

    // The result is also sorted, which is what makes it reproducible.
    BOOST_CHECK(std::is_sorted(returned.begin(), returned.end()));
}

// (13) stop_at bounds the derivation, and a stop_at off this branch is an error.
BOOST_AUTO_TEST_CASE(stop_at_bounds_the_ancestor_chain)
{
    CreateBranch();
    CreateAsset("&OTHER");

    const Holder leafHolder = NewHolder();
    const Holder midHolder = NewHolder();
    const Holder rootHolder = NewHolder();
    SetBalance(LEAF_TOKEN, leafHolder.address, 1);
    SetBalance(MID_TOKEN, midHolder.address, 1);
    SetBalance(ROOT_TOKEN, rootHolder.address, 1);

    CDepinAncestorRecipients result;
    std::string error;
    BOOST_REQUIRE_MESSAGE(
        GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error, MID_TOKEN), error);

    const std::vector<std::string> expectedAncestors = {LEAF_TOKEN, MID_TOKEN};
    BOOST_CHECK_EQUAL_COLLECTIONS(result.ancestors.begin(), result.ancestors.end(),
                                  expectedAncestors.begin(), expectedAncestors.end());
    BOOST_CHECK_EQUAL(result.recipients.size(), 2U);
    BOOST_CHECK(Contains(result, leafHolder.address));
    BOOST_CHECK(Contains(result, midHolder.address));
    BOOST_CHECK_MESSAGE(!Contains(result, rootHolder.address),
                        "stop_at must keep root holders out");

    // stop_at equal to the token itself: that level only.
    BOOST_REQUIRE_MESSAGE(
        GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error, LEAF_TOKEN), error);
    BOOST_CHECK_EQUAL(result.ancestors.size(), 1U);
    BOOST_CHECK_EQUAL(result.recipients.size(), 1U);
    BOOST_CHECK(Contains(result, leafHolder.address));

    // A valid DEPIN token that is not on this branch.
    error.clear();
    BOOST_CHECK(!GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error, "&OTHER"));
    BOOST_CHECK(error.find("stop_at") != std::string::npos);

    // A descendant is not an ancestor either: derivation only goes up.
    error.clear();
    BOOST_CHECK(!GetDepinAncestorRecipients(MID_TOKEN, 100, result, error, LEAF_TOKEN));
    BOOST_CHECK(error.find("stop_at") != std::string::npos);
}

// (14) The RPC validates its parameters and serialises the whole result.
BOOST_AUTO_TEST_CASE(rpc_validates_and_serialises)
{
    CreateBranch();

    const Holder leafHolder = NewHolder();
    const Holder rootHolder = NewHolder();
    const Holder hidden = NewHolder(/*revealPubKey=*/false);
    SetBalance(LEAF_TOKEN, leafHolder.address, 1);
    SetBalance(ROOT_TOKEN, rootHolder.address, 1);
    SetBalance(ROOT_TOKEN, hidden.address, 1);

    UniValue params(UniValue::VARR);
    params.push_back(LEAF_TOKEN);
    const UniValue result = CallAncestorRecipientsRPC(params);

    BOOST_CHECK_EQUAL(find_value(result, "token").get_str(), LEAF_TOKEN);
    BOOST_CHECK_EQUAL(find_value(result, "stop_at").get_str(), "");
    BOOST_CHECK_EQUAL(find_value(result, "max_results").get_int64(),
                      (int64_t)DEFAULT_DEPIN_ANCESTOR_RECIPIENTS_LIMIT);
    BOOST_CHECK_EQUAL(find_value(result, "returned").get_int64(), 2);
    BOOST_CHECK(!find_value(result, "truncated").get_bool());
    BOOST_CHECK_EQUAL(find_value(result, "skipped_no_pubkey").get_int64(), 1);
    BOOST_CHECK(find_value(result, "skipped_no_pubkey_complete").get_bool());
    BOOST_CHECK_EQUAL(find_value(result, "skipped_restricted").get_int64(), 0);
    BOOST_CHECK(find_value(result, "skipped_restricted_complete").get_bool());

    const UniValue ancestors = find_value(result, "ancestors");
    BOOST_REQUIRE_EQUAL(ancestors.size(), 3U);
    BOOST_CHECK_EQUAL(ancestors[0].get_str(), LEAF_TOKEN);
    BOOST_CHECK_EQUAL(ancestors[1].get_str(), MID_TOKEN);
    BOOST_CHECK_EQUAL(ancestors[2].get_str(), ROOT_TOKEN);

    // Public keys come back as hex that decodes to the address they belong to.
    const UniValue recipients = find_value(result, "recipients");
    BOOST_REQUIRE_EQUAL(recipients.size(), 2U);
    for (size_t i = 0; i < recipients.size(); ++i) {
        const std::string address = find_value(recipients[i], "address").get_str();
        const std::string pubkeyHex = find_value(recipients[i], "pubkey").get_str();
        const std::vector<unsigned char> bytes = ParseHex(pubkeyHex);
        const CPubKey pubkey(bytes.begin(), bytes.end());
        BOOST_CHECK(pubkey.IsFullyValid());
        BOOST_CHECK_EQUAL(EncodeDestination(pubkey.GetID()), address);
    }

    // stop_at travels through the RPC.
    UniValue stopParams(UniValue::VARR);
    stopParams.push_back(LEAF_TOKEN);
    stopParams.push_back(100);
    stopParams.push_back(LEAF_TOKEN);
    const UniValue stopped = CallAncestorRecipientsRPC(stopParams);
    BOOST_CHECK_EQUAL(find_value(stopped, "stop_at").get_str(), LEAF_TOKEN);
    BOOST_CHECK_EQUAL(find_value(stopped, "ancestors").size(), 1U);
    BOOST_CHECK_EQUAL(find_value(stopped, "returned").get_int64(), 1);

    // Parameter validation.
    UniValue zero(UniValue::VARR);
    zero.push_back(LEAF_TOKEN);
    zero.push_back((int64_t)0);
    BOOST_CHECK_THROW(CallAncestorRecipientsRPC(zero), UniValue);

    UniValue overCap(UniValue::VARR);
    overCap.push_back(LEAF_TOKEN);
    overCap.push_back((int64_t)MAX_DEPIN_ANCESTOR_RECIPIENTS_HARD_CAP + 1);
    BOOST_CHECK_THROW(CallAncestorRecipientsRPC(overCap), UniValue);

    UniValue badToken(UniValue::VARR);
    badToken.push_back("PLAINASSET");
    BOOST_CHECK_THROW(CallAncestorRecipientsRPC(badToken), UniValue);

    // neurai-cli hands every argument over as a string unless the command is
    // listed in vRPCConvertParams (rpc/client.cpp). Without an entry for
    // max_results, `neurai-cli depingetancestorrecipients "&TEST" 5` dies with
    // "JSON value is not an integer as expected" before the RPC body runs --
    // a failure the checks above cannot see, because they build the UniValue
    // themselves and so bypass that layer entirely. This was a real defect,
    // found by the regtest/testnet walkthrough rather than by this suite.
    const std::vector<std::string> cliArgs = {LEAF_TOKEN, "5", LEAF_TOKEN};
    const UniValue converted = RPCConvertValues("depingetancestorrecipients", cliArgs);
    BOOST_REQUIRE_EQUAL(converted.size(), 3U);
    BOOST_CHECK(converted[0].isStr());
    BOOST_CHECK_MESSAGE(converted[1].isNum(),
                        "max_results must be converted to a number by the CLI layer");
    BOOST_CHECK_EQUAL(converted[1].get_int64(), 5);
    BOOST_CHECK(converted[2].isStr());

    // And the converted parameters actually work end to end.
    const UniValue viaCli = CallAncestorRecipientsRPC(converted);
    BOOST_CHECK_EQUAL(find_value(viaCli, "max_results").get_int64(), 5);
    BOOST_CHECK_EQUAL(find_value(viaCli, "stop_at").get_str(), LEAF_TOKEN);
}

// (15) The *_complete flags tell the caller whether a count is a total or only
// what was seen before the walk stopped.
BOOST_AUTO_TEST_CASE(skipped_counters_report_their_own_completeness)
{
    CreateBranch();

    // Alternate eligible / ineligible so a small maxResults stops the walk with
    // skips both before and after the cut.
    std::vector<Holder> holders;
    for (int i = 0; i < 8; ++i) {
        holders.push_back(NewHolder(/*revealPubKey=*/false));
    }
    std::sort(holders.begin(), holders.end(),
              [](const Holder& a, const Holder& b) { return a.address < b.address; });

    size_t totalHidden = 0;
    for (size_t i = 0; i < holders.size(); ++i) {
        SetBalance(LEAF_TOKEN, holders[i].address, 1);
        if (i % 2 == 0) {
            RevealPubKey(holders[i].address, holders[i].pubkey);
        } else {
            totalHidden += 1;
        }
    }

    CDepinAncestorRecipients result;
    std::string error;

    // No truncation: the counts cover the entire query.
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error), error);
    BOOST_CHECK(!result.truncated);
    BOOST_CHECK(result.skippedNoPubKeyComplete);
    BOOST_CHECK(result.skippedRestrictedComplete);
    BOOST_CHECK_EQUAL(result.skippedNoPubKey, totalHidden);

    // Truncated: the counts only cover the addresses examined, and say so.
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(LEAF_TOKEN, 1, result, error), error);
    BOOST_CHECK(result.truncated);
    BOOST_CHECK(!result.skippedNoPubKeyComplete);
    BOOST_CHECK(!result.skippedRestrictedComplete);
    BOOST_CHECK_MESSAGE(result.skippedNoPubKey < totalHidden,
                        "a truncated walk cannot have seen every skipped address");
}

// (16) Both kinds of block exclude a holder, and lifting either brings it back.
BOOST_AUTO_TEST_CASE(owner_freeze_and_self_revoke_exclude_and_can_be_lifted)
{
    CreateBranch();

    const Holder frozen = NewHolder();
    const Holder revoked = NewHolder();
    const Holder active = NewHolder();
    SetBalance(LEAF_TOKEN, frozen.address, 1);
    SetBalance(LEAF_TOKEN, revoked.address, 1);
    SetBalance(LEAF_TOKEN, active.address, 1);

    BOOST_REQUIRE(prestricteddb->WriteRestrictedAddress(frozen.address, LEAF_TOKEN));
    BOOST_REQUIRE(prestricteddb->WriteSelfRestriction(revoked.address, LEAF_TOKEN));

    CDepinAncestorRecipients result;
    std::string error;
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error), error);

    BOOST_CHECK_EQUAL(result.recipients.size(), 1U);
    BOOST_CHECK(Contains(result, active.address));
    BOOST_CHECK(!Contains(result, frozen.address));
    BOOST_CHECK(!Contains(result, revoked.address));
    BOOST_CHECK_EQUAL(result.skippedRestricted, 2U);
    BOOST_CHECK(result.skippedRestrictedComplete);

    // Unfreeze and un-revoke: both come back, balance and key unchanged.
    BOOST_REQUIRE(prestricteddb->EraseRestrictedAddress(frozen.address, LEAF_TOKEN));
    BOOST_REQUIRE(prestricteddb->EraseSelfRestriction(revoked.address, LEAF_TOKEN));

    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error), error);
    BOOST_CHECK_EQUAL(result.recipients.size(), 3U);
    BOOST_CHECK_EQUAL(result.skippedRestricted, 0U);
}

// (17) Restriction is per (asset, address). Being active in ONE ancestor is
// enough -- revoking in a section does not withdraw what holding the root
// grants -- and an address blocked everywhere is counted exactly once, not
// once per blocked pair.
BOOST_AUTO_TEST_CASE(restriction_is_per_pair_not_per_address)
{
    CreateBranch();

    // Revoked in the middle level, still active at the root.
    const Holder partly = NewHolder();
    SetBalance(MID_TOKEN, partly.address, 1);
    SetBalance(ROOT_TOKEN, partly.address, 1);
    BOOST_REQUIRE(prestricteddb->WriteSelfRestriction(partly.address, MID_TOKEN));

    // Blocked in every level where it holds anything.
    const Holder fully = NewHolder();
    SetBalance(MID_TOKEN, fully.address, 1);
    SetBalance(ROOT_TOKEN, fully.address, 1);
    BOOST_REQUIRE(prestricteddb->WriteSelfRestriction(fully.address, MID_TOKEN));
    BOOST_REQUIRE(prestricteddb->WriteRestrictedAddress(fully.address, ROOT_TOKEN));

    CDepinAncestorRecipients result;
    std::string error;
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error), error);

    BOOST_CHECK_MESSAGE(Contains(result, partly.address),
                        "active in one ancestor is enough to be a recipient");
    BOOST_CHECK(!Contains(result, fully.address));

    // One address omitted, not two blocked pairs and not the still-active one.
    BOOST_CHECK_EQUAL(result.skippedRestricted, 1U);
    BOOST_CHECK_EQUAL(result.recipients.size(), 1U);
}

// (18) and (19): the exploration bound.
//
// Both boundaries live in one case because the fixture is rebuilt per case and
// populating the limit twice would double an already heavy test.
//
// Crossing it is an ERROR, never truncated == true: truncation promises "the
// first N in a deterministic order", and here the candidate set was never
// collected in full, so ordering what did arrive and returning its head would
// be an arbitrary answer that looks correct.
BOOST_AUTO_TEST_CASE(exploration_limit_is_an_error_not_a_truncation)
{
    CreateBranch();

    // Exactly the limit, all ineligible: cheap to walk, and enough to prove the
    // boundary is not off by one.
    for (uint32_t i = 0; i < MAX_DEPIN_ANCESTOR_SCAN_ROWS; ++i) {
        SetBalance(LEAF_TOKEN, SyntheticAddress(i), 1);
    }

    CDepinAncestorRecipients result;
    std::string error;
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(LEAF_TOKEN, 10, result, error),
                          "exactly MAX_DEPIN_ANCESTOR_SCAN_ROWS rows must not fail: " + error);
    BOOST_CHECK(result.recipients.empty());
    BOOST_CHECK(!result.truncated);
    BOOST_CHECK_EQUAL(result.skippedNoPubKey, (size_t)MAX_DEPIN_ANCESTOR_SCAN_ROWS);

    // One more row, and the query refuses to answer.
    SetBalance(LEAF_TOKEN, SyntheticAddress(MAX_DEPIN_ANCESTOR_SCAN_ROWS), 1);

    error.clear();
    BOOST_CHECK(!GetDepinAncestorRecipients(LEAF_TOKEN, 10, result, error));
    BOOST_CHECK_MESSAGE(error.find("exploration limit") != std::string::npos,
                        "error should name the exploration limit, got: " + error);
    BOOST_CHECK_MESSAGE(!result.truncated,
                        "an exploration cut must not masquerade as a maxResults truncation");
    BOOST_CHECK(result.recipients.empty());
}

// (20) Restriction cost per address does not grow with the depth of the branch.
// Going back to one CheckForDEPINRestriction() call per (ancestor, address)
// pair is the easy regression here; it keeps the answer correct and multiplies
// the random reads by 2 x depth.
BOOST_AUTO_TEST_CASE(restriction_cost_does_not_grow_with_depth)
{
    // A four-level branch, one address holding all four levels.
    const std::vector<std::string> chain = {"&AAA", "&AAA/BBB", "&AAA/BBB/CCC", "&AAA/BBB/CCC/DDD"};
    for (const std::string& name : chain) {
        CreateAsset(name);
    }

    const Holder holder = NewHolder();
    for (const std::string& name : chain) {
        SetBalance(name, holder.address, 1);
    }

    gDepinAncestorRecipientsStats.Reset();

    CDepinAncestorRecipients result;
    std::string error;
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(chain.back(), 100, result, error), error);

    BOOST_CHECK_EQUAL(result.ancestors.size(), 4U);
    BOOST_CHECK_EQUAL(result.recipients.size(), 1U);

    // One address examined, so one restriction resolution -- regardless of the
    // four levels it was checked against.
    BOOST_CHECK_EQUAL(gDepinAncestorRecipientsStats.restrictionQueries.load(), 1U);
    BOOST_CHECK_EQUAL(gDepinAncestorRecipientsStats.pubkeyQueries.load(), 1U);
}

// (21) Restriction lookups stop early too. Resolving every address's
// restrictions in a pass before touching public keys also works, but it throws
// away the early stop: with a small maxResults the work must stay proportional
// to the addresses examined, not to the size of the branch.
BOOST_AUTO_TEST_CASE(restriction_lookups_stop_early_with_a_small_max_results)
{
    CreateBranch();

    const size_t kHolders = 60;
    for (size_t i = 0; i < kHolders; ++i) {
        const Holder holder = NewHolder();
        SetBalance(LEAF_TOKEN, holder.address, 1);
    }

    gDepinAncestorRecipientsStats.Reset();

    CDepinAncestorRecipients result;
    std::string error;
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(LEAF_TOKEN, 2, result, error), error);

    BOOST_CHECK_EQUAL(result.recipients.size(), 2U);
    BOOST_CHECK(result.truncated);

    // Every holder here is eligible, so the walk stops at the probe: two
    // returned plus one that only proves there are more.
    BOOST_CHECK_EQUAL(gDepinAncestorRecipientsStats.restrictionQueries.load(), 3U);
    BOOST_CHECK_EQUAL(gDepinAncestorRecipientsStats.pubkeyQueries.load(), 3U);
    BOOST_CHECK_MESSAGE(gDepinAncestorRecipientsStats.restrictionQueries.load() < kHolders,
                        "restriction lookups must not scale with the whole branch");
}

// (22) Within an address the order is restriction first, public key second: an
// address already dropped must not cost an index read.
BOOST_AUTO_TEST_CASE(restricted_address_costs_no_pubkey_lookup)
{
    CreateBranch();

    const Holder blocked = NewHolder();
    SetBalance(LEAF_TOKEN, blocked.address, 1);
    BOOST_REQUIRE(prestricteddb->WriteSelfRestriction(blocked.address, LEAF_TOKEN));

    gDepinAncestorRecipientsStats.Reset();

    CDepinAncestorRecipients result;
    std::string error;
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error), error);

    BOOST_CHECK(result.recipients.empty());
    BOOST_CHECK_EQUAL(result.skippedRestricted, 1U);
    BOOST_CHECK_EQUAL(gDepinAncestorRecipientsStats.restrictionQueries.load(), 1U);
    BOOST_CHECK_EQUAL(gDepinAncestorRecipientsStats.pubkeyQueries.load(), 0U);
}

// (23) One flush per query, whatever its size -- and the read helpers do not
// flush at all.
//
// This is the most expensive regression of the set: copying the body of
// GetAddressRestrictions() brings its unconditional FlushStateToDisk() along,
// turning one query into thousands of global flushes with no functional test
// noticing. The helpers are checked with pcoinsTip nulled: FlushStateToDisk()
// dereferences it unguarded, so a helper that flushed would crash here instead
// of passing.
//
// Called directly rather than through the RPC on purpose: the lock-and-flush
// contract belongs to the function, so the function alone must satisfy it.
BOOST_AUTO_TEST_CASE(flushes_exactly_once_and_helpers_never_flush)
{
    CreateBranch();

    // A branch with several ancestors and several addresses, so a per-ancestor
    // or per-address flush would show up as a count above one.
    for (int i = 0; i < 5; ++i) {
        const Holder holder = NewHolder();
        SetBalance(LEAF_TOKEN, holder.address, 1);
        SetBalance(MID_TOKEN, holder.address, 1);
        SetBalance(ROOT_TOKEN, holder.address, 1);
    }

    gDepinAncestorRecipientsStats.Reset();

    CDepinAncestorRecipients result;
    std::string error;
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error), error);

    BOOST_CHECK_EQUAL(result.recipients.size(), 5U);
    BOOST_CHECK_EQUAL(gDepinAncestorRecipientsStats.flushCalls.load(), 1U);
    BOOST_CHECK_EQUAL(gDepinAncestorRecipientsStats.restrictionQueries.load(), 5U);

    // Now with pcoinsTip gone: neither helper may flush, so both must still
    // work. A raw FlushStateToDisk() inside either would take the node down at
    // validation.cpp:3202 rather than return.
    {
        NullGuard<CCoinsViewCache> guard(pcoinsTip);

        std::map<std::string, std::vector<std::pair<std::string, CAmount> > > rows;
        bool hitRowLimit = true;
        BOOST_CHECK(passetsdb->AssetAddressDirMulti(result.ancestors, rows,
                                                    MAX_DEPIN_ANCESTOR_SCAN_ROWS, hitRowLimit));
        BOOST_CHECK(!hitRowLimit);
        BOOST_CHECK_EQUAL(rows.size(), 3U);
        BOOST_CHECK_EQUAL(rows[LEAF_TOKEN].size(), 5U);

        // Rows come back sorted by address, so the caller's ordering does not
        // depend on LevelDB's physical layout.
        BOOST_CHECK(std::is_sorted(rows[LEAF_TOKEN].begin(), rows[LEAF_TOKEN].end()));

        std::set<std::string> ownerFrozen;
        std::set<std::string> selfRevoked;
        BOOST_CHECK(prestricteddb->GetAddressDepinRestrictions(result.recipients[0].address,
                                                               ownerFrozen, selfRevoked));
        BOOST_CHECK(ownerFrozen.empty());
        BOOST_CHECK(selfRevoked.empty());
    }
}

// (24) GetAddressDepinRestrictions() returns self-revocations as well as
// freezes. Calling GetAddressRestrictions() twice would not: it only ever scans
// RESTRICTED_ADDRESS_FLAG, and no ranged read of SELF_RESTRICTED_FLAG existed
// before this helper.
BOOST_AUTO_TEST_CASE(address_restrictions_helper_covers_self_revocations)
{
    CreateBranch();

    const Holder selfOnly = NewHolder();
    const Holder freezeOnly = NewHolder();
    const Holder both = NewHolder();

    BOOST_REQUIRE(prestricteddb->WriteSelfRestriction(selfOnly.address, LEAF_TOKEN));
    BOOST_REQUIRE(prestricteddb->WriteRestrictedAddress(freezeOnly.address, LEAF_TOKEN));
    BOOST_REQUIRE(prestricteddb->WriteSelfRestriction(both.address, MID_TOKEN));
    BOOST_REQUIRE(prestricteddb->WriteRestrictedAddress(both.address, ROOT_TOKEN));

    std::set<std::string> ownerFrozen;
    std::set<std::string> selfRevoked;

    BOOST_REQUIRE(prestricteddb->GetAddressDepinRestrictions(selfOnly.address, ownerFrozen, selfRevoked));
    BOOST_CHECK(ownerFrozen.empty());
    BOOST_CHECK_EQUAL(selfRevoked.size(), 1U);
    BOOST_CHECK(selfRevoked.count(LEAF_TOKEN) == 1);

    BOOST_REQUIRE(prestricteddb->GetAddressDepinRestrictions(freezeOnly.address, ownerFrozen, selfRevoked));
    BOOST_CHECK_EQUAL(ownerFrozen.size(), 1U);
    BOOST_CHECK(ownerFrozen.count(LEAF_TOKEN) == 1);
    BOOST_CHECK(selfRevoked.empty());

    // The two flags are separate key ranges, so both have to be scanned.
    BOOST_REQUIRE(prestricteddb->GetAddressDepinRestrictions(both.address, ownerFrozen, selfRevoked));
    BOOST_CHECK(ownerFrozen.count(ROOT_TOKEN) == 1);
    BOOST_CHECK(selfRevoked.count(MID_TOKEN) == 1);

    // An untouched address comes back clean rather than inheriting the previous
    // call's output.
    const Holder clean = NewHolder();
    BOOST_REQUIRE(prestricteddb->GetAddressDepinRestrictions(clean.address, ownerFrozen, selfRevoked));
    BOOST_CHECK(ownerFrozen.empty());
    BOOST_CHECK(selfRevoked.empty());

    // And through the query: self-revocation alone is enough to exclude.
    SetBalance(LEAF_TOKEN, selfOnly.address, 1);
    CDepinAncestorRecipients result;
    std::string error;
    BOOST_REQUIRE_MESSAGE(GetDepinAncestorRecipients(LEAF_TOKEN, 100, result, error), error);
    BOOST_CHECK(result.recipients.empty());
    BOOST_CHECK_EQUAL(result.skippedRestricted, 1U);
}

BOOST_AUTO_TEST_SUITE_END()
