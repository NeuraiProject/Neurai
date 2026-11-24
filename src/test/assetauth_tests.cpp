// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NIP-054: OP_CHECKASSETAUTH (P2AH inside AuthScript).

#include "assets/assets.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/validation.h"
#include "hash.h"
#include "policy/policy.h"
#include "primitives/transaction.h"
#include "script/assetauth.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "script/standard.h"
#include "test/test_neurai.h"
#include "validation.h"

#include <boost/test/unit_test.hpp>

bool CheckInputs(const CTransaction &tx, CValidationState &state, const CCoinsViewCache &inputs, bool fScriptChecks, script_verify_flags flags, bool cacheSigStore, bool cacheFullScriptStore, PrecomputedTransactionData &txdata, std::vector<CScriptCheck> *pvChecks = nullptr, std::shared_ptr<std::vector<CTxOut>> pRefOutputs = nullptr, ChainContext chainCtx = {}, bool* pfUsesChainContext = nullptr, std::shared_ptr<PoseidonWorkBudget> poseidonWork = nullptr, std::shared_ptr<ScriptExecutionStatus> executionStatus = nullptr, bool fBlockValidation = false, std::shared_ptr<AssetAuthWorkBudget> assetAuthWork = nullptr);

namespace {

constexpr script_verify_flags FLAGS = SCRIPT_VERIFY_ASSETAUTH | SCRIPT_VERIFY_AUTHSCRIPT_STRICT;
constexpr int64_t HEIGHT = 1000;

using Stack = std::vector<std::vector<unsigned char>>;

CScript ProgramDest(opcodetype version, unsigned char fill)
{
    std::vector<unsigned char> bytes{static_cast<unsigned char>(version), 0x20};
    bytes.insert(bytes.end(), 32, fill);
    return CScript(bytes.begin(), bytes.end());
}

CScript P2PKHDest(unsigned char fill)
{
    return CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, fill) << OP_EQUALVERIFY << OP_CHECKSIG;
}

// Custodies and vote locks are generic AuthScript v1 destinations.
const CScript CUSTODY = ProgramDest(OP_1, 0xc1);
const CScript CUSTODY_B = ProgramDest(OP_1, 0xc2);
const CScript LOCK_A = ProgramDest(OP_1, 0xa1);
const CScript LOCK_B = ProgramDest(OP_1, 0xa2);
const CScript LOCK_C = ProgramDest(OP_1, 0xa3);

CTxOut XnaOut(const CScript& dest, CAmount value)
{
    return CTxOut(value, dest);
}

CTxOut AssetOut(const CScript& dest, const std::string& name, CAmount amount, const std::string& message = "")
{
    CTxOut out(0, dest);
    CAssetTransfer transfer(name, amount, message);
    transfer.ConstructTransaction(out.scriptPubKey, AssetMarker::NEURAI_XNA);
    return out;
}

CTxOut OwnerOut(const CScript& dest, const std::string& name, const std::string& message = "")
{
    return AssetOut(dest, name, OWNER_ASSET_AMOUNT, message);
}

/** The owner output of an issuance of `root`: an owner without a transfer payload. */
CTxOut OwnerIssuanceOut(const CScript& dest, const std::string& root)
{
    CTxOut out(0, dest);
    CNewAsset asset(root, 0);
    asset.ConstructOwnerTransaction(out.scriptPubKey, AssetMarker::NEURAI_XNA);
    return out;
}

std::string MessageOf(const uint256& hash)
{
    return std::string(hash.begin(), hash.end());
}

CScript SigScript(unsigned char hashType)
{
    std::vector<unsigned char> sig(71, 0x30);
    sig.back() = hashType;
    return CScript() << sig << std::vector<unsigned char>(33, 0x02);
}

CScriptWitness StrictWitness(unsigned char hashType)
{
    std::vector<unsigned char> sig(71, 0x30);
    sig.back() = hashType;
    CScriptWitness witness;
    witness.stack = {{0x02}, sig, std::vector<unsigned char>(33, 0x02), {OP_TRUE}};
    return witness;
}

AssetAuthCall Policy(int M, int G, std::vector<std::string> roles, int64_t c = 0, int64_t a = 0, int64_t b = 0, int64_t T = HEIGHT)
{
    AssetAuthCall call;
    call.version = ASSETAUTH_POLICY_VERSION;
    call.M = M;
    call.G = G;
    call.roles = std::move(roles);
    call.c = c;
    call.a = a;
    call.b = b;
    call.T = T;
    return call;
}

AssetAuthCall PolicyV2(int M, int G, std::vector<std::string> roles, int64_t c = 0, int64_t a = 0, int64_t b = 0,
                       int64_t r = 0, int64_t T = HEIGHT)
{
    AssetAuthCall call = Policy(M, G, std::move(roles), c, a, b, T);
    call.version = ASSETAUTH_POLICY_VERSION_2;
    call.r = r;
    return call;
}

ChainContext Context(int64_t height = HEIGHT)
{
    return ChainContext{height, 0, 2, true};
}

/** A spending transaction with its prevouts, built input by input. */
struct Spend {
    CMutableTransaction mtx;
    std::vector<CTxOut> prevouts;
    std::vector<CTxOut> refOutputs; //!< NIP-014: the output of each reference input

    Spend() { mtx.nVersion = 2; }

    /** A reference input (NIP-014); only version 3 transactions carry them. */
    void Ref(const CTxOut& out)
    {
        mtx.nVersion = 3;
        mtx.vrefin.emplace_back(uint256S(strprintf("%064x", 0x2000 + mtx.vrefin.size())), 0);
        refOutputs.push_back(out);
    }

    void Input(const CTxOut& prevout, const CScript& scriptSig = CScript(), const CScriptWitness& witness = CScriptWitness())
    {
        CTxIn in(COutPoint(uint256S(strprintf("%064x", 0x1000 + mtx.vin.size())), 0), scriptSig);
        in.scriptWitness = witness;
        mtx.vin.push_back(in);
        prevouts.push_back(prevout);
    }

    void Output(const CTxOut& out) { mtx.vout.push_back(out); }

    uint256 Hash(const AssetAuthCall& call) const
    {
        const CTransaction tx(mtx);
        return AssetAuthProposalHash(AssetAuthProposalMessage(tx, Context().chainId, call), call.version);
    }

    ScriptError Eval(const AssetAuthCall& call, unsigned int nIn, script_verify_flags flags = FLAGS,
                     ChainContext context = Context(), AssetAuthWorkBudget* budget = nullptr,
                     bool* usedHeight = nullptr, bool fRefOutputs = true) const
    {
        const CTransaction tx(mtx);
        ScriptError err = SCRIPT_ERR_OK;
        bool fUsedHeight = false;
        if (EvaluateAssetAuth(call, tx, nIn, prevouts, context, flags, budget, fUsedHeight, &err,
                              fRefOutputs ? &refOutputs : nullptr))
            err = SCRIPT_ERR_OK;
        if (usedHeight) *usedHeight = fUsedHeight;
        return err;
    }
};

const std::vector<std::string> ABC{"ALICE!", "BOB!", "CARL!"};

/** Asynchronous transfer: ALICE votes from a lock, BOB signs, BOB pays the fee. */
struct AsyncFixture {
    AssetAuthCall call = Policy(2, 3, ABC, /*c=*/2, /*a=*/3);
    Spend spend;

    explicit AsyncFixture(CAmount change = 4 * CENT)
    {
        spend.Input(XnaOut(CUSTODY, 10 * COIN));                    // 0 custody XNA
        spend.Input(AssetOut(CUSTODY, "GOLD", 10 * COIN));          // 1 custody asset
        spend.Input(OwnerOut(LOCK_A, "ALICE!"));                    // 2 vote, message set below
        spend.Input(OwnerOut(P2PKHDest(0xb0), "BOB!"), SigScript(SIGHASH_ALL)); // 3 direct
        spend.Input(XnaOut(P2PKHDest(0xb1), 5 * CENT), SigScript(SIGHASH_ALL)); // 4 fee
        spend.Output(XnaOut(CUSTODY, 10 * COIN - CENT));            // 0 prefix
        spend.Output(AssetOut(P2PKHDest(0xe0), "GOLD", COIN));      // 1 prefix
        spend.Output(AssetOut(CUSTODY, "GOLD", 9 * COIN));          // 2 prefix
        spend.Output(OwnerOut(P2PKHDest(0xa0), "ALICE!"));          // 3 return
        spend.Output(OwnerOut(P2PKHDest(0xb0), "BOB!"));            // 4 return
        spend.Output(XnaOut(P2PKHDest(0xb1), change));              // 5 change
        Vote(2, LOCK_A, "ALICE!");
    }

    void Vote(size_t input, const CScript& lock, const std::string& role)
    {
        spend.prevouts[input] = OwnerOut(lock, role, MessageOf(spend.Hash(call)));
    }
};

/**
 * Version 2 payment by third parties (NIP-054 v7, example 6.2): ALICE votes by
 * reference from P2PKH and BOB from strict v2, CARL does not vote, and E
 * executes and pays the fee. Neither token moves.
 */
struct RefFixture {
    AssetAuthCall call = PolicyV2(2, 3, ABC, /*c=*/1, /*a=*/2);
    Spend spend;

    explicit RefFixture(CAmount change = 4 * CENT)
    {
        spend.mtx.nVersion = 3;
        spend.Input(XnaOut(CUSTODY, 150 * COIN));                                // 0 custody
        spend.Input(XnaOut(P2PKHDest(0xe1), 5 * CENT), SigScript(SIGHASH_ALL));  // 1 fee of E
        spend.Output(XnaOut(P2PKHDest(0xe0), 100 * COIN));                      // 0 prefix: payment
        spend.Output(XnaOut(CUSTODY, 50 * COIN));                               // 1 prefix: back to the custody
        spend.Output(XnaOut(P2PKHDest(0xe1), change));                          // 2 change of E
        Vote(P2PKHDest(0xa0), "ALICE!");                                        // reference 0
        Vote(ProgramDest(OP_2, 0xb0), "BOB!");                                  // reference 1
    }

    uint256 H2() const { return spend.Hash(call); }

    /** A vote by reference: `role` at `dest` carrying H2, after the other references. */
    void Vote(const CScript& dest, const std::string& role)
    {
        spend.Ref(OwnerOut(dest, role, MessageOf(H2())));
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(assetauth_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// Decoding: stack, integers and policy (§3.4, §3.5)
// ---------------------------------------------------------------------------

Stack CallStack(int64_t c, int64_t a, int64_t b, int64_t T, int64_t version, int64_t M, int64_t G,
                const std::vector<std::string>& roles)
{
    Stack stack;
    for (int64_t v : {c, a, b, T, version, M, G})
        stack.push_back(CScriptNum(v).getvch());
    for (const std::string& role : roles)
        stack.emplace_back(role.begin(), role.end());
    stack.push_back(CScriptNum(static_cast<int64_t>(roles.size())).getvch());
    return stack;
}

ScriptError Decode(const Stack& stack, AssetAuthCall* out = nullptr, size_t* consumed = nullptr)
{
    AssetAuthCall call;
    size_t n = 0;
    ScriptError err = SCRIPT_ERR_OK;
    if (DecodeAssetAuthCall(stack, call, n, &err))
        err = SCRIPT_ERR_OK;
    if (out) *out = call;
    if (consumed) *consumed = n;
    return err;
}

BOOST_AUTO_TEST_CASE(decode_valid_call)
{
    AssetAuthCall call;
    size_t consumed = 0;
    BOOST_CHECK_EQUAL(Decode(CallStack(2, 3, 1, 500, 1, 2, 3, ABC), &call, &consumed), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(consumed, ABC.size() + ASSETAUTH_FIXED_ITEMS);
    BOOST_CHECK_EQUAL(call.c, 2);
    BOOST_CHECK_EQUAL(call.a, 3);
    BOOST_CHECK_EQUAL(call.b, 1);
    BOOST_CHECK_EQUAL(call.T, 500);
    BOOST_CHECK_EQUAL(call.M, 2);
    BOOST_CHECK_EQUAL(call.G, 3);
    BOOST_CHECK(call.roles == ABC);

    // Extra items below the call are left alone.
    Stack deeper = CallStack(0, 0, 0, 0, 1, 1, 1, {"ALICE!"});
    deeper.insert(deeper.begin(), {0x07});
    BOOST_CHECK_EQUAL(Decode(deeper, nullptr, &consumed), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(consumed, 1 + ASSETAUTH_FIXED_ITEMS);
}

BOOST_AUTO_TEST_CASE(decode_policy_errors)
{
    BOOST_CHECK_EQUAL(Decode(CallStack(0, 0, 0, 0, 3, 1, 1, {"ALICE!"})), SCRIPT_ERR_ASSETAUTH_POLICY); // version
    BOOST_CHECK_EQUAL(Decode(CallStack(0, 0, 0, 0, 0, 1, 1, {"ALICE!"})), SCRIPT_ERR_ASSETAUTH_POLICY); // version 0
    BOOST_CHECK_EQUAL(Decode(CallStack(0, 0, 0, 0, 1, 0, 1, {"ALICE!"})), SCRIPT_ERR_ASSETAUTH_POLICY); // M < 1
    BOOST_CHECK_EQUAL(Decode(CallStack(0, 0, 0, 0, 1, 3, 2, ABC)), SCRIPT_ERR_ASSETAUTH_POLICY);        // M > G
    BOOST_CHECK_EQUAL(Decode(CallStack(0, 0, 0, 0, 1, 2, 4, ABC)), SCRIPT_ERR_ASSETAUTH_POLICY);        // G > n
    BOOST_CHECK_EQUAL(Decode(CallStack(0, 0, 0, 0, 1, 1, 1, {"BOB!", "ALICE!"})), SCRIPT_ERR_ASSETAUTH_POLICY); // order
    BOOST_CHECK_EQUAL(Decode(CallStack(0, 0, 0, 0, 1, 1, 1, {"ALICE!", "ALICE!"})), SCRIPT_ERR_ASSETAUTH_POLICY); // duplicate
    // Owner names are checked when evaluating, once their work is paid.
    BOOST_CHECK_EQUAL(Decode(CallStack(0, 0, 0, 0, 1, 1, 1, {"ALICE"})), SCRIPT_ERR_OK);
    Stack empty = CallStack(0, 0, 0, 0, 1, 1, 1, {});
    BOOST_CHECK_EQUAL(Decode(empty), SCRIPT_ERR_ASSETAUTH_POLICY);                                       // n = 0

    std::vector<std::string> sixteen, seventeen;
    for (int i = 0; i < 17; ++i) {
        std::string name = strprintf("ROLE%02d!", i);
        if (i < 16) sixteen.push_back(name);
        seventeen.push_back(name);
    }
    BOOST_CHECK_EQUAL(Decode(CallStack(0, 0, 0, 0, 1, 16, 16, sixteen)), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(Decode(CallStack(0, 0, 0, 0, 1, 16, 16, seventeen)), SCRIPT_ERR_ASSETAUTH_POLICY);
}

BOOST_AUTO_TEST_CASE(decode_argument_errors)
{
    BOOST_CHECK_EQUAL(Decode(CallStack(-1, 0, 0, 0, 1, 1, 1, {"ALICE!"})), SCRIPT_ERR_ASSETAUTH_ARGS);
    BOOST_CHECK_EQUAL(Decode(CallStack(0, -1, 0, 0, 1, 1, 1, {"ALICE!"})), SCRIPT_ERR_ASSETAUTH_ARGS);
    BOOST_CHECK_EQUAL(Decode(CallStack(0, 0, -1, 0, 1, 1, 1, {"ALICE!"})), SCRIPT_ERR_ASSETAUTH_ARGS);
    BOOST_CHECK_EQUAL(Decode(CallStack(0, 0, 0, -1, 1, 1, 1, {"ALICE!"})), SCRIPT_ERR_ASSETAUTH_ARGS);

    Stack nonMinimal = CallStack(0, 0, 0, 0, 1, 1, 1, {"ALICE!"});
    nonMinimal[3] = {0x05, 0x00}; // T = 5, not minimally encoded
    BOOST_CHECK_EQUAL(Decode(nonMinimal), SCRIPT_ERR_ASSETAUTH_ARGS);

    Stack tooWide = CallStack(0, 0, 0, 0, 1, 1, 1, {"ALICE!"});
    tooWide[3] = {0x01, 0x02, 0x03, 0x04, 0x05}; // 5-byte number
    BOOST_CHECK_EQUAL(Decode(tooWide), SCRIPT_ERR_ASSETAUTH_ARGS);

    Stack shortStack = CallStack(0, 0, 0, 0, 1, 1, 1, {"ALICE!"});
    shortStack.erase(shortStack.begin());
    BOOST_CHECK_EQUAL(Decode(shortStack), SCRIPT_ERR_INVALID_STACK_OPERATION);
    BOOST_CHECK_EQUAL(Decode(Stack{}), SCRIPT_ERR_INVALID_STACK_OPERATION);
}

// ---------------------------------------------------------------------------
// Synchronous mode (§3.6, §3.7, §3.11)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(sync_direct_signatures)
{
    Spend spend;
    spend.Input(XnaOut(CUSTODY, COIN));
    spend.Input(OwnerOut(P2PKHDest(0xa0), "ALICE!"), SigScript(SIGHASH_ALL));
    spend.Input(OwnerOut(P2PKHDest(0xb0), "BOB!"), SigScript(SIGHASH_ALL));
    spend.Output(XnaOut(P2PKHDest(0xe0), COIN - CENT));
    spend.Output(OwnerOut(P2PKHDest(0xa0), "ALICE!"));
    spend.Output(OwnerOut(P2PKHDest(0xb0), "BOB!"));

    bool usedHeight = true;
    BOOST_CHECK_EQUAL(spend.Eval(Policy(2, 3, ABC), 0, FLAGS, Context(), nullptr, &usedHeight), SCRIPT_ERR_OK);
    BOOST_CHECK(!usedHeight); // no vote: no expiry, no shape
    BOOST_CHECK_EQUAL(spend.Eval(Policy(3, 3, ABC), 0), SCRIPT_ERR_ASSETAUTH_THRESHOLD);

    // A direct signature that is not SIGHASH_ALL is rejected.
    const std::vector<unsigned char> otherTypes{SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ALL | SIGHASH_ANYONECANPAY};
    for (unsigned char hashType : otherTypes) {
        Spend bad = spend;
        bad.mtx.vin[2].scriptSig = SigScript(hashType);
        BOOST_CHECK_EQUAL(bad.Eval(Policy(1, 1, ABC), 0), SCRIPT_ERR_ASSETAUTH_SIGHASH);
    }
    // An unreadable P2PKH scriptSig counts as a wrong hash type.
    Spend extra = spend;
    extra.mtx.vin[1].scriptSig << OP_1;
    BOOST_CHECK_EQUAL(extra.Eval(Policy(1, 1, ABC), 0), SCRIPT_ERR_ASSETAUTH_SIGHASH);

    // A role listed twice in the inputs counts once.
    Spend twice = spend;
    twice.prevouts[2] = OwnerOut(P2PKHDest(0xa0), "ALICE!");
    BOOST_CHECK_EQUAL(twice.Eval(Policy(2, 2, {"ALICE!", "BOB!"}), 0), SCRIPT_ERR_ASSETAUTH_THRESHOLD);

    // Roles outside the list do not count.
    BOOST_CHECK_EQUAL(spend.Eval(Policy(1, 1, {"DAVE!"}), 0), SCRIPT_ERR_ASSETAUTH_THRESHOLD);

    // Sync mode leaves the shape free: foreign assets and OP_RETURN are fine.
    Spend free = spend;
    free.Input(AssetOut(P2PKHDest(0xf0), "SILVER", 3 * COIN), SigScript(SIGHASH_NONE));
    free.Output(CTxOut(0, CScript() << OP_RETURN << std::vector<unsigned char>{0x01}));
    BOOST_CHECK_EQUAL(free.Eval(Policy(2, 3, ABC), 0), SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(strict_families_count_only_when_enforced)
{
    Spend spend;
    spend.Input(XnaOut(CUSTODY, COIN));
    spend.Input(OwnerOut(ProgramDest(OP_3, 0xa0), "ALICE!"), CScript(), StrictWitness(SIGHASH_ALL));
    spend.Input(OwnerOut(ProgramDest(OP_2, 0xb0), "BOB!"), CScript(), StrictWitness(SIGHASH_ALL));
    spend.Output(XnaOut(P2PKHDest(0xe0), COIN - CENT));

    BOOST_CHECK_EQUAL(spend.Eval(Policy(2, 2, {"ALICE!", "BOB!"}), 0), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(spend.Eval(Policy(2, 2, {"ALICE!", "BOB!"}), 0, SCRIPT_VERIFY_ASSETAUTH),
                      SCRIPT_ERR_ASSETAUTH_THRESHOLD);

    Spend none = spend;
    none.mtx.vin[1].scriptWitness = StrictWitness(SIGHASH_NONE);
    BOOST_CHECK_EQUAL(none.Eval(Policy(1, 1, {"ALICE!", "BOB!"}), 0), SCRIPT_ERR_ASSETAUTH_SIGHASH);
}

BOOST_AUTO_TEST_CASE(threshold_rises_when_an_owner_leaves)
{
    Spend spend;
    spend.Input(OwnerOut(CUSTODY, "TOKEN!"));
    spend.Input(OwnerOut(P2PKHDest(0xa0), "ALICE!"), SigScript(SIGHASH_ALL));
    spend.Input(OwnerOut(P2PKHDest(0xb0), "BOB!"), SigScript(SIGHASH_ALL));
    spend.Output(OwnerOut(CUSTODY, "TOKEN!"));
    spend.Output(OwnerOut(P2PKHDest(0xa0), "ALICE!"));
    spend.Output(OwnerOut(P2PKHDest(0xb0), "BOB!"));
    BOOST_CHECK_EQUAL(spend.Eval(Policy(2, 3, ABC), 0), SCRIPT_ERR_OK); // stays: M

    Spend leave = spend;
    leave.mtx.vout[0] = OwnerOut(CUSTODY_B, "TOKEN!");
    BOOST_CHECK_EQUAL(leave.Eval(Policy(2, 3, ABC), 0), SCRIPT_ERR_ASSETAUTH_THRESHOLD); // G = 3
    leave.Input(OwnerOut(P2PKHDest(0xc0), "CARL!"), SigScript(SIGHASH_ALL));
    BOOST_CHECK_EQUAL(leave.Eval(Policy(2, 3, ABC), 0), SCRIPT_ERR_OK);

    // A custody without owners never needs G.
    Spend xna;
    xna.Input(XnaOut(CUSTODY, COIN));
    xna.Input(OwnerOut(P2PKHDest(0xa0), "ALICE!"), SigScript(SIGHASH_ALL));
    xna.Output(XnaOut(CUSTODY_B, COIN - CENT));
    BOOST_CHECK_EQUAL(xna.Eval(Policy(1, 3, ABC), 0), SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(verdict_depends_on_the_evaluated_input)
{
    // Review counterexample: custodies A and B share the policy M = 1, G = 2.
    // One approval spends XNA of A and moves an owner of B elsewhere. A passes
    // with M; B must fail because it needs G.
    Spend spend;
    spend.Input(XnaOut(CUSTODY, COIN));                        // A
    spend.Input(OwnerOut(CUSTODY_B, "TOKEN!"));                // B
    spend.Input(OwnerOut(P2PKHDest(0xa0), "ALICE!"), SigScript(SIGHASH_ALL));
    spend.Output(XnaOut(P2PKHDest(0xe0), COIN - CENT));
    spend.Output(OwnerOut(P2PKHDest(0xe1), "TOKEN!"));
    spend.Output(OwnerOut(P2PKHDest(0xa0), "ALICE!"));
    const AssetAuthCall call = Policy(1, 2, {"ALICE!", "BOB!"});
    BOOST_CHECK_EQUAL(spend.Eval(call, 0), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(spend.Eval(call, 1), SCRIPT_ERR_ASSETAUTH_THRESHOLD);
}

// ---------------------------------------------------------------------------
// Asynchronous mode (§3.8 to §3.10)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(async_vote_and_direct_signature)
{
    AsyncFixture f;
    bool usedHeight = false;
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0, FLAGS, Context(), nullptr, &usedHeight), SCRIPT_ERR_OK);
    BOOST_CHECK(usedHeight);
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 1), SCRIPT_ERR_OK); // the other custody input

    // Expiry.
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0, FLAGS, Context(HEIGHT)), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0, FLAGS, Context(HEIGHT + 1)), SCRIPT_ERR_ASSETAUTH_EXPIRED);

    // Without BOB the vote alone is not enough.
    AsyncFixture alone;
    alone.spend.mtx.vin.erase(alone.spend.mtx.vin.begin() + 3);
    alone.spend.prevouts.erase(alone.spend.prevouts.begin() + 3);
    alone.spend.mtx.vout.erase(alone.spend.mtx.vout.begin() + 4);
    alone.Vote(2, LOCK_A, "ALICE!");
    BOOST_CHECK_EQUAL(alone.spend.Eval(alone.call, 0), SCRIPT_ERR_ASSETAUTH_THRESHOLD);
}

BOOST_AUTO_TEST_CASE(async_two_votes)
{
    AsyncFixture f;
    // BOB votes from a lock too: no member signs the execution.
    f.spend.mtx.vin[3].scriptSig = CScript();
    f.Vote(3, LOCK_B, "BOB!");
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(foreign_vote_fails)
{
    AsyncFixture f;
    f.spend.prevouts[2] = OwnerOut(LOCK_A, "ALICE!", std::string(32, '\x11'));
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_ASSETAUTH_FOREIGN_VOTE);

    // A 34-byte IPFS message is not a vote either.
    AsyncFixture ipfs;
    std::string ipfsMessage = std::string("\x12\x20", 2) + std::string(32, '\x22');
    ipfs.spend.prevouts[2] = OwnerOut(LOCK_A, "ALICE!", ipfsMessage);
    BOOST_CHECK_EQUAL(ipfs.spend.Eval(ipfs.call, 0), SCRIPT_ERR_ASSETAUTH_FOREIGN_VOTE);

    // A role without message in a lock does not approve and, in async mode,
    // is not an allowed extra input.
    AsyncFixture silent;
    silent.spend.Input(OwnerOut(LOCK_C, "CARL!"));
    BOOST_CHECK_EQUAL(silent.spend.Eval(silent.call, 0), SCRIPT_ERR_ASSETAUTH_SHAPE);
}

BOOST_AUTO_TEST_CASE(shape_rules)
{
    // Rule 1: the evaluated input belongs to the proposal.
    {
        AsyncFixture f;
        AssetAuthCall call = f.call;
        call.c = 1;
        f.call = call;
        f.Vote(2, LOCK_A, "ALICE!");
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 1), SCRIPT_ERR_ASSETAUTH_SHAPE);
    }
    // Rule 2: no other input of the custody after c.
    {
        AsyncFixture f;
        f.spend.Input(XnaOut(CUSTODY, COIN));
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_ASSETAUTH_SHAPE);
    }
    // Rule 3: an input with a foreign asset after c.
    {
        AsyncFixture f;
        f.spend.Input(AssetOut(P2PKHDest(0xf0), "SILVER", COIN), SigScript(SIGHASH_ALL));
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_ASSETAUTH_SHAPE);
    }
    // Rule 4: intermediate outputs are returns or change.
    {
        AsyncFixture f; // custody owner smuggled to an intermediate output
        f.spend.Input(OwnerOut(P2PKHDest(0xf1), "ROGUE!"), SigScript(SIGHASH_ALL));
        f.spend.Output(OwnerOut(P2PKHDest(0xf1), "GOLD!"));
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_ASSETAUTH_SHAPE);
    }
    {
        AsyncFixture f; // return carrying XNA
        f.spend.mtx.vout[3].nValue = CENT;
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_ASSETAUTH_SHAPE);
    }
    {
        AsyncFixture f; // OP_RETURN in the middle
        f.spend.Output(CTxOut(0, CScript() << OP_RETURN << std::vector<unsigned char>{0x01}));
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_ASSETAUTH_SHAPE);
    }
    {
        AsyncFixture f; // a non-owner asset in the middle
        f.spend.Output(AssetOut(P2PKHDest(0xf2), "GOLD", COIN));
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_ASSETAUTH_SHAPE);
    }
    // Rule 5: change never exceeds the fee inputs.
    {
        AsyncFixture f(5 * CENT);
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_OK);
    }
    {
        AsyncFixture f(5 * CENT + 1);
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_ASSETAUTH_SHAPE);
    }
}

BOOST_AUTO_TEST_CASE(treasury_change_counts_only_intermediate_outputs)
{
    // Spend 10 XNA of the custody, pay 1, return 9; the executor brings 0.05
    // and takes 0.04 back. Proposal outputs are not change.
    AssetAuthCall call = Policy(1, 1, {"ALICE!"}, /*c=*/1, /*a=*/2);
    Spend spend;
    spend.Input(XnaOut(CUSTODY, 10 * COIN));
    spend.Input(OwnerOut(LOCK_A, "ALICE!"));
    spend.Input(XnaOut(P2PKHDest(0xb1), 5 * CENT), SigScript(SIGHASH_ALL));
    spend.Output(XnaOut(P2PKHDest(0xe0), COIN));
    spend.Output(XnaOut(CUSTODY, 9 * COIN - CENT));
    spend.Output(OwnerOut(P2PKHDest(0xa0), "ALICE!"));
    spend.Output(XnaOut(P2PKHDest(0xb1), 4 * CENT));
    spend.prevouts[1] = OwnerOut(LOCK_A, "ALICE!", MessageOf(spend.Hash(call)));
    BOOST_CHECK_EQUAL(spend.Eval(call, 0), SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(suffix_keeps_issuance_last)
{
    // Prefix a = 1, suffix b = 2 (where an issuance would sit). Returns and
    // change go between them.
    AssetAuthCall call = Policy(1, 1, {"ALICE!"}, /*c=*/1, /*a=*/1, /*b=*/2);
    Spend spend;
    spend.Input(XnaOut(CUSTODY, 10 * COIN));
    spend.Input(OwnerOut(LOCK_A, "ALICE!"));
    spend.Output(XnaOut(CUSTODY, 9 * COIN));                   // prefix
    spend.Output(OwnerOut(P2PKHDest(0xa0), "ALICE!"));         // return
    spend.Output(OwnerOut(CUSTODY, "NEWTOKEN!"));              // suffix
    spend.Output(AssetOut(CUSTODY, "NEWTOKEN", 1000 * COIN));  // suffix
    spend.prevouts[1] = OwnerOut(LOCK_A, "ALICE!", MessageOf(spend.Hash(call)));
    BOOST_CHECK_EQUAL(spend.Eval(call, 0), SCRIPT_ERR_OK);

    // With b = 0 those last outputs would be intermediate, and rejected.
    AssetAuthCall noSuffix = call;
    noSuffix.b = 0;
    spend.prevouts[1] = OwnerOut(LOCK_A, "ALICE!", MessageOf(spend.Hash(noSuffix)));
    BOOST_CHECK_EQUAL(spend.Eval(noSuffix, 0), SCRIPT_ERR_ASSETAUTH_SHAPE);
}

BOOST_AUTO_TEST_CASE(composition_of_disjoint_policies)
{
    // A board 2-of-3 and an auditor 1-of-1 approve the same transaction with
    // votes. Each counts its own roles; the shape accepts the other's.
    const std::vector<std::string> board{"BOARDA!", "BOARDB!", "BOARDC!"};
    AssetAuthCall boardCall = Policy(2, 2, board, /*c=*/1, /*a=*/1);
    AssetAuthCall auditCall = Policy(1, 1, {"AUDITOR!"}, /*c=*/1, /*a=*/1);
    Spend spend;
    spend.Input(XnaOut(CUSTODY, 10 * COIN));
    spend.Input(OwnerOut(LOCK_A, "BOARDA!"));
    spend.Input(OwnerOut(LOCK_B, "BOARDB!"));
    spend.Input(OwnerOut(LOCK_C, "AUDITOR!"));
    spend.Output(XnaOut(P2PKHDest(0xe0), 10 * COIN - CENT));
    spend.Output(OwnerOut(P2PKHDest(0xa0), "BOARDA!"));
    spend.Output(OwnerOut(P2PKHDest(0xa1), "BOARDB!"));
    spend.Output(OwnerOut(P2PKHDest(0xa2), "AUDITOR!"));
    const std::string message = MessageOf(spend.Hash(boardCall));
    BOOST_CHECK(spend.Hash(boardCall) == spend.Hash(auditCall)); // same c, a, b, T
    spend.prevouts[1] = OwnerOut(LOCK_A, "BOARDA!", message);
    spend.prevouts[2] = OwnerOut(LOCK_B, "BOARDB!", message);
    spend.prevouts[3] = OwnerOut(LOCK_C, "AUDITOR!", message);
    BOOST_CHECK_EQUAL(spend.Eval(boardCall, 0), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(spend.Eval(auditCall, 0), SCRIPT_ERR_OK);

    // The auditor's vote never completes the board's quorum.
    Spend thin = spend;
    thin.mtx.vin.erase(thin.mtx.vin.begin() + 2);
    thin.prevouts.erase(thin.prevouts.begin() + 2);
    thin.mtx.vout.erase(thin.mtx.vout.begin() + 2);
    const std::string message2 = MessageOf(thin.Hash(boardCall));
    thin.prevouts[1] = OwnerOut(LOCK_A, "BOARDA!", message2);
    thin.prevouts[2] = OwnerOut(LOCK_C, "AUDITOR!", message2);
    BOOST_CHECK_EQUAL(thin.Eval(boardCall, 0), SCRIPT_ERR_ASSETAUTH_THRESHOLD);

    // Different T in one of the calls gives another H: its votes do not match.
    AssetAuthCall otherT = auditCall;
    otherT.T = HEIGHT + 5;
    BOOST_CHECK_EQUAL(spend.Eval(otherT, 0), SCRIPT_ERR_ASSETAUTH_FOREIGN_VOTE);
}

BOOST_AUTO_TEST_CASE(external_approval_requires_sighash_all)
{
    // An owner of another list signed directly after c: fine with ALL, an
    // error otherwise (async mode). It never counts for this policy.
    AsyncFixture f;
    f.spend.Input(OwnerOut(P2PKHDest(0xd0), "AUDITOR!"), SigScript(SIGHASH_ALL));
    f.spend.Output(OwnerOut(P2PKHDest(0xd0), "AUDITOR!"));
    f.Vote(2, LOCK_A, "ALICE!");
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_OK);

    f.spend.mtx.vin[5].scriptSig = SigScript(SIGHASH_NONE);
    f.Vote(2, LOCK_A, "ALICE!");
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_ASSETAUTH_SIGHASH);
}

// ---------------------------------------------------------------------------
// Proposal hash (§3.8)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(proposal_hash_commitments)
{
    AsyncFixture base;
    const uint256 h0 = base.spend.Hash(base.call);

    auto changes = [&](const std::function<void(AsyncFixture&)>& mutate) {
        AsyncFixture f;
        mutate(f);
        return f.spend.Hash(f.call) != h0;
    };
    BOOST_CHECK(changes([](AsyncFixture& f) { f.spend.mtx.nVersion = 3; }));
    BOOST_CHECK(changes([](AsyncFixture& f) { f.spend.mtx.nLockTime = 7; }));
    BOOST_CHECK(changes([](AsyncFixture& f) { f.call.T += 1; }));
    BOOST_CHECK(changes([](AsyncFixture& f) { f.call.c = 1; }));
    BOOST_CHECK(changes([](AsyncFixture& f) { f.call.a = 2; }));
    BOOST_CHECK(changes([](AsyncFixture& f) { f.call.b = 1; }));
    BOOST_CHECK(changes([](AsyncFixture& f) { f.spend.mtx.vin[0].prevout.n = 9; }));
    BOOST_CHECK(changes([](AsyncFixture& f) { f.spend.mtx.vin[1].nSequence = 5; }));
    BOOST_CHECK(changes([](AsyncFixture& f) { f.spend.mtx.vout[2].nValue += 1; }));
    // A suffix output is committed: both hashes use b = 1, so only the output differs.
    {
        AsyncFixture f;
        f.call.b = 1;
        const uint256 before = f.spend.Hash(f.call);
        f.spend.mtx.vout.back().nValue += 1;
        BOOST_CHECK(f.spend.Hash(f.call) != before);
    }
    BOOST_CHECK(changes([](AsyncFixture& f) {
        f.spend.mtx.nVersion = 3;
        f.spend.mtx.vrefin.push_back(COutPoint(uint256S("01"), 0));
    }));

    // Free for the executor: sequences of inputs c.. and intermediate outputs.
    BOOST_CHECK(!changes([](AsyncFixture& f) { f.spend.mtx.vin[4].nSequence = 5; }));
    BOOST_CHECK(!changes([](AsyncFixture& f) { f.spend.mtx.vout[5].nValue -= 1; }));
    BOOST_CHECK(!changes([](AsyncFixture& f) { f.spend.mtx.vin[3].scriptSig = SigScript(SIGHASH_NONE); }));

    // The chain id is part of the message.
    const CTransaction tx(base.spend.mtx);
    BOOST_CHECK(AssetAuthProposalHash(AssetAuthProposalMessage(tx, 1, base.call)) !=
                AssetAuthProposalHash(AssetAuthProposalMessage(tx, 2, base.call)));

    // The tag is NeuraiAssetAuthProposal.
    const std::vector<unsigned char> m = AssetAuthProposalMessage(tx, 2, base.call);
    BOOST_CHECK(AssetAuthProposalHash(m) == TaggedHash("NeuraiAssetAuthProposal", m));
    BOOST_CHECK_EQUAL(m[0], 2);
}

// Exact vectors for other implementations (wallets, explorers): a version 2
// transaction with one proposal input, one prefix and one suffix output.
BOOST_AUTO_TEST_CASE(proposal_hash_vectors)
{
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.nLockTime = 0;
    mtx.vin.emplace_back(COutPoint(uint256S("11"), 1), CScript(), uint32_t{CTxIn::SEQUENCE_FINAL});
    mtx.vin.emplace_back(COutPoint(uint256S("22"), 0), CScript(), uint32_t{CTxIn::SEQUENCE_FINAL - 1});
    mtx.vout.emplace_back(9 * COIN, P2PKHDest(0xe0));
    mtx.vout.emplace_back(4 * CENT, P2PKHDest(0xb1));
    mtx.vout.emplace_back(COIN, P2PKHDest(0xe1));
    const CTransaction tx(mtx);
    const AssetAuthCall call = Policy(2, 3, ABC, /*c=*/1, /*a=*/1, /*b=*/1, /*T=*/1000);

    // H as raw bytes, the order a vote carries in its transfer message.
    auto hash = [&](uint8_t chainId) {
        const uint256 h = AssetAuthProposalHash(AssetAuthProposalMessage(tx, chainId, call));
        return HexStr(h.begin(), h.end());
    };
    BOOST_CHECK_EQUAL(HexStr(AssetAuthProposalMessage(tx, 2, call)),
                      "02" "02000000" "00000000" "e8030000" "010101"                                // chain, version, locktime, T, c a b
                      "1100000000000000000000000000000000000000000000000000000000000000" "01000000" "ffffffff" // input 0
                      "00e9a43500000000" "1976a914e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e088ac"    // prefix output
                      "00e1f50500000000" "1976a914e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e188ac"    // suffix output
                      "00");                                                                       // no references
    BOOST_CHECK_EQUAL(hash(0), "98c900705cdb1f6703248f117f2026850b2a27c93043c688102bbcc0e5525308");
    BOOST_CHECK_EQUAL(hash(1), "ff8d6c87e36de48e0af7293fce80d076c4d0b48ba625def71e022e460f72417e");
    BOOST_CHECK_EQUAL(hash(2), "90ce27337ba58ba0e6f7e06e7fd7dde2841bed637109d63a73336c9de42b245f");
}

// ---------------------------------------------------------------------------
// Work budget and context (§3.3, §3.13)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(work_budget)
{
    AsyncFixture f;
    const CTransaction tx(f.spend.mtx);
    const size_t messageSize = AssetAuthProposalMessage(tx, 2, f.call).size();
    const uint64_t nameWork = AssetAuthNameWork(f.call, tx, f.spend.prevouts, FLAGS);
    const uint64_t work = AssetAuthWork(tx, messageSize, nameWork);
    BOOST_CHECK_EQUAL(work, 1 + tx.vin.size() + tx.vout.size() + (messageSize + 63) / 64 + nameWork);

    AssetAuthWorkBudget exact(work);
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0, FLAGS, Context(), &exact), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(exact.Used(), work);
    // A second execution does not fit any more.
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 1, FLAGS, Context(), &exact), SCRIPT_ERR_ASSETAUTH_BUDGET);
    BOOST_CHECK(exact.Exceeded());

    // Repeated executions add up.
    AssetAuthWorkBudget roomy(10 * work);
    for (int i = 0; i < 3; ++i)
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0, FLAGS, Context(), &roomy), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(roomy.Used(), 3 * work);

    // The charge happens before any failure of the authorization itself.
    AssetAuthWorkBudget charged(10 * work);
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0, FLAGS, Context(HEIGHT + 1), &charged), SCRIPT_ERR_ASSETAUTH_EXPIRED);
    BOOST_CHECK_EQUAL(charged.Used(), work);
}

BOOST_AUTO_TEST_CASE(name_work)
{
    AsyncFixture f;
    const CTransaction tx(f.spend.mtx);
    // Three roles, three named inputs and four named outputs, all under 33 bytes.
    BOOST_CHECK_EQUAL(AssetAuthNameWork(f.call, tx, f.spend.prevouts, FLAGS), 10U);
    // A name pays one unit per started 32 bytes.
    AssetAuthCall longer = f.call;
    longer.roles = {std::string(32, 'A') + "!", "BOB!"};
    BOOST_CHECK_EQUAL(AssetAuthNameWork(longer, tx, f.spend.prevouts, FLAGS), 2U + 1U + 7U);
}

BOOST_AUTO_TEST_CASE(role_names_checked_after_charge)
{
    Spend s;
    s.Input(XnaOut(CUSTODY, COIN));
    s.Output(XnaOut(P2PKHDest(0x01), COIN - CENT));
    const std::vector<std::vector<std::string>> bad{{"ALICE"}, {"a!"}, {"ALICE!", "BOB"}};
    for (const std::vector<std::string>& roles : bad) {
        BOOST_CHECK_EQUAL(s.Eval(Policy(1, 1, roles), 0), SCRIPT_ERR_ASSETAUTH_POLICY);
        // Without room for the work, the budget fails before any name is checked.
        AssetAuthWorkBudget tight(1);
        BOOST_CHECK_EQUAL(s.Eval(Policy(1, 1, roles), 0, FLAGS, Context(), &tight), SCRIPT_ERR_ASSETAUTH_BUDGET);
        BOOST_CHECK_EQUAL(tight.Used(), 0U);
    }
}

BOOST_AUTO_TEST_CASE(context_and_arguments)
{
    AsyncFixture f;
    ChainContext unavailable = Context();
    unavailable.available = false;
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0, FLAGS, unavailable), SCRIPT_ERR_ASSETAUTH_CONTEXT);

    Spend missing = f.spend;
    missing.prevouts.pop_back();
    BOOST_CHECK_EQUAL(missing.Eval(f.call, 0), SCRIPT_ERR_ASSETAUTH_CONTEXT);

    AssetAuthCall tooManyInputs = f.call;
    tooManyInputs.c = 6;
    BOOST_CHECK_EQUAL(f.spend.Eval(tooManyInputs, 0), SCRIPT_ERR_ASSETAUTH_ARGS);
    AssetAuthCall tooManyOutputs = f.call;
    tooManyOutputs.a = 4;
    tooManyOutputs.b = 3;
    BOOST_CHECK_EQUAL(f.spend.Eval(tooManyOutputs, 0), SCRIPT_ERR_ASSETAUTH_ARGS);
}

// ---------------------------------------------------------------------------
// Interpreter (§3.1 to §3.3)
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(opcode_in_the_interpreter)
{
    BOOST_CHECK_EQUAL(OP_CHECKASSETAUTH, 0xdf);
    // NIP-060 moved MAX_OPCODE to OP_CHECKSIG_P256 (0xe0), the next slot.
    BOOST_CHECK_EQUAL(MAX_OPCODE, static_cast<unsigned int>(OP_CHECKSIG_P256));
    BOOST_CHECK_EQUAL(std::string(GetOpName(OP_CHECKASSETAUTH)), "OP_CHECKASSETAUTH");

    Spend spend;
    spend.Input(XnaOut(CUSTODY, COIN));
    spend.Input(OwnerOut(P2PKHDest(0xa0), "ALICE!"), SigScript(SIGHASH_ALL));
    spend.Output(XnaOut(P2PKHDest(0xe0), COIN - CENT));
    const CTransaction tx(spend.mtx);
    const PrecomputedTransactionData txdata(tx);
    const CScript script = CScript() << 1 << 1 << 1 << std::vector<unsigned char>{'A', 'L', 'I', 'C', 'E', '!'}
                                     << 1 << OP_CHECKASSETAUTH;
    const Stack args{CScriptNum(0).getvch(), CScriptNum(0).getvch(), CScriptNum(0).getvch(), CScriptNum(0).getvch()};

    {
        TransactionSignatureChecker checker(&tx, 0, COIN, txdata, spend.prevouts[0].scriptPubKey, &spend.prevouts, Context());
        Stack stack = args;
        ScriptError err;
        BOOST_CHECK(EvalScript(stack, script, FLAGS, checker, SIGVERSION_AUTHSCRIPT, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_OK);
        BOOST_REQUIRE_EQUAL(stack.size(), 1U);
        BOOST_CHECK(stack[0] == std::vector<unsigned char>{1});

        // Flag off: the byte is a bad opcode.
        stack = args;
        BOOST_CHECK(!EvalScript(stack, script, SCRIPT_VERIFY_AUTHSCRIPT_STRICT, checker, SIGVERSION_AUTHSCRIPT, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_BAD_OPCODE);

        // Outside AuthScript.
        for (SigVersion version : {SIGVERSION_BASE, SIGVERSION_WITNESS_V0}) {
            stack = args;
            BOOST_CHECK(!EvalScript(stack, script, FLAGS, checker, version, &err));
            BOOST_CHECK_EQUAL(err, SCRIPT_ERR_ASSETAUTH_SIGVERSION);
        }

        // A failed authorization fails the script; it never pushes false.
        const CScript twoOfOne = CScript() << 1 << 2 << 2 << std::vector<unsigned char>{'A', 'L', 'I', 'C', 'E', '!'}
                                           << std::vector<unsigned char>{'B', 'O', 'B', '!'} << 2 << OP_CHECKASSETAUTH;
        stack = args;
        BOOST_CHECK(!EvalScript(stack, twoOfOne, FLAGS, checker, SIGVERSION_AUTHSCRIPT, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_ASSETAUTH_THRESHOLD);
    }
    {
        // No prevouts: context error before decoding anything.
        TransactionSignatureChecker checker(&tx, 0, COIN, txdata, spend.prevouts[0].scriptPubKey, Context());
        Stack stack;
        ScriptError err;
        BOOST_CHECK(!EvalScript(stack, script, FLAGS, checker, SIGVERSION_AUTHSCRIPT, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_ASSETAUTH_CONTEXT);
    }
    {
        // No chain context.
        TransactionSignatureChecker checker(&tx, 0, COIN, txdata, spend.prevouts[0].scriptPubKey, &spend.prevouts);
        Stack stack = args;
        ScriptError err;
        BOOST_CHECK(!EvalScript(stack, script, FLAGS, checker, SIGVERSION_AUTHSCRIPT, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_ASSETAUTH_CONTEXT);
    }
    {
        // A checker without transaction context fails closed too.
        BaseSignatureChecker checker;
        Stack stack = args;
        ScriptError err;
        BOOST_CHECK(!EvalScript(stack, script, FLAGS, checker, SIGVERSION_AUTHSCRIPT, &err));
        BOOST_CHECK_EQUAL(err, SCRIPT_ERR_ASSETAUTH_CONTEXT);
    }
}

BOOST_AUTO_TEST_CASE(async_marks_chain_context)
{
    AsyncFixture f;
    const CTransaction tx(f.spend.mtx);
    const PrecomputedTransactionData txdata(tx);
    TransactionSignatureChecker checker(&tx, 0, 10 * COIN, txdata, f.spend.prevouts[0].scriptPubKey, &f.spend.prevouts, Context());
    ScriptError err;
    BOOST_CHECK(checker.CheckAssetAuth(f.call, FLAGS, &err));
    BOOST_CHECK(checker.fChainContextObserved);
}

// ---------------------------------------------------------------------------
// Random inputs: no crash, deterministic verdicts, successes within bounds
// ---------------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(random_calls_keep_invariants)
{
    SeedInsecureRand(true);
    // In byte order; GOLD is not an owner.
    const std::vector<std::string> names{"ALICE!", "BOB!", "CARL!", "DAVE!", "GOLD"};
    auto small = [] { return static_cast<int64_t>(InsecureRandRange(8)) - 1; };
    int decoded = 0;
    for (int iter = 0; iter < 5000; ++iter) {
        Stack stack;
        if (InsecureRandBool()) {
            // Random items: numbers, names, raw bytes.
            for (uint64_t i = InsecureRandRange(24); i > 0; --i) {
                switch (InsecureRandRange(3)) {
                case 0:
                    stack.push_back(CScriptNum(small()).getvch());
                    break;
                case 1: {
                    const std::string& name = names[InsecureRandRange(names.size())];
                    stack.emplace_back(name.begin(), name.end());
                    break;
                }
                default: {
                    const uint256 bytes = InsecureRand256();
                    stack.emplace_back(bytes.begin(), bytes.begin() + InsecureRandRange(6));
                    break;
                }
                }
            }
        } else {
            // Nearly well-formed calls, so decoding often gets past the policy.
            std::vector<std::string> roles;
            for (const std::string& name : names)
                if (InsecureRandBool()) roles.push_back(name);
            if (!roles.empty() && InsecureRandRange(4) == 0)
                roles.push_back(roles.front()); // out of order and repeated
            const int64_t M = InsecureRandRange(roles.size() + 2);
            const int64_t G = M + InsecureRandRange(2);
            stack = CallStack(small(), small(), small(), HEIGHT, 1, M, G, roles);
            if (InsecureRandBool()) {
                // Version 2: r goes between b and T.
                const size_t T = stack.size() - roles.size() - 5;
                stack[T + 1] = CScriptNum(ASSETAUTH_POLICY_VERSION_2).getvch();
                stack.insert(stack.begin() + T, CScriptNum(small()).getvch());
            }
            if (InsecureRandBool())
                stack.insert(stack.begin(), CScriptNum(small()).getvch());
            if (InsecureRandRange(4) == 0) {
                std::vector<unsigned char>& item = stack[InsecureRandRange(stack.size())];
                item.resize(InsecureRandRange(6));
                for (unsigned char& byte : item)
                    byte = static_cast<unsigned char>(InsecureRandBits(8));
            }
        }
        AssetAuthCall call;
        size_t consumed = 0;
        if (Decode(stack, &call, &consumed) != SCRIPT_ERR_OK)
            continue;
        ++decoded;
        const bool fV2 = call.version == ASSETAUTH_POLICY_VERSION_2;
        BOOST_CHECK(call.version == ASSETAUTH_POLICY_VERSION || fV2);
        BOOST_CHECK_EQUAL(consumed, call.roles.size() + (fV2 ? ASSETAUTH_FIXED_ITEMS_V2 : ASSETAUTH_FIXED_ITEMS));
        BOOST_CHECK(consumed <= stack.size());
        BOOST_CHECK(1 <= call.M && call.M <= call.G && call.G <= static_cast<int>(call.roles.size()));
        BOOST_CHECK(call.roles.size() <= ASSETAUTH_MAX_ROLES);
        BOOST_CHECK(call.c >= 0 && call.a >= 0 && call.b >= 0 && call.r >= 0 && call.T >= 0);
        BOOST_CHECK(fV2 || call.r == 0);
        for (size_t i = 1; i < call.roles.size(); ++i)
            BOOST_CHECK(call.roles[i - 1] < call.roles[i]);
    }
    BOOST_CHECK(decoded > 100);
}

BOOST_AUTO_TEST_CASE(random_transactions_keep_invariants)
{
    SeedInsecureRand(true);
    const std::string ipfs = std::string("\x12\x20", 2) + std::string(32, 'q');
    const std::vector<CTxOut> pool{
        XnaOut(CUSTODY, COIN),
        XnaOut(P2PKHDest(0xb2), 3 * CENT),
        AssetOut(CUSTODY, "GOLD", COIN),
        OwnerOut(CUSTODY, "TOKEN!"),
        OwnerOut(LOCK_C, "CARL!", MessageOf(uint256S("77"))),
        OwnerOut(LOCK_C, "CARL!", ipfs),
        OwnerOut(LOCK_B, "BOB!"),
        OwnerOut(P2PKHDest(0xc0), "CARL!"),
        OwnerOut(ProgramDest(OP_2, 0xc3), "CARL!"),
        AssetOut(LOCK_A, "GOLD", 5 * COIN),
    };
    int passed = 0;
    for (int iter = 0; iter < 3000; ++iter) {
        AsyncFixture f;
        Spend& s = f.spend;
        for (uint64_t i = InsecureRandRange(4); i > 0; --i) {
            switch (InsecureRandRange(5)) {
            case 0:
                if (s.mtx.vin.size() > 1) {
                    const size_t k = InsecureRandRange(s.mtx.vin.size());
                    s.mtx.vin.erase(s.mtx.vin.begin() + k);
                    s.prevouts.erase(s.prevouts.begin() + k);
                }
                break;
            case 1:
                if (!s.mtx.vout.empty())
                    s.mtx.vout.erase(s.mtx.vout.begin() + InsecureRandRange(s.mtx.vout.size()));
                break;
            case 2: {
                const size_t j = InsecureRandRange(s.mtx.vin.size()), k = InsecureRandRange(s.mtx.vin.size());
                std::swap(s.mtx.vin[j], s.mtx.vin[k]);
                std::swap(s.prevouts[j], s.prevouts[k]);
                break;
            }
            case 3:
                s.Input(pool[InsecureRandRange(pool.size())],
                        InsecureRandBool() ? SigScript(InsecureRandBool() ? SIGHASH_ALL : SIGHASH_NONE) : CScript(),
                        InsecureRandBool() ? StrictWitness(SIGHASH_ALL) : CScriptWitness());
                break;
            default:
                s.Output(pool[InsecureRandRange(pool.size())]);
                break;
            }
        }
        AssetAuthCall call = f.call;
        if (InsecureRandBool()) {
            call.c = InsecureRandRange(8);
            call.a = InsecureRandRange(8);
            call.b = InsecureRandRange(8);
            call.T = HEIGHT - 1 + InsecureRandRange(3);
        }
        const unsigned int nIn = InsecureRandRange(s.mtx.vin.size() + 1);
        const script_verify_flags flags = InsecureRandBool() ? FLAGS : SCRIPT_VERIFY_ASSETAUTH;
        AssetAuthWorkBudget budget(1000);
        const ScriptError err = s.Eval(call, nIn, flags, Context(), &budget);
        BOOST_CHECK_EQUAL(s.Eval(call, nIn, flags), err);
        if (err != SCRIPT_ERR_OK)
            continue;
        ++passed;
        BOOST_CHECK(nIn < s.mtx.vin.size());
        BOOST_CHECK(call.c <= static_cast<int64_t>(s.mtx.vin.size()));
        BOOST_CHECK(call.a + call.b <= static_cast<int64_t>(s.mtx.vout.size()));
        const CTransaction tx(s.mtx);
        BOOST_CHECK_EQUAL(budget.Used(), AssetAuthWork(tx, AssetAuthProposalMessage(tx, Context().chainId, call).size(),
                                                       AssetAuthNameWork(call, tx, s.prevouts, flags)));
    }
    BOOST_CHECK(passed > 0);
}

// ---------------------------------------------------------------------------
// Policy version 2: votes by reference (NIP-054 v7)
// ---------------------------------------------------------------------------

Stack CallStackV2(int64_t c, int64_t a, int64_t b, int64_t r, int64_t T, int64_t M, int64_t G,
                  const std::vector<std::string>& roles)
{
    Stack stack;
    for (int64_t v : {c, a, b, r, T, int64_t{ASSETAUTH_POLICY_VERSION_2}, M, G})
        stack.push_back(CScriptNum(v).getvch());
    for (const std::string& role : roles)
        stack.emplace_back(role.begin(), role.end());
    stack.push_back(CScriptNum(static_cast<int64_t>(roles.size())).getvch());
    return stack;
}

BOOST_AUTO_TEST_CASE(v2_decode)
{
    AssetAuthCall call;
    size_t consumed = 0;
    BOOST_CHECK_EQUAL(Decode(CallStackV2(2, 3, 1, 4, 500, 2, 3, ABC), &call, &consumed), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(consumed, ABC.size() + ASSETAUTH_FIXED_ITEMS_V2);
    BOOST_CHECK_EQUAL(call.version, ASSETAUTH_POLICY_VERSION_2);
    BOOST_CHECK_EQUAL(call.c, 2);
    BOOST_CHECK_EQUAL(call.a, 3);
    BOOST_CHECK_EQUAL(call.b, 1);
    BOOST_CHECK_EQUAL(call.r, 4);
    BOOST_CHECK_EQUAL(call.T, 500);
    BOOST_CHECK_EQUAL(call.M, 2);
    BOOST_CHECK_EQUAL(call.G, 3);
    BOOST_CHECK(call.roles == ABC);

    // Extra items below the call are left alone.
    Stack deeper = CallStackV2(0, 0, 0, 0, 0, 1, 1, {"ALICE!"});
    deeper.insert(deeper.begin(), {0x07});
    BOOST_CHECK_EQUAL(Decode(deeper, nullptr, &consumed), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(consumed, 1 + ASSETAUTH_FIXED_ITEMS_V2);

    // Version 1 decodes as before, with r = 0.
    BOOST_CHECK_EQUAL(Decode(CallStack(2, 3, 1, 500, 1, 2, 3, ABC), &call, &consumed), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(consumed, ABC.size() + ASSETAUTH_FIXED_ITEMS);
    BOOST_CHECK_EQUAL(call.r, 0);

    // n + 8 items are enough to read the version, but not a version 2 call.
    Stack shallow = CallStackV2(0, 0, 0, 0, 0, 1, 1, {"ALICE!"});
    shallow.erase(shallow.begin());
    BOOST_CHECK_EQUAL(Decode(shallow), SCRIPT_ERR_INVALID_STACK_OPERATION);

    // r and c, the item version 2 adds, are minimal numbers of up to 4 bytes.
    Stack nonMinimal = CallStackV2(0, 0, 0, 0, 0, 1, 1, {"ALICE!"});
    nonMinimal[3] = {0x05, 0x00};
    BOOST_CHECK_EQUAL(Decode(nonMinimal), SCRIPT_ERR_ASSETAUTH_ARGS);
    Stack tooWide = CallStackV2(0, 0, 0, 0, 0, 1, 1, {"ALICE!"});
    tooWide[3] = {0x01, 0x02, 0x03, 0x04, 0x05};
    BOOST_CHECK_EQUAL(Decode(tooWide), SCRIPT_ERR_ASSETAUTH_ARGS);
    Stack wideC = CallStackV2(0, 0, 0, 0, 0, 1, 1, {"ALICE!"});
    wideC[0] = {0x01, 0x00};
    BOOST_CHECK_EQUAL(Decode(wideC), SCRIPT_ERR_ASSETAUTH_ARGS);
    BOOST_CHECK_EQUAL(Decode(CallStackV2(0, 0, 0, -1, 0, 1, 1, {"ALICE!"})), SCRIPT_ERR_ASSETAUTH_ARGS);
    BOOST_CHECK_EQUAL(Decode(CallStackV2(-1, 0, 0, 0, 0, 1, 1, {"ALICE!"})), SCRIPT_ERR_ASSETAUTH_ARGS);

    // Version 3 is unknown in either layout.
    Stack three = CallStackV2(0, 0, 0, 0, 0, 1, 1, {"ALICE!"});
    three[5] = CScriptNum(3).getvch();
    BOOST_CHECK_EQUAL(Decode(three), SCRIPT_ERR_ASSETAUTH_POLICY);
    // Policy rules of version 1 apply.
    BOOST_CHECK_EQUAL(Decode(CallStackV2(0, 0, 0, 0, 0, 3, 2, ABC)), SCRIPT_ERR_ASSETAUTH_POLICY);
    BOOST_CHECK_EQUAL(Decode(CallStackV2(0, 0, 0, 0, 0, 1, 1, {"BOB!", "ALICE!"})), SCRIPT_ERR_ASSETAUTH_POLICY);
}

BOOST_AUTO_TEST_CASE(v2_arguments_and_context)
{
    RefFixture f;
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_OK);

    // r is at most the number of references.
    AssetAuthCall tooMany = f.call;
    tooMany.r = 3;
    BOOST_CHECK_EQUAL(f.spend.Eval(tooMany, 0), SCRIPT_ERR_ASSETAUTH_ARGS);

    // A transaction that is not version 3 has no references, so r = 0.
    Spend plain;
    plain.Input(XnaOut(CUSTODY, COIN));
    plain.Input(OwnerOut(P2PKHDest(0xa0), "ALICE!"), SigScript(SIGHASH_ALL));
    plain.Output(XnaOut(P2PKHDest(0xe0), COIN - CENT));
    BOOST_CHECK_EQUAL(plain.Eval(PolicyV2(1, 1, ABC), 0), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(plain.Eval(PolicyV2(1, 1, ABC, 0, 0, 0, /*r=*/1), 0), SCRIPT_ERR_ASSETAUTH_ARGS);
    // Without references, version 2 needs no referenced outputs.
    BOOST_CHECK_EQUAL(plain.Eval(PolicyV2(1, 1, ABC), 0, FLAGS, Context(), nullptr, nullptr, false), SCRIPT_ERR_OK);

    // With references, it fails closed without their outputs.
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0, FLAGS, Context(), nullptr, nullptr, false), SCRIPT_ERR_ASSETAUTH_CONTEXT);
    RefFixture missing;
    missing.spend.refOutputs.pop_back();
    BOOST_CHECK_EQUAL(missing.spend.Eval(missing.call, 0), SCRIPT_ERR_ASSETAUTH_CONTEXT);

    // Version 1 only commits the reference outpoints: it does not need them.
    Spend sync = plain;
    sync.Input(OwnerOut(P2PKHDest(0xb0), "BOB!"), SigScript(SIGHASH_ALL));
    sync.Ref(XnaOut(P2PKHDest(0x90), COIN));
    BOOST_CHECK_EQUAL(sync.Eval(Policy(2, 3, ABC), 0, FLAGS, Context(), nullptr, nullptr, false), SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(v2_proposal_hash_commitments)
{
    RefFixture base;
    const uint256 h0 = base.H2();

    auto changes = [&](const std::function<void(RefFixture&)>& mutate) {
        RefFixture f;
        mutate(f);
        return f.H2() != h0;
    };
    // r and the proposal references are committed.
    BOOST_CHECK(changes([](RefFixture& f) { f.call.r = 1; }));
    {
        RefFixture f;
        f.call.r = 1;
        const uint256 before = f.H2();
        f.spend.mtx.vrefin[0].n = 7;
        BOOST_CHECK(f.H2() != before);
    }
    // So is everything version 1 commits but the references.
    BOOST_CHECK(changes([](RefFixture& f) { f.spend.mtx.nLockTime = 7; }));
    BOOST_CHECK(changes([](RefFixture& f) { f.call.T += 1; }));
    BOOST_CHECK(changes([](RefFixture& f) { f.call.c = 2; }));
    BOOST_CHECK(changes([](RefFixture& f) { f.call.a = 1; }));
    BOOST_CHECK(changes([](RefFixture& f) { f.call.b = 1; }));
    BOOST_CHECK(changes([](RefFixture& f) { f.spend.mtx.vin[0].prevout.n = 9; }));
    BOOST_CHECK(changes([](RefFixture& f) { f.spend.mtx.vin[0].nSequence = 5; }));
    BOOST_CHECK(changes([](RefFixture& f) { f.spend.mtx.vout[1].nValue -= 1; }));

    // Vote references are not: adding, removing or reordering them keeps H2.
    BOOST_CHECK(!changes([](RefFixture& f) { f.spend.Ref(XnaOut(P2PKHDest(0x90), COIN)); }));
    BOOST_CHECK(!changes([](RefFixture& f) { f.spend.mtx.vrefin.pop_back(); }));
    BOOST_CHECK(!changes([](RefFixture& f) { std::swap(f.spend.mtx.vrefin[0], f.spend.mtx.vrefin[1]); }));
    // Nor the inputs c.. or the intermediate outputs.
    BOOST_CHECK(!changes([](RefFixture& f) { f.spend.mtx.vin[1].nSequence = 5; }));
    BOOST_CHECK(!changes([](RefFixture& f) { f.spend.mtx.vout[2].nValue -= 1; }));

    // With r equal to the number of references, m2 and m match byte for byte,
    // and the tags still keep H2 and H apart.
    const CTransaction tx(base.spend.mtx);
    AssetAuthCall all = base.call;
    all.r = static_cast<int64_t>(tx.vrefin.size());
    AssetAuthCall v1 = base.call;
    v1.version = ASSETAUTH_POLICY_VERSION;
    v1.r = 0;
    const std::vector<unsigned char> m2 = AssetAuthProposalMessage(tx, 2, all);
    BOOST_CHECK(m2 == AssetAuthProposalMessage(tx, 2, v1));
    BOOST_CHECK(AssetAuthProposalHash(m2, ASSETAUTH_POLICY_VERSION_2) != AssetAuthProposalHash(m2, ASSETAUTH_POLICY_VERSION));
    BOOST_CHECK(AssetAuthProposalHash(m2, ASSETAUTH_POLICY_VERSION_2) == TaggedHash("NeuraiAssetAuthProposalV2", m2));
}

// Exact vectors, checked against an independent implementation: a version 3
// transaction with one proposal input, one prefix and one suffix output, and
// two references of which the first belongs to the proposal (r = 1).
BOOST_AUTO_TEST_CASE(v2_proposal_hash_vectors)
{
    CMutableTransaction mtx;
    mtx.nVersion = 3;
    mtx.nLockTime = 0;
    mtx.vin.emplace_back(COutPoint(uint256S("11"), 1), CScript(), uint32_t{CTxIn::SEQUENCE_FINAL});
    mtx.vin.emplace_back(COutPoint(uint256S("22"), 0), CScript(), uint32_t{CTxIn::SEQUENCE_FINAL - 1});
    mtx.vout.emplace_back(9 * COIN, P2PKHDest(0xe0));
    mtx.vout.emplace_back(4 * CENT, P2PKHDest(0xb1));
    mtx.vout.emplace_back(COIN, P2PKHDest(0xe1));
    mtx.vrefin = {COutPoint(uint256S("33"), 2), COutPoint(uint256S("44"), 0)};
    const CTransaction tx(mtx);
    const AssetAuthCall call = PolicyV2(2, 3, ABC, /*c=*/1, /*a=*/1, /*b=*/1, /*r=*/1, /*T=*/1000);

    auto hash = [&](const AssetAuthCall& c, uint8_t chainId) {
        const uint256 h = AssetAuthProposalHash(AssetAuthProposalMessage(tx, chainId, c), c.version);
        return HexStr(h.begin(), h.end());
    };
    BOOST_CHECK_EQUAL(HexStr(AssetAuthProposalMessage(tx, 2, call)),
                      "02" "03000000" "00000000" "e8030000" "010101"                                // chain, version, locktime, T, c a b
                      "1100000000000000000000000000000000000000000000000000000000000000" "01000000" "ffffffff" // input 0
                      "00e9a43500000000" "1976a914e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e088ac"    // prefix output
                      "00e1f50500000000" "1976a914e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e188ac"    // suffix output
                      "01" "3300000000000000000000000000000000000000000000000000000000000000" "02000000"); // r, reference 0
    BOOST_CHECK_EQUAL(hash(call, 0), "8a64677ea55c31e1f262169e4701adfe43e814306cd846062da54a5ee0459f73");
    BOOST_CHECK_EQUAL(hash(call, 1), "e45286dbed5534ee9ad0867bd9743d6383c3ac808ca1ac84d963c056a0d77457");
    BOOST_CHECK_EQUAL(hash(call, 2), "408465300d5d5763ffc79ce4854df4537dfbbf60622af104f96cb84db3ce6e7e");

    // r = 2: the message is m of version 1, the hash is not.
    AssetAuthCall all = call;
    all.r = 2;
    BOOST_CHECK_EQUAL(hash(all, 2), "61d1ad7778c945de4fa2f5bcc49b3dfb05e4f02c6b084126fb0a62054d97c20e");
    BOOST_CHECK_EQUAL(hash(Policy(2, 3, ABC, 1, 1, 1, 1000), 2),
                      "9c140f6de1efc3f88af1c1d91c3cc4ceb51ff54c70d79c730d51cd7a92fa41f3");
}

BOOST_AUTO_TEST_CASE(v2_votes_by_reference)
{
    RefFixture f;
    bool usedHeight = false;
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0, FLAGS, Context(), nullptr, &usedHeight), SCRIPT_ERR_OK);
    BOOST_CHECK(usedHeight);
    // The other custody-side checks see the same verdict for every proposal input.
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0, FLAGS, Context(HEIGHT)), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0, FLAGS, Context(HEIGHT + 1)), SCRIPT_ERR_ASSETAUTH_EXPIRED);

    // Strict v3 holds a vote too.
    RefFixture v3;
    v3.spend.refOutputs[1] = OwnerOut(ProgramDest(OP_3, 0xb0), "BOB!", MessageOf(v3.H2()));
    BOOST_CHECK_EQUAL(v3.spend.Eval(v3.call, 0), SCRIPT_ERR_OK);

    // References of BOB that are not votes. ALICE's vote keeps the call
    // asynchronous, so each fails rule 6.
    const uint256 h2 = f.H2();
    const std::vector<unsigned char> m2 = AssetAuthProposalMessage(CTransaction(f.spend.mtx), 2, f.call);
    const std::string ipfs = std::string("\x12\x20", 2) + std::string(32, '\x22');
    const std::vector<CTxOut> notVotes{
        OwnerOut(LOCK_B, "BOB!", MessageOf(h2)),                                   // generic AuthScript v1
        OwnerOut(P2PKHDest(0xb0), "BOB!"),                                         // no message
        OwnerOut(P2PKHDest(0xb0), "BOB!", std::string(32, '\x11')),                // another proposal
        OwnerOut(P2PKHDest(0xb0), "BOB!", ipfs),                                   // 34-byte IPFS message
        OwnerOut(P2PKHDest(0xb0), "BOB!", MessageOf(TaggedHash("NeuraiAssetAuthProposal", m2))), // version 1 tag
        AssetOut(P2PKHDest(0xb0), "GOLD", COIN, MessageOf(h2)),                    // not an owner
        AssetOut(P2PKHDest(0xb0), "BOB!", 2 * COIN, MessageOf(h2)),                // not one owner token
        OwnerIssuanceOut(P2PKHDest(0xb0), "BOB"),                                  // issuance, no transfer
        XnaOut(P2PKHDest(0xb0), COIN),                                             // no asset
    };
    for (const CTxOut& out : notVotes) {
        RefFixture g;
        g.spend.refOutputs[1] = out;
        BOOST_CHECK_EQUAL(g.spend.Eval(g.call, 0), SCRIPT_ERR_ASSETAUTH_SHAPE);
    }

    // None of them approves BOB: without ALICE's vote the call is synchronous
    // and ALICE's direct signature alone is short of M = 2.
    for (const CTxOut& out : notVotes) {
        Spend s;
        s.mtx.nVersion = 3;
        s.Input(XnaOut(CUSTODY, COIN));
        s.Input(OwnerOut(P2PKHDest(0xa0), "ALICE!"), SigScript(SIGHASH_ALL));
        s.Output(XnaOut(P2PKHDest(0xe0), COIN - CENT));
        s.Ref(out);
        bool used = true;
        BOOST_CHECK_EQUAL(s.Eval(PolicyV2(2, 3, ABC), 0, FLAGS, Context(), nullptr, &used),
                          SCRIPT_ERR_ASSETAUTH_THRESHOLD);
        BOOST_CHECK(!used);
    }

    // An owner of another list does not count but is a valid vote (rule 6).
    RefFixture dave;
    dave.Vote(P2PKHDest(0xd0), "DAVE!");
    BOOST_CHECK_EQUAL(dave.spend.Eval(dave.call, 0), SCRIPT_ERR_OK);
    RefFixture daveOnly;
    daveOnly.spend.refOutputs[1] = OwnerOut(P2PKHDest(0xd0), "DAVE!", MessageOf(daveOnly.H2()));
    BOOST_CHECK_EQUAL(daveOnly.spend.Eval(daveOnly.call, 0), SCRIPT_ERR_ASSETAUTH_THRESHOLD);
    // A name that is not an owner name is no vote, of any list.
    RefFixture badName;
    badName.spend.refOutputs[1] = OwnerOut(P2PKHDest(0xd0), "DAVE", MessageOf(badName.H2()));
    BOOST_CHECK_EQUAL(badName.spend.Eval(badName.call, 0), SCRIPT_ERR_ASSETAUTH_SHAPE);
}

BOOST_AUTO_TEST_CASE(v2_classification)
{
    // A role spent from another family never approves in version 2, with or
    // without a message, and is no foreign vote either.
    Spend s;
    s.mtx.nVersion = 3;
    s.Input(XnaOut(CUSTODY, COIN));
    s.Input(OwnerOut(P2PKHDest(0xb0), "BOB!"), SigScript(SIGHASH_ALL));
    s.Input(OwnerOut(LOCK_A, "ALICE!"));
    s.Output(XnaOut(P2PKHDest(0xe0), COIN - CENT));
    const AssetAuthCall call = PolicyV2(2, 3, ABC);
    for (const std::string& message : {std::string(), MessageOf(s.Hash(call)), std::string(32, '\x11')}) {
        s.prevouts[2] = OwnerOut(LOCK_A, "ALICE!", message);
        BOOST_CHECK_EQUAL(s.Eval(call, 0), SCRIPT_ERR_ASSETAUTH_THRESHOLD);
    }
    // Version 1 calls the last one a foreign vote.
    BOOST_CHECK_EQUAL(s.Eval(Policy(2, 3, ABC), 0), SCRIPT_ERR_ASSETAUTH_FOREIGN_VOTE);

    // A direct signature must be SIGHASH_ALL.
    Spend direct = s;
    direct.prevouts[2] = OwnerOut(P2PKHDest(0xa0), "ALICE!");
    direct.mtx.vin[2].scriptSig = SigScript(SIGHASH_ALL);
    BOOST_CHECK_EQUAL(direct.Eval(call, 0), SCRIPT_ERR_OK);
    direct.mtx.vin[2].scriptSig = SigScript(SIGHASH_NONE);
    BOOST_CHECK_EQUAL(direct.Eval(call, 0), SCRIPT_ERR_ASSETAUTH_SIGHASH);

    // A proposal reference (index < r) that carries a vote does not count.
    RefFixture f;
    f.call.r = 1;
    const uint256 h2 = f.H2();
    f.spend.refOutputs[0] = OwnerOut(P2PKHDest(0xa0), "ALICE!", MessageOf(h2));
    f.spend.refOutputs[1] = OwnerOut(ProgramDest(OP_2, 0xb0), "BOB!", MessageOf(h2));
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_ASSETAUTH_THRESHOLD);
    f.Vote(ProgramDest(OP_3, 0xc0), "CARL!");
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_OK);
    // The proposal reference itself is free: it need not be a vote.
    f.spend.refOutputs[0] = XnaOut(P2PKHDest(0x90), COIN);
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(v2_modes)
{
    // Synchronous: direct signatures only, and the references are free.
    Spend s;
    s.mtx.nVersion = 3;
    s.Input(XnaOut(CUSTODY, COIN));
    s.Input(OwnerOut(P2PKHDest(0xa0), "ALICE!"), SigScript(SIGHASH_ALL));
    s.Input(OwnerOut(P2PKHDest(0xb0), "BOB!"), SigScript(SIGHASH_ALL));
    s.Output(XnaOut(P2PKHDest(0xe0), COIN - CENT));
    s.Output(CTxOut(0, CScript() << OP_RETURN << std::vector<unsigned char>{0x01}));
    s.Ref(XnaOut(P2PKHDest(0x90), COIN));
    s.Ref(AssetOut(LOCK_C, "GOLD", COIN));
    const AssetAuthCall call = PolicyV2(2, 3, ABC);
    bool used = true;
    BOOST_CHECK_EQUAL(s.Eval(call, 0, FLAGS, Context(), nullptr, &used), SCRIPT_ERR_OK);
    BOOST_CHECK(!used);
    BOOST_CHECK_EQUAL(s.Eval(call, 0, FLAGS, Context(HEIGHT + 1)), SCRIPT_ERR_OK); // no expiry

    // A vote of another list leaves this policy synchronous.
    Spend other = s;
    other.Ref(OwnerOut(P2PKHDest(0xd0), "DAVE!", MessageOf(other.Hash(call))));
    BOOST_CHECK_EQUAL(other.Eval(call, 0, FLAGS, Context(), nullptr, &used), SCRIPT_ERR_OK);
    BOOST_CHECK(!used);

    // A vote of the list makes it asynchronous, and the free shape fails.
    Spend own = s;
    own.Ref(OwnerOut(P2PKHDest(0xc0), "CARL!", MessageOf(own.Hash(call))));
    BOOST_CHECK_EQUAL(own.Eval(call, 0, FLAGS, Context(), nullptr, &used), SCRIPT_ERR_ASSETAUTH_SHAPE);
    BOOST_CHECK(used);
}

BOOST_AUTO_TEST_CASE(v2_role_as_input_and_reference)
{
    // Only inside a block: ALICE's reference sees her output before the block,
    // and the execution spends with a direct signature the output an earlier
    // transaction of the block created (§3.5).
    auto build = [](bool withBob) {
        RefFixture f;
        if (!withBob) {
            f.spend.mtx.vrefin.pop_back();
            f.spend.refOutputs.pop_back();
        }
        f.spend.Input(OwnerOut(P2PKHDest(0xa1), "ALICE!"), SigScript(SIGHASH_ALL));
        f.spend.mtx.vout.insert(f.spend.mtx.vout.begin() + 2, OwnerOut(P2PKHDest(0xa1), "ALICE!")); // return
        return f;
    };
    RefFixture f = build(true);
    bool used = false;
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0, FLAGS, Context(), nullptr, &used), SCRIPT_ERR_OK);
    BOOST_CHECK(used);

    // ALICE counts once: alone she is short of M = 2.
    RefFixture alone = build(false);
    BOOST_CHECK_EQUAL(alone.spend.Eval(alone.call, 0), SCRIPT_ERR_ASSETAUTH_THRESHOLD);

    // Her vote makes the call asynchronous although she also signs: expiry
    // and the fixed shape apply.
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0, FLAGS, Context(HEIGHT + 1)), SCRIPT_ERR_ASSETAUTH_EXPIRED);
    RefFixture extra = build(true);
    extra.spend.mtx.vout.insert(extra.spend.mtx.vout.begin() + 2, AssetOut(P2PKHDest(0xf1), "GOLD", COIN));
    BOOST_CHECK_EQUAL(extra.spend.Eval(extra.call, 0), SCRIPT_ERR_ASSETAUTH_SHAPE);

    // Without the vote references, the same approvals are synchronous.
    RefFixture sync = build(false);
    sync.spend.mtx.vrefin.clear();
    sync.spend.refOutputs.clear();
    sync.spend.Input(OwnerOut(P2PKHDest(0xb1), "BOB!"), SigScript(SIGHASH_ALL));
    sync.spend.mtx.vout.insert(sync.spend.mtx.vout.begin() + 2, AssetOut(P2PKHDest(0xf1), "GOLD", COIN));
    BOOST_CHECK_EQUAL(sync.spend.Eval(sync.call, 0, FLAGS, Context(HEIGHT + 1), nullptr, &used), SCRIPT_ERR_OK);
    BOOST_CHECK(!used);
}

BOOST_AUTO_TEST_CASE(v2_fixed_shape)
{
    // Rule 1: the evaluated input is a proposal input.
    {
        RefFixture f;
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 1), SCRIPT_ERR_ASSETAUTH_SHAPE);
    }
    // Rule 2: no input c.. at the custody.
    {
        RefFixture f;
        f.spend.Input(XnaOut(CUSTODY, CENT));
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_ASSETAUTH_SHAPE);
    }
    // Rule 3: inputs c.. are direct approvals, of any list, or carry no asset.
    {
        RefFixture f;
        f.spend.Input(AssetOut(P2PKHDest(0xf0), "GOLD", COIN), SigScript(SIGHASH_ALL));
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_ASSETAUTH_SHAPE);
    }
    {
        // A version 1 vote: a role spent from a lock with the message.
        RefFixture f;
        f.spend.Input(OwnerOut(LOCK_C, "CARL!", MessageOf(f.H2())));
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_ASSETAUTH_SHAPE);
    }
    {
        RefFixture f;
        f.spend.Input(OwnerOut(P2PKHDest(0xd0), "DAVE!"), SigScript(SIGHASH_NONE));
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_ASSETAUTH_SIGHASH);
    }
    {
        RefFixture f;
        f.spend.Input(OwnerOut(P2PKHDest(0xd0), "DAVE!"), SigScript(SIGHASH_ALL));
        f.spend.mtx.vout.insert(f.spend.mtx.vout.begin() + 2, OwnerOut(P2PKHDest(0xd0), "DAVE!"));
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_OK);
    }
    // Rule 4: intermediate outputs are returns of direct approvals or change.
    {
        RefFixture f;
        f.spend.mtx.vout.insert(f.spend.mtx.vout.begin() + 2, AssetOut(P2PKHDest(0xf1), "GOLD", COIN));
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_ASSETAUTH_SHAPE);
    }
    {
        // A vote by reference has no return: returning ALICE! is not allowed.
        RefFixture f;
        f.spend.mtx.vout.insert(f.spend.mtx.vout.begin() + 2, OwnerOut(P2PKHDest(0xa0), "ALICE!"));
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_ASSETAUTH_SHAPE);
    }
    {
        RefFixture f;
        f.spend.mtx.vout.insert(f.spend.mtx.vout.begin() + 2,
                                CTxOut(0, CScript() << OP_RETURN << std::vector<unsigned char>{0x01}));
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_ASSETAUTH_SHAPE);
    }
    // Rule 5: change never exceeds the fee inputs.
    {
        RefFixture f(5 * CENT);
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_OK);
        RefFixture over(5 * CENT + 1);
        BOOST_CHECK_EQUAL(over.spend.Eval(over.call, 0), SCRIPT_ERR_ASSETAUTH_SHAPE);
    }
    // Rule 6: every reference r.. is a vote by reference.
    {
        RefFixture f;
        f.spend.Ref(XnaOut(P2PKHDest(0x90), COIN));
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_ASSETAUTH_SHAPE);
    }
    // Example 6.3: BOB approves directly in the execution instead of voting.
    {
        RefFixture f;
        f.spend.mtx.vrefin.pop_back();
        f.spend.refOutputs.pop_back();
        f.spend.Input(OwnerOut(P2PKHDest(0xb0), "BOB!"), SigScript(SIGHASH_ALL));
        f.spend.mtx.vout.insert(f.spend.mtx.vout.begin() + 2, OwnerOut(P2PKHDest(0xb0), "BOB!"));
        BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0), SCRIPT_ERR_OK);
    }
}

BOOST_AUTO_TEST_CASE(v2_composition)
{
    // A board 2-of-2 and an auditor 1-of-1 share c, a, b, r and T, so H2 too.
    const AssetAuthCall board = PolicyV2(2, 2, ABC, /*c=*/2, /*a=*/2);
    const AssetAuthCall auditor = PolicyV2(1, 1, {"AUDITOR!"}, /*c=*/2, /*a=*/2);
    Spend s;
    s.mtx.nVersion = 3;
    s.Input(XnaOut(CUSTODY, 100 * COIN));
    s.Input(XnaOut(CUSTODY_B, COIN));
    s.Input(XnaOut(P2PKHDest(0xe1), 5 * CENT), SigScript(SIGHASH_ALL));
    s.Output(XnaOut(P2PKHDest(0xe0), 100 * COIN));
    s.Output(XnaOut(CUSTODY_B, COIN));
    s.Output(XnaOut(P2PKHDest(0xe1), 4 * CENT));
    const uint256 h2 = s.Hash(board);
    BOOST_CHECK(h2 == s.Hash(auditor));
    s.Ref(OwnerOut(P2PKHDest(0xa0), "ALICE!", MessageOf(h2)));
    s.Ref(OwnerOut(ProgramDest(OP_2, 0xb0), "BOB!", MessageOf(h2)));
    Spend noAuditor = s;
    s.Ref(OwnerOut(P2PKHDest(0x0a), "AUDITOR!", MessageOf(h2)));
    BOOST_CHECK_EQUAL(s.Eval(board, 0), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(s.Eval(auditor, 1), SCRIPT_ERR_OK);

    // Each policy needs its own threshold.
    BOOST_CHECK_EQUAL(noAuditor.Eval(board, 0), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(noAuditor.Eval(auditor, 1), SCRIPT_ERR_ASSETAUTH_THRESHOLD);

    // With a different r the votes carry another H2: the auditor fails.
    AssetAuthCall auditorR1 = auditor;
    auditorR1.r = 1;
    BOOST_CHECK(s.Eval(auditorR1, 1) != SCRIPT_ERR_OK);

    // A version 1 vote input in the same transaction breaks rule 3 of version 2.
    Spend mixed = s;
    mixed.Input(OwnerOut(LOCK_A, "AUDITOR!", MessageOf(mixed.Hash(Policy(1, 1, {"AUDITOR!"}, 2, 2)))));
    BOOST_CHECK_EQUAL(mixed.Eval(board, 0), SCRIPT_ERR_ASSETAUTH_SHAPE);

    // Two version 2 custodies with the same roles count the same votes.
    BOOST_CHECK_EQUAL(s.Eval(board, 1), SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(v2_threshold)
{
    // TOKEN! leaves the custody: G = 3 applies, with votes by reference.
    Spend s;
    s.mtx.nVersion = 3;
    s.Input(OwnerOut(CUSTODY, "TOKEN!"));
    s.Input(XnaOut(P2PKHDest(0xe1), 5 * CENT), SigScript(SIGHASH_ALL));
    s.Output(OwnerOut(P2PKHDest(0xe5), "TOKEN!"));
    s.Output(XnaOut(P2PKHDest(0xe1), 4 * CENT));
    const AssetAuthCall call = PolicyV2(2, 3, ABC, /*c=*/1, /*a=*/1);
    const std::string message = MessageOf(s.Hash(call));
    s.Ref(OwnerOut(P2PKHDest(0xa0), "ALICE!", message));
    s.Ref(OwnerOut(P2PKHDest(0xb0), "BOB!", message));
    BOOST_CHECK_EQUAL(s.Eval(call, 0), SCRIPT_ERR_ASSETAUTH_THRESHOLD);
    s.Ref(OwnerOut(P2PKHDest(0xc0), "CARL!", message));
    BOOST_CHECK_EQUAL(s.Eval(call, 0), SCRIPT_ERR_OK);

    // When it stays, M = 2 is enough.
    Spend stay;
    stay.mtx.nVersion = 3;
    stay.Input(OwnerOut(CUSTODY, "TOKEN!"));
    stay.Input(XnaOut(P2PKHDest(0xe1), 5 * CENT), SigScript(SIGHASH_ALL));
    stay.Output(OwnerOut(CUSTODY, "TOKEN!"));
    stay.Output(XnaOut(P2PKHDest(0xe1), 4 * CENT));
    const std::string stayMessage = MessageOf(stay.Hash(call));
    stay.Ref(OwnerOut(P2PKHDest(0xa0), "ALICE!", stayMessage));
    stay.Ref(OwnerOut(P2PKHDest(0xb0), "BOB!", stayMessage));
    BOOST_CHECK_EQUAL(stay.Eval(call, 0), SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(v2_work_budget)
{
    RefFixture f;
    const CTransaction tx(f.spend.mtx);
    const size_t messageSize = AssetAuthProposalMessage(tx, 2, f.call).size();
    // Three roles and two referenced owners, all under 33 bytes; no input or
    // output of the transaction carries an asset.
    const uint64_t nameWork = AssetAuthNameWork(f.call, tx, f.spend.prevouts, FLAGS, &f.spend.refOutputs);
    BOOST_CHECK_EQUAL(nameWork, 5U);
    // Version 1 does not read the referenced outputs.
    AssetAuthCall v1 = f.call;
    v1.version = ASSETAUTH_POLICY_VERSION;
    v1.r = 0;
    BOOST_CHECK_EQUAL(AssetAuthNameWork(v1, tx, f.spend.prevouts, FLAGS, &f.spend.refOutputs), 3U);

    const uint64_t work = AssetAuthWork(tx, messageSize, nameWork, tx.vrefin.size());
    BOOST_CHECK_EQUAL(work, 1 + tx.vin.size() + tx.vout.size() + tx.vrefin.size() + (messageSize + 63) / 64 + nameWork);
    AssetAuthWorkBudget exact(work);
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0, FLAGS, Context(), &exact), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(exact.Used(), work);
    AssetAuthWorkBudget shortOfOne(work - 1);
    BOOST_CHECK_EQUAL(f.spend.Eval(f.call, 0, FLAGS, Context(), &shortOfOne), SCRIPT_ERR_ASSETAUTH_BUDGET);

    // Each reference pays one unit and its name: ceil(41 / 32) = 2 here. The
    // name is no owner name, so rule 6 refuses it, after the charge.
    RefFixture longer;
    longer.spend.Ref(OwnerOut(P2PKHDest(0xd0), std::string(40, 'd') + "!", MessageOf(longer.H2())));
    const CTransaction longerTx(longer.spend.mtx);
    const uint64_t longerNames = AssetAuthNameWork(longer.call, longerTx, longer.spend.prevouts, FLAGS,
                                                   &longer.spend.refOutputs);
    BOOST_CHECK_EQUAL(longerNames, nameWork + 2);
    BOOST_CHECK_EQUAL(AssetAuthWork(longerTx, messageSize, longerNames, longerTx.vrefin.size()), work + 3);
    AssetAuthWorkBudget charged(10 * work);
    BOOST_CHECK_EQUAL(longer.spend.Eval(longer.call, 0, FLAGS, Context(), &charged), SCRIPT_ERR_ASSETAUTH_SHAPE);
    BOOST_CHECK_EQUAL(charged.Used(), work + 3);

    // 64 references, the relay limit, with 31-byte names ending in digits.
    RefFixture many;
    for (int i = 0; i < 62; ++i)
        many.Vote(P2PKHDest(0xd0), strprintf("VOTER%025d!", i));
    const CTransaction manyTx(many.spend.mtx);
    BOOST_CHECK_EQUAL(manyTx.vrefin.size(), 64U);
    AssetAuthWorkBudget roomy(1000);
    BOOST_CHECK_EQUAL(many.spend.Eval(many.call, 0, FLAGS, Context(), &roomy), SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(roomy.Used(),
                      AssetAuthWork(manyTx, AssetAuthProposalMessage(manyTx, 2, many.call).size(),
                                    AssetAuthNameWork(many.call, manyTx, many.spend.prevouts, FLAGS, &many.spend.refOutputs),
                                    64));

    // Without room for the work, the call fails before checking any name.
    RefFixture badRoles;
    badRoles.call.roles = {"ALICE", "BOB!", "CARL!"};
    BOOST_CHECK_EQUAL(badRoles.spend.Eval(badRoles.call, 0), SCRIPT_ERR_ASSETAUTH_POLICY);
    AssetAuthWorkBudget tight(1);
    BOOST_CHECK_EQUAL(badRoles.spend.Eval(badRoles.call, 0, FLAGS, Context(), &tight), SCRIPT_ERR_ASSETAUTH_BUDGET);
    BOOST_CHECK_EQUAL(tight.Used(), 0U);
}

BOOST_AUTO_TEST_CASE(v2_random_transactions_keep_invariants)
{
    SeedInsecureRand(true);
    const std::vector<CTxOut> pool{
        XnaOut(CUSTODY, COIN),
        XnaOut(P2PKHDest(0xb2), 3 * CENT),
        AssetOut(CUSTODY, "GOLD", COIN),
        OwnerOut(CUSTODY, "TOKEN!"),
        OwnerOut(LOCK_C, "CARL!", MessageOf(uint256S("77"))),
        OwnerOut(P2PKHDest(0xc0), "CARL!"),
        OwnerOut(ProgramDest(OP_2, 0xc3), "CARL!"),
        OwnerOut(P2PKHDest(0xd0), "DAVE!"),
        AssetOut(LOCK_A, "GOLD", 5 * COIN),
    };
    int passed = 0;
    for (int iter = 0; iter < 3000; ++iter) {
        RefFixture f;
        Spend& s = f.spend;
        for (uint64_t i = InsecureRandRange(4); i > 0; --i) {
            switch (InsecureRandRange(7)) {
            case 0:
                if (s.mtx.vin.size() > 1) {
                    const size_t k = InsecureRandRange(s.mtx.vin.size());
                    s.mtx.vin.erase(s.mtx.vin.begin() + k);
                    s.prevouts.erase(s.prevouts.begin() + k);
                }
                break;
            case 1:
                if (!s.mtx.vout.empty())
                    s.mtx.vout.erase(s.mtx.vout.begin() + InsecureRandRange(s.mtx.vout.size()));
                break;
            case 2:
                s.Input(pool[InsecureRandRange(pool.size())],
                        InsecureRandBool() ? SigScript(InsecureRandBool() ? SIGHASH_ALL : SIGHASH_NONE) : CScript(),
                        InsecureRandBool() ? StrictWitness(SIGHASH_ALL) : CScriptWitness());
                break;
            case 3:
                s.Output(pool[InsecureRandRange(pool.size())]);
                break;
            case 4:
                if (!s.mtx.vrefin.empty()) {
                    const size_t j = InsecureRandRange(s.mtx.vrefin.size());
                    s.mtx.vrefin.erase(s.mtx.vrefin.begin() + j);
                    s.refOutputs.erase(s.refOutputs.begin() + j);
                }
                break;
            case 5:
                // H2 needs the prefix of the fixture's call (a = 2) in place.
                if (InsecureRandBool() && s.mtx.vout.size() >= 2)
                    f.Vote(InsecureRandBool() ? P2PKHDest(0xc0) : LOCK_C, InsecureRandBool() ? "CARL!" : "DAVE!");
                else
                    s.Ref(pool[InsecureRandRange(pool.size())]);
                break;
            default:
                if (s.mtx.vrefin.size() > 1) {
                    const size_t j = InsecureRandRange(s.mtx.vrefin.size()), k = InsecureRandRange(s.mtx.vrefin.size());
                    std::swap(s.mtx.vrefin[j], s.mtx.vrefin[k]);
                    std::swap(s.refOutputs[j], s.refOutputs[k]);
                }
                break;
            }
        }
        AssetAuthCall call = f.call;
        if (InsecureRandBool()) {
            call.c = InsecureRandRange(4);
            call.a = InsecureRandRange(4);
            call.b = InsecureRandRange(3);
            call.r = InsecureRandRange(3);
            call.T = HEIGHT - 1 + InsecureRandRange(3);
        }
        const unsigned int nIn = InsecureRandRange(s.mtx.vin.size() + 1);
        const script_verify_flags flags = InsecureRandBool() ? FLAGS : SCRIPT_VERIFY_ASSETAUTH;
        AssetAuthWorkBudget budget(1000);
        const ScriptError err = s.Eval(call, nIn, flags, Context(), &budget);
        BOOST_CHECK_EQUAL(s.Eval(call, nIn, flags), err);
        if (err != SCRIPT_ERR_OK)
            continue;
        ++passed;
        const CTransaction tx(s.mtx);
        BOOST_CHECK(nIn < tx.vin.size());
        BOOST_CHECK(call.c <= static_cast<int64_t>(tx.vin.size()));
        BOOST_CHECK(call.a + call.b <= static_cast<int64_t>(tx.vout.size()));
        BOOST_CHECK(call.r <= static_cast<int64_t>(tx.vrefin.size()));
        BOOST_CHECK_EQUAL(budget.Used(),
                          AssetAuthWork(tx, AssetAuthProposalMessage(tx, Context().chainId, call).size(),
                                        AssetAuthNameWork(call, tx, s.prevouts, flags, &s.refOutputs), tx.vrefin.size()));
    }
    BOOST_CHECK(passed > 0);
}

BOOST_AUTO_TEST_SUITE_END()

// ---------------------------------------------------------------------------
// Validation: metering and the script execution cache (§3.13)
// ---------------------------------------------------------------------------

BOOST_FIXTURE_TEST_SUITE(assetauth_validation_tests, TestChain100Setup)

BOOST_AUTO_TEST_CASE(metered_execution_skips_the_script_cache)
{
    LOCK(cs_main);
    CCoinsView dummy;
    CCoinsViewCache view(&dummy);

    const std::string role = "ROLE!";
    const CScript custodyScript = CScript() << 1 << 1 << 1 << std::vector<unsigned char>(role.begin(), role.end())
                                            << 1 << OP_CHECKASSETAUTH;
    const CScript custodySpk = CScript() << OP_1 << ToByteVector(GetAuthScriptCommitment(0, nullptr, custodyScript));
    const CScript lockScript = CScript() << OP_TRUE;
    const CScript lockSpk = CScript() << OP_1 << ToByteVector(GetAuthScriptCommitment(0, nullptr, lockScript));

    CMutableTransaction mtx;
    mtx.nVersion = 2;
    const COutPoint custodyPrev(GetRandHash(), 0), votePrev(GetRandHash(), 0);
    mtx.vin.emplace_back(custodyPrev);
    mtx.vin.emplace_back(votePrev);
    mtx.vout.emplace_back(COIN - CENT, CScript() << OP_TRUE);      // prefix, a = 1
    mtx.vout.push_back(OwnerOut(P2PKHDest(0xa0), role));            // return
    const AssetAuthCall call = Policy(1, 1, {role}, /*c=*/1, /*a=*/1, /*b=*/0, HEIGHT);
    const std::vector<unsigned char> message = AssetAuthProposalMessage(CTransaction(mtx), 2, call);
    const uint256 hash = AssetAuthProposalHash(message);

    view.AddCoin(custodyPrev, Coin(CTxOut(COIN, custodySpk), 1, false), false);
    view.AddCoin(votePrev, Coin(OwnerOut(lockSpk, role, MessageOf(hash)), 1, false), false);
    mtx.vin[0].scriptWitness.stack = {{0x00}, CScriptNum(1).getvch(), CScriptNum(1).getvch(), {},
                                      CScriptNum(HEIGHT).getvch(),
                                      std::vector<unsigned char>(custodyScript.begin(), custodyScript.end())};
    mtx.vin[1].scriptWitness.stack = {{0x00}, std::vector<unsigned char>(lockScript.begin(), lockScript.end())};
    const CTransaction tx(mtx);
    BOOST_CHECK(AssetAuthProposalHash(AssetAuthProposalMessage(tx, 2, call)) == hash); // witness-free
    const std::vector<CTxOut> prevouts{CTxOut(COIN, custodySpk), OwnerOut(lockSpk, role, MessageOf(hash))};

    PrecomputedTransactionData data(tx);
    auto flags = GetStandardScriptVerifyFlagsWithConsensusOptIns(GetParams().GetConsensus());
    flags &= ~SCRIPT_VERIFY_POSEIDON_WORK; // isolate the asset-auth meter
    BOOST_REQUIRE(flags & SCRIPT_VERIFY_ASSETAUTH);
    const uint64_t work = AssetAuthWork(tx, message.size(), AssetAuthNameWork(call, tx, prevouts, flags));
    const ChainContext context{HEIGHT, 0, 2, true};

    // Validate with the cache allowed: a metered transaction is never stored.
    CValidationState warm;
    BOOST_REQUIRE_MESSAGE(CheckInputs(tx, warm, view, true, flags, true, true, data, nullptr, nullptr, context),
                          FormatStateMessage(warm));
    std::vector<CScriptCheck> checks;
    CValidationState again;
    BOOST_REQUIRE(CheckInputs(tx, again, view, true, flags, true, true, data, &checks, nullptr, context));
    BOOST_CHECK_EQUAL(checks.size(), 2U);

    // Every validation charges the full amount.
    for (int repeat = 0; repeat < 2; ++repeat) {
        auto budget = std::make_shared<AssetAuthWorkBudget>(10 * work);
        CValidationState state;
        BOOST_REQUIRE(CheckInputs(tx, state, view, true, flags, true, true, data, nullptr, nullptr, context,
                                  nullptr, nullptr, nullptr, false, budget));
        BOOST_CHECK_EQUAL(budget->Used(), work);
    }

    // A budget that cannot take one execution rejects the transaction.
    auto tiny = std::make_shared<AssetAuthWorkBudget>(work - 1);
    CValidationState reject;
    BOOST_CHECK(!CheckInputs(tx, reject, view, true, flags, true, true, data, nullptr, nullptr, context,
                             nullptr, nullptr, nullptr, false, tiny));
    BOOST_CHECK(tiny->Exceeded());
    BOOST_CHECK_EQUAL(reject.GetRejectReason(), "bad-txns-assetauth-work");

    // Without the chain context the opcode fails closed.
    CValidationState noContext;
    BOOST_CHECK(!CheckInputs(tx, noContext, view, true, flags, true, false, data, nullptr));
}

// Version 2 through the interpreter: a custody script `<2> <M> <G> <role> <1>
// OP_CHECKASSETAUTH` spent with the witness [0x00, c, a, b, r, T, script] and
// one vote by reference (NIP-054 v7).
BOOST_AUTO_TEST_CASE(version_2_through_the_interpreter)
{
    LOCK(cs_main);
    CCoinsView dummy;
    CCoinsViewCache view(&dummy);

    const std::string role = "ROLE!";
    const CScript custodyScript = CScript() << ASSETAUTH_POLICY_VERSION_2 << 1 << 1
                                            << std::vector<unsigned char>(role.begin(), role.end()) << 1
                                            << OP_CHECKASSETAUTH;
    const CScript custodySpk = CScript() << OP_1 << ToByteVector(GetAuthScriptCommitment(0, nullptr, custodyScript));

    CMutableTransaction mtx;
    mtx.nVersion = 3;
    const COutPoint custodyPrev(GetRandHash(), 0), votePrev(GetRandHash(), 0);
    mtx.vin.emplace_back(custodyPrev);
    mtx.vout.emplace_back(COIN - CENT, CScript() << OP_TRUE); // prefix, a = 1
    mtx.vrefin.push_back(votePrev);
    const AssetAuthCall call = PolicyV2(1, 1, {role}, /*c=*/1, /*a=*/1, /*b=*/0, /*r=*/0, HEIGHT);
    const std::vector<unsigned char> message = AssetAuthProposalMessage(CTransaction(mtx), 2, call);
    const uint256 hash = AssetAuthProposalHash(message, ASSETAUTH_POLICY_VERSION_2);
    view.AddCoin(custodyPrev, Coin(CTxOut(COIN, custodySpk), 1, false), false);
    mtx.vin[0].scriptWitness.stack = {{0x00}, CScriptNum(1).getvch(), CScriptNum(1).getvch(), {}, {},
                                      CScriptNum(HEIGHT).getvch(),
                                      std::vector<unsigned char>(custodyScript.begin(), custodyScript.end())};
    const CTransaction tx(mtx);
    BOOST_CHECK(AssetAuthProposalHash(AssetAuthProposalMessage(tx, 2, call), ASSETAUTH_POLICY_VERSION_2) == hash);
    const std::vector<CTxOut> prevouts{CTxOut(COIN, custodySpk)};
    auto refs = std::make_shared<std::vector<CTxOut>>(std::vector<CTxOut>{OwnerOut(P2PKHDest(0xa0), role, MessageOf(hash))});

    PrecomputedTransactionData data(tx);
    auto flags = GetStandardScriptVerifyFlagsWithConsensusOptIns(GetParams().GetConsensus());
    flags &= ~SCRIPT_VERIFY_POSEIDON_WORK; // isolate the asset-auth meter
    BOOST_REQUIRE(flags & SCRIPT_VERIFY_ASSETAUTH);
    BOOST_REQUIRE(flags & SCRIPT_VERIFY_CLEANSTACK);
    const ChainContext context{HEIGHT, 0, 2, true};

    // The call consumes n + 9 items and leaves true alone (CLEANSTACK).
    CValidationState ok;
    BOOST_CHECK_MESSAGE(CheckInputs(tx, ok, view, true, flags, true, false, data, nullptr, refs, context),
                        FormatStateMessage(ok));

    // The work counts the reference and its name: 1 + one input + one output
    // + one reference + ceil(67 / 64) for m2 + the role and the referenced owner.
    BOOST_CHECK_EQUAL(message.size(), 67U);
    const uint64_t work = AssetAuthWork(tx, message.size(), AssetAuthNameWork(call, tx, prevouts, flags, refs.get()), 1);
    BOOST_CHECK_EQUAL(work, 1U + 1 + 1 + 1 + 2 + 2);
    auto budget = std::make_shared<AssetAuthWorkBudget>(10 * work);
    CValidationState metered;
    BOOST_CHECK(CheckInputs(tx, metered, view, true, flags, true, false, data, nullptr, refs, context,
                            nullptr, nullptr, nullptr, false, budget));
    BOOST_CHECK_EQUAL(budget->Used(), work);

    // Without the referenced outputs a version 2 call fails closed.
    CValidationState missing;
    BOOST_CHECK(!CheckInputs(tx, missing, view, true, flags, true, false, data, nullptr, nullptr, context));

    // After T the vote no longer counts.
    CValidationState expired;
    BOOST_CHECK(!CheckInputs(tx, expired, view, true, flags, true, false, data, nullptr, refs,
                             ChainContext{HEIGHT + 1, 0, 2, true}));

    // A reference that is not a vote leaves the call without approvals.
    auto notVote = std::make_shared<std::vector<CTxOut>>(std::vector<CTxOut>{OwnerOut(P2PKHDest(0xa0), role)});
    CValidationState noVote;
    BOOST_CHECK(!CheckInputs(tx, noVote, view, true, flags, true, false, data, nullptr, notVote, context));

    // The version 1 layout of the same witness leaves items on the stack: the
    // extra r would be read as T and the call fails.
    CMutableTransaction v1 = mtx;
    v1.vin[0].scriptWitness.stack.erase(v1.vin[0].scriptWitness.stack.begin() + 4);
    const CTransaction v1tx(v1);
    PrecomputedTransactionData v1data(v1tx);
    CValidationState shortWitness;
    BOOST_CHECK(!CheckInputs(v1tx, shortWitness, view, true, flags, true, false, v1data, nullptr, refs, context));
}

BOOST_AUTO_TEST_SUITE_END()

