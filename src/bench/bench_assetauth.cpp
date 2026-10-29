// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-054 §3.13 bench for OP_CHECKASSETAUTH. Dividing the time per iteration
// by the work W it charges gives the cost of one work unit, which is what
// MAX_BLOCK_ASSETAUTH_WORK and MAX_STANDARD_TX_ASSETAUTH_WORK must bound.
//
// Name validation is the costly step: it grows with the length of the name and
// is slowest for DEPIN owners and for names that end in digits. Mainnet cases
// use 31-byte names; testnet cases, which share the budget constants, use
// 121-byte DEPIN names (&...).
//
// Evaluator regimes (one iteration = one successful call), with 16 roles,
// M = 15 and G = 16 so the threshold scan runs, and 1000 extra entries:
//   - AssetAuthSyncSmall    : 16 direct approvals and one custody input,
//                             8-byte names. W = 84.
//   - AssetAuthAsyncVotes   : asynchronous, 1016 vote inputs carrying H and
//                             no returns (they are optional); the 1000 votes
//                             from other lists need an owner check each.
//                             W = 2053 (mainnet), 5149 (testnet).
//   - AssetAuthAssetsLeave  : synchronous, 1000 assets of the custody that
//                             leave it. W = 4082 (mainnet), 10226 (testnet).
//   - AssetAuthOwnersStay   : synchronous, 1000 owners held by the custody
//                             that stay there. W = 4082.
// Whole opcode through VerifyScript (one iteration = one transaction):
//   - AssetAuthRepeatedCalls: one input builds 16 roles once and calls
//                             OP_CHECKASSETAUTH 25 times on a two-input
//                             transaction, so every call checks the 16 names
//                             again. W = 23 per call, 575 per iteration
//                             (mainnet); 77 and 1925 (testnet).

#include "bench.h"
#include "assets/assets.h"
#include "chainparams.h"
#include "chainparamsbase.h"
#include "primitives/transaction.h"
#include "script/assetauth.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/standard.h"
#include "tinyformat.h"
#include "uint256.h"

#include <cassert>
#include <string>
#include <vector>

namespace {

constexpr script_verify_flags kFlags = SCRIPT_VERIFY_ASSETAUTH | SCRIPT_VERIFY_AUTHSCRIPT_STRICT;
constexpr int64_t kHeight = 1000;
constexpr int kExtra = 1000;

/** Asset names of one network. */
struct Names {
    std::string role;  //!< prefix of the roles
    std::string extra; //!< prefix of the extra entries
    size_t length;     //!< longest name of the network
};
const Names kShort{"R", "X", 8};
const Names kMainnet{"R", "X", 31};
const Names kTestnet{"&R", "&X", 121};

/** Selects a network for one bench and restores mainnet afterwards. */
struct ScopedNetwork {
    explicit ScopedNetwork(const std::string& chain) { SelectParams(chain); }
    ~ScopedNetwork() { SelectParams(CBaseChainParams::MAIN); }
};

/** "<prefix>ZZZ...<index>[!]", `length` bytes long. */
std::string Name(const std::string& prefix, int index, size_t length, bool owner)
{
    const std::string tail = strprintf("%04d", index) + (owner ? "!" : "");
    return prefix + std::string(length - prefix.size() - tail.size(), 'Z') + tail;
}

CScript ProgramDest(unsigned char fill)
{
    std::vector<unsigned char> bytes{OP_1, 0x20};
    bytes.insert(bytes.end(), 32, fill);
    return CScript(bytes.begin(), bytes.end());
}

CScript P2PKHDest(unsigned char fill)
{
    return CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, fill) << OP_EQUALVERIFY << OP_CHECKSIG;
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

CScript SigScript()
{
    std::vector<unsigned char> sig(71, 0x30);
    sig.back() = SIGHASH_ALL;
    return CScript() << sig << std::vector<unsigned char>(33, 0x02);
}

AssetAuthCall Policy(const Names& names, int64_t c, int64_t a)
{
    AssetAuthCall call;
    call.version = ASSETAUTH_POLICY_VERSION;
    call.M = ASSETAUTH_MAX_ROLES - 1;
    call.G = ASSETAUTH_MAX_ROLES;
    for (int i = 0; i < ASSETAUTH_MAX_ROLES; ++i)
        call.roles.push_back(Name(names.role, i, names.length, true));
    call.c = c;
    call.a = a;
    call.b = 0;
    call.T = kHeight;
    return call;
}

struct Case {
    CMutableTransaction mtx;
    std::vector<CTxOut> prevouts;
    AssetAuthCall call;
    unsigned int nIn{0};

    Case() { mtx.nVersion = 2; }

    void Input(const CTxOut& prevout, const CScript& scriptSig = CScript())
    {
        mtx.vin.emplace_back(COutPoint(uint256S(strprintf("%064x", 0x1000 + mtx.vin.size())), 0), scriptSig);
        prevouts.push_back(prevout);
    }

    /** Roles approve by direct signature and get their tokens back. */
    void DirectApprovals()
    {
        for (const std::string& role : call.roles) {
            Input(OwnerOut(P2PKHDest(0x11), role), SigScript());
            mtx.vout.push_back(OwnerOut(P2PKHDest(0x11), role));
        }
    }
};

void Run(benchmark::State& state, const Case& c)
{
    const CTransaction tx(c.mtx);
    const ChainContext context{kHeight, 0, 2, true};
    bool fUsedHeight = false;
    ScriptError err = SCRIPT_ERR_OK;
    // The bench must time the successful path, which visits every rule.
    const bool ok = EvaluateAssetAuth(c.call, tx, c.nIn, c.prevouts, context, kFlags, nullptr, fUsedHeight, &err);
    assert(ok);
    while (state.KeepRunning()) {
        EvaluateAssetAuth(c.call, tx, c.nIn, c.prevouts, context, kFlags, nullptr, fUsedHeight, &err);
    }
}

void SyncSmall(benchmark::State& state)
{
    Case c;
    c.call = Policy(kShort, 0, 0);
    c.DirectApprovals();
    c.nIn = c.mtx.vin.size();
    c.Input(CTxOut(10 * COIN, ProgramDest(0xc1)));
    c.mtx.vout.emplace_back(9 * COIN, P2PKHDest(0x22));
    Run(state, c);
}

void AsyncVotes(benchmark::State& state, const Names& names)
{
    Case c;
    c.call = Policy(names, 1, 1);
    // Proposal: the custody input and one payment.
    c.Input(CTxOut(10 * COIN, ProgramDest(0xc1)));
    c.mtx.vout.emplace_back(9 * COIN, P2PKHDest(0x22));

    std::vector<std::string> voters = c.call.roles;
    for (int i = 0; i < kExtra; ++i)
        voters.push_back(Name(names.extra, i, names.length, true));
    for (size_t i = 0; i < voters.size(); ++i)
        c.mtx.vin.emplace_back(COutPoint(uint256S(strprintf("%064x", 0x9000 + i)), 0));

    // H covers the proposal only, so the vote prevouts can carry it.
    const CTransaction draft(c.mtx);
    const uint256 hash = AssetAuthProposalHash(AssetAuthProposalMessage(draft, 2, c.call));
    const std::string message(hash.begin(), hash.end());
    for (const std::string& voter : voters)
        c.prevouts.push_back(OwnerOut(ProgramDest(0xa1), voter, message));
    Run(state, c);
}

void AssetsLeave(benchmark::State& state, const Names& names)
{
    Case c;
    c.call = Policy(names, 0, 0);
    c.DirectApprovals();
    c.nIn = c.mtx.vin.size();
    for (int i = 0; i < kExtra; ++i) {
        // A root leaves room for the "!" of its owner.
        const std::string name = Name(names.extra, i, names.length - 1, false);
        c.Input(AssetOut(ProgramDest(0xc1), name, COIN));
        c.mtx.vout.push_back(AssetOut(P2PKHDest(0x33), name, COIN));
    }
    Run(state, c);
}

void OwnersStay(benchmark::State& state, const Names& names)
{
    Case c;
    c.call = Policy(names, 0, 0);
    c.DirectApprovals();
    c.nIn = c.mtx.vin.size();
    for (int i = 0; i < kExtra; ++i) {
        const std::string name = Name(names.extra, i, names.length, true);
        c.Input(OwnerOut(ProgramDest(0xc1), name));
        c.mtx.vout.push_back(OwnerOut(ProgramDest(0xc1), name));
    }
    Run(state, c);
}

void RepeatedCalls(benchmark::State& state, const Names& names)
{
    using Bytes = std::vector<unsigned char>;
    const int calls = 25;
    // Roles share a long prefix and differ in a short suffix, so the script
    // builds them with OP_CAT and copies them with OP_PICK on every call.
    const std::string prefix = names.role + std::string(names.length - names.role.size() - 5, 'Z');
    std::vector<std::string> roles;
    CScript script;
    script << Bytes(prefix.begin(), prefix.end());
    for (int i = 0; i < ASSETAUTH_MAX_ROLES; ++i) {
        const std::string suffix = std::to_string(1000 + i) + "!";
        roles.push_back(prefix + suffix);
        script << OP_DUP << Bytes(suffix.begin(), suffix.end()) << OP_CAT << OP_SWAP;
    }
    script << OP_DROP;
    for (int i = 0; i < calls; ++i) {
        script << 1 << 0 << 0 << 1000000 << 1 << 1 << 1;
        for (int r = 0; r < ASSETAUTH_MAX_ROLES; ++r)
            script << 22 << OP_PICK;
        script << ASSETAUTH_MAX_ROLES << OP_CHECKASSETAUTH << OP_DROP;
    }
    for (int i = 0; i < ASSETAUTH_MAX_ROLES / 2; ++i)
        script << OP_2DROP;
    script << OP_TRUE;

    const CScript custody = CScript() << OP_1 << ToByteVector(GetAuthScriptCommitment(0, nullptr, script));
    const CScript lock = CScript() << OP_1 << ToByteVector(GetAuthScriptCommitment(0, nullptr, CScript() << OP_TRUE));
    CMutableTransaction mtx;
    mtx.nVersion = 2;
    mtx.vin.emplace_back(COutPoint(uint256S("01"), 0));
    mtx.vin.emplace_back(COutPoint(uint256S("02"), 0));
    mtx.vout.push_back(OwnerOut(lock, roles[0]));
    mtx.vin[0].scriptWitness.stack = {{0}, Bytes(script.begin(), script.end())};
    const CTransaction tx(mtx);

    // The vote of the first role carries H, so every call is asynchronous.
    AssetAuthCall call;
    call.version = ASSETAUTH_POLICY_VERSION;
    call.M = 1;
    call.G = 1;
    call.roles = roles;
    call.c = 1;
    call.T = 1000000;
    const uint256 hash = AssetAuthProposalHash(AssetAuthProposalMessage(tx, 2, call));
    const std::vector<CTxOut> prevouts{CTxOut(10000, custody),
                                       OwnerOut(lock, roles[0], std::string(hash.begin(), hash.end()))};

    const PrecomputedTransactionData txdata(tx);
    const script_verify_flags flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CLEANSTACK |
                                      SCRIPT_VERIFY_AUTHSCRIPT | SCRIPT_VERIFY_AUTHSCRIPT_STRICT | SCRIPT_VERIFY_CAT |
                                      SCRIPT_VERIFY_64BIT_INTEGERS | SCRIPT_VERIFY_AUTHSCRIPT_BUDGET |
                                      SCRIPT_VERIFY_MINIMALDATA | SCRIPT_VERIFY_ASSETAUTH;
    TransactionSignatureChecker checker(&tx, 0, 10000, txdata, custody, &prevouts, ChainContext{kHeight, 0, 2, true});
    ScriptError err = SCRIPT_ERR_OK;
    const bool ok = VerifyScript(tx.vin[0].scriptSig, custody, &tx.vin[0].scriptWitness, flags, checker, &err);
    assert(ok);
    while (state.KeepRunning()) {
        VerifyScript(tx.vin[0].scriptSig, custody, &tx.vin[0].scriptWitness, flags, checker, &err);
    }
}

} // namespace

static void AssetAuthSyncSmall(benchmark::State& state) { SyncSmall(state); }
static void AssetAuthAsyncVotes(benchmark::State& state) { AsyncVotes(state, kMainnet); }
static void AssetAuthAssetsLeave(benchmark::State& state) { AssetsLeave(state, kMainnet); }
static void AssetAuthOwnersStay(benchmark::State& state) { OwnersStay(state, kMainnet); }
static void AssetAuthRepeatedCalls(benchmark::State& state) { RepeatedCalls(state, kMainnet); }

static void AssetAuthAsyncVotesTestnet(benchmark::State& state)
{
    ScopedNetwork testnet(CBaseChainParams::TESTNET);
    AsyncVotes(state, kTestnet);
}
static void AssetAuthAssetsLeaveTestnet(benchmark::State& state)
{
    ScopedNetwork testnet(CBaseChainParams::TESTNET);
    AssetsLeave(state, kTestnet);
}
static void AssetAuthRepeatedCallsTestnet(benchmark::State& state)
{
    ScopedNetwork testnet(CBaseChainParams::TESTNET);
    RepeatedCalls(state, kTestnet);
}

BENCHMARK(AssetAuthSyncSmall);
BENCHMARK(AssetAuthAsyncVotes);
BENCHMARK(AssetAuthAssetsLeave);
BENCHMARK(AssetAuthOwnersStay);
BENCHMARK(AssetAuthRepeatedCalls);
BENCHMARK(AssetAuthAsyncVotesTestnet);
BENCHMARK(AssetAuthAssetsLeaveTestnet);
BENCHMARK(AssetAuthRepeatedCallsTestnet);
