// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// libFuzzer harness for OP_CHECKASSETAUTH (NIP-054), policy versions 1 and 2.
//
// The first input byte picks a mode:
//
//  - decode: an arbitrary stack goes through DecodeAssetAuthCall and through
//    an independent decoder written from the NIP. Both must return the same
//    error and, on success, the same call.
//  - evaluate: a transaction is built from a small vocabulary of inputs,
//    outputs and referenced outputs whose meaning the harness knows (family,
//    asset, owner name, message, signature type). An abstract model of the
//    rules, written from the NIP and blind to scripts, predicts the exact
//    error, whether the call went asynchronous and the work W. The
//    implementation must match all three; a budget of W must pass with W
//    charged and one of W - 1 must fail with the budget error; the call must
//    give the same result through VerifyScript as a real custody script; and,
//    for version 2, reordering the vote references must not change anything.
//
// Any disagreement aborts and leaves the input as an artifact.
// Build and run: see README.md in this directory.

#include "assets/assets.h"
#include "assets/assettypes.h"
#include "chainparams.h"
#include "chainparamsbase.h"
#include "hash.h"
#include "primitives/transaction.h"
#include "script/assetauth.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/standard.h"
#include "uint256.h"
#include "tinyformat.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <set>
#include <string>
#include <vector>

namespace {

using Stack = std::vector<std::vector<unsigned char>>;

constexpr int64_t HEIGHT = 1000;
constexpr uint8_t CHAIN_ID = 2;
const script_verify_flags EVAL_FLAGS = SCRIPT_VERIFY_ASSETAUTH | SCRIPT_VERIFY_AUTHSCRIPT_STRICT;
const script_verify_flags SCRIPT_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CLEANSTACK |
                                         SCRIPT_VERIFY_AUTHSCRIPT | SCRIPT_VERIFY_AUTHSCRIPT_STRICT |
                                         SCRIPT_VERIFY_MINIMALDATA | SCRIPT_VERIFY_ASSETAUTH;

class Reader
{
public:
    Reader(const uint8_t* data, size_t size) : m_p(data), m_end(data + size) {}
    uint8_t Byte() { return m_p < m_end ? *m_p++ : 0; }
    bool Bool() { return Byte() & 1; }
    unsigned Pick(unsigned n) { return n ? Byte() % n : 0; }

private:
    const uint8_t* m_p;
    const uint8_t* m_end;
};

[[noreturn]] void Fail(const char* what, long long implementation, long long model)
{
    fprintf(stderr, "DISAGREEMENT: %s (implementation %lld, model %lld)\n", what, implementation, model);
    abort();
}

// ---------------------------------------------------------------------------
// Mode 1: decoding
// ---------------------------------------------------------------------------

/** A minimal script number of up to 4 bytes, read without CScriptNum. */
bool RefNumber(const std::vector<unsigned char>& v, int64_t& out)
{
    if (v.size() > 4) return false;
    if (!v.empty() && (v.back() & 0x7f) == 0 && (v.size() == 1 || (v[v.size() - 2] & 0x80) == 0)) return false;
    uint64_t magnitude = 0;
    for (size_t i = 0; i < v.size(); ++i)
        magnitude |= static_cast<uint64_t>(v[i]) << (8 * i);
    bool negative = false;
    if (!v.empty() && (v.back() & 0x80)) {
        negative = true;
        magnitude &= ~(uint64_t{0x80} << (8 * (v.size() - 1)));
    }
    out = negative ? -static_cast<int64_t>(magnitude) : static_cast<int64_t>(magnitude);
    return true;
}

/** The decoder of NIP-054 v5 §3.4 and v7 §3.3, written again. */
ScriptError RefDecode(const Stack& s, AssetAuthCall& call, size_t& consumed)
{
    if (s.empty()) return SCRIPT_ERR_INVALID_STACK_OPERATION;
    int64_t n = 0;
    if (!RefNumber(s.back(), n) || n < 0) return SCRIPT_ERR_ASSETAUTH_ARGS;
    if (static_cast<uint64_t>(n) + 8 > s.size()) return SCRIPT_ERR_INVALID_STACK_OPERATION;
    const size_t base = s.size() - 1 - static_cast<size_t>(n);
    int64_t v[8] = {};
    for (int i = 0; i < 7; ++i)
        if (!RefNumber(s[base - 1 - i], v[i])) return SCRIPT_ERR_ASSETAUTH_ARGS;
    const int64_t G = v[0], M = v[1], version = v[2];
    size_t fixed = 8;
    if (version == 2) {
        if (static_cast<uint64_t>(n) + 9 > s.size()) return SCRIPT_ERR_INVALID_STACK_OPERATION;
        if (!RefNumber(s[base - 8], v[7])) return SCRIPT_ERR_ASSETAUTH_ARGS;
        call.T = v[3];
        call.r = v[4];
        call.b = v[5];
        call.a = v[6];
        call.c = v[7];
        fixed = 9;
    } else {
        call.T = v[3];
        call.r = 0;
        call.b = v[4];
        call.a = v[5];
        call.c = v[6];
    }
    if ((version != 1 && version != 2) || n < 1 || n > 16 || M < 1 || M > G || G > n)
        return SCRIPT_ERR_ASSETAUTH_POLICY;
    call.roles.clear();
    for (size_t i = base; i + 1 < s.size(); ++i) {
        std::string name(s[i].begin(), s[i].end());
        if (!call.roles.empty() && !(call.roles.back() < name)) return SCRIPT_ERR_ASSETAUTH_POLICY;
        call.roles.push_back(name);
    }
    if (call.c < 0 || call.a < 0 || call.b < 0 || call.r < 0 || call.T < 0) return SCRIPT_ERR_ASSETAUTH_ARGS;
    call.version = static_cast<int>(version);
    call.M = static_cast<int>(M);
    call.G = static_cast<int>(G);
    consumed = static_cast<size_t>(n) + fixed;
    return SCRIPT_ERR_OK;
}

const char* const NAMES[] = {"ALICE!", "BOB!", "CARL!", "DAVE!", "EVE!", "ALICE", "dave!"};

void FuzzDecode(Reader& in)
{
    Stack stack;
    if (in.Bool()) {
        // A well-formed call of either version, then a few mutations.
        const bool v2 = in.Bool();
        std::vector<int64_t> head{in.Pick(4), in.Pick(4), in.Pick(4)};
        if (v2) head.push_back(in.Pick(4));
        head.push_back(HEIGHT);
        head.push_back(v2 ? 2 : 1);
        std::set<std::string> roleSet;
        for (unsigned i = in.Pick(5) + 1; i > 0; --i)
            roleSet.insert(NAMES[in.Pick(7)]);
        const int64_t n = roleSet.size();
        const int64_t M = 1 + in.Pick(n), G = M + in.Pick(n - M + 1);
        head.push_back(M);
        head.push_back(G);
        for (int64_t v : head)
            stack.push_back(CScriptNum(v).getvch());
        for (const std::string& role : roleSet)
            stack.emplace_back(role.begin(), role.end());
        stack.push_back(CScriptNum(n).getvch());
        for (unsigned i = in.Pick(4); i > 0 && !stack.empty(); --i) {
            const size_t k = in.Pick(stack.size());
            switch (in.Pick(4)) {
            case 0: stack.erase(stack.begin() + k); break;
            case 1: stack[k] = CScriptNum(static_cast<int64_t>(in.Pick(40)) - 4).getvch(); break;
            case 2: stack.insert(stack.begin() + k, CScriptNum(static_cast<int64_t>(in.Pick(4))).getvch()); break;
            default: stack[k].push_back(in.Byte()); break;
            }
        }
    } else {
        for (unsigned i = in.Pick(32); i > 0; --i) {
            std::vector<unsigned char> item(in.Pick(7));
            for (unsigned char& byte : item)
                byte = in.Byte();
            stack.push_back(item);
        }
    }

    AssetAuthCall got, want;
    size_t gotConsumed = 0, wantConsumed = 0;
    ScriptError gotErr = SCRIPT_ERR_OK;
    if (DecodeAssetAuthCall(stack, got, gotConsumed, &gotErr)) gotErr = SCRIPT_ERR_OK;
    const ScriptError wantErr = RefDecode(stack, want, wantConsumed);
    if (gotErr != wantErr) Fail("decode error", gotErr, wantErr);
    if (gotErr != SCRIPT_ERR_OK) return;
    if (gotConsumed != wantConsumed) Fail("decode consumed", gotConsumed, wantConsumed);
    if (got.version != want.version) Fail("decode version", got.version, want.version);
    if (got.M != want.M || got.G != want.G) Fail("decode M/G", got.M * 100 + got.G, want.M * 100 + want.G);
    if (got.c != want.c || got.a != want.a || got.b != want.b || got.r != want.r || got.T != want.T)
        Fail("decode arguments", got.c, want.c);
    if (got.roles != want.roles) Fail("decode roles", got.roles.size(), want.roles.size());
}

// ---------------------------------------------------------------------------
// Mode 2: evaluation against an abstract model
// ---------------------------------------------------------------------------

enum Dest { D_CUSTODY, D_CUSTODY_B, D_P2PKH, D_P2PKH_B, D_STRICT_V2, D_STRICT_V3, D_LOCK, D_COUNT };
enum Kind { K_XNA, K_OWNER, K_ROOT, K_ISSUANCE, K_OPRETURN };
enum Msg { M_NONE, M_H, M_H2, M_OTHER, M_IPFS, M_COUNT };
enum Sig { S_ALL, S_NONE, S_SINGLE, S_ALL_ACP, S_BAD, S_COUNT };

/** What the harness knows about one prevout, output or referenced output. */
struct Item {
    Dest dest{D_P2PKH};
    Kind kind{K_XNA};
    std::string name;     //!< asset name as the script carries it
    bool ownerName{false}; //!< a valid owner name
    CAmount amount{0};    //!< asset amount
    Msg msg{M_NONE};      //!< transfer message
    Sig sig{S_ALL};       //!< inputs: signature hash type
    CAmount value{0};     //!< XNA value

    bool Asset() const { return kind == K_OWNER || kind == K_ROOT || kind == K_ISSUANCE; }
    bool Transfer() const { return kind == K_OWNER || kind == K_ROOT; }
};

bool DirectFamily(Dest d) { return d == D_P2PKH || d == D_P2PKH_B || d == D_STRICT_V2 || d == D_STRICT_V3; }

CScript Program(opcodetype version, unsigned char fill)
{
    std::vector<unsigned char> bytes{static_cast<unsigned char>(version), 0x20};
    bytes.insert(bytes.end(), 32, fill);
    return CScript(bytes.begin(), bytes.end());
}

CScript P2PKH(unsigned char fill)
{
    return CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, fill) << OP_EQUALVERIFY << OP_CHECKSIG;
}

CScript DestScript(Dest d, const CScript& custody)
{
    switch (d) {
    case D_CUSTODY: return custody;
    case D_CUSTODY_B: return Program(OP_1, 0xc2);
    case D_P2PKH: return P2PKH(0xa0);
    case D_P2PKH_B: return P2PKH(0xa1);
    case D_STRICT_V2: return Program(OP_2, 0xb0);
    case D_STRICT_V3: return Program(OP_3, 0xb1);
    default: return Program(OP_1, 0xd0);
    }
}

std::string MessageBytes(Msg m, const uint256& h, const uint256& h2)
{
    switch (m) {
    case M_H: return std::string(h.begin(), h.end());
    case M_H2: return std::string(h2.begin(), h2.end());
    case M_OTHER: return std::string(32, '\x11');
    case M_IPFS: return std::string("\x12\x20", 2) + std::string(32, '\x22');
    default: return "";
    }
}

CTxOut Build(const Item& it, const CScript& custody, const uint256& h, const uint256& h2)
{
    CTxOut out(it.value, DestScript(it.dest, custody));
    if (it.kind == K_OPRETURN) {
        out.scriptPubKey = CScript() << OP_RETURN << std::vector<unsigned char>{0x01};
    } else if (it.Transfer()) {
        CAssetTransfer transfer(it.name, it.amount, MessageBytes(it.msg, h, h2));
        transfer.ConstructTransaction(out.scriptPubKey, AssetMarker::NEURAI_XNA);
    } else if (it.kind == K_ISSUANCE) {
        CNewAsset asset(it.name.substr(0, it.name.size() - 1), 0);
        asset.ConstructOwnerTransaction(out.scriptPubKey, AssetMarker::NEURAI_XNA);
    }
    return out;
}

Item RandomItem(Reader& in, bool output)
{
    Item it;
    it.dest = static_cast<Dest>(in.Pick(D_COUNT));
    const unsigned kind = in.Pick(output ? 5 : 4);
    if (kind == 1) {
        const unsigned k = in.Pick(7);
        it.kind = K_OWNER;
        it.name = NAMES[k];
        it.ownerName = k < 5;
        it.amount = in.Pick(8) == 0 ? 2 * COIN : OWNER_ASSET_AMOUNT;
    } else if (kind == 2) {
        it.kind = K_ROOT;
        it.name = in.Bool() ? "GOLD" : "SILVER";
        it.amount = (1 + in.Pick(3)) * COIN;
    } else if (kind == 3) {
        it.kind = K_ISSUANCE;
        it.name = in.Bool() ? "GOLD!" : "ALICE!";
        it.ownerName = true;
        it.amount = OWNER_ASSET_AMOUNT;
    } else if (kind == 4) {
        it.kind = K_OPRETURN;
    } else {
        it.kind = K_XNA;
        it.value = static_cast<CAmount>(in.Pick(8)) * CENT;
    }
    if (it.Transfer() && !output)
        it.msg = static_cast<Msg>(in.Pick(M_COUNT));
    it.sig = static_cast<Sig>(in.Pick(S_COUNT));
    return it;
}

uint64_t NameWork(const std::string& name) { return (name.size() + 31) / 32; }

size_t CompactSize(uint64_t n) { return n < 253 ? 1 : n <= 0xffff ? 3 : n <= 0xffffffffu ? 5 : 9; }

size_t SerializedOutput(const CTxOut& out)
{
    return 8 + CompactSize(out.scriptPubKey.size()) + out.scriptPubKey.size();
}

struct Case {
    AssetAuthCall call;
    std::vector<Item> inputs, outputs, refs;
    unsigned nIn{0};
    bool dropRefs{false};
    int32_t txVersion{2};
};

struct Verdict {
    ScriptError err{SCRIPT_ERR_OK};
    bool async{false};
    uint64_t work{0}; //!< W, when the call gets as far as charging it
};

/** The rules of NIP-054 v5 (version 1) and v7 (version 2), on the abstract case. */
Verdict Model(const Case& k, const CTransaction& tx)
{
    Verdict v;
    const AssetAuthCall& call = k.call;
    const bool v2 = call.version == 2;
    const size_t nIn = k.inputs.size(), nOut = k.outputs.size(), nRefs = k.refs.size();
    if (v2 && nRefs > 0 && k.dropRefs) { v.err = SCRIPT_ERR_ASSETAUTH_CONTEXT; return v; }
    if (static_cast<uint64_t>(call.c) > nIn || static_cast<uint64_t>(call.a + call.b) > nOut ||
        static_cast<uint64_t>(call.r) > (v2 ? nRefs : 0)) {
        v.err = SCRIPT_ERR_ASSETAUTH_ARGS;
        return v;
    }

    // W = 1 + inputs + outputs + references (v2) + ceil(|m| / 64) + names.
    const size_t R = v2 ? call.r : (k.txVersion == 3 ? nRefs : 0);
    size_t m = 1 + 4 + 4 + 4 + CompactSize(call.c) + CompactSize(call.a) + CompactSize(call.b) + 40 * call.c;
    for (int64_t j = 0; j < call.a; ++j) m += SerializedOutput(tx.vout[j]);
    for (size_t j = nOut - call.b; j < nOut; ++j) m += SerializedOutput(tx.vout[j]);
    m += CompactSize(R) + 36 * R;
    uint64_t names = 0;
    for (const std::string& role : call.roles) names += NameWork(role);
    for (const Item& it : k.inputs) if (it.Asset()) names += NameWork(it.name);
    for (const Item& it : k.outputs) if (it.Asset()) names += NameWork(it.name);
    if (v2) for (const Item& it : k.refs) if (it.Asset()) names += NameWork(it.name);
    v.work = 1 + nIn + nOut + (v2 ? nRefs : 0) + (m + 63) / 64 + names;

    std::set<std::string> roles(call.roles.begin(), call.roles.end());
    for (const std::string& role : call.roles)
        if (role != "ALICE!" && role != "BOB!" && role != "CARL!" && role != "DAVE!" && role != "EVE!") {
            v.err = SCRIPT_ERR_ASSETAUTH_POLICY;
            return v;
        }

    const Msg own = v2 ? M_H2 : M_H; // the message that is a vote for this call
    auto refVote = [&](const Item& it) {
        return it.Transfer() && it.amount == OWNER_ASSET_AMOUNT && DirectFamily(it.dest) && it.msg == own;
    };

    // Classification (§3.6). The result depends on the height only once the
    // classification ends with a vote counted.
    std::set<std::string> approved;
    bool async = false;
    for (const Item& it : k.inputs) {
        if (!it.Asset() || !roles.count(it.name)) continue;
        if (DirectFamily(it.dest)) {
            if (it.sig != S_ALL) { v.err = SCRIPT_ERR_ASSETAUTH_SIGHASH; return v; }
            approved.insert(it.name);
            continue;
        }
        if (v2 || !it.Transfer() || it.msg == M_NONE) continue;
        if (it.msg == M_H) {
            approved.insert(it.name);
            async = true;
        } else {
            v.err = SCRIPT_ERR_ASSETAUTH_FOREIGN_VOTE;
            return v;
        }
    }
    if (v2) {
        for (size_t j = call.r; j < nRefs; ++j) {
            const Item& it = k.refs[j];
            if (it.Asset() && roles.count(it.name) && refVote(it)) {
                approved.insert(it.name);
                async = true;
            }
        }
    }

    const Dest ownDest = k.inputs[k.nIn].dest;
    v.async = async;
    if (async) {
        if (HEIGHT > call.T) { v.err = SCRIPT_ERR_ASSETAUTH_EXPIRED; return v; }
        if (static_cast<int64_t>(k.nIn) >= call.c) { v.err = SCRIPT_ERR_ASSETAUTH_SHAPE; return v; }
        CAmount feeIn = 0;
        std::set<std::string> approvalOwners;
        for (size_t i = call.c; i < nIn; ++i) {
            const Item& it = k.inputs[i];
            if (it.dest == ownDest) { v.err = SCRIPT_ERR_ASSETAUTH_SHAPE; return v; }
            if (!it.Asset()) { feeIn += it.value; continue; }
            if (it.amount != OWNER_ASSET_AMOUNT || (!roles.count(it.name) && !it.ownerName)) {
                v.err = SCRIPT_ERR_ASSETAUTH_SHAPE;
                return v;
            }
            if (DirectFamily(it.dest)) {
                if (it.sig != S_ALL) { v.err = SCRIPT_ERR_ASSETAUTH_SIGHASH; return v; }
            } else if (v2 || !it.Transfer() || it.msg != M_H) {
                v.err = SCRIPT_ERR_ASSETAUTH_SHAPE;
                return v;
            }
            approvalOwners.insert(it.name);
        }
        CAmount changeOut = 0;
        for (size_t j = call.a; j < nOut - call.b; ++j) {
            const Item& it = k.outputs[j];
            if (it.Asset()) {
                if (!it.Transfer() || !approvalOwners.count(it.name) || it.amount != OWNER_ASSET_AMOUNT || it.value != 0) {
                    v.err = SCRIPT_ERR_ASSETAUTH_SHAPE;
                    return v;
                }
                continue;
            }
            if (it.kind == K_OPRETURN) { v.err = SCRIPT_ERR_ASSETAUTH_SHAPE; return v; }
            changeOut += it.value;
        }
        if (changeOut > feeIn) { v.err = SCRIPT_ERR_ASSETAUTH_SHAPE; return v; }
        if (v2) {
            for (size_t j = call.r; j < nRefs; ++j) {
                const Item& it = k.refs[j];
                if (!it.Asset() || !refVote(it) || (!roles.count(it.name) && !it.ownerName)) {
                    v.err = SCRIPT_ERR_ASSETAUTH_SHAPE;
                    return v;
                }
            }
        }
    }

    // Threshold (§3.11): G when an owner held at the evaluated destination leaves it.
    int threshold = call.M;
    std::set<std::string> held;
    for (const Item& it : k.inputs)
        if (it.Asset() && it.dest == ownDest) held.insert(it.name);
    for (const Item& it : k.outputs)
        if (it.Asset() && it.dest != ownDest && held.count(it.name) && it.ownerName) threshold = call.G;
    if (approved.size() < static_cast<size_t>(threshold)) v.err = SCRIPT_ERR_ASSETAUTH_THRESHOLD;
    return v;
}

struct Built {
    CMutableTransaction mtx;
    std::vector<CTxOut> prevouts, refOutputs;
};

uint256 HashOf(const CTransaction& tx, AssetAuthCall call, int version, size_t nRefs)
{
    call.version = version;
    if (version == 1) call.r = 0;
    if (static_cast<uint64_t>(call.c) > tx.vin.size() || static_cast<uint64_t>(call.a + call.b) > tx.vout.size() ||
        static_cast<uint64_t>(call.r) > nRefs)
        return uint256();
    return AssetAuthProposalHash(AssetAuthProposalMessage(tx, CHAIN_ID, call), version);
}

Built BuildCase(const Case& k, const CScript& custody, std::vector<COutPoint> refOrder = {})
{
    Built b;
    b.mtx.nVersion = k.txVersion;
    for (size_t i = 0; i < k.inputs.size(); ++i) {
        CTxIn in(COutPoint(uint256S(strprintf("%064x", 0x1000 + i)), 0));
        const Item& it = k.inputs[i];
        if (it.dest == D_P2PKH || it.dest == D_P2PKH_B) {
            static const unsigned char types[] = {SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ALL | SIGHASH_ANYONECANPAY, SIGHASH_ALL};
            std::vector<unsigned char> sig(71, 0x30);
            sig.back() = types[it.sig];
            in.scriptSig = CScript() << sig << std::vector<unsigned char>(33, 0x02);
            if (it.sig == S_BAD) in.scriptSig << OP_1;
        } else if (it.dest == D_STRICT_V2 || it.dest == D_STRICT_V3) {
            static const unsigned char types[] = {SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ALL | SIGHASH_ANYONECANPAY, SIGHASH_ALL};
            std::vector<unsigned char> sig(71, 0x30);
            sig.back() = types[it.sig];
            in.scriptWitness.stack = {{0x02}, sig, std::vector<unsigned char>(33, 0x02), {OP_TRUE}};
            if (it.sig == S_BAD) in.scriptWitness.stack.pop_back();
        }
        b.mtx.vin.push_back(in);
    }
    for (const Item& it : k.outputs)
        b.mtx.vout.push_back(Build(it, custody, uint256(), uint256()));
    for (size_t j = 0; j < k.refs.size(); ++j)
        b.mtx.vrefin.emplace_back(uint256S(strprintf("%064x", 0x2000 + j)), 0);
    if (!refOrder.empty()) b.mtx.vrefin = refOrder;
    // The hashes commit the proposal only: prevouts and referenced outputs
    // can carry them.
    const CTransaction draft(b.mtx);
    const uint256 h = HashOf(draft, k.call, 1, k.refs.size());
    const uint256 h2 = HashOf(draft, k.call, 2, k.refs.size());
    for (const Item& it : k.inputs) b.prevouts.push_back(Build(it, custody, h, h2));
    for (const Item& it : k.refs) b.refOutputs.push_back(Build(it, custody, h, h2));
    return b;
}

std::vector<unsigned char> Num(int64_t v) { return CScriptNum(v).getvch(); }

void FuzzEvaluate(Reader& in)
{
    Case k;
    k.call.version = in.Bool() ? 2 : 1;
    std::set<std::string> roleSet;
    for (unsigned i = in.Pick(4) + 1; i > 0; --i)
        roleSet.insert(NAMES[in.Pick(5)]);
    if (in.Pick(16) == 0) roleSet.insert("ALICE"); // not an owner name
    k.call.roles.assign(roleSet.begin(), roleSet.end());
    const int n = k.call.roles.size();
    k.call.M = 1 + in.Pick(n);
    k.call.G = k.call.M + in.Pick(n - k.call.M + 1);

    CScript script;
    script << k.call.version << k.call.M << k.call.G;
    for (const std::string& role : k.call.roles)
        script << std::vector<unsigned char>(role.begin(), role.end());
    script << n << OP_CHECKASSETAUTH;
    const CScript custody = CScript() << OP_1 << ToByteVector(GetAuthScriptCommitment(0, nullptr, script));

    for (unsigned i = in.Pick(6) + 1; i > 0; --i) k.inputs.push_back(RandomItem(in, false));
    for (unsigned i = in.Pick(7); i > 0; --i) k.outputs.push_back(RandomItem(in, true));
    for (unsigned i = in.Pick(7); i > 0; --i) k.refs.push_back(RandomItem(in, false));
    k.nIn = in.Pick(k.inputs.size());
    if (in.Pick(4) != 0) { // usually the custody holds the evaluated input
        k.inputs[k.nIn].dest = D_CUSTODY;
        k.inputs[k.nIn].kind = K_XNA;
        k.inputs[k.nIn].name.clear();
        k.inputs[k.nIn].value = COIN;
    }
    k.txVersion = !k.refs.empty() || in.Bool() ? 3 : 2;
    k.call.c = in.Pick(k.inputs.size() + 2);
    k.call.a = in.Pick(k.outputs.size() + 2);
    k.call.b = in.Pick(k.outputs.size() + 2);
    k.call.r = k.call.version == 2 ? in.Pick(k.refs.size() + 2) : 0;
    k.call.T = HEIGHT - 1 + in.Pick(3);
    k.dropRefs = in.Pick(16) == 0;

    const Built b = BuildCase(k, custody);
    const CTransaction tx(b.mtx);
    const Verdict want = Model(k, tx);
    const ChainContext context{HEIGHT, 0, CHAIN_ID, true};
    const std::vector<CTxOut>* refs = k.dropRefs ? nullptr : &b.refOutputs;

    auto eval = [&](AssetAuthWorkBudget* budget, bool& used) {
        ScriptError err = SCRIPT_ERR_OK;
        if (EvaluateAssetAuth(k.call, tx, k.nIn, b.prevouts, context, EVAL_FLAGS, budget, used, &err, refs))
            err = SCRIPT_ERR_OK;
        return err;
    };
    bool used = false;
    const ScriptError got = eval(nullptr, used);
    if (got != want.err) Fail("verdict", got, want.err);
    if (used != want.async) Fail("asynchronous mode", used, want.async);

    // The budget: W passes with W charged, W - 1 fails before any rule.
    const bool charged = want.err != SCRIPT_ERR_ASSETAUTH_CONTEXT && want.err != SCRIPT_ERR_ASSETAUTH_ARGS;
    if (charged) {
        AssetAuthWorkBudget exact(want.work);
        if (eval(&exact, used) != want.err) Fail("verdict with budget W", eval(&exact, used), want.err);
        if (exact.Used() != want.work) Fail("work W", exact.Used(), want.work);
        AssetAuthWorkBudget shortBudget(want.work - 1);
        if (eval(&shortBudget, used) != SCRIPT_ERR_ASSETAUTH_BUDGET) Fail("budget W - 1", got, SCRIPT_ERR_ASSETAUTH_BUDGET);
    } else {
        AssetAuthWorkBudget unused(1);
        eval(&unused, used);
        if (unused.Used() != 0) Fail("charged before the arguments", unused.Used(), 0);
    }

    // Through VerifyScript, as the witness of a real custody input.
    if (k.inputs[k.nIn].dest == D_CUSTODY) {
        CMutableTransaction mtx = b.mtx;
        Stack& witness = mtx.vin[k.nIn].scriptWitness.stack;
        witness = {{0x00}, Num(k.call.c), Num(k.call.a), Num(k.call.b)};
        if (k.call.version == 2) witness.push_back(Num(k.call.r));
        witness.push_back(Num(k.call.T));
        witness.emplace_back(script.begin(), script.end());
        mtx.vin[k.nIn].scriptSig = CScript();
        const CTransaction spend(mtx);
        const PrecomputedTransactionData txdata(spend);
        TransactionSignatureChecker checker(&spend, k.nIn, b.prevouts[k.nIn].nValue, txdata, custody, &b.prevouts,
                                            refs, context);
        ScriptError err = SCRIPT_ERR_OK;
        const bool ok = VerifyScript(spend.vin[k.nIn].scriptSig, custody, &spend.vin[k.nIn].scriptWitness,
                                     SCRIPT_FLAGS, checker, &err);
        if (ok != (want.err == SCRIPT_ERR_OK) || (!ok && err != want.err)) Fail("VerifyScript", err, want.err);
    }

    // Version 2: the vote references can come in any order.
    if (k.call.version == 2 && !k.dropRefs && k.refs.size() > static_cast<size_t>(k.call.r) + 1 &&
        want.err != SCRIPT_ERR_ASSETAUTH_ARGS) {
        Case shuffled = k;
        std::vector<size_t> order(k.refs.size());
        for (size_t j = 0; j < order.size(); ++j) order[j] = j;
        for (size_t j = order.size() - 1; j > static_cast<size_t>(k.call.r); --j)
            std::swap(order[j], order[k.call.r + in.Pick(j - k.call.r + 1)]);
        std::vector<COutPoint> outpoints;
        for (size_t j = 0; j < order.size(); ++j) {
            shuffled.refs[j] = k.refs[order[j]];
            outpoints.push_back(b.mtx.vrefin[order[j]]);
        }
        const Built s = BuildCase(shuffled, custody, outpoints);
        const CTransaction stx(s.mtx);
        ScriptError err = SCRIPT_ERR_OK;
        bool sused = false;
        if (EvaluateAssetAuth(k.call, stx, k.nIn, s.prevouts, context, EVAL_FLAGS, nullptr, sused, &err, &s.refOutputs))
            err = SCRIPT_ERR_OK;
        if (err != got) Fail("reordered votes", err, got);
    }
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    SelectParams(CBaseChainParams::MAIN);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    Reader in(data, size);
    if (in.Byte() & 1)
        FuzzEvaluate(in);
    else
        FuzzDecode(in);
    return 0;
}
