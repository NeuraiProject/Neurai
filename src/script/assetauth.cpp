// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/assetauth.h"

#include "assets/assets.h"
#include "assets/assettypes.h"
#include "hash.h"
#include "script/script.h"
#include "script/standard.h"
#include "serialize.h"
#include "streams.h"
#include "version.h"

#include <cstring>
#include <limits>
#include <set>

namespace {

bool set_error(ScriptError* serror, ScriptError error)
{
    if (serror) *serror = error;
    return false;
}

/** Minimally encoded script number of up to 4 bytes. */
bool ParseSmallNumber(const std::vector<unsigned char>& item, int64_t& value)
{
    try {
        value = CScriptNum(item, /*fRequireMinimal=*/true, /*nMaxNumSize=*/4).getint64();
        return true;
    } catch (const scriptnum_error&) {
        return false;
    }
}

/** Asset name and amount carried by a scriptPubKey, if any. */
bool GetScriptAsset(const CScript& scriptPubKey, std::string& name, CAmount& amount)
{
    if (!scriptPubKey.IsAssetScript())
        return false;
    std::string strAddress;

    CAssetTransfer transfer;
    if (TransferAssetFromScript(scriptPubKey, transfer, strAddress)) {
        name = transfer.strName;
        amount = transfer.nAmount;
        return true;
    }
    CNewAsset newAsset;
    if (AssetFromScript(scriptPubKey, newAsset, strAddress) ||
        MsgChannelAssetFromScript(scriptPubKey, newAsset, strAddress) ||
        QualifierAssetFromScript(scriptPubKey, newAsset, strAddress) ||
        RestrictedAssetFromScript(scriptPubKey, newAsset, strAddress)) {
        name = newAsset.strName;
        amount = newAsset.nAmount;
        return true;
    }
    CReissueAsset reissue;
    if (ReissueAssetFromScript(scriptPubKey, reissue, strAddress)) {
        name = reissue.strName;
        amount = reissue.nAmount;
        return true;
    }
    std::string ownerName;
    if (OwnerAssetFromScript(scriptPubKey, ownerName, strAddress)) {
        name = ownerName;
        amount = OWNER_ASSET_AMOUNT;
        return true;
    }
    return false;
}

/** The asset of one scriptPubKey, read once per execution. */
struct ScriptAsset {
    bool fAsset{false};
    std::string name;
    CAmount amount{0};
};

std::vector<ScriptAsset> ReadAssets(const std::vector<CTxOut>& outs)
{
    std::vector<ScriptAsset> assets(outs.size());
    for (size_t i = 0; i < outs.size(); ++i)
        assets[i].fAsset = GetScriptAsset(outs[i].scriptPubKey, assets[i].name, assets[i].amount);
    return assets;
}

/** ceil(|name| / 32): the work of reading and validating one name. */
uint64_t NameWork(const std::string& name)
{
    return (name.size() + 31) / 32;
}

uint64_t NameWork(const AssetAuthCall& call, const std::vector<ScriptAsset>& inputs,
                  const std::vector<ScriptAsset>& outputs)
{
    uint64_t work = 0;
    for (const std::string& role : call.roles)
        work += NameWork(role);
    for (const std::vector<ScriptAsset>* assets : {&inputs, &outputs}) {
        for (const ScriptAsset& asset : *assets)
            if (asset.fAsset) work += NameWork(asset.name);
    }
    return work;
}

bool IsP2PKHDestination(const CScript& dest)
{
    return dest.size() == 25 && dest[0] == OP_DUP && dest[1] == OP_HASH160 && dest[2] == 0x14 &&
           dest[23] == OP_EQUALVERIFY && dest[24] == OP_CHECKSIG;
}

bool IsStrictDestination(const CScript& dest)
{
    return dest.size() == 34 && (dest[0] == OP_2 || dest[0] == OP_3) && dest[1] == 0x20;
}

/** P2PKH, or a strict AuthScript family once those families are enforced. */
bool IsDirectSignatureFamily(const CScript& dest, script_verify_flags flags)
{
    if (IsP2PKHDestination(dest))
        return true;
    // Before strict enforcement, OP_2/OP_3 programs carry no signature rule.
    return (flags & SCRIPT_VERIFY_AUTHSCRIPT_STRICT) && IsStrictDestination(dest);
}

/** True when the signature of input `nInput` is readable and SIGHASH_ALL. */
bool HasSighashAll(const CTransaction& tx, unsigned int nInput, const CScript& dest)
{
    const CTxIn& txin = tx.vin[nInput];
    std::vector<unsigned char> sig;
    if (IsP2PKHDestination(dest)) {
        // Exactly two pushes: <sig> <pubkey>.
        CScript::const_iterator pc = txin.scriptSig.begin();
        opcodetype opcode;
        std::vector<unsigned char> pubkey;
        if (!txin.scriptSig.GetOp(pc, opcode, sig) || opcode > OP_PUSHDATA4)
            return false;
        if (!txin.scriptSig.GetOp(pc, opcode, pubkey) || opcode > OP_PUSHDATA4)
            return false;
        if (pc != txin.scriptSig.end())
            return false;
    } else {
        // Strict template: [authType, signature, pubkey, OP_TRUE].
        const std::vector<std::vector<unsigned char>>& stack = txin.scriptWitness.stack;
        if (stack.size() != 4)
            return false;
        sig = stack[1];
    }
    return !sig.empty() && sig.back() == SIGHASH_ALL;
}

/** IsAssetNameAnOwner, without its costly validation for names that cannot
 *  be owners: every owner name ends in '!' (OWNER_INDICATOR). */
bool IsOwnerName(const std::string& name)
{
    return !name.empty() && name.back() == '!' && IsAssetNameAnOwner(name);
}

/** Vote check: a 32-byte NIP-043 transfer message equal to H. */
enum class MessageState { NONE, MATCH, OTHER };

MessageState ReadVoteMessage(const CScript& scriptPubKey, const uint256& hash)
{
    std::vector<unsigned char> message;
    if (!GetTransferMessage(scriptPubKey, message))
        return MessageState::NONE;
    if (message.size() == hash.size() && std::memcmp(message.data(), hash.begin(), hash.size()) == 0)
        return MessageState::MATCH;
    return MessageState::OTHER;
}

} // namespace

CScript AssetAuthDestination(const CScript& scriptPubKey)
{
    if (scriptPubKey.IsAssetScript()) {
        // Asset scripts are P2PKH- (25 bytes) or AuthScript-prefixed (34 bytes).
        const size_t prefix = scriptPubKey[0] == OP_DUP ? 25 : 34;
        if (scriptPubKey.size() > prefix && scriptPubKey[prefix] == OP_XNA_ASSET)
            return CScript(scriptPubKey.begin(), scriptPubKey.begin() + prefix);
    }
    return scriptPubKey;
}

bool DecodeAssetAuthCall(const std::vector<std::vector<unsigned char>>& stack, AssetAuthCall& call,
                         size_t& consumed, ScriptError* serror)
{
    if (stack.empty())
        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

    int64_t n = 0;
    if (!ParseSmallNumber(stack.back(), n) || n < 0)
        return set_error(serror, SCRIPT_ERR_ASSETAUTH_ARGS);
    if (static_cast<uint64_t>(n) + ASSETAUTH_FIXED_ITEMS > stack.size())
        return set_error(serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

    // Items below the roles, from the top: G, M, version, T, b, a, c.
    const size_t base = stack.size() - 1 - static_cast<size_t>(n);
    int64_t values[7];
    for (int i = 0; i < 7; ++i) {
        if (!ParseSmallNumber(stack[base - 1 - i], values[i]))
            return set_error(serror, SCRIPT_ERR_ASSETAUTH_ARGS);
    }
    const int64_t G = values[0], M = values[1], version = values[2];
    call.T = values[3];
    call.b = values[4];
    call.a = values[5];
    call.c = values[6];

    if (version != ASSETAUTH_POLICY_VERSION || n < 1 || n > ASSETAUTH_MAX_ROLES ||
        M < 1 || M > G || G > n)
        return set_error(serror, SCRIPT_ERR_ASSETAUTH_POLICY);
    call.version = static_cast<int>(version);
    call.M = static_cast<int>(M);
    call.G = static_cast<int>(G);

    call.roles.clear();
    call.roles.reserve(static_cast<size_t>(n));
    for (size_t i = base; i < stack.size() - 1; ++i) {
        std::string name(stack[i].begin(), stack[i].end());
        // Strictly increasing by bytes rules out duplicates. The owner check
        // waits until the name work is charged (EvaluateAssetAuth).
        if (!call.roles.empty() && !(call.roles.back() < name))
            return set_error(serror, SCRIPT_ERR_ASSETAUTH_POLICY);
        call.roles.push_back(std::move(name));
    }

    if (call.c < 0 || call.a < 0 || call.b < 0 || call.T < 0)
        return set_error(serror, SCRIPT_ERR_ASSETAUTH_ARGS);

    consumed = static_cast<size_t>(n) + ASSETAUTH_FIXED_ITEMS;
    return true;
}

std::vector<unsigned char> AssetAuthProposalMessage(const CTransaction& tx, uint8_t chainId,
                                                    const AssetAuthCall& call)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << chainId;
    ss << tx.nVersion;
    ss << tx.nLockTime;
    ss << static_cast<uint32_t>(call.T);
    WriteCompactSize(ss, static_cast<uint64_t>(call.c));
    WriteCompactSize(ss, static_cast<uint64_t>(call.a));
    WriteCompactSize(ss, static_cast<uint64_t>(call.b));
    for (int64_t i = 0; i < call.c; ++i) {
        ss << tx.vin[i].prevout;
        ss << tx.vin[i].nSequence;
    }
    for (int64_t i = 0; i < call.a; ++i)
        ss << tx.vout[i];
    for (size_t i = tx.vout.size() - static_cast<size_t>(call.b); i < tx.vout.size(); ++i)
        ss << tx.vout[i];
    const std::vector<COutPoint> noRefs;
    const std::vector<COutPoint>& refs = tx.nVersion == 3 ? tx.vrefin : noRefs;
    WriteCompactSize(ss, refs.size());
    for (const COutPoint& ref : refs)
        ss << ref;
    return std::vector<unsigned char>(ss.begin(), ss.end());
}

uint256 AssetAuthProposalHash(const std::vector<unsigned char>& message)
{
    return TaggedHash("NeuraiAssetAuthProposal", message);
}

uint64_t AssetAuthNameWork(const AssetAuthCall& call, const CTransaction& tx, const std::vector<CTxOut>& prevouts,
                           script_verify_flags flags)
{
    CStrictAuthScriptContext strictAuthScriptContext((flags & SCRIPT_VERIFY_AUTHSCRIPT_STRICT) != 0);
    return NameWork(call, ReadAssets(prevouts), ReadAssets(tx.vout));
}

uint64_t AssetAuthWork(const CTransaction& tx, size_t messageSize, uint64_t nameWork)
{
    return 1 + tx.vin.size() + tx.vout.size() + (messageSize + 63) / 64 + nameWork;
}

bool EvaluateAssetAuth(const AssetAuthCall& call, const CTransaction& tx, unsigned int nIn,
                       const std::vector<CTxOut>& prevouts, const ChainContext& context,
                       script_verify_flags flags, AssetAuthWorkBudget* budget,
                       bool& fUsedHeight, ScriptError* serror)
{
    fUsedHeight = false;
    if (!context.available || prevouts.size() != tx.vin.size() || nIn >= tx.vin.size())
        return set_error(serror, SCRIPT_ERR_ASSETAUTH_CONTEXT);

    // Asset scripts behind OP_2/OP_3 only parse once the strict families are
    // enforced; tie that to the flags of this verification, not to ambient state.
    CStrictAuthScriptContext strictAuthScriptContext((flags & SCRIPT_VERIFY_AUTHSCRIPT_STRICT) != 0);

    const size_t nInputs = tx.vin.size();
    const size_t nOutputs = tx.vout.size();
    if (static_cast<uint64_t>(call.c) > nInputs ||
        static_cast<uint64_t>(call.a) + static_cast<uint64_t>(call.b) > nOutputs)
        return set_error(serror, SCRIPT_ERR_ASSETAUTH_ARGS);

    // Charge before checking any name and before hashing (§3.13). The assets
    // are read once and reused by every rule below.
    const std::vector<ScriptAsset> inAssets = ReadAssets(prevouts);
    const std::vector<ScriptAsset> outAssets = ReadAssets(tx.vout);
    const std::vector<unsigned char> message = AssetAuthProposalMessage(tx, context.chainId, call);
    if (budget && !budget->Charge(AssetAuthWork(tx, message.size(), NameWork(call, inAssets, outAssets))))
        return set_error(serror, SCRIPT_ERR_ASSETAUTH_BUDGET);

    // Roles are owner names (§3.5).
    for (const std::string& role : call.roles) {
        if (!IsOwnerName(role))
            return set_error(serror, SCRIPT_ERR_ASSETAUTH_POLICY);
    }
    const uint256 hash = AssetAuthProposalHash(message);

    const std::set<std::string> roleSet(call.roles.begin(), call.roles.end());
    const CScript ownDest = AssetAuthDestination(prevouts[nIn].scriptPubKey);

    // Classification of every input (§3.6).
    std::set<std::string> approved;
    bool fAsync = false;
    for (size_t k = 0; k < nInputs; ++k) {
        const CScript& spk = prevouts[k].scriptPubKey;
        const std::string& name = inAssets[k].name;
        if (!inAssets[k].fAsset || !roleSet.count(name))
            continue;
        const CScript dest = AssetAuthDestination(spk);
        if (IsDirectSignatureFamily(dest, flags)) {
            if (!HasSighashAll(tx, k, dest))
                return set_error(serror, SCRIPT_ERR_ASSETAUTH_SIGHASH);
            approved.insert(name);
            continue;
        }
        switch (ReadVoteMessage(spk, hash)) {
        case MessageState::MATCH:
            approved.insert(name);
            fAsync = true;
            break;
        case MessageState::OTHER:
            return set_error(serror, SCRIPT_ERR_ASSETAUTH_FOREIGN_VOTE);
        case MessageState::NONE:
            break;
        }
    }

    if (fAsync) {
        // Expiry (§3.9).
        fUsedHeight = true;
        if (context.height > call.T)
            return set_error(serror, SCRIPT_ERR_ASSETAUTH_EXPIRED);

        // Fixed shape (§3.10). Rule 1: the evaluated input is a proposal input.
        if (static_cast<int64_t>(nIn) >= call.c)
            return set_error(serror, SCRIPT_ERR_ASSETAUTH_SHAPE);

        // Rules 2 and 3: inputs c.. are approval entries or carry no asset.
        CAmount feeIn = 0;
        std::set<std::string> approvalOwners;
        for (size_t k = static_cast<size_t>(call.c); k < nInputs; ++k) {
            const CScript& spk = prevouts[k].scriptPubKey;
            const CScript dest = AssetAuthDestination(spk);
            if (dest == ownDest)
                return set_error(serror, SCRIPT_ERR_ASSETAUTH_SHAPE);
            const std::string& name = inAssets[k].name;
            const CAmount amount = inAssets[k].amount;
            if (!inAssets[k].fAsset) {
                feeIn += prevouts[k].nValue;
                if (!MoneyRange(prevouts[k].nValue) || !MoneyRange(feeIn))
                    return set_error(serror, SCRIPT_ERR_ASSETAUTH_SHAPE);
                continue;
            }
            // Roles were checked as owners when decoding; the name check is
            // the costly part, so it only runs for owners of other lists.
            if (amount != OWNER_ASSET_AMOUNT || (!roleSet.count(name) && !IsOwnerName(name)))
                return set_error(serror, SCRIPT_ERR_ASSETAUTH_SHAPE);
            if (IsDirectSignatureFamily(dest, flags)) {
                if (!HasSighashAll(tx, k, dest))
                    return set_error(serror, SCRIPT_ERR_ASSETAUTH_SIGHASH);
            } else if (ReadVoteMessage(spk, hash) != MessageState::MATCH) {
                return set_error(serror, SCRIPT_ERR_ASSETAUTH_SHAPE);
            }
            approvalOwners.insert(name);
        }

        // Rule 4: intermediate outputs are returns or change.
        CAmount changeOut = 0;
        const size_t suffixStart = nOutputs - static_cast<size_t>(call.b);
        for (size_t j = static_cast<size_t>(call.a); j < suffixStart; ++j) {
            const CTxOut& out = tx.vout[j];
            const CScript& spk = out.scriptPubKey;
            int type = 0;
            bool fIsOwner = false;
            if (spk.IsAssetScript(type, fIsOwner)) {
                CAssetTransfer transfer;
                std::string strAddress;
                // approvalOwners only holds owners (rule 3), so membership
                // already implies the owner check.
                if (type != TX_TRANSFER_ASSET || !TransferAssetFromScript(spk, transfer, strAddress) ||
                    !approvalOwners.count(transfer.strName) || transfer.nAmount != OWNER_ASSET_AMOUNT ||
                    out.nValue != 0)
                    return set_error(serror, SCRIPT_ERR_ASSETAUTH_SHAPE);
                continue;
            }
            if (spk.IsNullAsset() || (!spk.empty() && spk[0] == OP_RETURN))
                return set_error(serror, SCRIPT_ERR_ASSETAUTH_SHAPE);
            changeOut += out.nValue;
            if (!MoneyRange(out.nValue) || !MoneyRange(changeOut))
                return set_error(serror, SCRIPT_ERR_ASSETAUTH_SHAPE);
        }

        // Rule 5: change never exceeds what the fee inputs bring.
        if (changeOut > feeIn)
            return set_error(serror, SCRIPT_ERR_ASSETAUTH_SHAPE);
    }

    // Threshold (§3.11): G when an owner kept at this destination leaves it.
    // One pass over inputs and one over outputs keeps the cost linear, as W
    // charges it. The owner check, the costly part, runs once per name that
    // actually leaves.
    int threshold = call.M;
    if (call.G != call.M) {
        std::set<std::string> ownAssets;
        for (size_t k = 0; k < nInputs; ++k) {
            if (inAssets[k].fAsset && AssetAuthDestination(prevouts[k].scriptPubKey) == ownDest)
                ownAssets.insert(inAssets[k].name);
        }
        for (size_t j = 0; j < nOutputs && !ownAssets.empty(); ++j) {
            if (!outAssets[j].fAsset || AssetAuthDestination(tx.vout[j].scriptPubKey) == ownDest)
                continue;
            const std::string& name = outAssets[j].name;
            const auto held = ownAssets.find(name);
            if (held == ownAssets.end())
                continue;
            if (IsOwnerName(name)) {
                threshold = call.G;
                break;
            }
            ownAssets.erase(held);
        }
    }
    if (approved.size() < static_cast<size_t>(threshold))
        return set_error(serror, SCRIPT_ERR_ASSETAUTH_THRESHOLD);

    return true;
}
