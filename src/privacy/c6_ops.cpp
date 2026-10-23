// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "privacy/c6_ops.h"

#include "crypto/groth16_bn254.h"
#include "privacy/c7.h"
#include "privacy/publication.h"
#include "script/script.h"
#include "streams.h"
#include "version.h"

#include <algorithm>
#include <map>
#include <set>

namespace privacy {
namespace {

const char* const EMPTY_W_DATA = "04bf938a28af8bc7ab2810e0adf3cbbb55aa4feb79827feed2722c5123baac15";
constexpr size_t TREE_CHUNK = 3072;

FieldLE LE(const Bytes32& be)
{
    FieldLE out;
    std::reverse_copy(be.begin(), be.end(), out.begin());
    return out;
}

FieldLE LE(uint64_t value) { return LE(FieldFromU64(value)); }

std::vector<FieldLE> ByteArray(const uint8_t* data, size_t size)
{
    std::vector<FieldLE> out(size, FieldLE{});
    for (size_t i = 0; i < size; ++i) out[i][0] = data[i];
    return out;
}

template <typename T>
std::vector<FieldLE> ByteArray(const T& data) { return ByteArray(data.data(), data.size()); }

void Input(std::vector<CircuitInput>& inputs, const std::string& name, std::vector<FieldLE> values)
{
    inputs.emplace_back(name, std::move(values));
}

void Input(std::vector<CircuitInput>& inputs, const std::string& name, const FieldLE& value)
{
    inputs.emplace_back(name, std::vector<FieldLE>{value});
}

/** Inputs shared by every operation: pool context, instance, quantum and fee. */
bool Context(const C6Config& config, const std::string& op, uint64_t fee, C6Prepared& out, std::string& error)
{
    const auto levels = config.fees.find(op);
    if (levels == config.fees.end() || std::find(levels->second.begin(), levels->second.end(), fee) == levels->second.end()) {
        error = "unapproved fee level";
        return false;
    }
    out = C6Prepared{};
    out.operation = op;
    out.fee = fee;
    Input(out.inputs, "ctx", LE(config.context));
    Input(out.inputs, "D", ByteArray(config.domain));
    Input(out.inputs, "AID", ByteArray(config.assetId));
    Input(out.inputs, "unit", LE(1));
    Input(out.inputs, "registryRoot", std::vector<FieldLE>(32, FieldLE{}));
    Input(out.inputs, "fee", LE(fee));
    return true;
}

bool Money(uint64_t value) { return value >= 1 && value <= MAX_NOTE_AMOUNT; }

Bytes SerializePoint(const COutPoint& point)
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << point;
    return Bytes(stream.begin(), stream.end());
}

/** Checks an owned note and its membership in the historical root, and adds the
 *  spend inputs shared by withdrawals and transfers (spent() in c6-operations.js). */
bool Spent(const C6Config& config, const C6Spend& spend, const Bytes32& spendSecret, C6Prepared& out, Note& note,
           Bytes32& cm, Bytes32& nf, std::string& error)
{
    if (!DecodeNote(spend.note, note, error) || !NoteCommitment(spend.note, cm, error) ||
        !NoteNullifier(spend.note, spendSecret, nf, error)) {
        return false;
    }
    if (note.domain != config.domain || note.assetId != config.assetId || IsZero(spend.root) || spend.path.size() != 32) {
        error = "spent note belongs to another pool instance";
        return false;
    }
    Bytes32 member = cm;
    for (size_t level = 0; level < 32; ++level) {
        const bool right = (spend.index >> level) & 1;
        if (!PoseidonNode(right ? spend.path[level] : member, right ? member : spend.path[level], member)) {
            error = "invalid membership path";
            return false;
        }
    }
    if (member != spend.root) {
        error = "spent note is not in the historical root";
        return false;
    }
    Input(out.inputs, "R", LE(spend.root));
    Input(out.inputs, "nf", LE(nf));
    Input(out.inputs, "sk", ByteArray(spendSecret));
    Input(out.inputs, "spentNote", ByteArray(spend.note));
    Input(out.inputs, "spentCm", LE(cm));
    Input(out.inputs, "spentAmount", LE(note.amount));
    Input(out.inputs, "spentIndex", LE(spend.index));
    std::vector<FieldLE> path;
    for (const Bytes32& node : spend.path) path.push_back(LE(node));
    Input(out.inputs, "spentPath", std::move(path));
    return true;
}

/** Receiving descriptor of a note's owner: change goes back to the same address. */
Recipient OwnerOf(const Note& note)
{
    Recipient own;
    own.domain = note.domain;
    own.assetId = note.assetId;
    own.owner = note.owner;
    own.viewPub = note.viewPub;
    return own;
}

/** Where the change of a spent note goes: its own address. */
bool ChangeRecipient(const C6Config& config, const C6Spend& spend, const Note& note, Recipient& out, std::string& error)
{
    if (spend.changeTo) {
        out = *spend.changeTo;
    } else if (config.c7) {
        error = "internal error: the C7 change address is unknown";
        return false;
    } else {
        out = OwnerOf(note);
    }
    if (out.owner != note.owner || out.viewPub != note.viewPub) {
        error = "internal error: the change address does not hold the spent note";
        return false;
    }
    return true;
}

/** Seals a new note: HPKE CP1 record for a C6 pool, 230-byte C7 record (to the
 *  recipient's diversified address) for a C7 pool. */
bool SealFor(const C6Config& config, const Recipient& recipient, uint64_t amount, SealedNote& out, std::string& error)
{
    if (recipient.domain != config.domain || recipient.assetId != config.assetId) {
        error = "recipient belongs to another pool instance";
        return false;
    }
    if (recipient.v3 != config.c7) {
        error = config.c7 ? "this C7 pool needs a version 3 private address" : "this C6 pool needs a version 1 private address";
        return false;
    }
    if (!config.c7) return SealNote(recipient, amount, out, error);
    c7::Recipient to;
    to.owner = recipient.owner;
    to.d = recipient.diversifier;
    to.pkd = recipient.viewPub;
    const c7::Instance instance{"", config.domain, config.assetId};
    for (int attempt = 0; attempt < 4; ++attempt) {
        // rho is fresh and secret: it fixes esk, the nullifier and the commitment.
        const Bytes32 rho = RandomBytes32();
        c7::SealedNote sealed;
        if (c7::SealNote(to, amount, rho, instance, sealed, error)) {
            out.note = sealed.note;
            out.cm = sealed.cm;
            out.record = sealed.record;
            return true;
        }
        if (error != "esk-zero") return false;
    }
    return false;
}

} // namespace

bool IsC6Destination(const Bytes& script)
{
    if (script.size() == 25) {
        return script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac;
    }
    return script.size() == 34 && (script[0] == 0x52 || script[0] == 0x53) && script[1] == 0x20;
}

bool PrepareC6Deposit(const C6Config& config, const Recipient& self, uint64_t amount, uint64_t fee,
                      const COutPoint& funding, uint64_t fundingValue, C6Prepared& out, std::string& error)
{
    if (!Context(config, "D", fee, out, error)) return false;
    if (!Money(amount) || amount % C6_QUANTUM) {
        error = "deposit must be a multiple of 100 XNA";
        return false;
    }
    if (fundingValue != amount + fee) {
        error = "funding coin must equal amount plus fee";
        return false;
    }
    SealedNote created;
    if (!SealFor(config, self, amount, created, error)) return false;
    Publication publication;
    publication.cms = {created.cm};
    publication.records = {created.record};
    Bytes32 data;
    if (!EncodePublication("D0", publication, out.publication, error, config.Format()) ||
        !PublicationHash("D0", out.publication, data, error, config.Format())) {
        return false;
    }
    Bytes depBytes;
    Append(depBytes, std::string("NIP045/dep\x01"));
    Append(depBytes, U64LE(amount));
    Append(depBytes, created.cm);
    const Bytes32 dep = PoseidonBytes(depBytes);

    Input(out.inputs, "note", ByteArray(created.note));
    Input(out.inputs, "cm", LE(created.cm));
    Input(out.inputs, "amount", LE(amount));
    Input(out.inputs, "dep", LE(dep));
    Input(out.inputs, "data_hash", LE(data));
    out.publics = {config.context, dep, data, FieldFromU64(amount), FieldFromU64(fee)};
    out.cms = {created.cm};
    out.created = {std::move(created)};
    out.funding = funding;
    out.amount = amount;
    return true;
}

bool PrepareC6Withdrawal(const C6Config& config, const C6Spend& spend, const Bytes32& spendSecret, uint64_t amount,
                         uint64_t fee, const Bytes& payoutScript, C6Prepared& out, std::string& error)
{
    if (!Context(config, "W", fee, out, error)) return false;
    Note note;
    Bytes32 cm, nf;
    if (!Spent(config, spend, spendSecret, out, note, cm, nf, error)) return false;
    if (!IsC6Destination(payoutScript)) {
        error = "payout must be a Legacy or strict PQ/ECDSA address";
        return false;
    }
    if (!Money(amount) || amount > note.amount || note.amount - amount < fee) {
        error = "withdrawal exceeds the note";
        return false;
    }
    const uint64_t left = note.amount - amount - fee;
    if (amount >= C6_QUANTUM) {
        if (amount % C6_QUANTUM) {
            error = "withdrawal must be a multiple of 100 XNA";
            return false;
        }
    } else if (left != 0) {
        error = "a withdrawal below 100 XNA must empty the note";
        return false;
    }

    Note changeNote;
    Bytes changeBytes;
    Bytes32 data{}, cmChange{};
    if (left) {
        SealedNote created;
        Recipient back;
        if (!ChangeRecipient(config, spend, note, back, error) || !SealFor(config, back, left, created, error)) return false;
        Publication publication;
        publication.cms = {created.cm};
        publication.records = {created.record};
        publication.nf = nf;
        if (!EncodePublication("T1", publication, out.publication, error, config.Format()) ||
            !PublicationHash("T1", out.publication, data, error, config.Format())) {
            return false;
        }
        cmChange = created.cm;
        changeBytes = created.note;
        out.cms = {created.cm};
        out.created = {std::move(created)};
    } else {
        // The circuit still reads a well-formed dummy change note.
        changeNote.domain = config.domain;
        changeNote.assetId = config.assetId;
        changeNote.owner = FieldFromU64(1);
        changeNote.viewPub[0] = 9;
        changeNote.amount = 1;
        if (!EncodeNote(changeNote, changeBytes, error)) return false;
        ParseHex32(EMPTY_W_DATA, data);
    }
    Bytes payBytes;
    Append(payBytes, std::string("NeuraiPoolC6/pay\x01"));
    payBytes.push_back(static_cast<uint8_t>(payoutScript.size()));
    Append(payBytes, payoutScript);
    const Bytes32 pay = PoseidonBytes(payBytes);

    Input(out.inputs, "amount", LE(amount));
    Input(out.inputs, "pay", LE(pay));
    Input(out.inputs, "cm_change", LE(cmChange));
    Input(out.inputs, "data_hash", LE(data));
    Input(out.inputs, "has_change", LE(left ? 1 : 0));
    Input(out.inputs, "changeNote", ByteArray(changeBytes));
    Input(out.inputs, "changeAmount", LE(left ? left : 1));
    out.publics = {config.context, spend.root, nf, FieldFromU64(amount), FieldFromU64(fee), pay, cmChange, data};
    out.nfs = {nf};
    out.payout = payoutScript;
    out.amount = amount;
    out.hasChange = left != 0;
    return true;
}

bool PrepareC6Transfer(const C6Config& config, const C6Spend& spend, const Bytes32& spendSecret,
                       const std::vector<C6Payment>& payments, uint64_t fee, C6Prepared& out, std::string& error)
{
    if (payments.empty() || payments.size() > 3) {
        error = "one to three recipients required";
        return false;
    }
    Note note;
    if (!DecodeNote(spend.note, note, error)) return false;
    uint64_t total = fee;
    for (const C6Payment& payment : payments) {
        if (payment.recipient.domain != config.domain || payment.recipient.assetId != config.assetId ||
            payment.recipient.v3 != config.c7) {
            error = "recipient belongs to another pool instance";
            return false;
        }
        if (!Money(payment.amount) || payment.amount % C6_QUANTUM) {
            error = "recipient amounts must be multiples of 100 XNA";
            return false;
        }
        if (payment.amount > MAX_NOTE_AMOUNT - total) {
            error = "transfer amount out of range";
            return false;
        }
        total += payment.amount;
    }
    if (total > note.amount) {
        error = "the note cannot cover the transfer and its fee";
        return false;
    }
    // Recipients first, then the change back to the spent note's address (as NeuraiWallet does).
    std::vector<C6Payment> outputs = payments;
    std::vector<bool> change(payments.size(), false);
    if (note.amount > total) {
        Recipient back;
        if (!ChangeRecipient(config, spend, note, back, error)) return false;
        outputs.push_back({back, note.amount - total});
        change.push_back(true);
    }
    if (outputs.size() > 3) {
        error = "at most three outputs including the change";
        return false;
    }
    const std::string op = "T" + std::to_string(outputs.size());
    if (!Context(config, op, fee, out, error)) return false;
    Bytes32 cm, nf;
    if (!Spent(config, spend, spendSecret, out, note, cm, nf, error)) return false;

    Publication publication;
    publication.nf = nf;
    Bytes notes;
    std::vector<FieldLE> amounts, cms, flags;
    for (size_t i = 0; i < outputs.size(); ++i) {
        SealedNote created;
        if (!SealFor(config, outputs[i].recipient, outputs[i].amount, created, error)) return false;
        if (created.cm == cm || std::find(out.cms.begin(), out.cms.end(), created.cm) != out.cms.end()) {
            error = "output commitments must be fresh and distinct";
            return false;
        }
        Append(notes, created.note);
        amounts.push_back(LE(outputs[i].amount));
        cms.push_back(LE(created.cm));
        flags.push_back(LE(change[i] ? 1 : 0));
        publication.cms.push_back(created.cm);
        publication.records.push_back(created.record);
        out.cms.push_back(created.cm);
        out.created.push_back(std::move(created));
    }
    Bytes32 data;
    if (!EncodePublication(op, publication, out.publication, error, config.Format()) ||
        !PublicationHash(op, out.publication, data, error, config.Format())) {
        return false;
    }
    Input(out.inputs, "data_hash", LE(data));
    Input(out.inputs, "notes", ByteArray(notes));
    Input(out.inputs, "amounts", std::move(amounts));
    Input(out.inputs, "cms", std::move(cms));
    Input(out.inputs, "changeFlags", std::move(flags));
    out.publics = {config.context, spend.root, nf, data, FieldFromU64(fee)};
    for (const Bytes32& created : out.cms) out.publics.push_back(created);
    out.nfs = {nf};
    out.amount = total - fee;
    out.hasChange = note.amount > total;
    return true;
}

bool ProveC6(const C6Config& config, const C6Prepared& prepared, const std::vector<uint8_t>& wasm, const ProvingKey& key,
             std::array<uint8_t, 128>& proof, std::string& error, const std::function<void(const std::string&)>& stage)
{
    const auto vk = config.vks.find(prepared.operation);
    if (vk == config.vks.end()) {
        error = "missing verifying key";
        return false;
    }
    if (stage) stage("witness");
    std::vector<FieldLE> witness;
    if (!ComputeWitness(wasm, prepared.inputs, witness, error)) return false;
    if (witness.size() <= prepared.publics.size() || key.nPublic != prepared.publics.size()) {
        error = "circuit does not match the operation";
        return false;
    }
    for (size_t i = 0; i < prepared.publics.size(); ++i) {
        if (witness[i + 1] != LE(prepared.publics[i])) {
            error = "public signals differ from the wallet intent";
            return false;
        }
    }
    if (stage) stage("proving");
    Groth16Proof result;
    if (!ProveGroth16(key, witness, result, error)) return false;
    for (FieldLE& wire : witness) Wipe(wire);
    if (stage) stage("verifying");
    Bytes inputs;
    for (const Bytes32& value : prepared.publics) Append(inputs, value);
    if (neurai::zk::Verify(vk->second, result.compressed, inputs, false) != neurai::zk::Result::VALID) {
        error = "generated proof does not verify";
        return false;
    }
    proof = result.compressed;
    return true;
}

bool BuildC6Transaction(const C6Config& config, const C6PoolState& state, const C6Prepared& prepared,
                        const std::array<uint8_t, 128>& proof, CMutableTransaction& tx, int& fundingInput,
                        std::string& form, std::string& error)
{
    C6World world = state.world;
    if (world.Opening() != state.opening || (state.reserve > 0) != (world.Mode() == 1) ||
        (state.reserve > 0) != !state.reservePoint.IsNull()) {
        error = "scanned pool state is inconsistent";
        return false;
    }
    std::vector<COutPoint> points = {state.statePoint};
    if (state.reserve) {
        if (state.reservePoint != COutPoint(state.statePoint.hash, 1)) {
            error = "reserve is not paired with the state";
            return false;
        }
        points.push_back(state.reservePoint);
    }
    const bool deposit = prepared.operation == "D", withdraw = prepared.operation == "W";
    const bool transfer = prepared.operation == "T1" || prepared.operation == "T2" || prepared.operation == "T3";
    if (!deposit && !withdraw && !transfer) {
        error = "unsupported operation";
        return false;
    }
    const uint64_t reserve = static_cast<uint64_t>(state.reserve);
    uint64_t left;
    C6Event event;
    event.cms = prepared.cms;
    event.nfs = prepared.nfs;
    fundingInput = -1;
    if (deposit) {
        left = reserve + prepared.amount;
        form = reserve ? "D1" : "D0";
        points.push_back(prepared.funding);
        fundingInput = static_cast<int>(points.size()) - 1;
    } else {
        const auto& roots = world.Roots();
        const auto found = std::find(roots.begin(), roots.end(), prepared.publics[1]);
        if (found == roots.end()) {
            error = "historical root not found in the pool";
            return false;
        }
        event.rootIndex = found - roots.begin();
        if (transfer) {
            // Only the fee leaves the pool; the reserve must stay non-empty.
            if (reserve <= prepared.fee) {
                error = "pool reserve cannot cover the transfer fee";
                return false;
            }
            left = reserve - prepared.fee;
            form = prepared.operation;
        } else {
            if (reserve < prepared.amount + prepared.fee) {
                error = "pool reserve cannot cover the withdrawal";
                return false;
            }
            left = reserve - prepared.amount - prepared.fee;
            if (!left && prepared.hasChange) {
                error = "a full withdrawal cannot leave change";
                return false;
            }
            form = !left ? "W_full_no_change" : prepared.hasChange ? "W_partial_change" : "W_partial_no_change";
        }
    }
    if (left > MAX_NOTE_AMOUNT || std::set<COutPoint>(points.begin(), points.end()).size() != points.size()) {
        error = "pool reserve or inputs out of range";
        return false;
    }
    event.form = form;
    Bytes transcript;
    if (!world.Transition(event, transcript, error)) return false;
    const C6Leaf* leaf = config.Leaf(form);
    if (!leaf) {
        error = "missing contract leaf";
        return false;
    }

    std::map<std::string, Bytes> values;
    values["proof"] = Bytes(proof.begin(), proof.end());
    values["vk"] = config.vks.at(prepared.operation);
    for (const COutPoint& point : points) Append(values["prevouts"], SerializePoint(point));
    values["nf"] = prepared.nfs.empty() ? Bytes(32, 0) : Bytes(prepared.nfs[0].begin(), prepared.nfs[0].end());
    values["R"] = Bytes(prepared.publics[1].begin(), prepared.publics[1].end());
    values["amount"] = CScriptNum::serialize(static_cast<int64_t>(transfer ? 0 : prepared.amount));
    const size_t half = std::min<size_t>(prepared.publication.size(), 2048);
    values["chunk1"] = Bytes(prepared.publication.begin(), prepared.publication.begin() + half);
    values["chunk2"] = Bytes(prepared.publication.begin() + half, prepared.publication.end());
    for (size_t i = 0; i < 5; ++i) {
        const size_t begin = std::min(transcript.size(), i * TREE_CHUNK), end = std::min(transcript.size(), (i + 1) * TREE_CHUNK);
        values["tree" + std::to_string(i)] = Bytes(transcript.begin() + begin, transcript.begin() + end);
    }

    tx = CMutableTransaction();
    tx.nVersion = 3;
    tx.nLockTime = 0;
    for (const COutPoint& point : points) tx.vin.emplace_back(point, CScript(), 0xffffffff);
    const Bytes stateScript = config.StateScript(world.Opening());
    tx.vout.emplace_back(0, CScript(stateScript.begin(), stateScript.end()));
    if (left) {
        const Bytes reserveScript = config.ReserveScript();
        tx.vout.emplace_back(static_cast<CAmount>(left), CScript(reserveScript.begin(), reserveScript.end()));
    }
    if (withdraw) tx.vout.emplace_back(static_cast<CAmount>(prepared.amount), CScript(prepared.payout.begin(), prepared.payout.end()));

    auto& stack = tx.vin[0].scriptWitness.stack;
    stack.push_back({0x10});
    for (const std::string& name : leaf->args) {
        const auto value = values.find(name);
        if (value == values.end()) {
            error = "missing witness argument " + name;
            return false;
        }
        stack.emplace_back(value->second.begin(), value->second.end());
    }
    stack.emplace_back(leaf->script.begin(), leaf->script.end());
    stack.emplace_back(leaf->control.begin(), leaf->control.end());
    if (state.reserve) {
        const Bytes guard = config.ReserveGuard();
        tx.vin[1].scriptWitness.stack = {{0x00}, std::vector<unsigned char>(guard.begin(), guard.end())};
    }
    return true;
}

} // namespace privacy
