// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "privacy/c6_scan.h"

#include "privacy/notes.h"
#include "privacy/publication.h"

#include <algorithm>
#include <map>

namespace privacy {
namespace {

Bytes32 Slice32(const Bytes& data, size_t offset)
{
    Bytes32 out;
    std::copy(data.begin() + offset, data.begin() + offset + 32, out.begin());
    return out;
}

uint32_t ReadU32LE(const Bytes& data, size_t offset)
{
    return static_cast<uint32_t>(data[offset]) | static_cast<uint32_t>(data[offset + 1]) << 8 |
           static_cast<uint32_t>(data[offset + 2]) << 16 | static_cast<uint32_t>(data[offset + 3]) << 24;
}

Bytes ScriptBytes(const CScript& script) { return Bytes(script.begin(), script.end()); }

} // namespace

bool ParseC6Transition(const C6Config& config, const CTransaction& tx, C6Event& event, Bytes& transcript,
                       std::vector<Bytes>& records, Bytes32& root, std::string& error)
{
    if (tx.vin.empty()) {
        error = "transition without inputs";
        return false;
    }
    const auto& stack = tx.vin[0].scriptWitness.stack;
    if (stack.size() < 3 || stack[0] != std::vector<unsigned char>{0x10}) {
        error = "state input is not a MAST spend";
        return false;
    }
    const Bytes script(stack[stack.size() - 2].begin(), stack[stack.size() - 2].end());
    const C6Leaf* leaf = nullptr;
    for (const C6Leaf& candidate : config.leaves) {
        if (candidate.script == script) leaf = &candidate;
    }
    if (!leaf || stack.size() != leaf->args.size() + 3 ||
        Bytes(stack.back().begin(), stack.back().end()) != leaf->control) {
        error = "state input does not use a pinned contract leaf";
        return false;
    }
    std::map<std::string, Bytes> args;
    for (size_t i = 0; i < leaf->args.size(); ++i) args[leaf->args[i]] = Bytes(stack[i + 1].begin(), stack[i + 1].end());

    const std::string& form = leaf->form;
    const bool join = form == "J2", deposit = form[0] == 'D';
    const size_t count = deposit || join || form == "W_partial_change" ? 1 :
                         form[0] == 'T'                                ? static_cast<size_t>(form[1] - '0') :
                                                                         0;
    transcript.clear();
    for (int i = 0; i < 5; ++i) Append(transcript, args["tree" + std::to_string(i)]);
    const size_t length = join ? 9824 : 324 + 32 * count + 3144 * count + 1024 * (count > 0) + (deposit ? 0 : 3148);
    if (transcript.size() != length || transcript[0] != (join ? 3 : 2) || transcript[1] != C6FormIndex(form)) {
        error = "transcript profile, form or length";
        return false;
    }
    event = C6Event{};
    event.form = form;
    if (!deposit) {
        event.nfs.push_back(Slice32(transcript, 292));
        if (join) event.nfs.push_back(Slice32(transcript, 324));
    }
    records.clear();
    if (count) {
        Bytes blob = args["chunk1"];
        Append(blob, args["chunk2"]);
        if (join) {
            if (blob.size() != PUBLICATION_SIZE || blob[0] != 3 || blob[1] != 1 || blob[98] != 1 || blob[99] != 217 ||
                blob[100] != 0 || std::any_of(blob.begin() + 318, blob.end(), [](uint8_t b) { return b != 0; })) {
                error = "J2 publication";
                return false;
            }
            for (size_t i = 0; i < 2; ++i) {
                if (Slice32(blob, 2 + 32 * i) != event.nfs[i]) {
                    error = "J2 publication nullifiers";
                    return false;
                }
            }
            event.cms.push_back(Slice32(blob, 66));
            Bytes record(RECORD_SIZE, 0);
            std::copy(blob.begin() + 98, blob.begin() + 318, record.begin());
            records.push_back(std::move(record));
        } else {
            Publication publication;
            const std::string pubForm = deposit ? "D0" : form == "W_partial_change" ? "T1" : form;
            if (!DecodePublication(pubForm, blob, publication, error)) return false;
            if (!deposit && (!publication.nf || *publication.nf != event.nfs[0])) {
                error = "publication nullifier";
                return false;
            }
            event.cms = publication.cms;
            records = publication.records;
        }
        const size_t offset = join ? 356 : 324;
        for (size_t i = 0; i < event.cms.size(); ++i) {
            if (Slice32(transcript, offset + 32 * i) != event.cms[i]) {
                error = "publication commitment";
                return false;
            }
        }
    }
    if (!deposit) {
        event.rootIndex = ReadU32LE(transcript, join ? 388 : 324 + 32 * count);
        const Bytes& r = args["R"];
        if (r.size() != 32) {
            error = "historical root argument";
            return false;
        }
        std::copy(r.begin(), r.end(), root.begin());
    }
    return true;
}

bool ApplyC6Transition(const C6Config& config, C6PoolState& state, const CTransaction& tx, int height, std::string& error)
{
    if (tx.vin.empty() || tx.vin[0].prevout != state.statePoint) {
        error = "state must be input zero";
        return false;
    }
    if (tx.nVersion != 3 || tx.nLockTime != 0 || tx.vout.empty()) {
        error = "transition fixed fields";
        return false;
    }
    C6Event event;
    Bytes transcript, replayed;
    std::vector<Bytes> records;
    Bytes32 root{};
    if (!ParseC6Transition(config, tx, event, transcript, records, root, error)) return false;
    if (event.rootIndex >= 0 &&
        (static_cast<size_t>(event.rootIndex) >= state.world.Roots().size() || state.world.Roots()[event.rootIndex] != root)) {
        error = "historical root binding";
        return false;
    }
    const uint32_t firstIndex = state.world.NoteCount();
    if (!state.world.Transition(event, replayed, error)) return false;
    if (replayed != transcript) {
        error = "confirmed transcript does not replay";
        return false;
    }
    const Bytes opening = state.world.Opening();
    if (ScriptBytes(tx.vout[0].scriptPubKey) != config.StateScript(opening)) {
        error = "state output does not commit to the new opening";
        return false;
    }
    for (size_t i = 0; i < event.cms.size(); ++i) {
        state.records.push_back({event.cms[i], records[i], firstIndex + static_cast<uint32_t>(i), height, tx.GetHash()});
    }
    if (!event.cms.empty()) state.rootHeights.push_back(height);
    if (state.world.Mode()) {
        if (tx.vout.size() < 2 || ScriptBytes(tx.vout[1].scriptPubKey) != config.ReserveScript()) {
            error = "reserve output";
            return false;
        }
        state.reserve = tx.vout[1].nValue;
        state.reservePoint = COutPoint(tx.GetHash(), 1);
    } else {
        state.reserve = 0;
        state.reservePoint.SetNull();
    }
    state.opening = opening;
    state.statePoint = COutPoint(tx.GetHash(), 0);
    state.transitionTxids.insert(tx.GetHash());
    ++state.transitions;
    return true;
}

} // namespace privacy
