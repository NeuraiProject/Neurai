// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "privacy/c6_world.h"

#include <algorithm>

namespace privacy {

const char* const C6_FORMS[9] = {"D0", "D1", "T1", "T2", "T3", "W_partial_no_change", "W_partial_change",
                                 "W_full_no_change", "J2"};

int C6FormIndex(const std::string& form)
{
    for (int i = 0; i < 9; ++i) {
        if (form == C6_FORMS[i]) return i;
    }
    return -1;
}

namespace {

constexpr size_t MAX_TRANSCRIPT = 15360;

Bytes32 Node(const Bytes32& left, const Bytes32& right)
{
    Bytes32 out;
    PoseidonNode(left, right, out);
    return out;
}

} // namespace

const std::vector<Bytes32>& SparseTree::Zeros()
{
    static const std::vector<Bytes32> zeros = [] {
        std::vector<Bytes32> z(33);
        for (int i = 0; i < 32; ++i) z[i + 1] = Node(z[i], z[i]);
        return z;
    }();
    return zeros;
}

SparseTree::SparseTree() : m_levels(33) {}

const Bytes32& SparseTree::Get(int level, uint32_t index) const
{
    const auto& layer = m_levels[level];
    const auto found = layer.find(index);
    return found == layer.end() ? Zeros()[level] : found->second;
}

std::vector<Bytes32> SparseTree::Path(uint32_t index) const
{
    std::vector<Bytes32> path;
    path.reserve(32);
    uint64_t at = index;
    for (int level = 0; level < 32; ++level) {
        path.push_back(Get(level, static_cast<uint32_t>(at ^ 1)));
        at >>= 1;
    }
    return path;
}

void SparseTree::Set(uint32_t index, const Bytes32& value)
{
    m_levels[0][index] = value;
    uint64_t at = index;
    for (int level = 0; level < 32; ++level) {
        at >>= 1;
        const uint32_t n = static_cast<uint32_t>(at);
        m_levels[level + 1][n] = Node(Get(level, n * 2), Get(level, n * 2 + 1));
    }
}

void SparseSnapshot(const std::vector<Bytes32>& leaves, size_t count, uint32_t index, Bytes32& root,
                    std::vector<Bytes32>& path)
{
    const auto& zeros = SparseTree::Zeros();
    std::vector<Bytes32> layer(leaves.begin(), leaves.begin() + std::min(count, leaves.size()));
    path.clear();
    uint64_t at = index;
    for (int level = 0; level < 32; ++level) {
        const uint64_t sibling = at ^ 1;
        path.push_back(sibling < layer.size() ? layer[sibling] : zeros[level]);
        std::vector<Bytes32> next((layer.size() + 1) / 2);
        for (size_t i = 0; i < next.size(); ++i) {
            next[i] = Node(layer[2 * i], 2 * i + 1 < layer.size() ? layer[2 * i + 1] : zeros[level]);
        }
        layer.swap(next);
        at >>= 1;
    }
    root = layer.empty() ? zeros[32] : layer[0];
}

IndexedTree::IndexedTree(const std::string& kind) : m_kind(kind)
{
    m_entries.push_back({Bytes32{}, Bytes32{}, 0});
    m_tree.Set(0, Leaf(m_entries[0]));
}

Bytes32 IndexedTree::Leaf(const Entry& entry) const
{
    Bytes data;
    Append(data, "NIP043/" + m_kind + "leaf");
    Append(data, entry.value);
    Append(data, entry.next);
    Append(data, U32LE(entry.nextIndex));
    return PoseidonBytes(data);
}

bool IndexedTree::Contains(const Bytes32& value) const
{
    return m_values.count(value) > 0;
}

bool IndexedTree::Insert(const Bytes32& value, Bytes& witness)
{
    if (IsZero(value) || !IsCanonicalField(value) || m_entries.size() >= 0xffffffffu || Contains(value)) return false;
    // Predecessor: the largest stored value below the new one (big-endian bytes
    // compare like the integers they encode).
    size_t index = 0;
    for (size_t i = 0; i < m_entries.size(); ++i) {
        if (m_entries[i].value < value && m_entries[index].value < m_entries[i].value) index = i;
    }
    const Entry pred = m_entries[index];
    const uint32_t next = static_cast<uint32_t>(m_entries.size());
    if (!IsZero(pred.next) && !(value < pred.next)) return false;
    witness.clear();
    Append(witness, U32LE(static_cast<uint32_t>(index)));
    Append(witness, pred.value);
    Append(witness, pred.next);
    Append(witness, U32LE(pred.nextIndex));
    for (const Bytes32& node : m_tree.Path(static_cast<uint32_t>(index))) Append(witness, node);
    m_entries[index] = {pred.value, value, next};
    m_tree.Set(static_cast<uint32_t>(index), Leaf(m_entries[index]));
    for (const Bytes32& node : m_tree.Path(next)) Append(witness, node);
    m_entries.push_back({value, pred.next, pred.nextIndex});
    m_values.insert(value);
    m_tree.Set(next, Leaf(m_entries.back()));
    return true;
}

C6World::C6World() : m_nfs("nf"), m_seen("cm") {}

Bytes C6World::Opening() const
{
    Bytes out;
    out.reserve(145);
    Append(out, m_notes.Root());
    Append(out, m_nfs.Root());
    Append(out, m_seen.Root());
    Append(out, U32LE(m_noteCount));
    Append(out, U32LE(m_nfs.Size()));
    Append(out, U32LE(m_seen.Size()));
    out.push_back(m_mode);
    Append(out, m_history.Root());
    Append(out, U32LE(static_cast<uint32_t>(m_roots.size())));
    return out;
}

bool C6World::Transition(const C6Event& event, Bytes& transcript, std::string& error)
{
    const int formIndex = C6FormIndex(event.form);
    if (formIndex < 0) {
        error = "unknown C6 form";
        return false;
    }
    const bool deposit = event.form[0] == 'D', join = event.form == "J2";
    const size_t count = deposit || join || event.form == "W_partial_change" ? 1 :
                         event.form[0] == 'T'                                 ? static_cast<size_t>(event.form[1] - '0') :
                                                                                0;
    if (event.cms.size() != count || event.nfs.size() != (deposit ? 0u : join ? 2u : 1u)) {
        error = "transition shape";
        return false;
    }
    if (m_mode != (event.form != "D0" ? 1 : 0)) {
        error = "transition does not match the reserve mode";
        return false;
    }
    const Bytes old = Opening();
    Bytes parts;
    if (!deposit) {
        if (event.rootIndex < 0 || static_cast<size_t>(event.rootIndex) >= m_roots.size()) {
            error = "unknown historical root";
            return false;
        }
        Append(parts, U32LE(static_cast<uint32_t>(event.rootIndex)));
        for (const Bytes32& node : m_history.Path(static_cast<uint32_t>(event.rootIndex))) Append(parts, node);
    }
    if (std::set<Bytes32>(event.nfs.begin(), event.nfs.end()).size() != event.nfs.size()) {
        error = "duplicate nullifiers";
        return false;
    }
    for (const Bytes32& nf : event.nfs) {
        Bytes witness;
        if (!m_nfs.Insert(nf, witness)) {
            error = "nullifier already spent or invalid";
            return false;
        }
        Append(parts, witness);
    }
    for (const Bytes32& cm : event.cms) {
        if (m_noteCount > 0xfffffffdu || IsZero(cm) || !IsCanonicalField(cm)) {
            error = "note capacity or commitment value";
            return false;
        }
        for (const Bytes32& node : m_notes.Path(m_noteCount)) Append(parts, node);
        m_notes.Set(m_noteCount++, cm);
        m_leaves.push_back(cm);
        Bytes witness;
        if (!m_seen.Insert(cm, witness)) {
            error = "duplicate commitment";
            return false;
        }
        Append(parts, witness);
    }
    if (!event.cms.empty()) {
        const uint32_t slot = static_cast<uint32_t>(m_roots.size());
        for (const Bytes32& node : m_history.Path(slot)) Append(parts, node);
        m_history.Set(slot, m_notes.Root());
        m_roots.push_back(m_notes.Root());
        m_rootCounts.push_back(m_noteCount);
    }
    m_mode = event.form != "W_full_no_change" ? 1 : 0;
    transcript = {static_cast<uint8_t>(join ? 3 : 2), static_cast<uint8_t>(formIndex)};
    Append(transcript, old);
    Append(transcript, Opening());
    if (deposit) Append(transcript, Bytes32{});
    for (const Bytes32& nf : event.nfs) Append(transcript, nf);
    for (const Bytes32& cm : event.cms) Append(transcript, cm);
    Append(transcript, parts);
    if (transcript.size() > MAX_TRANSCRIPT) {
        error = "transcript capacity";
        return false;
    }
    return true;
}

} // namespace privacy
