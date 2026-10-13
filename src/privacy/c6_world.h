// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_PRIVACY_C6_WORLD_H
#define NEURAI_PRIVACY_C6_WORLD_H

#include "privacy/primitives.h"

#include <set>
#include <string>
#include <unordered_map>

namespace privacy {

/** C6 forms, in transcript order (index = form byte). */
extern const char* const C6_FORMS[9];
int C6FormIndex(const std::string& form);

/** NIP-043 sparse binary tree of depth 32; missing leaves are zero. */
class SparseTree
{
public:
    SparseTree();
    const Bytes32& Get(int level, uint32_t index) const;
    const Bytes32& Root() const { return Get(32, 0); }
    std::vector<Bytes32> Path(uint32_t index) const;
    void Set(uint32_t index, const Bytes32& value);
    static const std::vector<Bytes32>& Zeros();

private:
    std::vector<std::unordered_map<uint32_t, Bytes32>> m_levels;
};

/** Root and authentication path of leaf `index` in the tree holding only the first
 *  `count` leaves (an older state of an append-only tree). */
void SparseSnapshot(const std::vector<Bytes32>& leaves, size_t count, uint32_t index, Bytes32& root,
                    std::vector<Bytes32>& path);

/** NIP-043 indexed (sorted linked-list) tree of nullifiers or commitments. */
class IndexedTree
{
public:
    explicit IndexedTree(const std::string& kind);
    /** Inserts a new positive value and returns its non-membership witness. */
    bool Insert(const Bytes32& value, Bytes& witness);
    const Bytes32& Root() const { return m_tree.Root(); }
    uint32_t Size() const { return static_cast<uint32_t>(m_entries.size()); }
    bool Contains(const Bytes32& value) const;

private:
    struct Entry {
        Bytes32 value;
        Bytes32 next;
        uint32_t nextIndex;
    };
    Bytes32 Leaf(const Entry& entry) const;
    std::string m_kind;
    std::vector<Entry> m_entries;
    std::set<Bytes32> m_values;
    SparseTree m_tree;
};

/** One confirmed (or proposed) C6 state transition. */
struct C6Event {
    std::string form;
    std::vector<Bytes32> cms;
    std::vector<Bytes32> nfs;
    int64_t rootIndex = -1; //!< historical root used by spends, -1 for deposits
};

/** Deterministic public pool state (port of C6PublicWorld in c6-transaction.js). */
class C6World
{
public:
    C6World();
    /** 145-byte state opening committed by the state output. */
    Bytes Opening() const;
    /** Applies a transition and returns its public-tree transcript. */
    bool Transition(const C6Event& event, Bytes& transcript, std::string& error);

    uint32_t NoteCount() const { return m_noteCount; }
    uint8_t Mode() const { return m_mode; }
    const std::vector<Bytes32>& Roots() const { return m_roots; }
    /** Note count when each historical root was recorded. */
    const std::vector<uint32_t>& RootCounts() const { return m_rootCounts; }
    const std::vector<Bytes32>& Leaves() const { return m_leaves; }
    bool IsSpent(const Bytes32& nf) const { return m_nfs.Contains(nf); }

private:
    SparseTree m_notes;
    SparseTree m_history;
    IndexedTree m_nfs;
    IndexedTree m_seen;
    uint32_t m_noteCount = 0;
    std::vector<Bytes32> m_roots;
    std::vector<uint32_t> m_rootCounts;
    std::vector<Bytes32> m_leaves;
    uint8_t m_mode = 0;
};

} // namespace privacy

#endif // NEURAI_PRIVACY_C6_WORLD_H
