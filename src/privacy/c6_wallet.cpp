// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "privacy/c6_wallet.h"

#include <algorithm>

namespace privacy {

void C6Recovery::Reset()
{
    m_maxUsed = -1;
    m_processed = 0;
    m_lastCm = Bytes32{};
    m_addresses.clear();
    m_unowned.clear();
    m_notes.clear();
}

void C6Recovery::AddAddress(uint32_t chain, uint32_t index)
{
    auto address = std::make_unique<Address>();
    address->chain = chain;
    address->index = index;
    m_account.Keys(chain, index, address->keys);
    m_addresses.push_back(std::move(address));
}

bool C6Recovery::Try(const Address& address, const C6Record& record)
{
    OpenedNote opened;
    std::string error;
    if (!OpenNoteRecord(record.record, record.cm, m_account.Domain(), m_account.AssetId(), address.keys.viewSeed,
                        address.keys.spendSecret, opened, error)) {
        return false;
    }
    C6OwnedNote note;
    note.index = record.index;
    note.cm = record.cm;
    note.note = std::move(opened.note);
    note.amount = opened.amount;
    note.nf = opened.nf;
    note.chain = address.chain;
    note.address = address.index;
    note.height = record.height;
    note.txid = record.txid;
    m_notes.push_back(std::move(note));
    if (address.chain == NZK_CHAIN_RECEIVING && static_cast<int64_t>(address.index) > m_maxUsed) {
        m_maxUsed = address.index;
    }
    return true;
}

void C6Recovery::ExtendWindow(const std::vector<C6Record>& records)
{
    // Receiving addresses 0..max(gap - 1, maxUsed + gap); a newly found address can
    // extend the window, and records skipped so far are retried with new addresses.
    for (;;) {
        const uint32_t end = static_cast<uint32_t>(std::max<int64_t>(m_gap - 1, m_maxUsed + m_gap));
        const size_t before = m_addresses.size();
        while (m_addresses.size() < static_cast<size_t>(end) + 2) AddAddress(NZK_CHAIN_RECEIVING, static_cast<uint32_t>(m_addresses.size() - 1));
        if (m_addresses.size() == before) return;
        std::vector<size_t> still;
        for (size_t position : m_unowned) {
            bool owned = false;
            for (size_t a = before; a < m_addresses.size() && !owned; ++a) owned = Try(*m_addresses[a], records[position]);
            if (!owned) still.push_back(position);
        }
        m_unowned.swap(still);
    }
}

void C6Recovery::Update(const std::vector<C6Record>& records)
{
    if (records.size() < m_processed || (m_processed && records[m_processed - 1].cm != m_lastCm)) Reset();
    if (m_addresses.empty()) {
        AddAddress(NZK_CHAIN_CHANGE, 0);
        ExtendWindow(records);
    }
    for (size_t position = m_processed; position < records.size(); ++position) {
        bool owned = false;
        for (size_t a = 0; a < m_addresses.size() && !owned; ++a) owned = Try(*m_addresses[a], records[position]);
        if (!owned) m_unowned.push_back(position);
        m_processed = position + 1;
        m_lastCm = records[position].cm;
        if (owned) ExtendWindow(records);
    }
    std::sort(m_notes.begin(), m_notes.end(), [](const C6OwnedNote& a, const C6OwnedNote& b) { return a.index < b.index; });
}

bool C6Recovery::KeysFor(const C6OwnedNote& note, NzkAddressKeys& keys) const
{
    return m_account.Keys(note.chain, note.address, keys);
}

} // namespace privacy
