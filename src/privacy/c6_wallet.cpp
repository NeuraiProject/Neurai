// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "privacy/c6_wallet.h"
#include "privacy/c7.h"

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

namespace {

/** C6: one HPKE view key per address, trial decryption over the address window. */
class C6PoolAccount : public PoolAccount
{
public:
    C6PoolAccount(const uint8_t root[64], NzkFamily family, const C6Config& config)
        : m_account(root, family, 0, config.domain, config.assetId), m_recovery(m_account) {}

    void Update(const std::vector<C6Record>& records) override { m_recovery.Update(records); }
    const std::vector<C6OwnedNote>& Notes() const override { return m_recovery.Notes(); }

    std::string ReceiveAddress(const std::string& hrp) const override
    {
        return EncodeNzkAddress(m_account.RecipientAt(NZK_CHAIN_RECEIVING, m_recovery.CurrentIndex()), hrp);
    }

    bool SelfRecipient(Recipient& self, std::string&) const override
    {
        self = m_account.RecipientAt(NZK_CHAIN_CHANGE, 0);
        return true;
    }

    bool SpendKeysFor(const C6OwnedNote& note, Bytes32& spendSecret, Recipient& changeTo, std::string& error) const override
    {
        NzkAddressKeys keys;
        if (!m_recovery.KeysFor(note, keys)) {
            error = "cannot derive the note's spending key";
            return false;
        }
        spendSecret = keys.spendSecret;
        changeTo = m_account.RecipientAt(note.chain, note.address);
        return true;
    }

private:
    NzkAccount m_account;
    C6Recovery m_recovery;
};

/** C7: one viewing key per account; each record costs one multiplication,
 *  whatever the number of addresses, and the full scanner checks ownership. */
class C7PoolAccount : public PoolAccount
{
public:
    C7PoolAccount(std::unique_ptr<c7::Account> account, const C6Config& config)
        : m_account(std::move(account)), m_domain(config.domain), m_assetId(config.assetId) {}

    void Update(const std::vector<C6Record>& records) override
    {
        if (records.size() < m_processed || (m_processed && records[m_processed - 1].cm != m_lastCm)) {
            m_processed = 0;
            m_maxUsed = -1;
            m_notes.clear();
        }
        for (size_t position = m_processed; position < records.size(); ++position) {
            const C6Record& record = records[position];
            c7::OwnedNote owned;
            std::string reason;
            if (c7::ScanFull(record.record, record.cm, *m_account, owned, reason)) {
                C6OwnedNote note;
                note.index = record.index;
                note.cm = record.cm;
                note.note = owned.note;
                note.amount = owned.amount;
                note.nf = owned.nf;
                note.chain = owned.branch;
                note.address = owned.index;
                note.height = record.height;
                note.txid = record.txid;
                m_notes.push_back(std::move(note));
                if (owned.branch == NZK_CHAIN_RECEIVING) m_maxUsed = std::max<int64_t>(m_maxUsed, owned.index);
            }
            m_processed = position + 1;
            m_lastCm = record.cm;
        }
        std::sort(m_notes.begin(), m_notes.end(), [](const C6OwnedNote& a, const C6OwnedNote& b) { return a.index < b.index; });
    }

    const std::vector<C6OwnedNote>& Notes() const override { return m_notes; }

    std::string ReceiveAddress(const std::string& hrp) const override
    {
        Recipient recipient;
        std::string error;
        const uint32_t index = static_cast<uint32_t>(std::min<int64_t>(m_maxUsed + 1, c7::MAX_INDEX));
        if (!At(NZK_CHAIN_RECEIVING, index, recipient, error)) return std::string();
        c7::Recipient address;
        address.owner = recipient.owner;
        address.d = recipient.diversifier;
        address.pkd = recipient.viewPub;
        return c7::EncodeAddress(address, c7::Instance{hrp, m_domain, m_assetId});
    }

    bool SelfRecipient(Recipient& self, std::string& error) const override { return At(NZK_CHAIN_CHANGE, 0, self, error); }

    bool SpendKeysFor(const C6OwnedNote& note, Bytes32& spendSecret, Recipient& changeTo, std::string& error) const override
    {
        c7::SpendKeys keys;
        if (!m_account->SpendKeysAt(note.chain, note.address, keys, error)) return false;
        spendSecret = keys.spendSecret;
        return At(note.chain, note.address, changeTo, error);
    }

private:
    bool At(uint32_t branch, uint32_t index, Recipient& out, std::string& error) const
    {
        c7::Address address;
        if (!m_account->AddressAt(branch, index, address, error)) return false;
        out = Recipient{};
        out.domain = m_domain;
        out.assetId = m_assetId;
        out.owner = address.owner;
        out.viewPub = address.pkd;
        out.v3 = true;
        out.diversifier = address.d;
        return true;
    }

    std::unique_ptr<c7::Account> m_account;
    Bytes32 m_domain, m_assetId;
    size_t m_processed = 0;
    Bytes32 m_lastCm{};
    int64_t m_maxUsed = -1;
    std::vector<C6OwnedNote> m_notes;
};

} // namespace

std::unique_ptr<PoolAccount> OpenPoolAccount(const C6Config& config, const uint8_t root[64], NzkFamily family,
                                             std::string& error)
{
    if (!config.c7) return std::make_unique<C6PoolAccount>(root, family, config);
    auto account = c7::Account::Create(root, family, 0, c7::Instance{"", config.domain, config.assetId}, error);
    if (!account) {
        error = "cannot derive the C7 private account (" + error + ")";
        return nullptr;
    }
    return std::make_unique<C7PoolAccount>(std::move(account), config);
}

bool DecodePoolAddress(bool c7, const std::string& text, const std::string& hrp, const Bytes32& domain,
                       const Bytes32& assetId, Recipient& recipient, std::string& error)
{
    if (!c7) return DecodeNzkAddress(text, hrp, domain, assetId, recipient, error);
    c7::Recipient parsed;
    if (!c7::ParseAddress(text, c7::Instance{hrp, domain, assetId}, parsed, error)) {
        error = "not a private address of this C7 pool (" + error + ")";
        return false;
    }
    recipient = Recipient{};
    recipient.domain = domain;
    recipient.assetId = assetId;
    recipient.owner = parsed.owner;
    recipient.viewPub = parsed.pkd;
    recipient.v3 = true;
    recipient.diversifier = parsed.d;
    return true;
}

} // namespace privacy
