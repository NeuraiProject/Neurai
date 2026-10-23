// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_PRIVACY_C6_WALLET_H
#define NEURAI_PRIVACY_C6_WALLET_H

#include "privacy/c6_scan.h"
#include "privacy/nzk.h"

#include <map>
#include <memory>

namespace privacy {

constexpr uint32_t NZK_DEFAULT_GAP = 20;

/** A pool note owned by this wallet. */
struct C6OwnedNote {
    uint32_t index = 0; //!< position in the note tree
    Bytes32 cm{};
    Bytes note;
    uint64_t amount = 0;
    Bytes32 nf{};
    uint32_t chain = 0;   //!< 0 receiving, 1 change
    uint32_t address = 0; //!< address index within the chain
    int height = 0;
    uint256 txid;
};

/** Finds the wallet's notes among published records (port of
 *  ZkWalletIdentity.scanRecords): the change address and receiving addresses up
 *  to `gap` past the highest used one. Records are processed incrementally. */
class C6Recovery
{
public:
    C6Recovery(const NzkAccount& account, uint32_t gap = NZK_DEFAULT_GAP) : m_account(account), m_gap(gap) {}

    void Update(const std::vector<C6Record>& records);
    const std::vector<C6OwnedNote>& Notes() const { return m_notes; }
    /** Receiving index to show: the first after the highest used one. */
    uint32_t CurrentIndex() const { return static_cast<uint32_t>(m_maxUsed + 1); }
    /** Keys of the address that received a note (to spend it). */
    bool KeysFor(const C6OwnedNote& note, NzkAddressKeys& keys) const;

private:
    struct Address {
        uint32_t chain;
        uint32_t index;
        NzkAddressKeys keys;
    };
    void Reset();
    void AddAddress(uint32_t chain, uint32_t index);
    bool Try(const Address& address, const C6Record& record);
    void ExtendWindow(const std::vector<C6Record>& records);

    const NzkAccount& m_account;
    uint32_t m_gap;
    int64_t m_maxUsed = -1;
    size_t m_processed = 0;
    Bytes32 m_lastCm{};
    std::vector<std::unique_ptr<Address>> m_addresses;
    std::vector<size_t> m_unowned;
    std::vector<C6OwnedNote> m_notes;
};

/** Keys and note recovery of one private account in one pool, whatever its
 *  generation: C6 (NeuraiZK/v2, trial decryption per address of the window) or
 *  C7 (NeuraiZK/v3, one viewing key per account, diversified addresses). */
class PoolAccount
{
public:
    virtual ~PoolAccount() = default;
    /** Processes new records; restarts when the record list was replaced (reorg). */
    virtual void Update(const std::vector<C6Record>& records) = 0;
    virtual const std::vector<C6OwnedNote>& Notes() const = 0;
    /** Receiving address to show: the first after the highest used one. */
    virtual std::string ReceiveAddress(const std::string& hrp) const = 0;
    /** The wallet's own descriptor for deposits (change address, index 0). */
    virtual bool SelfRecipient(Recipient& self, std::string& error) const = 0;
    /** Spend secret of the address that received a note, and that address for its change. */
    virtual bool SpendKeysFor(const C6OwnedNote& note, Bytes32& spendSecret, Recipient& changeTo, std::string& error) const = 0;
};

/** Opens the account of `family` (account 0) for the pool of `config` from the
 *  private root R. Fails, without retrying, if the root yields a zero key. */
std::unique_ptr<PoolAccount> OpenPoolAccount(const C6Config& config, const uint8_t root[64], NzkFamily family,
                                             std::string& error);

/** Decodes a private address of this pool: version 1 for C6, version 3 for C7. */
bool DecodePoolAddress(bool c7, const std::string& text, const std::string& hrp, const Bytes32& domain,
                       const Bytes32& assetId, Recipient& recipient, std::string& error);

} // namespace privacy

#endif // NEURAI_PRIVACY_C6_WALLET_H
