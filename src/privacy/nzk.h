// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_PRIVACY_NZK_H
#define NEURAI_PRIVACY_NZK_H

#include "privacy/notes.h"

#include <string>

namespace privacy {

/** NeuraiZK/v2 deterministic private identities (port of zk-wallet.js).
 *
 *  BIP39 seed + ZK passphrase -> Argon2id root -> HKDF keys per family,
 *  account, chain (0 receiving, 1 change) and address index, bound to one pool
 *  instance. The same words give the same private wallet as NeuraiWallet and
 *  the web wallet. */

enum class NzkFamily : uint8_t { LEGACY = 0, ECDSA = 1, PQ = 2 };

constexpr uint32_t NZK_CHAIN_RECEIVING = 0;
constexpr uint32_t NZK_CHAIN_CHANGE = 1;
constexpr uint32_t NZK_ARGON2_PASSES = 3;
constexpr uint32_t NZK_ARGON2_MEMORY_KIB = 64 * 1024;

/** BIP39 seed. Both strings must already be NFKD-normalised UTF-8; runs of
 *  whitespace in the mnemonic are collapsed to single spaces. */
void NzkWalletSeed(const std::string& mnemonic, const std::string& passphrase, uint8_t seed[64]);

/** R = Argon2id(S || u32le(len(Z)) || Z), Z the NFKD-normalised ZK passphrase. Memory-hard (64 MiB). */
bool NzkRoot(const uint8_t seed[64], const std::string& zkPassphrase, uint8_t root[64]);

/** Human-readable part of nzk addresses for "main", "test" or "regtest" (empty if unknown). */
std::string NzkHrp(const std::string& chain);

/** Pool instance tag carried by nzk addresses. */
std::array<uint8_t, 4> NzkInstanceTag(const Bytes32& domain, const Bytes32& assetId);
std::string EncodeNzkAddress(const Recipient& recipient, const std::string& hrp);
bool DecodeNzkAddress(const std::string& address, const std::string& hrp, const Bytes32& domain,
                      const Bytes32& assetId, Recipient& recipient, std::string& error);

/** Private keys of one address. Wiped on destruction. */
struct NzkAddressKeys {
    Bytes32 spendSecret{};
    Bytes32 viewSeed{};
    ~NzkAddressKeys() { Wipe(spendSecret); Wipe(viewSeed); }
};

/** Account of one family bound to one pool instance; holds only the account PRK. */
class NzkAccount
{
public:
    NzkAccount(const uint8_t root[64], NzkFamily family, uint32_t account, const Bytes32& domain, const Bytes32& assetId);
    ~NzkAccount();
    NzkAccount(const NzkAccount&) = delete;
    NzkAccount& operator=(const NzkAccount&) = delete;

    const Bytes32& Domain() const { return m_domain; }
    const Bytes32& AssetId() const { return m_assetId; }

    bool Keys(uint32_t chain, uint32_t index, NzkAddressKeys& keys) const;
    Recipient RecipientAt(uint32_t chain, uint32_t index) const;
    /** Local comparison hint (4 bytes hex); never an authentication token. */
    std::string Fingerprint() const;
    /** Stable opaque identifier for local storage. */
    std::string StorageId() const;
    /** Key that seals the local scan checkpoint and journal. */
    Bytes32 CheckpointKey() const;

private:
    Bytes AccountScope() const;
    Bytes32 m_prk{};
    NzkFamily m_family;
    uint32_t m_account;
    Bytes32 m_domain;
    Bytes32 m_assetId;
};

namespace bech32m {
/** BIP-350 bech32m without the 90-character limit (as in ZIP-316). */
std::string Encode(const std::string& hrp, const Bytes& data);
bool Decode(const std::string& text, std::string& hrp, Bytes& data);
} // namespace bech32m

} // namespace privacy

#endif // NEURAI_PRIVACY_NZK_H
