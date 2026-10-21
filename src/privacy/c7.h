// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef NEURAI_PRIVACY_C7_H
#define NEURAI_PRIVACY_C7_H

#include "privacy/nzk.h"
#include "privacy/primitives.h"

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace privacy {
namespace c7 {

/** C7 private pool notes (NeuraiZK/v3): diversified addresses, one viewing key
 *  per account and a one-byte view tag per record, over ristretto255. Byte
 *  level specification and reference: contrib/privacypool/privacy-c7/. TEST only.
 *
 *  Failures carry the reason names of the reference vectors
 *  (src/test/data/privacy_c7_vectors.json). */

constexpr size_t RECORD_SIZE = 230;
constexpr size_t NOTE_SIZE = 169;
constexpr size_t DIVERSIFIER_SIZE = 11;
constexpr size_t ADDRESS_PAYLOAD_SIZE = 80;
constexpr uint8_t ADDRESS_VERSION = 3;
constexpr uint8_t RECORD_VERSION = 2;
constexpr uint32_t MAX_ACCOUNT = 0x7fffffff;
constexpr uint32_t MAX_INDEX = 0x7fffffff;
constexpr uint64_t MAX_AMOUNT = 2100000000000000000ULL;

using Point = Bytes32;   //!< canonical ristretto255 encoding
using Scalar = Bytes32;  //!< little-endian integer below the group order
using Diversifier = std::array<uint8_t, DIVERSIFIER_SIZE>;

// --- primitives -------------------------------------------------------------

/** Canonical ristretto255 encoding (the identity, all zero, is valid). */
bool IsValidPoint(const Point& point);
bool IsIdentity(const Point& point);
/** [scalar]point in constant time. False for an invalid point or an identity result. */
bool ScalarMult(const Scalar& scalar, const Point& point, Point& out);
/** RFC 9496 one-way map of 64 uniform bytes. */
Point FromUniform(const uint8_t uniform[64]);
/** 64 little-endian bytes reduced modulo the group order. */
Scalar ToScalar(const uint8_t wide[64]);
/** RFC 7693 BLAKE2b without key or salt; personal is ASCII, zero-padded to 16 bytes. */
void Blake2b(const std::string& personal, const uint8_t* data, size_t size, uint8_t* out, size_t outSize);
/** RFC 9380 expand_message_xmd with SHA-512. */
bool ExpandMessageXmd(const Bytes& msg, const std::string& dst, uint8_t* out, size_t outSize);
/** FF1-AES256 (NIST SP 800-38G) on a numeral string, in place; needs radix^ceil(n/2) < 2^56. */
bool Ff1(const Bytes32& key, const Bytes& tweak, uint32_t radix, std::vector<uint32_t>& numerals, bool decrypt);
/** d = LEBS2OSP_88(FF1-AES256(dk, "", radix 2, I2LEBSP_88(j))). */
Diversifier DiversifierFromIndex(const Bytes32& dk, uint64_t j);
/** Inverse: the 88-bit index split into its low 32 bits and the 56 bits above them. */
void IndexFromDiversifier(const Bytes32& dk, const Diversifier& d, uint64_t& high, uint32_t& low);

// --- pool instance ----------------------------------------------------------

struct Instance {
    std::string hrp;  //!< nzk, tnzk or rnzk
    Bytes32 domain{};
    Bytes32 assetId{};
};

/** SHA256("NeuraiPoolC7/domain" || 01 || genesis || emission txid || u32le(vout) || u8(len) || identity);
 *  hashes in internal byte order, identity 1 to 64 printable ASCII bytes. */
bool PoolDomain(const Bytes32& genesis, const Bytes32& emissionTxid, uint32_t emissionVout,
                const std::string& identity, Bytes32& domain);
Bytes32 XnaAssetId();
/** Public input 0 of every C7 proof (same construction as C6). */
Bytes32 PoolContext(const Bytes32& domain, const Bytes32& assetId);
std::array<uint8_t, 4> InstanceTag(const Bytes32& domain, const Bytes32& assetId);

// --- keys and addresses -----------------------------------------------------

/** What a sender needs: the decoded payload of an address. */
struct Recipient {
    Bytes32 owner{};
    Diversifier d{};
    Point pkd{};
};

struct Address : Recipient {
    uint32_t branch{0};
    uint32_t index{0};
    std::array<uint8_t, 64> uniform{};  //!< expand_message_xmd output hashed to G_d
    Point gd{};
    Bytes payload;
    std::string text;
};

/** Spending material of one address; wiped on destruction. */
struct SpendKeys {
    Bytes32 spendSecret{};
    Bytes32 owner{};
    Bytes32 nk{};
    ~SpendKeys() { Wipe(spendSecret); Wipe(nk); }
};

/** Receive-only key (ivk, dk): lists incoming notes, cannot check ownership or nullifiers. */
class ViewKey
{
public:
    ViewKey(const Scalar& ivk, const Bytes32& dk, const Instance& instance) : m_ivk(ivk), m_dk(dk), m_instance(instance) {}
    ~ViewKey() { Wipe(m_ivk); Wipe(m_dk); }
    const Scalar& Ivk() const { return m_ivk; }
    const Bytes32& Dk() const { return m_dk; }
    const Instance& GetInstance() const { return m_instance; }

private:
    Scalar m_ivk;
    Bytes32 m_dk;
    Instance m_instance;
};

/** Keys of one (family, account) for one pool instance, from the NeuraiZK/v2 private root R. */
class Account
{
public:
    /** Null with reason "ivk-zero" (never retried) or an invalid parameter. */
    static std::unique_ptr<Account> Create(const uint8_t root[64], NzkFamily family, uint32_t account,
                                           const Instance& instance, std::string& reason);
    ~Account();
    Account(const Account&) = delete;
    Account& operator=(const Account&) = delete;

    const Instance& GetInstance() const { return m_instance; }
    const Bytes32& Prk() const { return m_prk; }
    const Bytes& Q() const { return m_q; }
    const Scalar& Ivk() const { return m_ivk; }
    const Bytes32& Dk() const { return m_dk; }
    ViewKey View() const { return ViewKey(m_ivk, m_dk, m_instance); }

    /** HKDF-Expand of the v2 account PRK, one block. */
    Bytes32 Expand32(const Bytes& info) const;
    /** P = family || u32le(account) || u32le(branch) || u32le(index) || domain || assetId. */
    bool AddressScope(uint32_t branch, uint32_t index, Bytes& scope, std::string& reason) const;
    bool SpendKeysAt(uint32_t branch, uint32_t index, SpendKeys& keys, std::string& reason) const;
    bool AddressAt(uint32_t branch, uint32_t index, Address& address, std::string& reason) const;

private:
    Account(NzkFamily family, uint32_t account, const Instance& instance);
    NzkFamily m_family;
    uint32_t m_account;
    Instance m_instance;
    Bytes32 m_prk{};
    Bytes m_q;
    Scalar m_ivk{};
    Bytes32 m_dk{};
};

/** 0x03 || owner || d || pk_d || instance tag (80 bytes). */
Bytes AddressPayload(const Recipient& recipient, const Instance& instance);
std::string EncodeAddress(const Recipient& recipient, const Instance& instance);
/** Reasons: address-encoding, address-hrp, address-length, address-version, address-instance,
 *  owner-invalid, pk_d-invalid. */
bool ParseAddress(const std::string& text, const Instance& instance, Recipient& recipient, std::string& reason);

// --- notes and records ------------------------------------------------------

struct SealedNote {
    Bytes note;
    Bytes32 cm{};
    Scalar esk{};
    Point epk{};
    Point shared{};
    uint8_t vtag{0};
    Bytes32 key{};
    Bytes record;
    ~SealedNote() { Wipe(esk); Wipe(shared); Wipe(key); }
};

/** Sender side: the 230-byte record of a new note for recipient. rho must be
 *  fresh and random; reason "esk-zero" asks for another rho. */
bool SealNote(const Recipient& recipient, uint64_t amount, const Bytes32& rho, const Instance& instance,
              SealedNote& out, std::string& reason);

struct ReceivedNote {
    uint32_t branch{0};
    uint32_t index{0};
    uint64_t amount{0};
    Bytes32 owner{};
    Bytes32 rho{};
    Diversifier d{};
    Bytes note;
};

struct OwnedNote : ReceivedNote {
    Bytes32 nf{};
};

/** Receive-only scanner (steps 1 to 8): the note was sent to this account, its
 *  ownership is NOT verified and it has no spend state. checkTag=false skips
 *  the view tag (brute force, tests only). */
bool ScanReceive(const Bytes& record, const Bytes32& cm, const ViewKey& view, ReceivedNote& out, std::string& reason,
                 bool checkTag = true);
/** Full scanner (steps 1 to 10): ownership checked and nullifier computed. */
bool ScanFull(const Bytes& record, const Bytes32& cm, const Account& account, OwnedNote& out, std::string& reason);

} // namespace c7
} // namespace privacy

#endif // NEURAI_PRIVACY_C7_H
