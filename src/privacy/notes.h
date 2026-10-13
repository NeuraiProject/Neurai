// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_PRIVACY_NOTES_H
#define NEURAI_PRIVACY_NOTES_H

#include "privacy/primitives.h"

#include <string>

namespace privacy {

/** NIP-043 CP1 notes and their HPKE note records (port of notes.js and hpke.js). */
constexpr size_t NOTE_SIZE = 169;
constexpr size_t RECORD_SIZE = 1024;
constexpr size_t RECORD_USED = 220;
constexpr uint64_t MAX_NOTE_AMOUNT = 2100000000000000000ULL;

/** Receiving descriptor of one address in one pool instance. */
struct Recipient {
    Bytes32 domain{};
    Bytes32 assetId{};
    Bytes32 owner{};
    Bytes32 viewPub{};
};

struct Note {
    Bytes32 domain{};
    Bytes32 assetId{};
    Bytes32 owner{};
    Bytes32 viewPub{};
    uint64_t amount = 0;
    Bytes32 rho{};
};

/** version || domain || asset || owner || view pubkey || u64LE amount || rho. */
bool EncodeNote(const Note& note, Bytes& out, std::string& error);
bool DecodeNote(const Bytes& encoded, Note& note, std::string& error);

Bytes32 DeriveOwner(const Bytes32& domain, const Bytes32& spendSecret);
Bytes32 DeriveNullifierKey(const Bytes32& domain, const Bytes32& spendSecret);
bool NoteCommitment(const Bytes& encoded, Bytes32& cm, std::string& error);
/** Refuses a note that the spend secret does not own. */
bool NoteNullifier(const Bytes& encoded, const Bytes32& spendSecret, Bytes32& nf, std::string& error);

/** Canonical, non-zero u-coordinate below 2^255 - 19. */
bool IsValidViewPublic(const Bytes32& viewPub);
Bytes32 DeriveViewPublic(const Bytes32& viewSeed);
Recipient RecipientFor(const Bytes32& domain, const Bytes32& assetId, const Bytes32& spendSecret, const Bytes32& viewSeed);

struct SealedNote {
    Bytes note;
    Bytes32 cm{};
    Bytes record;
};

/** Seals a fresh note for a recipient. ikm and rho come from the strong random
 *  source unless given (fixed values are for test vectors only). */
bool SealNote(const Recipient& recipient, uint64_t amount, SealedNote& out, std::string& error,
              const Bytes32* ikm = nullptr, const Bytes32* rho = nullptr);

struct OpenedNote {
    Bytes note;
    Bytes32 cm{};
    uint64_t amount = 0;
    Bytes32 nf{};
};

/** Decrypts a 1024-byte record addressed to viewSeed and checks it against the
 *  pool, the commitment and the owner derived from spendSecret. */
bool OpenNoteRecord(const Bytes& record, const Bytes32& cm, const Bytes32& domain, const Bytes32& assetId,
                    const Bytes32& viewSeed, const Bytes32& spendSecret, OpenedNote& out, std::string& error);

namespace hpke {
/** RFC 9180 DHKEM(X25519, HKDF-SHA256) and base-mode key schedule, exposed for test vectors. */
void DeriveKeyPair(const Bytes32& ikm, Bytes32& secret, Bytes32& publicKey);
bool Shared(const Bytes32& secret, const Bytes32& peer, const Bytes32& enc, const Bytes32& recipient, Bytes32& out);
void Schedule(const Bytes32& shared, const Bytes& info, Bytes32& key, std::array<uint8_t, 12>& nonce);
} // namespace hpke

} // namespace privacy

#endif // NEURAI_PRIVACY_NOTES_H
