// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_PRIVACY_PUBLICATION_H
#define NEURAI_PRIVACY_PUBLICATION_H

#include "privacy/primitives.h"

#include <optional>
#include <string>

namespace privacy {

/** NIP-045 note publication blob (port of c4-publication.js). */
constexpr size_t PUBLICATION_SIZE = 4096;

/** Poseidon pool context: domain, asset, quantum (10^0..10^8) and registry root. */
bool PoolContext(const Bytes32& domain, const Bytes32& assetId, uint64_t unit, Bytes32& ctx, std::string& error,
                 const Bytes32& registryRoot = Bytes32{});

/** Note records of a pool: C6 HPKE records (220 bytes published, 1024 in
 *  memory) or C7 records (230 bytes, version byte 0x02, view tag free). */
enum class RecordFormat { HPKE_CP1, C7 };

struct Publication {
    std::vector<Bytes32> cms;
    /** HPKE_CP1: full 1024-byte records; C7: 230-byte records. */
    std::vector<Bytes> records;
    std::optional<Bytes32> nf;
};

/** Forms: "D0", "D1" (deposits, one note, no nullifier) and "T1".."T4". */
bool EncodePublication(const std::string& form, const Publication& publication, Bytes& blob, std::string& error,
                       RecordFormat format = RecordFormat::HPKE_CP1);
bool DecodePublication(const std::string& form, const Bytes& blob, Publication& publication, std::string& error,
                       RecordFormat format = RecordFormat::HPKE_CP1);
bool PublicationHash(const std::string& form, const Bytes& blob, Bytes32& hash, std::string& error,
                     RecordFormat format = RecordFormat::HPKE_CP1);
/** Bytes one record takes in a publication, and whether a stored record is canonical. */
size_t PublishedRecordSize(RecordFormat format);
bool CanonicalRecord(const Bytes& record, RecordFormat format);

} // namespace privacy

#endif // NEURAI_PRIVACY_PUBLICATION_H
