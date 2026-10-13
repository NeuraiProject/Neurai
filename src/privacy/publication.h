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

struct Publication {
    std::vector<Bytes32> cms;
    /** Full 1024-byte note records. */
    std::vector<Bytes> records;
    std::optional<Bytes32> nf;
};

/** Forms: "D0", "D1" (deposits, one note, no nullifier) and "T1".."T4". */
bool EncodePublication(const std::string& form, const Publication& publication, Bytes& blob, std::string& error);
bool DecodePublication(const std::string& form, const Bytes& blob, Publication& publication, std::string& error);
bool PublicationHash(const std::string& form, const Bytes& blob, Bytes32& hash, std::string& error);

} // namespace privacy

#endif // NEURAI_PRIVACY_PUBLICATION_H
