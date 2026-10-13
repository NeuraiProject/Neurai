// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_PRIVACY_C6_CONFIG_H
#define NEURAI_PRIVACY_C6_CONFIG_H

#include "privacy/primitives.h"

#include <map>
#include <string>

namespace privacy {

/** One MAST leaf of the pool contract and its control block. */
struct C6Leaf {
    std::string form;
    Bytes script;
    std::vector<std::string> args;
    Bytes control; //!< 0x01 || sibling hashes
};

struct C6Artifact {
    std::string wasm, zkey;
    Bytes32 wasmSha256{}, zkeySha256{};
    uint64_t wasmBytes = 0, zkeyBytes = 0;
};

/** Pinned C6 XNA pool instance (the web wallet's c6-testnet.json). */
struct C6Config {
    std::string profile;
    std::string identity;   //!< state thread identity, e.g. C6TEST261004A#POOL
    std::string network;    //!< "testnet"
    Bytes32 genesis{};      //!< genesis hash, internal byte order (manifest.network)
    Bytes32 commitment{};   //!< MAST commitment of the state contract
    Bytes32 context{};
    Bytes32 domain{};
    Bytes32 assetId{};
    std::map<std::string, Bytes> vks;                 //!< node-format verifying keys per operation
    std::map<std::string, std::vector<uint64_t>> fees; //!< approved fee levels per operation
    std::map<std::string, C6Artifact> artifacts;       //!< proving artifacts per operation

    int anchorHeight = 0;
    Bytes32 anchorHash{};     //!< block hash, internal byte order
    Bytes32 anchorTxid{};     //!< internal byte order
    uint32_t anchorVout = 0;
    Bytes anchorOpening;
    Bytes anchorScript;
    std::vector<C6Leaf> leaves;

    const C6Leaf* Leaf(const std::string& form) const;
    /** State output script committing to a 145-byte opening. */
    Bytes StateScript(const Bytes& opening) const;
    /** Reserve guard script and the AuthScript v1 output that commits to it. */
    Bytes ReserveGuard() const;
    Bytes ReserveScript() const;
};

/** Parses and checks a C6 config: profile, pins, VK digests, pool context, MAST
 *  commitment and birth opening. */
bool LoadC6Config(const std::string& json, C6Config& config, std::string& error);

/** sha256(sha256(tag) || sha256(tag) || data). */
Bytes32 TaggedHash(const std::string& tag, const Bytes& data);

} // namespace privacy

#endif // NEURAI_PRIVACY_C6_CONFIG_H
