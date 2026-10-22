// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#ifndef NEURAI_DEPINADDRESS_H
#define NEURAI_DEPINADDRESS_H

#include "pubkey.h"
#include "serialize.h"
#include "uint256.h"
#include <algorithm>
#include <string>
#include <cstdint>
#include <ios>

class CKeyStore;

// Exact destination identity, not the hash of the encryption key. The same
// secp256k1 key may own two different destinations with different permissions.
class DepinRecipient {
    uint8_t type = 0; // 0: Legacy P2PKH; 3: strict ECDSA witness v3.
    uint256 payload;
public:
    DepinRecipient() = default;
    DepinRecipient(const uint160& id) { std::copy(id.begin(), id.end(), payload.begin()); }
    static bool FromAddress(const std::string& address, DepinRecipient& out);
    std::string Address() const;
    bool IsLegacy() const { return type == 0; }
    uint160 LegacyID() const { uint160 id; std::copy(payload.begin(), payload.begin() + 20, id.begin()); return id; }
    friend bool operator<(const DepinRecipient& a, const DepinRecipient& b) {
        return a.type != b.type ? a.type < b.type : a.payload < b.payload;
    }
    friend bool operator==(const DepinRecipient& a, const DepinRecipient& b) { return a.type == b.type && a.payload == b.payload; }

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(type);
        if (type == 0) {
            uint160 id = LegacyID();
            READWRITE(id);
            if (ser_action.ForRead()) { payload.SetNull(); std::copy(id.begin(), id.end(), payload.begin()); }
        } else if (type == 3) READWRITE(payload);
        else throw std::ios_base::failure("unsupported DePIN recipient type");
    }
};

bool DepinPubKeyMatchesAddress(const std::string& address, const CPubKey& pubkey);
// Caller holds the wallet/keystore lock. Strict destinations use the wallet's
// AuthScript spend data and are checked against the actual public key.
bool GetDepinKeyID(const CKeyStore& store, const std::string& address, CKeyID& key);
#endif
