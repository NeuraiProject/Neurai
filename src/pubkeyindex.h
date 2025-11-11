// Copyright (c) 2024 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_PUBKEYINDEX_H
#define NEURAI_PUBKEYINDEX_H

#include "pubkey.h"
#include "uint256.h"
#include "serialize.h"

/**
 * Public Key Index
 *
 * This index tracks addresses that have revealed their public keys by spending.
 * When an address spends (creates a transaction input), the scriptSig reveals
 * the public key, which can then be used for encryption purposes (e.g., ECIES).
 *
 * The index maps: address hash (uint160) -> public key + metadata
 */

struct CPubKeyIndexKey {
    uint160 addressHash;

    CPubKeyIndexKey() {
        SetNull();
    }

    explicit CPubKeyIndexKey(uint160 addressHashIn) {
        addressHash = addressHashIn;
    }

    void SetNull() {
        addressHash.SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(addressHash);
    }
};

struct CPubKeyIndexValue {
    CPubKey pubkey;      // The revealed public key (33 or 65 bytes)
    int nHeight;         // Block height where pubkey was first revealed
    uint256 txid;        // Transaction ID where it was revealed

    CPubKeyIndexValue() {
        SetNull();
    }

    CPubKeyIndexValue(const CPubKey& pubkeyIn, int nHeightIn, const uint256& txidIn) {
        pubkey = pubkeyIn;
        nHeight = nHeightIn;
        txid = txidIn;
    }

    void SetNull() {
        pubkey = CPubKey();
        nHeight = 0;
        txid.SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(pubkey);
        READWRITE(nHeight);
        READWRITE(txid);
    }
};

#endif // NEURAI_PUBKEYINDEX_H
