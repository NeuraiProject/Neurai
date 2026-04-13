// Copyright (c) 2024 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_PUBKEYINDEX_H
#define NEURAI_PUBKEYINDEX_H

#include "pubkey.h"
#include "uint256.h"
#include "serialize.h"
#include "script/standard.h"

/**
 * Public Key Index
 *
 * This index tracks addresses that have revealed their public keys by spending.
 * When an address spends, the pubkey is revealed either in scriptSig (legacy)
 * or in scriptWitness (PQ witness), and can then be used for encryption
 * purposes (e.g., ECIES).
 *
 * The index maps: indexed destination payload -> public key + metadata
 */

struct CPubKeyIndexKey {
    int addressType;
    std::vector<unsigned char> addressHash;

    CPubKeyIndexKey() {
        SetNull();
    }

    explicit CPubKeyIndexKey(const CDestinationIndexData& addressData) {
        addressType = addressData.type;
        addressHash = addressData.payload;
    }

    void SetNull() {
        addressType = DEST_INDEX_NONE;
        addressHash.clear();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(addressType);
        READWRITE(addressHash);
    }
};

struct CPubKeyIndexValue {
    CPubKey pubkey;      // The revealed public key (legacy secp256k1 or PQ)
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
