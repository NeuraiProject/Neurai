// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_ADDRESSINDEX_H
#define NEURAI_ADDRESSINDEX_H

#include "uint256.h"
#include "amount.h"
#include "script/script.h"
#include "script/standard.h"

static const std::string XNA = "XNA";

struct CAddressUnspentKey {
    unsigned int type;
    std::vector<unsigned char> hashBytes;
    std::string asset;
    uint256 txhash;
    size_t index;

    size_t GetSerializeSize() const {
        return 37 + hashBytes.size() + asset.size();
    }
    template<typename Stream>
    void Serialize(Stream& s) const {
        ser_writedata8(s, type);
        hashBytes.Serialize(s);
        ::Serialize(s, asset);
        txhash.Serialize(s);
        ser_writedata32(s, index);
    }
    template<typename Stream>
    void Unserialize(Stream& s) {
        type = ser_readdata8(s);
        hashBytes.Unserialize(s);
        ::Unserialize(s, asset);
        txhash.Unserialize(s);
        index = ser_readdata32(s);
    }

    CAddressUnspentKey(const CDestinationIndexData& destination, uint256 txid, size_t indexValue) {
        type = destination.type;
        hashBytes = destination.payload;
        asset = XNA;
        txhash = txid;
        index = indexValue;
    }

    CAddressUnspentKey(const CDestinationIndexData& destination, std::string assetName, uint256 txid, size_t indexValue) {
        type = destination.type;
        hashBytes = destination.payload;
        asset = assetName;
        txhash = txid;
        index = indexValue;
    }

    CAddressUnspentKey() {
        SetNull();
    }

    void SetNull() {
        type = 0;
        hashBytes.clear();
        asset.clear();
        txhash.SetNull();
        index = 0;
    }
};

struct CAddressUnspentValue {
    CAmount satoshis;
    CScript script;
    int blockHeight;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(satoshis);
        READWRITE(*(CScriptBase*)(&script));
        READWRITE(blockHeight);
    }

    CAddressUnspentValue(CAmount sats, CScript scriptPubKey, int height) {
        satoshis = sats;
        script = scriptPubKey;
        blockHeight = height;
    }

    CAddressUnspentValue() {
        SetNull();
    }

    void SetNull() {
        satoshis = -1;
        script.clear();
        blockHeight = 0;
    }

    bool IsNull() const {
        return (satoshis == -1);
    }
};

struct CAddressIndexKey {
    unsigned int type;
    std::vector<unsigned char> hashBytes;
    std::string asset;
    int blockHeight;
    unsigned int txindex;
    uint256 txhash;
    size_t index;
    bool spending;

    size_t GetSerializeSize() const {
        return 14 + hashBytes.size() + asset.size();
    }
    template<typename Stream>
    void Serialize(Stream& s) const {
        ser_writedata8(s, type);
        hashBytes.Serialize(s);
        ::Serialize(s, asset);
        // Heights are stored big-endian for key sorting in LevelDB
        ser_writedata32be(s, blockHeight);
        ser_writedata32be(s, txindex);
        txhash.Serialize(s);
        ser_writedata32(s, index);
        char f = spending;
        ser_writedata8(s, f);
    }
    template<typename Stream>
    void Unserialize(Stream& s) {
        type = ser_readdata8(s);
        hashBytes.Unserialize(s);
        ::Unserialize(s, asset);
        blockHeight = ser_readdata32be(s);
        txindex = ser_readdata32be(s);
        txhash.Unserialize(s);
        index = ser_readdata32(s);
        char f = ser_readdata8(s);
        spending = f;
    }

    CAddressIndexKey(const CDestinationIndexData& destination, int height, int blockindex,
                     uint256 txid, size_t indexValue, bool isSpending) {
        type = destination.type;
        hashBytes = destination.payload;
        asset = XNA;
        blockHeight = height;
        txindex = blockindex;
        txhash = txid;
        index = indexValue;
        spending = isSpending;
    }

    CAddressIndexKey(const CDestinationIndexData& destination, std::string assetName, int height, int blockindex,
                     uint256 txid, size_t indexValue, bool isSpending) {
        type = destination.type;
        hashBytes = destination.payload;
        asset = assetName;
        blockHeight = height;
        txindex = blockindex;
        txhash = txid;
        index = indexValue;
        spending = isSpending;
    }

    CAddressIndexKey() {
        SetNull();
    }

    void SetNull() {
        type = 0;
        hashBytes.clear();
        asset.clear();
        blockHeight = 0;
        txindex = 0;
        txhash.SetNull();
        index = 0;
        spending = false;
    }

};

struct CAddressIndexIteratorKey {
    unsigned int type;
    std::vector<unsigned char> hashBytes;

    size_t GetSerializeSize() const {
        return 5 + hashBytes.size();
    }
    template<typename Stream>
    void Serialize(Stream& s) const {
        ser_writedata8(s, type);
        hashBytes.Serialize(s);
    }
    template<typename Stream>
    void Unserialize(Stream& s) {
        type = ser_readdata8(s);
        hashBytes.Unserialize(s);
    }

    explicit CAddressIndexIteratorKey(const CDestinationIndexData& destination) {
        type = destination.type;
        hashBytes = destination.payload;
    }

    CAddressIndexIteratorKey() {
        SetNull();
    }

    void SetNull() {
        type = 0;
        hashBytes.clear();
    }
};

struct CAddressIndexIteratorAssetKey {
    unsigned int type;
    std::vector<unsigned char> hashBytes;
    std::string asset;

    size_t GetSerializeSize() const {
        return 5 + hashBytes.size() + asset.size();
    }
    template<typename Stream>
    void Serialize(Stream& s) const {
        ser_writedata8(s, type);
        hashBytes.Serialize(s);
        ::Serialize(s, asset);
    }
    template<typename Stream>
    void Unserialize(Stream& s) {
        type = ser_readdata8(s);
        hashBytes.Unserialize(s);
        ::Unserialize(s, asset);
    }

    explicit CAddressIndexIteratorAssetKey(const CDestinationIndexData& destination) {
        type = destination.type;
        hashBytes = destination.payload;
        asset = XNA;
    }

    CAddressIndexIteratorAssetKey(const CDestinationIndexData& destination, std::string assetName) {
        type = destination.type;
        hashBytes = destination.payload;
        asset = assetName;
    }

    CAddressIndexIteratorAssetKey() {
        SetNull();
    }

    void SetNull() {
        type = 0;
        hashBytes.clear();
        asset.clear();
    }
};

struct CAddressIndexIteratorHeightKey {
    unsigned int type;
    std::vector<unsigned char> hashBytes;
    std::string asset;
    int blockHeight;

    size_t GetSerializeSize() const {
        return 9 + hashBytes.size() + asset.size();
    }
    template<typename Stream>
    void Serialize(Stream& s) const {
        ser_writedata8(s, type);
        hashBytes.Serialize(s);
        ::Serialize(s, asset);
        ser_writedata32be(s, blockHeight);
    }
    template<typename Stream>
    void Unserialize(Stream& s) {
        type = ser_readdata8(s);
        hashBytes.Unserialize(s);
        ::Unserialize(s, asset);
        blockHeight = ser_readdata32be(s);
    }

    CAddressIndexIteratorHeightKey(const CDestinationIndexData& destination, int height) {
        type = destination.type;
        hashBytes = destination.payload;
        asset = XNA;
        blockHeight = height;
    }

    CAddressIndexIteratorHeightKey(const CDestinationIndexData& destination, std::string assetName, int height) {
        type = destination.type;
        hashBytes = destination.payload;
        asset = assetName;
        blockHeight = height;
    }

    CAddressIndexIteratorHeightKey() {
        SetNull();
    }

    void SetNull() {
        type = 0;
        hashBytes.clear();
        asset.clear();
        blockHeight = 0;
    }
};

struct CMempoolAddressDelta
{
    int64_t time;
    CAmount amount;
    uint256 prevhash;
    unsigned int prevout;

    CMempoolAddressDelta(int64_t t, CAmount a, uint256 hash, unsigned int out) {
        time = t;
        amount = a;
        prevhash = hash;
        prevout = out;
    }

    CMempoolAddressDelta(int64_t t, CAmount a) {
        time = t;
        amount = a;
        prevhash.SetNull();
        prevout = 0;
    }
};

struct CMempoolAddressDeltaKey
{
    int type;
    std::vector<unsigned char> addressBytes;
    std::string asset;
    uint256 txhash;
    unsigned int index;
    int spending;

    CMempoolAddressDeltaKey(const CDestinationIndexData& destination, std::string assetName,
                            uint256 hash, unsigned int i, int s) {
        type = destination.type;
        addressBytes = destination.payload;
        asset = assetName;
        txhash = hash;
        index = i;
        spending = s;
    }

    CMempoolAddressDeltaKey(const CDestinationIndexData& destination, uint256 hash, unsigned int i, int s) {
        type = destination.type;
        addressBytes = destination.payload;
        asset = "";
        txhash = hash;
        index = i;
        spending = s;
    }

    CMempoolAddressDeltaKey(const CDestinationIndexData& destination, std::string assetName) {
        type = destination.type;
        addressBytes = destination.payload;
        asset = assetName;
        txhash.SetNull();
        index = 0;
        spending = 0;
    }

    explicit CMempoolAddressDeltaKey(const CDestinationIndexData& destination) {
        type = destination.type;
        addressBytes = destination.payload;
        asset = "";
        txhash.SetNull();
        index = 0;
        spending = 0;
    }
};

struct CMempoolAddressDeltaKeyCompare
{
    bool operator()(const CMempoolAddressDeltaKey& a, const CMempoolAddressDeltaKey& b) const {
        if (a.type == b.type) {
            if (a.addressBytes == b.addressBytes) {
                if (a.asset == b.asset) {
                    if (a.txhash == b.txhash) {
                        if (a.index == b.index) {
                            return a.spending < b.spending;
                        } else {
                            return a.index < b.index;
                        }
                    } else {
                        return a.txhash < b.txhash;
                    }
                } else {
                    return a.asset < b.asset;
                }
            } else {
                return a.addressBytes < b.addressBytes;
            }
        } else {
            return a.type < b.type;
        }
    }
};

#endif // NEURAI_ADDRESSINDEX_H
