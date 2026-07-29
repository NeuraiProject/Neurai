// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_ASSETDB_H
#define NEURAI_ASSETDB_H

#include "fs.h"
#include "serialize.h"

#include <string>
#include <map>
#include <dbwrapper.h>

const int8_t ASSET_UNDO_INCLUDES_VERIFIER_STRING = -1;

class CNewAsset;
class uint256;
class COutPoint;
class CDatabasedAssetData;

struct CBlockAssetUndo
{
    bool fChangedIPFS;
    bool fChangedUnits;
    std::string strIPFS;
    int32_t nUnits;
    int8_t version;
    bool fChangedVerifierString;
    std::string verifierString;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(fChangedUnits);
        READWRITE(fChangedIPFS);
        READWRITE(strIPFS);
        READWRITE(nUnits);
        if (ser_action.ForRead()) {
            if (!s.empty() and s.size() >= 1) {
                int8_t nVersionCheck;
                ::Unserialize(s, nVersionCheck);

                if (nVersionCheck == ASSET_UNDO_INCLUDES_VERIFIER_STRING) {
                    ::Unserialize(s, fChangedVerifierString);
                    ::Unserialize(s, verifierString);
                }
                version = nVersionCheck;
            }
        } else {
            ::Serialize(s, ASSET_UNDO_INCLUDES_VERIFIER_STRING);
            ::Serialize(s, fChangedVerifierString);
            ::Serialize(s, verifierString);
        }
    }
};

/** Access to the block database (blocks/index/) */
class CAssetsDB : public CDBWrapper
{
public:
    explicit CAssetsDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    CAssetsDB(const CAssetsDB&) = delete;
    CAssetsDB& operator=(const CAssetsDB&) = delete;

    // Write to database functions
    bool WriteAssetData(const CNewAsset& asset, const int nHeight, const uint256& blockHash);
    bool WriteAssetAddressQuantity(const std::string& assetName, const std::string& address, const CAmount& quantity);
    bool WriteAddressAssetQuantity( const std::string& address, const std::string& assetName, const CAmount& quantity);
    bool WriteBlockUndoAssetData(const uint256& blockhash, const std::vector<std::pair<std::string, CBlockAssetUndo> >& assetUndoData);
    bool WriteReissuedMempoolState();

    // Read from database functions
    bool ReadAssetData(const std::string& strName, CNewAsset& asset, int& nHeight, uint256& blockHash);
    bool ReadAssetAddressQuantity(const std::string& assetName, const std::string& address, CAmount& quantity);
    bool ReadAddressAssetQuantity(const std::string& address, const std::string& assetName, CAmount& quantity);
    bool ReadBlockUndoAssetData(const uint256& blockhash, std::vector<std::pair<std::string, CBlockAssetUndo> >& assetUndoData);
    bool ReadReissuedMempoolState();

    // Erase from database functions
    bool EraseAssetData(const std::string& assetName);
    bool EraseMyAssetData(const std::string& assetName);
    bool EraseAssetAddressQuantity(const std::string &assetName, const std::string &address);
    bool EraseAddressAssetQuantity(const std::string &address, const std::string &assetName);

    // Helper functions
    bool LoadAssets();
    bool AssetDir(std::vector<CDatabasedAssetData>& assets, const std::string filter, const size_t count, const long start);
    bool AssetDir(std::vector<CDatabasedAssetData>& assets);

    bool AddressDir(std::vector<std::pair<std::string, CAmount> >& vecAssetAmount, int& totalEntries, const bool& fGetTotal, const std::string& address, const size_t count, const long start);
    bool AssetAddressDir(std::vector<std::pair<std::string, CAmount> >& vecAddressAmount, int& totalEntries, const bool& fGetTotal, const std::string& assetName, const size_t count, const long start);

    /**
     * Holders of several assets in one pass, keyed by exact asset name.
     *
     * Exists so a caller that needs N assets at once (an ancestor chain, for
     * example) pays for one flush instead of N: unlike AssetAddressDir() this
     * function deliberately does NOT call FlushStateToDisk(). The caller must
     * flush once beforehand, under cs_main, and keep that lock while reading
     * so every asset resolves against the same chain state.
     *
     * Each name is matched with exact equality (key.second.first == assetName),
     * never by prefix: sharing leading characters does not make two assets
     * related, and LevelDB orders these keys by name LENGTH before content
     * anyway (Serialize(std::string) writes the length first), so a prefix scan
     * would be both wrong and expensive.
     *
     * maxRowsTotal bounds the (asset, address) rows accepted across all names.
     * Reading exactly maxRowsTotal rows is not an overflow; finding one more is,
     * and that sets hitRowLimit -- the scan then stops and the output is
     * incomplete. Callers must treat hitRowLimit as an error, not as a
     * truncated-but-usable result.
     *
     * Rows are sorted by address so the output does not depend on LevelDB's
     * physical ordering.
     */
    bool AssetAddressDirMulti(const std::vector<std::string>& assetNames,
                              std::map<std::string, std::vector<std::pair<std::string, CAmount> > >& out,
                              size_t maxRowsTotal,
                              bool& hitRowLimit);
};


#endif //NEURAI_ASSETDB_H
