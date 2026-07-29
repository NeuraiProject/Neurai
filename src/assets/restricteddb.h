// Copyright (c) 2019 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef NEURAICOIN_RESTRICTEDDB_H
#define NEURAICOIN_RESTRICTEDDB_H

#include <dbwrapper.h>

#include <set>
#include <string>
#include <vector>

class CRestrictedDB  : public CDBWrapper {

public:
    explicit CRestrictedDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    CRestrictedDB(const CRestrictedDB&) = delete;
    CRestrictedDB& operator=(const CRestrictedDB&) = delete;

    // Database of restricted asset verifier strings
    bool WriteVerifier(const std::string& assetName, const std::string& verifier);
    bool ReadVerifier(const std::string& assetName, std::string& verifier);
    bool EraseVerifier(const std::string& assetName);

    // Database of Addresses and the Tag that are assigned to them
    bool WriteAddressQualifier(const std::string &address, const std::string &tag);
    bool ReadAddressQualifier(const std::string &address, const std::string &tag);
    bool EraseAddressQualifier(const std::string &address, const std::string &tag);

    // Database of the Qualifier to the address that are assigned to them
    bool WriteQualifierAddress(const std::string &address, const std::string &tag);
    bool ReadQualifierAddress(const std::string &address, const std::string &tag);
    bool EraseQualifierAddress(const std::string &address, const std::string &tag);

    // Database of Blacklist addresses
    bool WriteRestrictedAddress(const std::string& address, const std::string& assetName);
    bool ReadRestrictedAddress(const std::string& address, const std::string& assetName);
    bool EraseRestrictedAddress(const std::string& address, const std::string& assetName);

    // Database of Restricted Trading Global Off
    bool WriteGlobalRestriction(const std::string& assetName);
    bool ReadGlobalRestriction(const std::string& assetName);
    bool EraseGlobalRestriction(const std::string& assetName);

    // Database of Self-Restrictions (DEPIN self-revocation)
    bool WriteSelfRestriction(const std::string& address, const std::string& assetName);
    bool ReadSelfRestriction(const std::string& address, const std::string& assetName);
    bool EraseSelfRestriction(const std::string& address, const std::string& assetName);

    // Write / Read Database flags
    bool WriteFlag(const std::string &name, bool fValue);
    bool ReadFlag(const std::string &name, bool &fValue);

    bool GetQualifierAddresses(std::string& qualifier, std::vector<std::string>& addresses);
    bool GetAddressQualifiers(std::string& address, std::vector<std::string>& qualifiers);
    bool GetAddressRestrictions(std::string& address, std::vector<std::string>& restrictions);
    bool GetGlobalRestrictions(std::vector<std::string>& restrictions);

    /**
     * Both ways a DEPIN asset can be blocked for one address, in a single call:
     * ownerFrozen  -- the token owner froze this address (RESTRICTED_ADDRESS_FLAG)
     * selfRevoked  -- the holder revoked itself       (SELF_RESTRICTED_FLAG)
     *
     * Restriction keys are (FLAG, (address, assetName)), so every restriction of
     * one address is contiguous within its flag. This does two ranged seeks --
     * one per flag, sharing a single iterator so both see the same snapshot --
     * instead of one point read per (asset, address) pair. Membership is then
     * resolved in memory by the caller, which keeps the cost per address
     * independent of how many assets it is checked against.
     *
     * It cannot be expressed as two calls to GetAddressRestrictions(): that one
     * only scans RESTRICTED_ADDRESS_FLAG (there is no ranged read of
     * SELF_RESTRICTED_FLAG anywhere else), and it starts with an unconditional
     * FlushStateToDisk(). This function deliberately does NOT flush -- a caller
     * looping over addresses would otherwise trigger one global flush per
     * address. Flush once beforehand, under cs_main, and hold that lock.
     *
     * Note this reads the database only. Restrictions added by the current
     * block and not yet dumped live in CAssetsCache's pending sets; flushing
     * before the call is what makes the database the authority.
     */
    bool GetAddressDepinRestrictions(const std::string& address,
                                     std::set<std::string>& ownerFrozen,
                                     std::set<std::string>& selfRevoked);

    bool CheckForAddressRootQualifier(const std::string& address, const std::string& qualifier);

    bool Flush();
};


#endif //NEURAICOIN_RESTRICTEDDB_H
