// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#ifndef NEURAI_DEPINMEMBERSHIP_H
#define NEURAI_DEPINMEMBERSHIP_H

#include "pubkeyindex.h"
#include "uint256.h"
#include <cstdint>
#include <set>
#include <string>
#include <vector>

class CAssetsCache;

struct DepinMembershipContext {
    std::string revision;
    std::string block;
    int64_t height = -1;
};

// One local epoch per configured pool, separate from the RPC process instance.
// These functions serialize with authorization and chain transitions via cs_main.
DepinMembershipContext GetDepinMembershipContext();
void ResetDepinMembershipContext();
bool IsDepinMembershipTracking();

// Called only for the real ConnectTip path, before overwriting the key index.
// No notification is emitted by block-validity checks or mempool transactions.
void CaptureDepinMembershipKeys(
    const std::vector<std::pair<CPubKeyIndexKey, CPubKeyIndexValue>>& keys,
    std::set<std::string>& revealed);
bool DepinMembershipAffected(const CAssetsCache& changes,
                             const std::set<std::string>& revealed = {});
// Publish only after the connected/disconnected state and chainActive agree.
void NotifyDepinMembershipTip(const uint256& previousTip, bool relevant);

#endif
