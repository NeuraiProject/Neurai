// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#include "depinmembership.h"
#include "amount.h"
#include "assets/assetdb.h"
#include "assets/assets.h"
#include "base58.h"
#include "depinchallenge.h"
#include "depinmsgpool.h"
#include "random.h"
#include "txdb.h"
#include "util.h"
#include "utilstrencodings.h"
#include "validation.h"

namespace {
DepinMembershipContext context;
std::string contextRoot;
uint256 observedTip;
// Bound the extra observer work, independently of the directory's page size.
const size_t MAX_MEMBERSHIP_SCAN_ROWS = 10000;

uint256 TipHash() { return chainActive.Tip() ? chainActive.Tip()->GetBlockHash() : uint256(); }

bool InScope(std::string name, const std::string& root)
{
    if (!name.empty() && name.back() == '!') name.pop_back();
    return IsDepinSectionOrRoot(name, root);
}

void Renew(const std::string& root, bool invalidate)
{
    unsigned char bytes[32];
    GetStrongRandBytes(bytes, sizeof(bytes));
    context.revision = HexStr(bytes, bytes + sizeof(bytes));
    context.block = TipHash().ToString();
    context.height = chainActive.Height();
    contextRoot = root;
    observedTip = TipHash();
    if (invalidate) g_depinChallenges.Clear(); // RECEIVE and ADMIN, same pool.
}

bool AnchorIsActive()
{
    return context.height < 0 || (context.height <= chainActive.Height() &&
        chainActive[context.height]->GetBlockHash().ToString() == context.block);
}
}

DepinMembershipContext GetDepinMembershipContext()
{
    LOCK(cs_main);
    const auto root = pDepinMsgPool ? pDepinMsgPool->GetActiveToken() : "";
    if (context.revision.empty()) Renew(root, false);
    else if (root != contextRoot || observedTip != TipHash() || !AnchorIsActive()) Renew(root, true);
    return context;
}

void ResetDepinMembershipContext()
{
    LOCK(cs_main);
    context = DepinMembershipContext();
    contextRoot.clear();
    observedTip.SetNull();
}

bool IsDepinMembershipTracking()
{
    LOCK(cs_main);
    return pDepinMsgPool && pDepinMsgPool->IsEnabled() && !context.revision.empty();
}

void CaptureDepinMembershipKeys(
    const std::vector<std::pair<CPubKeyIndexKey, CPubKeyIndexValue>>& keys,
    std::set<std::string>& revealed)
{
    AssertLockHeld(cs_main);
    if (!IsDepinMembershipTracking() || !pblocktree) return;
    for (const auto& item : keys) {
        const auto& key = item.second.pubkey;
        if (item.first.addressType != DEST_INDEX_KEY || !key.IsFullyValid()) continue;
        CDestinationIndexData destination;
        if (!GetDestinationIndexData(CTxDestination(key.GetID()), destination) ||
            destination.payload != item.first.addressHash) continue;
        CPubKeyIndexValue previous;
        if (!pblocktree->ReadPubKeyIndex(destination, previous) || previous.pubkey != key)
            revealed.insert(EncodeDestination(key.GetID()));
    }
}

bool DepinMembershipAffected(const CAssetsCache& changes, const std::set<std::string>& revealed)
{
    AssertLockHeld(cs_main);
    if (!IsDepinMembershipTracking()) return false;
    const auto root = pDepinMsgPool->GetActiveToken();
    if (root != contextRoot) return true;
    // Local per-block cache, never the accumulated global dirty cache: an
    // unrelated block must not keep repeating an earlier notification.
    for (const auto& item : changes.mapAssetsAddressAmount) if (InScope(item.first.first, root)) return true;
    for (const auto& item : changes.setNewAssetsToAdd) if (InScope(item.asset.strName, root)) return true;
    for (const auto& item : changes.setNewAssetsToRemove) if (InScope(item.asset.strName, root)) return true;
    const auto scoped = [&](const auto& entries) {
        for (const auto& item : entries) if (InScope(item.assetName, root)) return true;
        return false;
    };
    if (scoped(changes.setNewOwnerAssetsToAdd) || scoped(changes.setNewOwnerAssetsToRemove) ||
        scoped(changes.setNewRestrictedAddressToAdd) || scoped(changes.setNewRestrictedAddressToRemove) ||
        scoped(changes.setNewRestrictedGlobalToAdd) || scoped(changes.setNewRestrictedGlobalToRemove) ||
        scoped(changes.setNewSelfRestrictionToAdd) || scoped(changes.setNewSelfRestrictionToRemove) ||
        scoped(changes.setNewDepinStateToAdd) || scoped(changes.setNewDepinStateToRemove)) return true;
    if (revealed.empty()) return false;
    // A first Legacy key reveal changes the usable directory only if that
    // address holds a served asset/owner token. Merge dirty balances without a
    // chainstate flush. A bounded/incomplete observation invalidates conservatively.
    if (!passets || !passetsdb) return true;
    size_t budget = MAX_MEMBERSHIP_SCAN_ROWS;
    auto it = passets->mapAssetsAddressAmount.lower_bound({root, ""});
    for (; it != passets->mapAssetsAddressAmount.end() &&
           it->first.first.compare(0, root.size(), root) == 0; ++it) {
        if (!budget) return true;
        --budget;
        if (it->second > 0 && InScope(it->first.first, root) && revealed.count(it->first.second)) return true;
    }
    for (const auto& address : revealed) {
        std::vector<std::pair<std::string, CAmount>> rows;
        bool limited = false;
        if (!passetsdb->ReadAddressAssets(address, budget, rows, limited) || limited) return true;
        for (const auto& row : rows) {
            if (!InScope(row.first, root)) continue;
            const auto dirty = passets->mapAssetsAddressAmount.find({row.first, address});
            if ((dirty == passets->mapAssetsAddressAmount.end() ? row.second : dirty->second) > 0) return true;
        }
    }
    return false;
}

void NotifyDepinMembershipTip(const uint256& previousTip, bool relevant)
{
    AssertLockHeld(cs_main);
    if (!IsDepinMembershipTracking()) return;
    const auto root = pDepinMsgPool->GetActiveToken();
    if (relevant || root != contextRoot || observedTip != previousTip || !AnchorIsActive()) Renew(root, true);
    else observedTip = TipHash();
}
