// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NIP-047 wallet integration: identity, scanner, cursor and constructor.
// Protocol primitives live in wallet/silentpayments.cpp.

#include "wallet/wallet.h"

#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include <init.h> // ShutdownRequested (src/init.h, not wallet/init.h)
#include "policy/policy.h"
#include "policy/rbf.h"
#include "random.h"
#include "scheduler.h"
#include "script/standard.h"
#include "support/cleanse.h"
#include "txmempool.h"
#include "undo.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utiltime.h"
#include "validation.h"
#include "wallet/coincontrol.h"
#include "wallet/fees.h"

#include <algorithm>

namespace {

const CBlockIndex* LookupBlockIndex(const uint256& hash)
{
    BlockMap::const_iterator it = mapBlockIndex.find(hash);
    return it == mapBlockIndex.end() ? nullptr : it->second;
}

/** Estimated virtual size: version, locktime, counts and segwit marker, plus
 *  one strict v3 input (41 base bytes and a 4-item witness) or v3 output. */
unsigned int EstimateVsize(size_t nInputs, size_t nOutputs)
{
    return 11 + 69 * nInputs + 43 * nOutputs;
}

} // namespace

void CWallet::LoadSilentPayment(const COutPoint& outpoint, const silentpayments::PaymentRecord& record)
{
    mapSilentPayments[outpoint] = record;
    const CScript script = silentpayments::PaymentScript(record.key);
    if (!script.empty()) setSilentPaymentScripts.insert(script);
}

void CWallet::LoadSilentPaymentCursor(int height, const uint256& blockHash)
{
    nSilentPaymentHeight = height;
    hashSilentPaymentBlock = blockHash;
    fSilentPaymentCursorLoaded = true;
}

void CWallet::LoadSilentPaymentCode(const CPubKey& scanKey, const CPubKey& spendKey)
{
    silentPaymentScanPub = scanKey;
    silentPaymentSpendPub = spendKey;
}

bool CWallet::LoadSilentPaymentViewKey(const std::vector<unsigned char>& scanSecret, const CPubKey& spendKey)
{
    CKey scan;
    scan.Set(scanSecret.begin(), scanSecret.end(), true);
    bool valid = scan.IsValid() && spendKey.IsFullyValid() && spendKey.IsCompressed();
    if (valid) {
        const CPubKey scanPub = scan.GetPubKey();
        valid = !std::equal(scanPub.begin() + 1, scanPub.end(), spendKey.begin() + 1);
    }
    if (!valid) {
        // Keep the wallet loadable, but show a damaged identity instead of a
        // wallet that never had one.
        fSilentPaymentViewKeyCorrupt = true;
        silentPaymentViewScan = CKey();
        silentPaymentViewSpend = CPubKey();
        return false;
    }
    fSilentPaymentViewKeyCorrupt = false;
    silentPaymentViewScan = scan;
    silentPaymentViewSpend = spendKey;
    return true;
}

bool CWallet::HasSilentPaymentIdentity() const
{
    return IsSilentPaymentViewOnly() || (GetAddressType() == WalletAddressType::ECDSA && IsBip44Enabled());
}

std::string CWallet::GetSilentPaymentIdentityError() const
{
    if (fSilentPaymentViewKeyCorrupt) {
        return "The stored silent payment view key is invalid; import a valid view key again with importsilentpaymentviewkey";
    }
    return strSilentPaymentIdentityError;
}

bool CWallet::IsSilentPaymentScript(const CScript& script) const
{
    LOCK(cs_wallet);
    return setSilentPaymentScripts.count(script) != 0;
}

bool CWallet::LoadSilentPaymentKey(const CKey& key, const CPubKey& pubkey, const CKeyMetadata& meta)
{
    LOCK(cs_wallet);
    setSilentPaymentKeys.insert(pubkey.GetID());
    LoadKeyMetadata(pubkey.GetID(), meta);
    return LoadKey(key, pubkey);
}

bool CWallet::LoadSilentPaymentCryptedKey(const CPubKey& pubkey, const std::vector<unsigned char>& cryptedSecret, const CKeyMetadata& meta)
{
    LOCK(cs_wallet);
    setSilentPaymentKeys.insert(pubkey.GetID());
    LoadKeyMetadata(pubkey.GetID(), meta);
    return LoadCryptedKey(pubkey, cryptedSecret);
}

bool CWallet::IsSilentPaymentKey(const CKeyID& keyID) const
{
    LOCK(cs_wallet);
    return setSilentPaymentKeys.count(keyID) != 0;
}

bool CWallet::IsSilentPaymentCoin(const COutPoint& outpoint) const
{
    LOCK(cs_wallet);
    return mapSilentPayments.count(outpoint) != 0;
}

bool CWallet::GetSilentPaymentBalance(CAmount& available, CAmount& pending, bool& watchOnly, int* unspent) const
{
    LOCK2(cs_main, cs_wallet);
    available = pending = 0;
    if (unspent) *unspent = 0;
    watchOnly = IsSilentPaymentViewOnly();
    for (const auto& entry : mapSilentPayments) {
        const COutPoint& outpoint = entry.first;
        const auto it = mapWallet.find(outpoint.hash);
        if (it == mapWallet.end() || outpoint.n >= it->second.tx->vout.size()) continue;
        const CWalletTx& wtx = it->second;
        const CTxOut& txout = wtx.tx->vout[outpoint.n];
        if (IsSpent(outpoint.hash, outpoint.n) || !(IsMine(txout) & ISMINE_ALL)) continue;
        if (wtx.IsTrusted()) {
            available += txout.nValue;
        } else if (wtx.GetDepthInMainChain() == 0 && wtx.InMempool()) {
            pending += txout.nValue;
        } else {
            continue;
        }
        if (unspent) ++*unspent;
    }
    return !mapSilentPayments.empty();
}

std::vector<std::vector<size_t>> CWallet::SilentPaymentSelectionGroups(const std::vector<COutPoint>& coins,
                                                                       const std::vector<COutPoint>& preset) const
{
    LOCK(cs_wallet);
    std::vector<size_t> all, other;
    std::vector<std::pair<CAmount, size_t>> received;
    for (size_t i = 0; i < coins.size(); ++i) {
        all.push_back(i);
        if (!IsSilentPaymentCoin(coins[i])) {
            other.push_back(i);
            continue;
        }
        const auto it = mapWallet.find(coins[i].hash);
        const bool known = it != mapWallet.end() && coins[i].n < it->second.tx->vout.size();
        received.emplace_back(known ? it->second.tx->vout[coins[i].n].nValue : 0, i);
    }
    const bool presetReceived = std::any_of(preset.begin(), preset.end(),
                                            [this](const COutPoint& outpoint) { return IsSilentPaymentCoin(outpoint); });
    // No silent payment involved: selection as before.
    if (received.empty() && !presetReceived) return {all};

    std::vector<std::vector<size_t>> groups;
    if (presetReceived) {
        // A chosen payment is not completed with any other coin.
        groups.emplace_back();
    } else if (!preset.empty()) {
        // Chosen ordinary coins are only completed with ordinary coins.
        groups.push_back(other);
    } else {
        // Ordinary coins together; each received payment on its own, the
        // smallest that covers the amount first.
        if (!other.empty()) groups.push_back(other);
        std::sort(received.begin(), received.end());
        for (const auto& payment : received) groups.push_back({payment.second});
    }
    if (gArgs.GetBoolArg("-mixsilentpayments", DEFAULT_MIX_SILENT_PAYMENTS)) groups.push_back(all);
    return groups;
}

std::string CWallet::SilentPaymentMixRefusal()
{
    return _("Insufficient funds without combining received silent payments with each other or with other coins, which would "
             "link them on the blockchain. Choose the coins to spend with coin control, or start the wallet with -mixsilentpayments "
             "to allow it.");
}

bool CWallet::SilentPaymentsPaused() const
{
    return HasSilentPaymentIdentity() && !IsSilentPaymentViewOnly() && IsCrypted() && IsLocked();
}

int CWallet::GetSilentPaymentCursor(uint256* blockHash) const
{
    if (blockHash) *blockHash = hashSilentPaymentBlock;
    return nSilentPaymentHeight;
}

bool CWallet::SetSilentPaymentIdentityFailure(const std::string& reason)
{
    AssertLockHeld(cs_wallet);
    strSilentPaymentIdentityError = reason;
    silentPaymentKeyCache.reset();
    fSilentPaymentCodeVerified = false;
    LogPrintf("SilentPayments: identity check failed: %s\n", reason);
    return CWalletDB(*dbw).WriteSilentPaymentIdentityFailure(reason);
}

bool CWallet::DeriveSilentPaymentAccountKeys(silentpayments::AccountKeys& keys, std::string& error)
{
    AssertLockHeld(cs_wallet);
    SecureVector seed;
    {
        LOCK(cs_KeyStore);
        seed = g_vchSeed;
    }
    if (seed.size() < 32) {
        error = IsCrypted() && IsLocked() ? "Wallet is locked" : "Wallet seed is not available";
        return false;
    }
    if (!silentpayments::DeriveAccountKeys(seed, silentpayments::LocalNetworkId(), keys)) {
        error = "Silent payment key derivation failed";
        return false;
    }
    return true;
}

bool CWallet::GetSilentPaymentAccountKeys(silentpayments::AccountKeys& keys, std::string& error)
{
    AssertLockHeld(cs_wallet);
    const std::string identityError = GetSilentPaymentIdentityError();
    if (!identityError.empty()) {
        error = identityError;
        return false;
    }
    if (silentPaymentViewSpend.IsValid()) {
        keys.scan = silentPaymentViewScan;
        keys.scanPub = keys.scan.GetPubKey();
        keys.spend = CKey();
        keys.spendPub = silentPaymentViewSpend;
        fSilentPaymentCodeVerified = true;
        return true;
    }
    if (!HasSilentPaymentIdentity()) {
        error = "Silent payments need a strict ECDSA wallet (-addresstype=ecdsa) or an imported view key";
        return false;
    }
    if (silentPaymentKeyCache) {
        keys = *silentPaymentKeyCache;
        return true;
    }
    if (!DeriveSilentPaymentAccountKeys(keys, error)) return false;
    // The seed is authoritative. A stored code that differs from it was
    // replaced or damaged: never show it again until an explicit repair.
    if (silentPaymentScanPub.IsValid() &&
        (silentPaymentScanPub != keys.scanPub || silentPaymentSpendPub != keys.spendPub)) {
        error = "The stored silent payment code does not match the wallet seed and must not be used; "
                "check your backups, then run repairsilentpaymentidentity";
        if (!SetSilentPaymentIdentityFailure(error)) {
            LogPrintf("SilentPayments: writing the identity failure record failed\n");
        }
        return false;
    }
    if (!silentPaymentScanPub.IsValid()) {
        if (!CWalletDB(*dbw).WriteSilentPaymentCode(keys.scanPub, keys.spendPub)) {
            error = "Writing the silent payment code failed";
            return false;
        }
        silentPaymentScanPub = keys.scanPub;
        silentPaymentSpendPub = keys.spendPub;
    }
    fSilentPaymentCodeVerified = true;
    silentPaymentKeyCache.reset(new silentpayments::AccountKeys(keys));
    return true;
}

bool CWallet::GetSilentPaymentCode(silentpayments::PaymentCode& code, std::string& error, bool* verified)
{
    AssertLockHeld(cs_wallet);
    code.networkId = silentpayments::LocalNetworkId();
    const std::string identityError = GetSilentPaymentIdentityError();
    if (!identityError.empty()) {
        error = identityError;
        return false;
    }
    if (silentPaymentViewSpend.IsValid()) {
        code.scanKey = silentPaymentViewScan.GetPubKey();
        code.spendKey = silentPaymentViewSpend;
        if (verified) *verified = true;
        return true;
    }
    if (!HasSilentPaymentIdentity()) {
        error = "Silent payments need a strict ECDSA wallet (-addresstype=ecdsa) or an imported view key";
        return false;
    }
    if (!fSilentPaymentCodeVerified || !silentPaymentScanPub.IsValid()) {
        // 047c D8: the code is only shown once checked against the seed in
        // this session. A locked wallet that was not unlocked yet cannot do
        // that, so a stored code replaced offline is never handed out.
        silentpayments::AccountKeys keys;
        if (!GetSilentPaymentAccountKeys(keys, error)) {
            if (IsCrypted() && IsLocked() && GetSilentPaymentIdentityError().empty()) {
                error = "Unlock the wallet to check the silent payment code against its seed before it is shown";
            }
            return false;
        }
    }
    code.scanKey = silentPaymentScanPub;
    code.spendKey = silentPaymentSpendPub;
    if (verified) *verified = true;
    return true;
}

bool CWallet::RepairSilentPaymentIdentity(silentpayments::PaymentCode& previous, silentpayments::PaymentCode& code, std::string& error)
{
    AssertLockHeld(cs_wallet);
    if (IsSilentPaymentViewOnly()) {
        error = "A view-only identity is repaired by importing a valid view key again";
        return false;
    }
    if (GetAddressType() != WalletAddressType::ECDSA || !IsBip44Enabled()) {
        error = "This wallet has no silent payment identity";
        return false;
    }
    silentpayments::AccountKeys keys;
    if (!DeriveSilentPaymentAccountKeys(keys, error)) return false;
    previous = silentpayments::PaymentCode{silentpayments::LocalNetworkId(), silentPaymentScanPub, silentPaymentSpendPub};
    CWalletDB walletdb(*dbw);
    if (!walletdb.WriteSilentPaymentCode(keys.scanPub, keys.spendPub) || !walletdb.EraseSilentPaymentIdentityFailure()) {
        error = "Writing the silent payment code failed";
        return false;
    }
    silentPaymentScanPub = keys.scanPub;
    silentPaymentSpendPub = keys.spendPub;
    strSilentPaymentIdentityError.clear();
    fSilentPaymentCodeVerified = true;
    silentPaymentKeyCache.reset(new silentpayments::AccountKeys(keys));
    code = silentpayments::PaymentCode{silentpayments::LocalNetworkId(), keys.scanPub, keys.spendPub};
    LogPrintf("SilentPayments: identity repaired from the wallet seed\n");
    return true;
}

std::string CWallet::GetSilentPaymentStatus(const COutPoint& outpoint, const silentpayments::PaymentRecord& record, int& depth) const
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);
    depth = 0;
    // A record confirmed in a block this node does not know belongs to
    // another chain (reset network, wallet moved between chains).
    if (!record.blockHash.IsNull() && !LookupBlockIndex(record.blockHash)) return "other_chain";
    auto it = mapWallet.find(outpoint.hash);
    if (it == mapWallet.end()) return "unknown";
    const CWalletTx& wtx = it->second;
    depth = wtx.GetDepthInMainChain();
    if (depth < 0) return "conflicted";
    if (IsSpent(outpoint.hash, outpoint.n)) return "spent";
    if (depth > 0) return "confirmed";
    if (wtx.isAbandoned()) return "abandoned";
    return wtx.InMempool() ? "pending" : "unconfirmed";
}

bool CWallet::WriteSilentPaymentCursor(CWalletDB& walletdb, const CBlockIndex* pindex)
{
    nSilentPaymentHeight = pindex ? pindex->nHeight : -1;
    hashSilentPaymentBlock = pindex ? pindex->GetBlockHash() : uint256();
    fSilentPaymentCursorLoaded = true;
    return walletdb.WriteSilentPaymentCursor(nSilentPaymentHeight, hashSilentPaymentBlock);
}

bool CWallet::UnconfirmSilentPayments(CWalletDB& walletdb, int aboveHeight, const uint256* blockHash, std::string& error)
{
    AssertLockHeld(cs_wallet);
    for (auto& entry : mapSilentPayments) {
        const bool match = blockHash ? entry.second.blockHash == *blockHash : entry.second.height > aboveHeight;
        if (!match || entry.second.height < 0) continue;
        entry.second.blockHash.SetNull();
        entry.second.height = -1;
        if (!walletdb.WriteSilentPayment(entry.first, entry.second)) {
            error = "writing a silent payment record failed";
            return false;
        }
    }
    return true;
}

bool CWallet::RegisterSilentPayment(CWalletDB& walletdb, const COutPoint& outpoint, silentpayments::Match& match,
                                    const silentpayments::AccountKeys& keys, const CBlockIndex* pindex, bool& isNew)
{
    AssertLockHeld(cs_wallet);
    isNew = false;
    const CScript script = silentpayments::PaymentScript(match.key);
    if (script.empty()) {
        memory_cleanse(match.tweak.begin(), match.tweak.size());
        return false;
    }
    const int64_t nTime = pindex ? pindex->GetBlockTime() : GetTime();

    // The key (or the watched script) is registered for known payments too:
    // a damaged or partially restored wallet may keep the record without it.
    bool ok = true;
    if (keys.spend.IsValid()) {
        if (!HaveKey(match.key.GetID())) {
            // d_k joins the keystore (encrypted with the wallet), so spending
            // needs no extra path and the tweak is not kept. Its record is
            // "spkey"/"spckey", not "key"/"ckey" (see setSilentPaymentKeys).
            setSilentPaymentKeys.insert(match.key.GetID());
            CKey paymentKey;
            ok = silentpayments::PaymentPrivateKey(keys.spend, match.tweak, paymentKey) && paymentKey.GetPubKey() == match.key;
            if (ok) {
                CKeyMetadata metadata(nTime);
                metadata.hdKeypath = strprintf("silentpayment/%u", match.k);
                metadata.hd_seed_id = hdChain.seed_id;
                mapKeyMetadata[match.key.GetID()] = metadata;
                UpdateTimeFirstKey(nTime);
                ok = AddKeyPubKeyWithDB(walletdb, paymentKey, match.key);
            }
        }
        ok = ok && RegisterStrictAuthScriptForKey(match.key);
    } else if (!HaveWatchOnly(script)) {
        ok = AddWatchOnly(script, nTime);
    }
    memory_cleanse(match.tweak.begin(), match.tweak.size());
    if (!ok) return false;

    auto it = mapSilentPayments.find(outpoint);
    if (it != mapSilentPayments.end()) {
        // A mempool sighting never overrides a confirmation.
        if (pindex && it->second.blockHash != pindex->GetBlockHash()) {
            it->second.blockHash = pindex->GetBlockHash();
            it->second.height = pindex->nHeight;
            return walletdb.WriteSilentPayment(outpoint, it->second);
        }
        return true;
    }
    silentpayments::PaymentRecord record;
    record.k = match.k;
    record.key = match.key;
    record.viewOnly = !keys.spend.IsValid();
    if (pindex) {
        record.blockHash = pindex->GetBlockHash();
        record.height = pindex->nHeight;
    }
    if (!walletdb.WriteSilentPayment(outpoint, record)) return false;
    mapSilentPayments[outpoint] = record;
    setSilentPaymentScripts.insert(script);
    isNew = true;
    return true;
}

bool CWallet::ScanSilentPaymentBlock(CWalletDB& walletdb, const CBlock& block, const CBlockIndex* pindex,
                                     const silentpayments::AccountKeys& keys, const std::vector<unsigned char>& context,
                                     bool addTransactions, bool addAll, int& found, bool& matched, std::string& error)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);

    matched = false;
    bool any = false;
    for (size_t i = 1; i < block.vtx.size() && !any; ++i) {
        any = silentpayments::MayBeEligible(*block.vtx[i]);
    }
    if (any) {
        // Prevouts come from the undo data of the block (rev*.dat), read with
        // the checksum the node verifies; no -txindex and no UTXO lookups.
        CBlockUndo undo;
        if (!pindex->pprev || !(pindex->nStatus & BLOCK_HAVE_UNDO)) {
            error = strprintf("undo data of block %d (%s) is not available", pindex->nHeight, pindex->GetBlockHash().ToString());
            return false;
        }
        if (!UndoReadFromDisk(undo, pindex->GetUndoPos(), pindex->pprev->GetBlockHash())) {
            error = strprintf("undo data of block %d (%s) cannot be read or is corrupt", pindex->nHeight, pindex->GetBlockHash().ToString());
            return false;
        }
        if (undo.vtxundo.size() + 1 != block.vtx.size()) {
            error = strprintf("undo data of block %d does not match the block", pindex->nHeight);
            return false;
        }
        for (size_t i = 1; i < block.vtx.size(); ++i) {
            const CTransaction& tx = *block.vtx[i];
            if (!silentpayments::MayBeEligible(tx)) continue;
            const CTxUndo& txundo = undo.vtxundo[i - 1];
            if (txundo.vprevout.size() != tx.vin.size()) {
                error = strprintf("undo data of block %d does not match transaction %s", pindex->nHeight, tx.GetHash().ToString());
                return false;
            }
            std::vector<CTxOut> spent;
            spent.reserve(tx.vin.size());
            for (const Coin& coin : txundo.vprevout) spent.push_back(coin.out);
            std::vector<CPubKey> pubkeys;
            std::vector<COutPoint> outpoints;
            if (!silentpayments::GetEligibleInputs(tx, spent, pubkeys, outpoints)) continue;
            std::vector<silentpayments::Match> matches =
                silentpayments::ScanTransaction(context, tx, pubkeys, outpoints, keys.scan, keys.spendPub);
            bool ok = true;
            for (silentpayments::Match& match : matches) {
                bool isNew = false;
                if (ok && !RegisterSilentPayment(walletdb, COutPoint(tx.GetHash(), match.vout), match, keys, pindex, isNew)) {
                    error = strprintf("storing a payment of transaction %s failed", tx.GetHash().ToString());
                    ok = false;
                }
                memory_cleanse(match.tweak.begin(), match.tweak.size());
                if (isNew) ++found;
            }
            if (!ok) return false;
            if (!matches.empty()) matched = true;
        }
    }

    // Blocks behind the live notification: from the first block holding a
    // payment, new or already known, the wallet must also see the payment
    // transactions and every later spend of them (a rescan rebuilds them).
    if (addTransactions && (addAll || matched)) {
        for (size_t i = 0; i < block.vtx.size(); ++i) {
            AddToWalletIfInvolvingMe(block.vtx[i], pindex, i, true);
        }
    }
    return true;
}

bool CWallet::SyncSilentPayments(const CBlockIndex* target, const CBlock* block, int* found)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);
    if (!target || !HasSilentPaymentIdentity()) return true;
    if (SilentPaymentsPaused()) return false;
    const std::string identityError = GetSilentPaymentIdentityError();
    if (!identityError.empty()) {
        strSilentPaymentError = identityError;
        return false;
    }

    const CBlockIndex* cursor = nullptr;
    if (nSilentPaymentHeight >= 0) {
        cursor = LookupBlockIndex(hashSilentPaymentBlock);
        if (!cursor) {
            LogPrintf("SilentPayments: cursor block %s is unknown, scanning from the start\n", hashSilentPaymentBlock.ToString());
        }
    }
    if (cursor && cursor->GetAncestor(target->nHeight) == target) return true; // already scanned

    CWalletDB walletdb(*dbw);
    std::string error;
    if (cursor) {
        const CBlockIndex* fork = LastCommonAncestor(cursor, target);
        if (fork != cursor) {
            // The cursor left the branch being processed: confirmations above
            // the fork are forgotten and found again on the new branch.
            if (!UnconfirmSilentPayments(walletdb, fork->nHeight, nullptr, error) || !WriteSilentPaymentCursor(walletdb, fork)) {
                strSilentPaymentError = error.empty() ? "writing the scan cursor failed" : error;
                LogPrintf("SilentPayments: %s\n", strSilentPaymentError);
                return false;
            }
            cursor = fork;
        }
    }

    silentpayments::AccountKeys keys;
    if (!GetSilentPaymentAccountKeys(keys, error)) {
        strSilentPaymentError = error;
        return false;
    }
    const std::vector<unsigned char> context = silentpayments::LocalContext();
    const Consensus::Params& consensus = GetParams().GetConsensus();

    int nFound = 0;
    bool addAll = false;
    bool ok = true;
    const int start = cursor ? cursor->nHeight + 1 : 0;
    for (int height = start; height <= target->nHeight; ++height) {
        const CBlockIndex* pindex = target->GetAncestor(height);
        const bool live = block && pindex == target;
        CBlock diskBlock;
        if (!live) {
            if (!(pindex->nStatus & BLOCK_HAVE_DATA) || !ReadBlockFromDisk(diskBlock, pindex, consensus)) {
                error = strprintf("block %d (%s) is not available", height, pindex->GetBlockHash().ToString());
                ok = false;
                break;
            }
        }
        const int before = nFound;
        bool matched = false;
        if (!ScanSilentPaymentBlock(walletdb, live ? *block : diskBlock, pindex, keys, context, !live, addAll, nFound, matched, error)) {
            ok = false;
            break;
        }
        if (matched) addAll = true;
        // Ordered writes: the payments of this block are stored before the
        // cursor moves past it; a crash only repeats work.
        nSilentPaymentHeight = pindex->nHeight;
        hashSilentPaymentBlock = pindex->GetBlockHash();
        if ((nFound > before || height == target->nHeight || height % 1000 == 0) && !WriteSilentPaymentCursor(walletdb, pindex)) {
            error = "writing the scan cursor failed";
            ok = false;
            break;
        }
    }
    if (found) *found += nFound;
    if (!ok) {
        // Persist the last block really scanned and stop there.
        if (!walletdb.WriteSilentPaymentCursor(nSilentPaymentHeight, hashSilentPaymentBlock)) {
            LogPrintf("SilentPayments: writing the scan cursor failed\n");
        }
        strSilentPaymentError = error;
        LogPrintf("SilentPayments: scan stopped after height %d: %s\n", nSilentPaymentHeight, error);
        return false;
    }
    strSilentPaymentError.clear();
    return true;
}

void CWallet::SyncSilentPaymentsOnBlock(const CBlockIndex* pindex, const CBlock* block)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);
    if (!HasSilentPaymentIdentity() || SilentPaymentsPaused()) return;
    // The usual case is one block after the cursor. A long gap (restore,
    // long lock, data that came back) is scanned in chunks by the background
    // catch-up instead of holding cs_main here.
    static const int MAX_INLINE_GAP = 32;
    const CBlockIndex* cursor = nSilentPaymentHeight >= 0 ? LookupBlockIndex(hashSilentPaymentBlock) : nullptr;
    const int base = cursor ? LastCommonAncestor(cursor, pindex)->nHeight : -1;
    if (pindex->nHeight - base <= MAX_INLINE_GAP || !silentPaymentScheduler) {
        SyncSilentPayments(pindex, block);
    } else {
        ScheduleSilentPaymentsResume();
    }
}

bool CWallet::ScheduleSilentPaymentsResume()
{
    if (!silentPaymentScheduler) return false;
    if (fSilentPaymentCatchUpQueued.exchange(true)) return true;
    silentPaymentScheduler->schedule([this] {
        ResumeSilentPayments();
        fSilentPaymentCatchUpQueued = false;
    });
    return true;
}

bool CWallet::ResumeSilentPayments(int* found, int chunkBlocks)
{
    if (chunkBlocks < 1) chunkBlocks = 1;
    for (bool first = true;; first = false) {
        if (ShutdownRequested()) return false;
        // A short pause between chunks lets threads waiting for cs_main (RPC,
        // validation) take it; re-locking at once would starve them.
        if (!first) MilliSleep(1);
        LOCK2(cs_main, cs_wallet);
        if (!HasSilentPaymentIdentity()) return true;
        if (SilentPaymentsPaused()) return false;
        // Checked on every resume (an unlock among others): a replaced code
        // is caught even when there is nothing left to scan.
        silentpayments::AccountKeys keys;
        std::string error;
        if (!GetSilentPaymentAccountKeys(keys, error)) {
            strSilentPaymentError = error;
            return false;
        }
        const CBlockIndex* tip = chainActive.Tip();
        if (!tip) return true;
        const CBlockIndex* cursor = nSilentPaymentHeight >= 0 ? LookupBlockIndex(hashSilentPaymentBlock) : nullptr;
        const int base = cursor ? LastCommonAncestor(cursor, tip)->nHeight : -1;
        const CBlockIndex* target = tip->nHeight - base > chunkBlocks ? chainActive[base + chunkBlocks] : tip;
        if (!SyncSilentPayments(target, nullptr, found)) return false;
        if (target != tip) continue; // releases the locks between chunks

        // Mempool transactions announced while scanning was paused or behind
        // were not recognised then: scan them now and hand any match to the wallet.
        std::vector<CTransactionRef> pending;
        {
            LOCK(mempool.cs);
            for (const CTxMemPoolEntry& entry : mempool.mapTx) pending.push_back(entry.GetSharedTx());
        }
        for (const CTransactionRef& ptx : pending) {
            const size_t before = mapSilentPayments.size();
            ScanSilentPaymentsInMempoolTx(ptx);
            if (mapSilentPayments.size() > before) {
                if (found) *found += mapSilentPayments.size() - before;
                SyncTransaction(ptx);
            }
        }
        return true;
    }
}

void CWallet::InitSilentPayments(bool fFirstRun, bool fRestore)
{
    {
        LOCK2(cs_main, cs_wallet);
        if (!HasSilentPaymentIdentity()) return;
        if (!fSilentPaymentCursorLoaded) {
            CWalletDB walletdb(*dbw);
            // A brand-new identity cannot have earlier payments. A restore, or a
            // wallet that predates the cursor, scans from the start.
            if (!WriteSilentPaymentCursor(walletdb, fFirstRun && !fRestore ? chainActive.Tip() : nullptr)) {
                LogPrintf("SilentPayments: writing the scan cursor failed\n");
            }
        }
        silentpayments::PaymentCode code;
        std::string error;
        if (!GetSilentPaymentCode(code, error)) {
            LogPrintf("SilentPayments: payment code not available: %s\n", error);
        }
        if (SilentPaymentsPaused()) {
            LogPrintf("SilentPayments: wallet locked, scanning paused at height %d\n", nSilentPaymentHeight);
            return;
        }
    }
    int found = 0;
    const int64_t nStart = GetTimeMillis();
    ResumeSilentPayments(&found);
    LogPrintf("SilentPayments: scanned to height %d, %d new payments, %dms\n", GetSilentPaymentCursor(), found, GetTimeMillis() - nStart);
}

bool CWallet::RescanSilentPayments(int startHeight, int& found, std::string& error, int chunkBlocks)
{
    {
        LOCK2(cs_main, cs_wallet);
        if (!HasSilentPaymentIdentity()) {
            error = "Silent payments need a strict ECDSA wallet (-addresstype=ecdsa) or an imported view key";
            return false;
        }
        if (!GetSilentPaymentIdentityError().empty()) {
            error = GetSilentPaymentIdentityError();
            return false;
        }
        if (SilentPaymentsPaused()) {
            error = "Wallet is locked; unlock it to scan for silent payments";
            return false;
        }
        if (startHeight < 0 || startHeight > chainActive.Height()) {
            error = "Invalid start_height";
            return false;
        }
        CWalletDB walletdb(*dbw);
        if (!UnconfirmSilentPayments(walletdb, startHeight - 1, nullptr, error)) return false;
        if (startHeight - 1 < nSilentPaymentHeight || !LookupBlockIndex(hashSilentPaymentBlock)) {
            if (!WriteSilentPaymentCursor(walletdb, startHeight > 0 ? chainActive[startHeight - 1] : nullptr)) {
                error = "writing the scan cursor failed";
                return false;
            }
        }
    }
    if (!ResumeSilentPayments(&found, chunkBlocks)) {
        LOCK(cs_wallet);
        error = strSilentPaymentError.empty() ? "Silent payment scan failed" : strSilentPaymentError;
        return false;
    }
    return true;
}

void CWallet::SilentPaymentsBlockDisconnected(const uint256& blockHash)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);
    if (!HasSilentPaymentIdentity()) return;
    const CBlockIndex* pindex = LookupBlockIndex(blockHash);
    if (!pindex) return;
    CWalletDB walletdb(*dbw);
    std::string error;
    bool ok = UnconfirmSilentPayments(walletdb, 0, &blockHash, error);
    const CBlockIndex* cursor = nSilentPaymentHeight >= 0 ? LookupBlockIndex(hashSilentPaymentBlock) : nullptr;
    if (cursor && cursor->GetAncestor(pindex->nHeight) == pindex) {
        ok = WriteSilentPaymentCursor(walletdb, pindex->pprev) && ok;
    }
    if (!ok) {
        strSilentPaymentError = error.empty() ? "writing the scan cursor failed" : error;
        LogPrintf("SilentPayments: %s\n", strSilentPaymentError);
    }
}

void CWallet::ScanSilentPaymentsInMempoolTx(const CTransactionRef& ptx)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);
    const CTransaction& tx = *ptx;
    if (!HasSilentPaymentIdentity() || SilentPaymentsPaused() || !silentpayments::MayBeEligible(tx)) return;

    // Live reception reads prevouts from the mempool view: confirmed coins
    // or outputs of unconfirmed parents. A transaction already mined or
    // evicted resolves nothing here and is found by the block scan.
    std::vector<CTxOut> spent;
    {
        LOCK(mempool.cs);
        CCoinsViewMemPool view(pcoinsTip, mempool);
        for (const CTxIn& in : tx.vin) {
            Coin coin;
            if (!view.GetCoin(in.prevout, coin) || coin.IsSpent()) return;
            spent.push_back(coin.out);
        }
    }
    std::vector<CPubKey> pubkeys;
    std::vector<COutPoint> outpoints;
    if (!silentpayments::GetEligibleInputs(tx, spent, pubkeys, outpoints)) return;

    silentpayments::AccountKeys keys;
    std::string error;
    if (!GetSilentPaymentAccountKeys(keys, error)) return;
    std::vector<silentpayments::Match> matches =
        silentpayments::ScanTransaction(silentpayments::LocalContext(), tx, pubkeys, outpoints, keys.scan, keys.spendPub);
    CWalletDB walletdb(*dbw);
    for (silentpayments::Match& match : matches) {
        bool isNew = false;
        if (!RegisterSilentPayment(walletdb, COutPoint(tx.GetHash(), match.vout), match, keys, nullptr, isNew)) {
            LogPrintf("SilentPayments: storing a mempool payment failed\n");
        }
        memory_cleanse(match.tweak.begin(), match.tweak.size());
    }
}

bool CWallet::ImportSilentPaymentViewKey(const CKey& scanKey, const CPubKey& spendKey, std::string& error)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);
    // A damaged view key may be replaced; any other identity may not.
    if (HasSilentPaymentIdentity() && !fSilentPaymentViewKeyCorrupt) {
        error = IsSilentPaymentViewOnly() ? "This wallet already holds a silent payment view key"
                                          : "This wallet has its own silent payment identity; use another wallet to watch a code";
        return false;
    }
    if (IsCrypted()) {
        error = "A view key can only be imported into an unencrypted watch wallet";
        return false;
    }
    if (!scanKey.IsValid() || !scanKey.IsCompressed() || !spendKey.IsFullyValid() || !spendKey.IsCompressed()) {
        error = "Invalid view key";
        return false;
    }
    const CPubKey scanPub = scanKey.GetPubKey();
    if (std::equal(scanPub.begin() + 1, scanPub.end(), spendKey.begin() + 1)) {
        error = "Scan key equals +-spend key";
        return false;
    }
    CWalletDB walletdb(*dbw);
    if (!walletdb.WriteSilentPaymentViewKey(std::vector<unsigned char>(scanKey.begin(), scanKey.end()), spendKey)) {
        error = "Writing the view key failed";
        return false;
    }
    silentPaymentViewScan = scanKey;
    silentPaymentViewSpend = spendKey;
    fSilentPaymentViewKeyCorrupt = false;
    fSilentPaymentCodeVerified = true;
    return true;
}

bool CWallet::GetSilentPaymentViewKey(CKey& scanKey, CPubKey& spendKey, std::string& error)
{
    AssertLockHeld(cs_wallet);
    silentpayments::AccountKeys keys;
    if (!GetSilentPaymentAccountKeys(keys, error)) return false;
    scanKey = keys.scan;
    spendKey = keys.spendPub;
    return true;
}

bool CWallet::CreateSilentPaymentTransaction(const std::vector<silentpayments::Recipient>& recipients, CWalletTx& wtxNew,
                                             CReserveKey& reservekey, CAmount& nFeeRet, std::vector<unsigned int>& paymentPositions,
                                             std::string& error, const CCoinControl& coin_control)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(cs_wallet);
    paymentPositions.clear();

    if (recipients.empty()) {
        error = "No silent payment recipients";
        return false;
    }
    if (IsSilentPaymentViewOnly() || GetAddressType() != WalletAddressType::ECDSA || !IsBip44Enabled()) {
        error = "Silent payments are sent from a strict ECDSA wallet (-addresstype=ecdsa)";
        return false;
    }
    if (!IsAddressTypeActive("ecdsa", error)) return false;
    if (IsLocked()) {
        error = "Please enter the wallet passphrase with walletpassphrase first.";
        return false;
    }
    CAmount nValue = 0;
    for (const silentpayments::Recipient& r : recipients) {
        if (r.code.networkId != silentpayments::LocalNetworkId()) {
            error = "Payment code of another network";
            return false;
        }
        if (r.amount <= 0 || !MoneyRange(r.amount)) {
            error = "Invalid amount";
            return false;
        }
        nValue += r.amount;
        if (!MoneyRange(nValue)) {
            error = "Invalid amount";
            return false;
        }
    }

    // Only native strict v3 coins whose key this wallet holds: a payment code
    // never pulls Legacy or PQ funds, and every input feeds the derivation.
    struct Candidate {
        COutPoint outpoint;
        CAmount value;
        CKey key;
    };
    std::vector<COutput> available;
    AvailableCoins(available, true, &coin_control);
    std::vector<Candidate> candidates;
    for (const COutput& output : available) {
        const CTxOut& txout = output.tx->tx->vout[output.i];
        const COutPoint outpoint(output.tx->GetHash(), output.i);
        if (!output.fSpendable || !silentpayments::IsNativeV3Script(txout.scriptPubKey)) continue;
        if (coin_control.HasSelected() && !coin_control.IsSelected(outpoint)) continue;
        AuthScriptSpendData spendData;
        const uint256 commitment(std::vector<unsigned char>(txout.scriptPubKey.begin() + 2, txout.scriptPubKey.end()));
        CKey key;
        if (!GetAuthScriptSpendData(STRICT_AUTHSCRIPT_WITNESS_V3_ECDSA, commitment, spendData) ||
            !GetKey(spendData.key_id, key) || !key.IsCompressed() ||
            silentpayments::PaymentScript(key.GetPubKey()) != txout.scriptPubKey) continue;
        candidates.push_back(Candidate{outpoint, txout.nValue, key});
    }
    std::sort(candidates.begin(), candidates.end(), [](const Candidate& a, const Candidate& b) {
        return a.value != b.value ? a.value > b.value : a.outpoint < b.outpoint;
    });

    // 047c D2: received silent payments are not combined with each other or
    // with other coins automatically; a coin control selection is used as given.
    std::vector<std::vector<Candidate>> pools;
    if (coin_control.HasSelected()) {
        pools.push_back(candidates);
    } else {
        std::vector<COutPoint> outpoints;
        for (const Candidate& c : candidates) outpoints.push_back(c.outpoint);
        for (const std::vector<size_t>& group : SilentPaymentSelectionGroups(outpoints, {})) {
            std::vector<Candidate> pool;
            for (size_t i : group) pool.push_back(candidates[i]);
            pools.push_back(std::move(pool));
        }
    }
    const bool separated = pools.back().size() != candidates.size();
    CAmount nAvailable = 0;
    for (const Candidate& c : candidates) nAvailable += c.value;

    const std::vector<unsigned char> context = silentpayments::LocalContext();
    const unsigned int nMaxVsize = MAX_STANDARD_TX_WEIGHT / WITNESS_SCALE_FACTOR;
    unsigned int extraBytes = 0;
    for (int attempt = 0; attempt < 4; ++attempt) {
        auto fee = [&](size_t nIn, size_t nOut) {
            return GetMinimumFee(EstimateVsize(nIn, nOut) + extraBytes, coin_control, ::mempool, ::feeEstimator, nullptr);
        };

        // Largest coins first until the payments, the fee and either no
        // change or a change above dust are covered.
        CPubKey changePub;
        CScript changeScript;
        CAmount changeDust = 0;
        {
            CTxDestination changeDest;
            if (!reservekey.GetReservedStrictEcdsaKey(changePub, true) ||
                !GetStrictAuthScriptDestination(changePub, changeDest, false)) {
                error = "Keypool ran out, please call keypoolrefill first";
                return false;
            }
            changeScript = GetScriptForDestination(changeDest);
            changeDust = GetDustThreshold(CTxOut(0, changeScript), ::dustRelayFee);
        }
        size_t nSelected = 0;
        CAmount nIn = 0;
        CAmount nChange = 0;
        CAmount nFee = 0;
        bool covered = false;
        const std::vector<Candidate>* pool = nullptr;
        for (const std::vector<Candidate>& group : pools) {
            nSelected = 0;
            nIn = 0;
            while (nSelected < group.size()) {
                nIn += group[nSelected].value;
                ++nSelected;
                if (coin_control.HasSelected() && nSelected < group.size()) continue; // every selected coin is used
                const CAmount feeNoChange = fee(nSelected, recipients.size());
                if (nIn < nValue + feeNoChange) continue;
                const CAmount feeChange = fee(nSelected, recipients.size() + 1);
                if (nIn - nValue - feeChange >= changeDust) {
                    nChange = nIn - nValue - feeChange;
                    nFee = feeChange;
                } else {
                    nChange = 0;
                    nFee = nIn - nValue; // a change below dust goes to the fee
                }
                covered = true;
                break;
            }
            if (covered) {
                pool = &group;
                break;
            }
        }
        if (!covered) {
            if (separated && nAvailable >= nValue + fee(candidates.size(), recipients.size())) {
                error = SilentPaymentMixRefusal();
            } else {
                error = strprintf("Insufficient strict ECDSA (v3) funds: silent payments only spend native v3 outputs (%s available for %s plus fee)",
                                  FormatMoney(nAvailable), FormatMoney(nValue));
            }
            return false;
        }

        std::vector<CKey> inputKeys;
        std::vector<COutPoint> outpoints;
        for (size_t i = 0; i < nSelected; ++i) {
            inputKeys.push_back((*pool)[i].key);
            outpoints.push_back((*pool)[i].outpoint);
        }
        std::vector<CTxOut> outputs;
        if (!silentpayments::CreateOutputs(context, inputKeys, outpoints, recipients, outputs, error)) return false;
        for (const CTxOut& out : outputs) {
            if (IsDust(out, ::dustRelayFee)) {
                error = strprintf("Payment of %s is below the dust threshold", FormatMoney(out.nValue));
                return false;
            }
        }

        CMutableTransaction txNew;
        txNew.nVersion = 2;
        // Same anti-fee-sniping policy as ordinary sends (no own fingerprint).
        txNew.nLockTime = GetAntiFeeSnipingLockTime();
        const uint32_t nSequence = coin_control.signalRbf ? MAX_BIP125_RBF_SEQUENCE : CTxIn::SEQUENCE_FINAL - 1;
        for (const COutPoint& outpoint : outpoints) {
            txNew.vin.push_back(CTxIn(outpoint, CScript(), nSequence));
        }
        txNew.vout = outputs;
        for (unsigned int i = 0; i < outputs.size(); ++i) paymentPositions.push_back(i);
        if (nChange > 0) {
            const unsigned int pos = GetRandInt(txNew.vout.size() + 1);
            txNew.vout.insert(txNew.vout.begin() + pos, CTxOut(nChange, changeScript));
            for (unsigned int& p : paymentPositions) {
                if (p >= pos) ++p;
            }
        } else {
            reservekey.ReturnStrictEcdsaKey();
        }

        // Every input signs SIGHASH_ALL; ProduceSignature verifies each one.
        if (!SignTransaction(txNew)) {
            error = "Signing transaction failed";
            return false;
        }
        const CTransaction txFinal(txNew);
        const unsigned int vsize = GetVirtualTransactionSize(txFinal);
        if (vsize > nMaxVsize) {
            error = "Transaction too large";
            return false;
        }
        const CAmount feeNeeded = GetMinimumFee(vsize, coin_control, ::mempool, ::feeEstimator, nullptr);
        if (nFee < feeNeeded) {
            // The estimate fell short (larger signatures): retry with margin.
            extraBytes += vsize - std::min(vsize, EstimateVsize(nSelected, txNew.vout.size()));
            extraBytes += 1;
            paymentPositions.clear();
            continue;
        }
        if (nFee > maxTxFee) {
            error = "Fee exceeds maximum configured by -maxtxfee";
            return false;
        }

        wtxNew.fTimeReceivedIsTxTime = true;
        wtxNew.BindWallet(this);
        wtxNew.SetTx(MakeTransactionRef(std::move(txNew)));
        nFeeRet = nFee;
        return true;
    }
    error = "Could not reach the required fee";
    return false;
}
