// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "depinchallenge.h"

#include "base58.h"
#include "depinmsgpool.h" // access checks and CheckAddressHasPublicKey
#include "hash.h"
#include "key.h"
#include "pubkey.h"
#include "random.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "validation.h" // strMessageMagic

#include <algorithm>
#include <cctype>

CDepinChallengeManager g_depinChallenges;
CDepinRateLimiter g_depinRateLimiter;
CDepinReplayGuard g_depinRequestGuard;

// ---------------------------------------------------------------------------
// CDepinReplayGuard
// ---------------------------------------------------------------------------

bool CDepinReplayGuard::Remember(const std::string& key, int64_t nowMs, int64_t ttlMs, std::string& error)
{
    LOCK(cs_replay);
    const auto it = mapSeen.find(key);
    if (it != mapSeen.end() && it->second > nowMs) {
        error = "Request already used";
        return false;
    }
    if (it != mapSeen.end()) mapSeen.erase(it);
    if (mapSeen.size() >= maxEntries) {
        // Full: drop what can no longer be replayed (its window has closed)
        // and, if still full, refuse rather than grow.
        for (auto jt = mapSeen.begin(); jt != mapSeen.end();) {
            if (jt->second <= nowMs) jt = mapSeen.erase(jt); else ++jt;
        }
        if (mapSeen.size() >= maxEntries) {
            error = "Too many pending requests";
            return false;
        }
    }
    mapSeen[key] = nowMs + ttlMs;
    return true;
}

void CDepinReplayGuard::Prune(int64_t nowMs)
{
    LOCK(cs_replay);
    for (auto it = mapSeen.begin(); it != mapSeen.end();) {
        if (it->second <= nowMs) it = mapSeen.erase(it); else ++it;
    }
}

void CDepinReplayGuard::Clear()
{
    LOCK(cs_replay);
    mapSeen.clear();
}

size_t CDepinReplayGuard::Size() const
{
    LOCK(cs_replay);
    return mapSeen.size();
}

bool CheckDepinChallengeRequestAuth(DepinChallengeType type, const std::string& token,
                                    const std::string& address, int64_t timestampMs,
                                    const std::string& signatureBase64, int64_t nowMs,
                                    std::string& error)
{
    if (timestampMs < nowMs - DEPIN_REQUEST_WINDOW_MS || timestampMs > nowMs + DEPIN_REQUEST_WINDOW_MS) {
        error = strprintf("Request timestamp outside the accepted window (+/- %d s of node time %d ms)",
                          DEPIN_REQUEST_WINDOW_MS / 1000, nowMs);
        return false;
    }
    if (signatureBase64.empty()) {
        error = "Request signature is required";
        return false;
    }
    if (!VerifyDepinChallengeSignature(address, signatureBase64,
                                       DepinChallengeRequestPreimage(type, token, address, timestampMs), error)) {
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// CDepinRateLimiter
// ---------------------------------------------------------------------------

void CDepinRateLimiter::SetLimit(unsigned int perWindow)
{
    LOCK(cs_rate);
    limit = perWindow;
}

unsigned int CDepinRateLimiter::GetLimit() const
{
    LOCK(cs_rate);
    return limit;
}

bool CDepinRateLimiter::Allow(const std::string& key, int64_t now)
{
    LOCK(cs_rate);
    if (limit == 0) return true;
    // Keep the map bounded: once it is full and the key is new, sweep what
    // has left the window, and if it is STILL full refuse the key rather than
    // store it. A known key is never refused on capacity grounds: it is
    // judged by its own window below.
    if (mapHits.size() >= DEPIN_RATE_LIMITER_MAX_KEYS && !mapHits.count(key)) {
        for (auto it = mapHits.begin(); it != mapHits.end();) {
            std::deque<int64_t>& hits = it->second;
            while (!hits.empty() && hits.front() <= now - DEPIN_RATE_WINDOW) hits.pop_front();
            if (hits.empty()) it = mapHits.erase(it); else ++it;
        }
        if (mapHits.size() >= DEPIN_RATE_LIMITER_MAX_KEYS) return false;
    }
    std::deque<int64_t>& hits = mapHits[key];
    while (!hits.empty() && hits.front() <= now - DEPIN_RATE_WINDOW) hits.pop_front();
    if (hits.size() >= limit) return false;
    hits.push_back(now);
    return true;
}

void CDepinRateLimiter::Prune(int64_t now)
{
    LOCK(cs_rate);
    for (auto it = mapHits.begin(); it != mapHits.end();) {
        std::deque<int64_t>& hits = it->second;
        while (!hits.empty() && hits.front() <= now - DEPIN_RATE_WINDOW) hits.pop_front();
        if (hits.empty()) it = mapHits.erase(it); else ++it;
    }
}

void CDepinRateLimiter::Clear()
{
    LOCK(cs_rate);
    mapHits.clear();
}

size_t CDepinRateLimiter::Size() const
{
    LOCK(cs_rate);
    return mapHits.size();
}

std::string DepinChallengeTypeName(DepinChallengeType type)
{
    return type == DepinChallengeType::ADMIN ? "admin" : "receive";
}

bool ParseDepinChallengeType(const std::string& name, DepinChallengeType& type)
{
    std::string lower = name;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (lower == "receive") {
        type = DepinChallengeType::RECEIVE;
        return true;
    }
    if (lower == "admin") {
        type = DepinChallengeType::ADMIN;
        return true;
    }
    return false;
}

std::string DepinChallengePreimage(DepinChallengeType type, const std::string& token,
                                   const std::string& address, const std::string& nonce)
{
    const char* prefix = (type == DepinChallengeType::ADMIN) ? "DEPIN-CLEAR" : "DEPIN-GET";
    return strprintf("%s|%s|%s|%s", prefix, token, address, nonce);
}

std::string DepinChallengeRequestPreimage(DepinChallengeType type, const std::string& token,
                                          const std::string& address, int64_t timestampMs)
{
    return strprintf("DEPIN-REQ|%s|%s|%s|%d", DepinChallengeTypeName(type), token, address, timestampMs);
}

int64_t DepinRequestClockMillis()
{
    const int64_t mock = GetMockTime();
    return mock ? mock * 1000 : GetTimeMillis();
}

uint256 DepinChallengeSigningHash(const std::string& preimage)
{
    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << preimage;
    return ss.GetHash();
}

bool SignDepinChallengePreimage(const CKey& key, const std::string& preimage,
                                std::string& signatureBase64, std::string& error)
{
    if (!key.IsValid()) {
        error = "Invalid private key";
        return false;
    }
    std::vector<unsigned char> vchSig;
    if (!key.SignCompact(DepinChallengeSigningHash(preimage), vchSig)) {
        error = "Failed to sign challenge";
        return false;
    }
    signatureBase64 = EncodeBase64(vchSig.data(), vchSig.size());
    return true;
}

bool VerifyDepinChallengeSignature(const std::string& address, const std::string& signatureBase64,
                                   const std::string& preimage, std::string& error)
{
    const CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest)) {
        error = "Invalid address";
        return false;
    }
    const CKeyID* keyID = boost::get<CKeyID>(&dest);
    if (!keyID) {
        error = "Address does not refer to a key";
        return false;
    }

    bool fInvalid = false;
    const std::vector<unsigned char> vchSig = DecodeBase64(signatureBase64.c_str(), &fInvalid);
    if (fInvalid || vchSig.empty()) {
        error = "Malformed signature";
        return false;
    }

    CPubKey pubkey;
    if (!pubkey.RecoverCompact(DepinChallengeSigningHash(preimage), vchSig)) {
        error = "Failed to recover public key from signature";
        return false;
    }
    if (pubkey.GetID() != *keyID) {
        error = "Signature does not match address";
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// CDepinChallengeManager
// ---------------------------------------------------------------------------

std::string CDepinChallengeManager::Issue(const std::string& token, const std::string& address,
                                          DepinChallengeType type, std::string& error,
                                          int64_t lifetime)
{
    if (token.empty() || address.empty()) {
        error = "Token and address are required";
        return "";
    }

    unsigned char randBytes[32];
    GetRandBytes(randBytes, sizeof(randBytes));
    const std::string nonce = HexStr(randBytes, randBytes + sizeof(randBytes));

    const int64_t now = GetTime();

    LOCK(cs_challenges);
    CleanupExpiredLocked(now);

    // Per-address cap first: a holder re-requesting only recycles its own
    // slots and never counts against the global limit.
    std::deque<std::string>& mine = mapNoncesByAddress[address];
    while (mine.size() >= DEPIN_CHALLENGE_MAX_PER_ADDRESS) {
        const std::string oldest = mine.front();
        EraseLocked(oldest); // pops it from `mine` as well
    }

    if (mapChallenges.size() >= DEPIN_CHALLENGE_MAX_TOTAL) {
        if (mine.empty()) mapNoncesByAddress.erase(address);
        error = "Too many pending challenges";
        return "";
    }

    CDepinChallenge challenge;
    challenge.token = token;
    challenge.address = address;
    challenge.type = type;
    challenge.expiry = now + lifetime;

    mapChallenges[nonce] = challenge;
    mapNoncesByAddress[address].push_back(nonce);
    return nonce;
}

bool CDepinChallengeManager::Peek(const std::string& nonce, std::string& error) const
{
    LOCK(cs_challenges);
    const auto it = mapChallenges.find(nonce);
    if (it == mapChallenges.end()) {
        error = "Challenge not found";
        return false;
    }
    if (it->second.expiry <= GetTime()) {
        error = "Challenge expired";
        return false;
    }
    return true;
}

bool CDepinChallengeManager::Consume(const std::string& nonce, const std::string& token,
                                     const std::string& address, DepinChallengeType type,
                                     std::string& error)
{
    LOCK(cs_challenges);
    const auto it = mapChallenges.find(nonce);
    if (it == mapChallenges.end()) {
        error = "Challenge not found";
        return false;
    }
    if (it->second.expiry <= GetTime()) {
        EraseLocked(nonce);
        error = "Challenge expired";
        return false;
    }
    // A binding mismatch does NOT erase: the nonce stays usable for the
    // parameters it was actually issued for.
    if (it->second.token != token || it->second.address != address) {
        error = "Challenge does not match token/address";
        return false;
    }
    if (it->second.type != type) {
        error = "Challenge type mismatch";
        return false;
    }
    EraseLocked(nonce);
    return true;
}

size_t CDepinChallengeManager::CleanupExpired(int64_t now)
{
    LOCK(cs_challenges);
    return CleanupExpiredLocked(now);
}

size_t CDepinChallengeManager::Size() const
{
    LOCK(cs_challenges);
    return mapChallenges.size();
}

size_t CDepinChallengeManager::CountForAddress(const std::string& address) const
{
    LOCK(cs_challenges);
    const auto it = mapNoncesByAddress.find(address);
    return it == mapNoncesByAddress.end() ? 0 : it->second.size();
}

void CDepinChallengeManager::Clear()
{
    LOCK(cs_challenges);
    mapChallenges.clear();
    mapNoncesByAddress.clear();
}

void CDepinChallengeManager::EraseLocked(const std::string& nonce)
{
    const auto it = mapChallenges.find(nonce);
    if (it == mapChallenges.end()) return;

    const auto byAddr = mapNoncesByAddress.find(it->second.address);
    if (byAddr != mapNoncesByAddress.end()) {
        std::deque<std::string>& nonces = byAddr->second;
        nonces.erase(std::remove(nonces.begin(), nonces.end(), nonce), nonces.end());
        if (nonces.empty()) mapNoncesByAddress.erase(byAddr);
    }
    mapChallenges.erase(it);
}

size_t CDepinChallengeManager::CleanupExpiredLocked(int64_t now)
{
    std::vector<std::string> expired;
    for (const auto& entry : mapChallenges) {
        if (entry.second.expiry <= now) expired.push_back(entry.first);
    }
    for (const std::string& nonce : expired) EraseLocked(nonce);
    return expired.size();
}

// ---------------------------------------------------------------------------
// Issuance and verification with access checks (see header for the order)
// ---------------------------------------------------------------------------

namespace {

bool AddressHasDepinAccess(DepinChallengeType type, const std::string& address,
                           const std::string& token, const std::string& poolRoot,
                           std::string& error)
{
    if (type == DepinChallengeType::ADMIN) {
        return HasDepinSectionOwnerAccess(address, token, poolRoot, error);
    }
    return HasDepinSectionAccess(address, token, poolRoot, error);
}

bool IsP2PKH(const std::string& address, std::string& error)
{
    const CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest)) {
        error = "Invalid address";
        return false;
    }
    if (!boost::get<CKeyID>(&dest)) {
        error = "Address is not a P2PKH address";
        return false;
    }
    return true;
}

} // namespace

bool CheckDepinChallengeRequest(const std::string& token, const std::string& address,
                                DepinChallengeType type, const std::string& poolRoot,
                                CPubKey& pubkeyOut, std::string& error)
{
    if (!IsDepinSectionOrRoot(token, poolRoot)) {
        error = strprintf("Token '%s' is not configured token '%s' or a section inside it", token, poolRoot);
        return false;
    }
    if (!IsP2PKH(address, error)) {
        return false;
    }
    // The reply is encrypted for this key, and the signature check will need
    // it: an address that never revealed its key cannot take part.
    if (!CheckAddressHasPublicKey(address, pubkeyOut, error)) {
        return false;
    }
    // Access BEFORE issuing: anyone can ask, only holders get a nonce, so the
    // store cannot be filled by addresses that could never use one.
    return AddressHasDepinAccess(type, address, token, poolRoot, error);
}

bool IssueDepinChallengeForAddress(const std::string& token, const std::string& address,
                                   DepinChallengeType type, const std::string& poolRoot,
                                   std::string& nonce, CPubKey& pubkeyOut, std::string& error)
{
    if (!CheckDepinChallengeRequest(token, address, type, poolRoot, pubkeyOut, error)) {
        return false;
    }
    nonce = g_depinChallenges.Issue(token, address, type, error);
    return !nonce.empty();
}

bool CheckDepinChallengeAuth(DepinChallengeType type, const std::string& token,
                             const std::string& address, const std::string& nonce,
                             const std::string& signatureBase64, const std::string& poolRoot,
                             std::string& error)
{
    // 1. Form. Nothing here touches the store.
    if (!IsP2PKH(address, error)) {
        return false;
    }
    if (nonce.size() != 64 || !IsHex(nonce)) {
        error = "Malformed challenge (expected 64 hex characters)";
        return false;
    }
    if (signatureBase64.empty()) {
        error = "Signature is required";
        return false;
    }
    if (!IsDepinSectionOrRoot(token, poolRoot)) {
        error = strprintf("Token '%s' is not configured token '%s' or a section inside it", token, poolRoot);
        return false;
    }

    // 2. Existence, read-only: a cheap gate before the signature work.
    if (!g_depinChallenges.Peek(nonce, error)) {
        return false;
    }

    // 3. Signature over exactly these bindings.
    if (!VerifyDepinChallengeSignature(address, signatureBase64,
                                       DepinChallengePreimage(type, token, address, nonce), error)) {
        return false;
    }

    // 4. Access, re-validated at use: what was true at issuance may not be now.
    if (!AddressHasDepinAccess(type, address, token, poolRoot, error)) {
        return false;
    }

    // 5. Consume, atomically and only for matching bindings.
    return g_depinChallenges.Consume(nonce, token, address, type, error);
}
