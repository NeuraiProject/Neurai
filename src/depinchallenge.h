// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_DEPINCHALLENGE_H
#define NEURAI_DEPINCHALLENGE_H

#include "sync.h"
#include "uint256.h"

#include <cstdint>
#include <deque>
#include <map>
#include <string>

class CKey;
class CPubKey;

/**
 * Challenge/response authentication for the DePIN RPCs.
 *
 * A holder proves control of an address by signing a single-use nonce that
 * the node issued for exactly (token, address, type). The nonce travels as a
 * regular RPC parameter, so the proof works through any RPC proxy: nothing
 * here depends on a dedicated listener or on the caller's IP address (behind
 * a proxy every caller shares the proxy's IP, so binding to it would prove
 * nothing and break legitimate clients).
 *
 * The preimage is signed with the standard message-signing scheme
 * (strMessageMagic + compact signature, base64), so `signmessage` and
 * `verifymessage` interoperate with it.
 *
 * Only two things ever remove a nonce from the store: its expiry, and its
 * consumption after a VALID signature for matching bindings. A request that
 * presents an invalid signature, or a nonce issued for other bindings, fails
 * without touching the store; otherwise anyone who learned a nonce could
 * invalidate it for its owner by sending garbage.
 */
enum class DepinChallengeType {
    RECEIVE,  // read a holder's messages / section access (preimage "DEPIN-GET")
    ADMIN     // owner-level operations such as depinclearmsg (preimage "DEPIN-CLEAR")
};

/** Lifetime of a challenge issued by depinchallenge, in seconds. */
static const int64_t DEPIN_CHALLENGE_TIMEOUT = 30;
/**
 * Lifetime of a challenge chained into an authenticated reply
 * ("next_challenge"): a client that keeps reading within this window never
 * calls depinchallenge again, which is the session-like behaviour wanted
 * without a session -- every request still carries its own signature.
 */
static const int64_t DEPIN_CHAINED_CHALLENGE_TIMEOUT = 300;
/** Default for -depinratelimit: per address and minute, 0 = unlimited. */
static const unsigned int DEFAULT_DEPIN_RATE_LIMIT = 20;
static const int64_t DEPIN_RATE_WINDOW = 60;
/**
 * A challenge REQUEST is itself signed, over a millisecond timestamp: accepted
 * only within this window of the node's clock, and never twice. Without it
 * anyone could name a holder in depinchallenge and spend its quota or evict
 * its live nonces -- the reply being encrypted stops the use of the nonce,
 * not the damage of asking for it. Milliseconds because signatures are
 * deterministic (RFC 6979): two requests in the same instant would be the
 * same request.
 */
static const int64_t DEPIN_REQUEST_WINDOW_MS = 60 * 1000;
/**
 * Hard cap on the keys the rate limiter tracks at once. When it is reached
 * and nothing has left the window, a NEW key is refused rather than stored:
 * the map can never grow past this, whatever the callers send.
 */
static const size_t DEPIN_RATE_LIMITER_MAX_KEYS = 10000;
/** Live challenges kept per address; issuing one more evicts the oldest. */
static const size_t DEPIN_CHALLENGE_MAX_PER_ADDRESS = 4;
/** Live challenges kept in total; beyond this, issuance fails. */
static const size_t DEPIN_CHALLENGE_MAX_TOTAL = 10000;

struct CDepinChallenge {
    std::string token;
    std::string address;
    DepinChallengeType type;
    int64_t expiry;
};

/** "receive" / "admin". */
std::string DepinChallengeTypeName(DepinChallengeType type);
/** Parses "receive" / "admin" (case-insensitive); false on anything else. */
bool ParseDepinChallengeType(const std::string& name, DepinChallengeType& type);

/**
 * The exact string a holder signs: "DEPIN-GET|token|address|nonce" for
 * RECEIVE, "DEPIN-CLEAR|token|address|nonce" for ADMIN. Shared by the signer
 * (wallet) and the verifier (node) so the two can never drift apart.
 */
std::string DepinChallengePreimage(DepinChallengeType type, const std::string& token,
                                   const std::string& address, const std::string& nonce);

/**
 * What a holder signs to ASK for a challenge:
 * "DEPIN-REQ|receive|token|address|timestamp" (or "admin"). The timestamp is
 * Unix MILLISECONDS from the client's clock.
 */
std::string DepinChallengeRequestPreimage(DepinChallengeType type, const std::string& token,
                                          const std::string& address, int64_t timestampMs);

/** The clock requests are checked against: Unix ms, honouring mock time in tests. */
int64_t DepinRequestClockMillis();

/** Message-scheme hash of a preimage (strMessageMagic || preimage). */
uint256 DepinChallengeSigningHash(const std::string& preimage);

/** Compact signature of `preimage` with `key`, base64-encoded (signmessage-compatible). */
bool SignDepinChallengePreimage(const CKey& key, const std::string& preimage,
                                std::string& signatureBase64, std::string& error);

/**
 * Verifies a base64 compact signature of `preimage` against a P2PKH address.
 * Pure computation: it never touches the challenge store.
 */
bool VerifyDepinChallengeSignature(const std::string& address, const std::string& signatureBase64,
                                   const std::string& preimage, std::string& error);

/** The nonce store. Thread-safe; all methods take cs_challenges. */
class CDepinChallengeManager
{
public:
    /**
     * Issues a nonce bound to (token, address, type), valid for
     * DEPIN_CHALLENGE_TIMEOUT seconds. Access checks (does the address hold the
     * token? is it an owner?) are the caller's job; this only manages the
     * store and its limits. Returns the 64-hex nonce, or "" with `error` set.
     */
    std::string Issue(const std::string& token, const std::string& address,
                      DepinChallengeType type, std::string& error,
                      int64_t lifetime = DEPIN_CHALLENGE_TIMEOUT);

    /**
     * Read-only existence check: the nonce is known and has not expired. A
     * cheap gate before signature verification; never modifies the store.
     */
    bool Peek(const std::string& nonce, std::string& error) const;

    /**
     * Atomic check-and-consume. Succeeds, and erases the nonce, only if it
     * exists, has not expired and was issued for exactly these bindings. A
     * mismatch leaves the nonce in place. Call this only AFTER the signature
     * over the same bindings has been verified.
     */
    bool Consume(const std::string& nonce, const std::string& token,
                 const std::string& address, DepinChallengeType type, std::string& error);

    /** Drops every challenge whose expiry is <= now. Returns how many. */
    size_t CleanupExpired(int64_t now);

    size_t Size() const;
    size_t CountForAddress(const std::string& address) const;
    void Clear();

private:
    mutable CCriticalSection cs_challenges;
    std::map<std::string, CDepinChallenge> mapChallenges;             // nonce -> challenge
    std::map<std::string, std::deque<std::string>> mapNoncesByAddress; // address -> nonces, oldest first

    void EraseLocked(const std::string& nonce);
    size_t CleanupExpiredLocked(int64_t now);
};

extern CDepinChallengeManager g_depinChallenges;

/**
 * Sliding-window counter per key (an address, prefixed by the operation): at
 * most `limit` events per DEPIN_RATE_WINDOW seconds. The node cannot
 * rate-limit by IP -- behind an RPC proxy every caller shares one -- so this
 * is the abuse control it can apply itself: challenge issuance and message
 * submission per address.
 *
 * Call Allow() only AFTER a request has been validated (form, access,
 * signature). Counting before validation would let anyone exhaust a holder's
 * quota by sending requests in its name that could never succeed, and would
 * let invented keys grow the map.
 */
class CDepinRateLimiter
{
public:
    void SetLimit(unsigned int perWindow); // 0 = unlimited
    unsigned int GetLimit() const;
    /**
     * Records the event and returns true, or returns false without recording:
     * the key is over the limit, or the key is new and the limiter already
     * tracks DEPIN_RATE_LIMITER_MAX_KEYS live keys.
     */
    bool Allow(const std::string& key, int64_t now);
    /** Drops events outside the window and keys left empty. */
    void Prune(int64_t now);
    void Clear();
    size_t Size() const;

private:
    mutable CCriticalSection cs_rate;
    unsigned int limit = DEFAULT_DEPIN_RATE_LIMIT;
    std::map<std::string, std::deque<int64_t>> mapHits;
};

extern CDepinRateLimiter g_depinRateLimiter;

/**
 * Remembers accepted request signatures for as long as their timestamp could
 * still fall inside the window, so a signed request cannot be replayed.
 * Bounded: past `maxEntries` live entries, new ones are refused until a
 * prune frees room (only valid signatures ever get here, so the bound is
 * holders' own traffic).
 */
class CDepinReplayGuard
{
public:
    /** True and recorded if `key` was not seen; false if it was or if full. Times in ms. */
    bool Remember(const std::string& key, int64_t nowMs, int64_t ttlMs, std::string& error);
    void Prune(int64_t nowMs);
    void Clear();
    size_t Size() const;

private:
    mutable CCriticalSection cs_replay;
    std::map<std::string, int64_t> mapSeen; // key -> expiry
    static const size_t maxEntries = 10000;
};

extern CDepinReplayGuard g_depinRequestGuard;

/**
 * Authenticates a challenge request: `timestampMs` within
 * DEPIN_REQUEST_WINDOW_MS of `nowMs`, `signatureBase64` valid for `address`
 * over DepinChallengeRequestPreimage, and not seen before. Pure except for
 * the replay record, which is only written for a VALID signature: a forged
 * request spends nothing of the address it names.
 */
bool CheckDepinChallengeRequestAuth(DepinChallengeType type, const std::string& token,
                                    const std::string& address, int64_t timestampMs,
                                    const std::string& signatureBase64, int64_t nowMs,
                                    std::string& error);

/**
 * The checks that make challenge issuance safe against abuse, without
 * issuing anything: `token` must be `poolRoot` or a section inside it,
 * `address` must be P2PKH with a revealed public key, and must hold the token
 * or an ancestor (RECEIVE) or the owner token of it or an ancestor (ADMIN).
 * On success `pubkeyOut` (to encrypt the reply) is set. The RPC runs this
 * first, applies the rate limit, and only then issues: a request that fails
 * here never counts against the address.
 */
bool CheckDepinChallengeRequest(const std::string& token, const std::string& address,
                                DepinChallengeType type, const std::string& poolRoot,
                                CPubKey& pubkeyOut, std::string& error);

/**
 * CheckDepinChallengeRequest followed by issuance (no rate limiting). On
 * success `nonce` and `pubkeyOut` are set.
 */
bool IssueDepinChallengeForAddress(const std::string& token, const std::string& address,
                                   DepinChallengeType type, const std::string& poolRoot,
                                   std::string& nonce, CPubKey& pubkeyOut, std::string& error);

/**
 * The complete check an authenticated RPC performs, in this order and with no
 * shortcuts:
 *   1. form (address, nonce, signature are well-formed)
 *   2. the nonce exists and has not expired (read-only)
 *   3. the signature over DepinChallengePreimage(type, token, address, nonce)
 *      verifies for `address`
 *   4. access is re-validated (a freeze, self-revoke or transfer between
 *      issuance and use invalidates the challenge)
 *   5. the nonce is consumed atomically for exactly these bindings
 * Nothing before step 5 modifies the store, so a request that fails cannot
 * invalidate someone else's nonce.
 */
bool CheckDepinChallengeAuth(DepinChallengeType type, const std::string& token,
                             const std::string& address, const std::string& nonce,
                             const std::string& signatureBase64, const std::string& poolRoot,
                             std::string& error);

#endif // NEURAI_DEPINCHALLENGE_H
