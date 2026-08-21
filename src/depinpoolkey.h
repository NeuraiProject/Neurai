// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_DEPINPOOLKEY_H
#define NEURAI_DEPINPOOLKEY_H

#include "key.h"
#include "pubkey.h"

#include <string>
#include <univalue.h>

/**
 * The DePIN service pool key.
 *
 * One secp256k1 key per service node, derived from the node's dedicated legacy
 * wallet at startup (wallet/depinpoolkeyload.cpp) and held here for the life
 * of the process. It does two things:
 *
 *  - opens the ECIES envelope clients wrap around depinsubmitmsg payloads, and
 *  - signs every DePIN RPC response ("poolsig"), so a client that has anchored
 *    the pool's public key can tell a genuine response from one fabricated by
 *    whatever sits between it and the node (typically an RPC proxy).
 *
 * The token owner vouches for the key by signing DepinPoolKeyOwnerPreimage()
 * with the address that holds the owner token; the node verifies that
 * signature at startup and republishes it through depingetmsginfo.
 *
 * This module has no wallet dependency so the RPC layer links the same way
 * with and without wallet support. Without a wallet nothing ever loads a key
 * and every DePIN RPC fails closed.
 */

/** Bumped whenever the DePIN RPC contract changes incompatibly. */
static const int DEPIN_RPC_PROTOCOL_VERSION = 2;

/** "DEPIN-POOLKEY|token|pubkeyhex": what the token owner signs (signmessage-compatible). */
std::string DepinPoolKeyOwnerPreimage(const std::string& token, const CPubKey& poolPubKey);

/**
 * Verifies the owner's base64 compact signature over DepinPoolKeyOwnerPreimage
 * and that the recovered address holds the owner token of `token`. On
 * success `ownerAddressOut` is the vouching address.
 */
bool VerifyDepinPoolKeyOwnerSignature(const std::string& token, const CPubKey& poolPubKey,
                                      const std::string& ownerSignatureBase64,
                                      std::string& ownerAddressOut, std::string& error);

/** Installs the pool key for the process. `walletName` is informational (depingetmsginfo). */
void SetDepinPoolKey(const CKey& key, const std::string& ownerAddress,
                     const std::string& ownerSignatureBase64, const std::string& walletName);
void ClearDepinPoolKey();
bool HaveDepinPoolKey();
bool GetDepinPoolKey(CKey& key, CPubKey& pubkey);
std::string GetDepinPoolKeyOwner();
std::string GetDepinPoolKeySig();
std::string GetDepinPoolKeyWalletName();

/**
 * "DEPIN-RESP|method|token|address|nonce|sha256hex(body)": the canonical
 * preimage of a response signature. `body` is the string value of the reply's
 * `encrypted` field (hex ECIES blob) or of its `body` field (hex of the JSON),
 * hashed exactly as transported. `nonce` is the challenge the request
 * consumed, "" when there was none.
 */
std::string DepinResponsePreimage(const std::string& method, const std::string& token,
                                  const std::string& address, const std::string& nonce,
                                  const std::string& body);

/** Base64 compact signature of DepinResponsePreimage with the pool key. */
bool SignDepinResponse(const std::string& method, const std::string& token,
                       const std::string& address, const std::string& nonce,
                       const std::string& body, std::string& signatureOut, std::string& error);

/** What a client does with "poolsig": verify against the anchored pool public key. */
bool VerifyDepinResponseSignature(const CPubKey& poolPubKey, const std::string& method,
                                  const std::string& token, const std::string& address,
                                  const std::string& nonce, const std::string& body,
                                  const std::string& signatureBase64, std::string& error);

/**
 * Applies the transport layer to an RPC result and returns what the RPC
 * answers:
 *
 *   with clientPubKey:    {"encrypted": <hex ECIES of the JSON>, "poolsig": ...}
 *   without:              {"body": <hex of the UTF-8 JSON>,     "poolsig": ...}
 *
 * Either way the signature is over the field's string value exactly as sent
 * (DepinResponsePreimage hashes that string), so a client never has to
 * re-serialise JSON to verify: hash the `encrypted` or `body` string, check
 * poolsig, then decrypt or hex-decode. Encrypt-then-sign. Throws
 * JSONRPCError when no pool key is loaded -- a DePIN response is never sent
 * unsigned.
 */
UniValue FinishDepinResponse(const UniValue& result, const std::string& method,
                             const std::string& token, const std::string& address,
                             const std::string& nonce, const CPubKey* clientPubKey);

/** Decodes a plain reply's "body" back into the JSON value it carries. */
UniValue DepinPlainBody(const UniValue& response);

#endif // NEURAI_DEPINPOOLKEY_H
