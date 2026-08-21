// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_WALLET_DEPINPOOLKEYLOAD_H
#define NEURAI_WALLET_DEPINPOOLKEYLOAD_H

#include "key.h"
#include "pubkey.h"

#include <string>

class CWallet;

/**
 * The wallet-side half of the DePIN pool key (see depinpoolkey.h): deriving
 * it from the service wallet and installing it at startup. This is the only
 * code that touches a wallet on behalf of the DePIN service.
 */

/** Derives the pool key at m/44'/coin'/200'/change/0 from the wallet's BIP44 seed. */
bool DeriveDepinPoolKeys(CWallet* pwallet, CKey& privKey, CPubKey& pubkey,
                         std::string& derivationPath, std::string& error);

/**
 * Picks the service wallet among the loaded ones. With a single wallet loaded
 * that is the one; with several, `requestedName` (-depinwallet) must name one
 * of them. Never falls back to vpwallets[0] by position: the load order would
 * otherwise decide the pool's identity. Returns nullptr with `error` set.
 */
CWallet* SelectDepinServiceWallet(const std::string& requestedName, std::string& error);

/**
 * Startup check + load: the wallet must be HD BIP44, legacy (not PQ) and not
 * encrypted; the derived key must be vouched for by an owner of `token`
 * through `ownerSignatureBase64` (-depinpoolkeysig). On success the key is
 * installed with SetDepinPoolKey(). Every failure names the exact condition.
 */
bool LoadDepinPoolKey(CWallet* pwallet, const std::string& token,
                      const std::string& ownerSignatureBase64, std::string& error);

#endif // NEURAI_WALLET_DEPINPOOLKEYLOAD_H
