// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/depinpoolkeyload.h"

#include "chainparams.h"
#include "depinpoolkey.h"
#include "tinyformat.h"
#include "validation.h" // cs_main
#include "wallet/wallet.h"

bool DeriveDepinPoolKeys(CWallet* pwallet, CKey& privKey, CPubKey& pubkey,
                         std::string& derivationPath, std::string& error)
{
    const uint32_t BIP32_HARDENED_KEY_LIMIT = 0x80000000;

    if (!pwallet) {
        error = "Wallet is not available";
        return false;
    }

    LOCK2(cs_main, pwallet->cs_wallet);

    if (pwallet->IsLocked()) {
        error = "Wallet is locked";
        return false;
    }

    const CHDChain& hdChain = pwallet->GetHDChain();
    if (!hdChain.IsBip44()) {
        error = "Wallet does not use BIP44";
        return false;
    }

    CExtKey masterKey;
    CExtKey purposeKey;      // m/44'
    CExtKey coinTypeKey;     // m/44'/coin'
    CExtKey accountKey;      // m/44'/coin'/200'
    CExtKey changeKey;       // m/44'/coin'/200'/change
    CExtKey addressKey;      // m/44'/coin'/200'/change/0

    {
        uint256 hash;
        std::vector<unsigned char> vchWords;
        std::vector<unsigned char> vchPassphrase;
        std::vector<unsigned char> vchSeed;

        pwallet->GetBip39Data(hash, vchWords, vchPassphrase, vchSeed);

        if (vchSeed.empty()) {
            error = "HD seed not available";
            return false;
        }

        masterKey.SetSeed(vchSeed.data(), vchSeed.size());
    }

    const bool isTestnet = (GetParams().NetworkIDString() == CBaseChainParams::TESTNET);
    const uint32_t changeIndex = isTestnet ? 1 : 0;
    derivationPath = strprintf("m/44'/0'/200'/%d/0", changeIndex);

    try {
        masterKey.Derive(purposeKey, 44 | BIP32_HARDENED_KEY_LIMIT);
        purposeKey.Derive(coinTypeKey, GetParams().ExtCoinType() | BIP32_HARDENED_KEY_LIMIT);
        coinTypeKey.Derive(accountKey, 200 | BIP32_HARDENED_KEY_LIMIT);
        accountKey.Derive(changeKey, changeIndex);
        changeKey.Derive(addressKey, 0);
    } catch (const std::exception& e) {
        error = strprintf("Failed to derive key: %s", e.what());
        return false;
    }

    privKey = addressKey.key;
    pubkey = privKey.GetPubKey();
    if (!pubkey.IsValid()) {
        error = "Derived public key is invalid";
        return false;
    }

    return true;
}

CWallet* SelectDepinServiceWallet(const std::string& requestedName, std::string& error)
{
    if (vpwallets.empty()) {
        error = "DePIN service requires a wallet (none loaded; is -disablewallet set?)";
        return nullptr;
    }
    if (requestedName.empty()) {
        if (vpwallets.size() == 1) {
            return vpwallets[0];
        }
        error = "DePIN service wallet is ambiguous; set -depinwallet=<file> to one of the loaded wallets";
        return nullptr;
    }
    for (CWallet* pwallet : vpwallets) {
        if (pwallet->GetName() == requestedName) {
            return pwallet;
        }
    }
    error = strprintf("-depinwallet='%s' is not a loaded wallet", requestedName);
    return nullptr;
}

bool LoadDepinPoolKey(CWallet* pwallet, std::string& error)
{
    if (!pwallet) {
        error = "DePIN service requires a wallet";
        return false;
    }
    if (!pwallet->IsBip44Enabled()) {
        error = strprintf("DePIN service requires a BIP44 wallet (wallet '%s' is not)", pwallet->GetName());
        return false;
    }
    if (pwallet->IsPQEnabled()) {
        error = strprintf("DePIN service requires a legacy (non-PQ) wallet (wallet '%s' is post-quantum)",
                          pwallet->GetName());
        return false;
    }
    if (pwallet->IsCrypted()) {
        // The key signs every response for as long as the node runs, so it is
        // hot anyway; a passphrase in the configuration would protect nothing.
        // Use a dedicated wallet that holds no funds instead.
        error = strprintf("DePIN service wallet must not be encrypted (wallet '%s' is)", pwallet->GetName());
        return false;
    }
    CKey key;
    CPubKey pubkey;
    std::string derivationPath;
    if (!DeriveDepinPoolKeys(pwallet, key, pubkey, derivationPath, error)) {
        return false;
    }

    SetDepinPoolKey(key, pwallet->GetName());
    return true;
}
