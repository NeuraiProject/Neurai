// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#include "depinaddress.h"
#include "base58.h"
#include "keystore.h"
#include "script/standard.h"

bool DepinRecipient::FromAddress(const std::string& address, DepinRecipient& out)
{
    const auto dest = DecodeDestination(address);
    if (!IsValidDestination(dest) || EncodeDestination(dest) != address) return false;
    if (const auto* id = boost::get<CKeyID>(&dest)) { out = DepinRecipient(*id); return true; }
    const auto* strict = boost::get<WitnessStrictAuthScript>(&dest);
    if (!strict || !strict->IsECDSA()) return false;
    out.type = 3;
    out.payload = strict->commitment;
    return true;
}

std::string DepinRecipient::Address() const
{
    return IsLegacy() ? EncodeDestination(CKeyID(LegacyID())) :
        EncodeDestination(WitnessStrictAuthScript(STRICT_AUTHSCRIPT_WITNESS_V3_ECDSA, payload));
}

bool DepinPubKeyMatchesAddress(const std::string& address, const CPubKey& pubkey)
{
    DepinRecipient recipient;
    if (!DepinRecipient::FromAddress(address, recipient) || !pubkey.IsFullyValid() || pubkey.IsPQ()) return false;
    const auto dest = DecodeDestination(address);
    if (const auto* id = boost::get<CKeyID>(&dest)) return pubkey.GetID() == *id;
    WitnessStrictAuthScript derived;
    return GetStrictAuthScriptDestinationForPubKey(pubkey, derived) &&
        derived == *boost::get<WitnessStrictAuthScript>(&dest);
}

bool GetDepinKeyID(const CKeyStore& store, const std::string& address, CKeyID& key)
{
    DepinRecipient recipient;
    if (!DepinRecipient::FromAddress(address, recipient)) return false;
    const auto dest = DecodeDestination(address);
    if (const auto* id = boost::get<CKeyID>(&dest)) { key = *id; return true; }
    const auto& strict = *boost::get<WitnessStrictAuthScript>(&dest);
    AuthScriptSpendData spend;
    CPubKey pubkey;
    if (!store.GetAuthScriptSpendData(strict.version, strict.commitment, spend) ||
        !store.GetPubKey(spend.key_id, pubkey) || !DepinPubKeyMatchesAddress(address, pubkey)) return false;
    key = spend.key_id;
    return true;
}
