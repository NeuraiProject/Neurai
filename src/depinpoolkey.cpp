// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "depinpoolkey.h"

#include "base58.h"
#include "crypto/sha256.h"
#include "depinchallenge.h" // message-magic signing/verification helpers
#include "depinecies.h"
#include "rpc/protocol.h"
#include "streams.h"
#include "sync.h"
#include "tinyformat.h"
#include "utilstrencodings.h"
#include "version.h"

#include <map>

namespace {

CCriticalSection cs_depinPoolKey;
bool g_havePoolKey = false;
CKey g_poolKey;
CPubKey g_poolPubKey;
std::string g_poolKeyWallet;

std::string Sha256Hex(const std::string& data)
{
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(reinterpret_cast<const unsigned char*>(data.data()), data.size()).Finalize(digest);
    return HexStr(digest, digest + CSHA256::OUTPUT_SIZE);
}

} // namespace

void SetDepinPoolKey(const CKey& key, const std::string& walletName)
{
    LOCK(cs_depinPoolKey);
    g_poolKey = key;
    g_poolPubKey = key.GetPubKey();
    g_poolKeyWallet = walletName;
    g_havePoolKey = key.IsValid();
}

void ClearDepinPoolKey()
{
    LOCK(cs_depinPoolKey);
    g_havePoolKey = false;
    g_poolKey = CKey();
    g_poolPubKey = CPubKey();
    g_poolKeyWallet.clear();
}

bool HaveDepinPoolKey()
{
    LOCK(cs_depinPoolKey);
    return g_havePoolKey;
}

bool GetDepinPoolKey(CKey& key, CPubKey& pubkey)
{
    LOCK(cs_depinPoolKey);
    if (!g_havePoolKey) return false;
    key = g_poolKey;
    pubkey = g_poolPubKey;
    return true;
}

std::string GetDepinPoolKeyWalletName()
{
    LOCK(cs_depinPoolKey);
    return g_poolKeyWallet;
}

std::string DepinResponsePreimage(const std::string& method, const std::string& token,
                                  const std::string& address, const std::string& nonce,
                                  const std::string& body)
{
    return strprintf("DEPIN-RESP|%s|%s|%s|%s|%s", method, token, address, nonce, Sha256Hex(body));
}

bool SignDepinResponse(const std::string& method, const std::string& token,
                       const std::string& address, const std::string& nonce,
                       const std::string& body, std::string& signatureOut, std::string& error)
{
    CKey key;
    CPubKey pubkey;
    if (!GetDepinPoolKey(key, pubkey)) {
        error = "DePIN pool key not loaded";
        return false;
    }
    return SignDepinChallengePreimage(key, DepinResponsePreimage(method, token, address, nonce, body),
                                      signatureOut, error);
}

bool VerifyDepinResponseSignature(const CPubKey& poolPubKey, const std::string& method,
                                  const std::string& token, const std::string& address,
                                  const std::string& nonce, const std::string& body,
                                  const std::string& signatureBase64, std::string& error)
{
    if (!poolPubKey.IsFullyValid()) {
        error = "Invalid pool public key";
        return false;
    }
    return VerifyDepinChallengeSignature(EncodeDestination(poolPubKey.GetID()), signatureBase64,
                                         DepinResponsePreimage(method, token, address, nonce, body),
                                         error);
}

UniValue FinishDepinResponse(const UniValue& result, const std::string& method,
                             const std::string& token, const std::string& address,
                             const std::string& nonce, const CPubKey* clientPubKey)
{
    if (!HaveDepinPoolKey()) {
        throw JSONRPCError(RPC_MISC_ERROR,
                           "DePIN pool key not loaded: the service is not available on this node");
    }

    UniValue out(UniValue::VOBJ);
    std::string body;

    if (clientPubKey != nullptr) {
        if (!clientPubKey->IsFullyValid()) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Invalid client public key for response encryption");
        }
        std::map<std::string, CPubKey> recipients;
        recipients[address.empty() ? EncodeDestination(clientPubKey->GetID()) : address] = *clientPubKey;

        CECIESEncryptedMessage ecies;
        std::string error;
        if (!ECIESEncryptMessage(result.write(), recipients, ecies, error)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Failed to encrypt response: %s", error));
        }
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << ecies;
        body = HexStr(ss.begin(), ss.end());
        out.push_back(Pair("encrypted", body));
    } else {
        // Hex of the canonical JSON: the exact bytes the signature covers, so
        // the client hashes the string it received instead of re-serialising.
        const std::string json = result.write();
        body = HexStr(json.begin(), json.end());
        out.push_back(Pair("body", body));
    }

    std::string signature;
    std::string error;
    if (!SignDepinResponse(method, token, address, nonce, body, signature, error)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("Failed to sign response: %s", error));
    }
    out.push_back(Pair("poolsig", signature));
    return out;
}

UniValue DepinPlainBody(const UniValue& response)
{
    if (!response.isObject() || !response.exists("body") || !response["body"].isStr()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Reply has no body");
    }
    const std::string hex = response["body"].get_str();
    if (!IsHex(hex)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Reply body is not hex");
    }
    const std::vector<unsigned char> bytes = ParseHex(hex);
    UniValue decoded;
    if (!decoded.read(std::string(bytes.begin(), bytes.end()))) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Reply body is not JSON");
    }
    return decoded;
}
