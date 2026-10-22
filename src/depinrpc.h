// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#ifndef NEURAI_DEPINRPC_H
#define NEURAI_DEPINRPC_H

#include "pubkey.h"
#include "depinmembership.h"
#include <cstdint>
#include <string>
#include <vector>
#include <univalue.h>

class CKey;
class CRPCTable;

struct DepinRpcIdentity {
    std::string network, poolKey, root, instance;
    DepinMembershipContext membership;
};
struct DepinRpcRequest {
    std::string method;
    uint8_t kind = 0; // public / timestamp / receive / admin
    DepinRpcIdentity target;
    std::string id, token, address, nonce, signature;
    int64_t timestamp = 0;
    UniValue args{UniValue::VOBJ}; // normalized arguments; never wire JSON hashing
    std::vector<unsigned char> argumentBytes;
    bool bootstrap = false;
    std::vector<unsigned char> Bytes() const;
    std::string Hash() const;
    std::string Preimage() const;
};

UniValue DepinRpcError(int code, const std::string& reason, const std::string& message);

// Pure, bounded parsing; does not consult local service identity or permissions.
DepinRpcRequest ParseDepinRpcRequest(const std::string& method, const UniValue& object);
// Construct a complete unsigned request for a known remote identity. Also useful
// to clients/tests: signing always parses and hashes the same effective values.
UniValue MakeDepinRpcRequest(const std::string& method, const DepinRpcIdentity& target,
                            const std::string& token, const std::string& address,
                            const std::string& nonce, const UniValue& args,
                            const std::string& id = "", int64_t timestamp = -1);
UniValue MakeDepinRpcBootstrap();
DepinRpcIdentity GetDepinRpcIdentity();
void ResetDepinRpcInstance();
// Called under cs_main at RPC entry. A backwards wall clock rotates the epoch;
// replay entries are pruned by signed wall deadlines, never by elapsed uptime.
void ObserveDepinRpcClock(int64_t nowMs);
bool CheckDepinRpcReplay(const DepinRpcRequest& request, std::string& error);
bool RememberDepinRpcRequest(const DepinRpcRequest& request, std::string& error);
size_t DepinRpcReplaySize();

std::string DepinRpcResponsePreimage(const DepinRpcIdentity& identity,
                                     const std::string& method, const std::string& requestHash,
                                     uint8_t bodyKind, const std::vector<unsigned char>& body);
UniValue FinishDepinRpcResponse(const UniValue& result, const DepinRpcRequest& request,
                                const CPubKey* clientKey = nullptr);
bool VerifyDepinRpcResponse(const UniValue& response, const DepinRpcRequest& request,
                            const CPubKey& pinnedKey, std::string& error);
void RegisterDepinRPCCommands(CRPCTable& table);

#endif
