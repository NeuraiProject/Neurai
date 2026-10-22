// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#ifndef NEURAI_TEST_DEPIN_RPC_TEST_CLIENT_H
#define NEURAI_TEST_DEPIN_RPC_TEST_CLIENT_H
#include "depinrpc.h"
#include "base58.h"
#include "depinmsgpool.h"
#include "depinchallenge.h"
#include "depinpoolkey.h"
#include "depinecies.h"
#include "rpc/server.h"
#include "rpc/protocol.h"
#include "streams.h"
#include "utilstrencodings.h"
#include "version.h"
#include "key.h"
#include "crypto/sha256.h"
#include <map>
#include <set>

// Test-only migration adapter. Existing permission/storage scenarios retain
// their compact positional builders. This converts them to real v5 requests
// and signs only when the old fixture proof matches its stated identity/scope.
// Raw v5 requests are NEVER re-signed: mutation/replay tests use that path.
inline std::map<std::string,CKey>& DepinTestKeys() { static std::map<std::string,CKey> keys;return keys; }
inline std::map<std::string,DepinRpcRequest>& DepinTestRequests() { static std::map<std::string,DepinRpcRequest> requests;return requests; }
inline void RememberDepinTestKey(const CKey& key) { DepinTestKeys()[EncodeDestination(key.GetPubKey().GetID())]=key; }
inline UniValue DepinTestReplace(const UniValue& o, const std::string& key, const UniValue& value)
{
    UniValue result(UniValue::VOBJ);bool found=false;
    for (size_t n=0;n<o.size();++n) { const auto& name=o.getKeys()[n];result.pushKV(name,name==key?value:o.getValues()[n]);found|=name==key; }
    if (!found) result.pushKV(key,value);return result;
}
inline UniValue DepinTestParams(const UniValue& request) { UniValue p(UniValue::VARR);p.push_back(request);return p; }
inline UniValue DepinTestSign(const std::string& method, UniValue object, const CKey& key)
{
    const auto parsed=ParseDepinRpcRequest(method,object);std::string signature,error;
    if (!SignDepinChallengePreimage(key,parsed.Preimage(),signature,error)) throw std::runtime_error(error);
    return DepinTestReplace(object,"signature",UniValue(signature));
}
inline UniValue DepinTestRequest(const std::string& method, const UniValue& p)
{
    if (p.size()==1 && p[0].isObject() && p[0].exists("protocol")) return p[0];
    const auto identity=GetDepinRpcIdentity();UniValue args(UniValue::VOBJ);
    std::string token=identity.root,address,nonce,proof,oldPreimage;
    int64_t timestamp=DepinRequestClockMillis();
    if (method=="depingetmsginfo") {
        if (p.size()) throw JSONRPCError(RPC_INVALID_PARAMETER,"Unexpected arguments");return MakeDepinRpcBootstrap();
    }
    if (method=="depinchallenge") {
        if (p.size()<4 || p.size()>5) throw JSONRPCError(RPC_INVALID_PARAMETER,"Incomplete test request");
        token=p[0].get_str();address=p[1].get_str();timestamp=p[2].get_int64();proof=p[3].get_str();
        const auto type=p.size()==5?p[4].get_str():"receive";DepinChallengeType kind;
        if (!ParseDepinChallengeType(type,kind)) throw JSONRPCError(RPC_INVALID_PARAMETER,"Invalid challenge type");
        args.pushKV("type",type);oldPreimage=DepinChallengeRequestPreimage(kind,token,address,timestamp);
    } else if (method=="depinreceivemsg" || method=="depinclearmsg") {
        if (p.size()<4 || p.size()>(method=="depinclearmsg"?5:7)) throw JSONRPCError(RPC_INVALID_PARAMETER,"Incomplete test request");
        token=p[0].isNull()?"":p[0].get_str();address=p[1].get_str();nonce=p[2].get_str();proof=p[3].get_str();
        if (method=="depinclearmsg") {
            const auto mode=p.size()==5?p[4]:NullUniValue;
            if (!mode.isNull()) {
                if (mode.isStr() && mode.get_str()=="all") args.pushKV("mode","all");
                else { args.pushKV("mode","hours");args.pushKV("hours",mode); }
            }
        } else {
            for (size_t n=4;n<p.size();++n) args.pushKV(n==4?"timestamp":n==5?"after_hash":"limit",p[n]);
        }
        oldPreimage=DepinChallengePreimage(method=="depinclearmsg"?DepinChallengeType::ADMIN:DepinChallengeType::RECEIVE,
                                           token.empty()?identity.root:token,address,nonce);
    } else if (method=="depinlistsections") {
        if (p.size() && p.size()!=4) throw JSONRPCError(RPC_INVALID_PARAMETER,"Incomplete test request");
        if (p.size()) {
            address=p[0].get_str();token=p[1].get_str();nonce=p[2].get_str();proof=p[3].get_str();
            oldPreimage=DepinChallengePreimage(DepinChallengeType::RECEIVE,token,address,nonce);
        }
    } else if (method=="depingetancestorrecipients") {
        if (p.size()<1 || p.size()>3) throw JSONRPCError(RPC_INVALID_PARAMETER,"Incomplete test request");
        token=p[0].get_str();if (p.size()>1) args.pushKV("max_results",p[1]);if (p.size()>2) args.pushKV("stop_at",p[2]);
    } else if (method=="depinsubmitmsg") {
        if (p.size()!=1 || !p[0].isObject()) throw JSONRPCError(RPC_INVALID_PARAMETER,"Incomplete test submit");
        address=p[0]["sender"].get_str();token="";args.pushKV("encrypted",p[0]["encrypted"]);
    } else if (p.size()) throw JSONRPCError(RPC_INVALID_PARAMETER,"Unexpected arguments");
    std::string id;
    if (!proof.empty()) { unsigned char bytes[32];CSHA256().Write(reinterpret_cast<const unsigned char*>(proof.data()),proof.size()).Finalize(bytes);id=HexStr(bytes,bytes+32); }
    auto object=MakeDepinRpcRequest(method,identity,token,address,nonce,args,id,timestamp);
    const auto parsed=ParseDepinRpcRequest(method,object);
    if (!parsed.kind) return object;
    std::string error;
    const bool valid=method=="depinsubmitmsg" || VerifyDepinChallengeSignature(address,proof,oldPreimage,error);
    const auto it=DepinTestKeys().find(address);
    if (valid && it!=DepinTestKeys().end()) return DepinTestSign(method,object,it->second);
    return DepinTestReplace(object,"signature",UniValue(proof));
}
inline UniValue DepinTestOpen(const UniValue& response, const std::string& address)
{
    if (response.exists("body")) return DepinPlainBody(response);
    const auto it=DepinTestKeys().find(address);if (it==DepinTestKeys().end()) throw std::runtime_error("Test key not registered");
    CECIESEncryptedMessage ecies;std::string error,plain;
    if (!DecodeDepinECIES(ParseHex(response["encrypted"].get_str()),MAX_DEPIN_REPLY_PLAINTEXT,MAX_DEPIN_RECIPIENTS,ecies,error) ||
        !ECIESDecryptMessage(ecies,it->second,address,plain,error)) throw std::runtime_error(error);
    UniValue result;if (!result.read(plain)) throw std::runtime_error("Invalid test response JSON");return result;
}
inline UniValue CallDepinTestRpc(const std::string& method, const UniValue& params)
{
    static const std::set<std::string> migrated={"depingetmsginfo","depinpoolstats","depinmcpstatus","depingetancestorrecipients","depinlistsections","depinchallenge","depinclearmsg","depinreceivemsg","depinreceiveseq","depinsubmitmsg"};
    JSONRPCRequest request;request.strMethod=method;request.params=params;request.fHelp=false;
    if (!migrated.count(method)) return (*tableRPC[method]->actor)(request);
    const auto object=DepinTestRequest(method,params);const auto parsed=ParseDepinRpcRequest(method,object);
    request.params=DepinTestParams(object);DepinTestRequests()[parsed.Hash()]=parsed;
    const auto response=(*tableRPC[method]->actor)(request);
    CKey key;CPubKey pub;std::string error;
    if (!GetDepinPoolKey(key,pub) || !VerifyDepinRpcResponse(response,parsed,pub,error)) throw JSONRPCError(RPC_INVALID_REQUEST,"Test response verification failed: "+error);
    const auto inner=DepinTestOpen(response,parsed.address);if (inner.isObject() && inner.exists("error")) throw inner["error"];
    if (parsed.kind && response["membership_revision"].get_str()!=parsed.target.membership.revision) throw JSONRPCError(RPC_INVALID_REQUEST,"Test success used another membership revision");
    return response;
}
#endif
