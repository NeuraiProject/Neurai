// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#if defined(HAVE_CONFIG_H)
#include "config/neurai-config.h"
#endif
#include "depinrpc.h"
#include "base58.h"
#include "depinchallenge.h"
#include "depinecies.h"
#include "depinmsgpool.h"
#include "depinpoolkey.h"
#include "rpc/server.h"
#include "rpc/protocol.h"
#include "streams.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "validation.h"
#include "version.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#include "wallet/rpcwallet.h"
#endif
#include <limits>
#include <algorithm>

// Public, non-authenticating business queries. Only the v3 dispatcher below is
// registered: their old positional forms are not reachable through the table.
UniValue depingetmsginfo(const JSONRPCRequest&);
UniValue depinpoolstats(const JSONRPCRequest&);
UniValue depinmcpstatus(const JSONRPCRequest&);
UniValue depingetancestorrecipients(const JSONRPCRequest&);

namespace {
void Ready()
{
    std::string error;
    if (!CheckDepinServiceReady(error)) throw DepinRpcError(RPC_CLIENT_IN_INITIAL_DOWNLOAD,"service_not_ready",error);
}
void Enabled()
{
    if (!pDepinMsgPool || !pDepinMsgPool->IsEnabled()) throw DepinRpcError(RPC_MISC_ERROR,"service_disabled","DePIN messaging pool is not enabled");
}
void Remember(const DepinRpcRequest& r)
{
    std::string error;if (!RememberDepinRpcRequest(r,error)) throw JSONRPCError(RPC_INVALID_REQUEST,error);
}
void Consume(const DepinRpcRequest& r)
{
    std::string error;
    if (!g_depinChallenges.Consume(r.nonce,r.token,r.address,r.kind==3?DepinChallengeType::ADMIN:DepinChallengeType::RECEIVE,error))
        throw JSONRPCError(RPC_INVALID_REQUEST,error);
}
CPubKey Access(const DepinRpcRequest& r)
{
    CPubKey key;std::string error;
    if (!CheckAddressHasPublicKey(r.address,key,error)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,error);
    if (!CheckDepinChallengeAuth(r.kind==3?DepinChallengeType::ADMIN:DepinChallengeType::RECEIVE,
                                 r.token,r.address,r.nonce,r.signature,r.target.root,error,r.Preimage(),false))
        throw JSONRPCError(RPC_INVALID_REQUEST,error);
    return key;
}
void Chain(UniValue& result, const DepinRpcRequest& r)
{
    std::string error;
    const auto nonce=g_depinChallenges.Issue(r.token,r.address,DepinChallengeType::RECEIVE,error,DEPIN_CHAINED_CHALLENGE_TIMEOUT);
    if (!nonce.empty()) { result.pushKV("next_challenge",nonce);result.pushKV("next_expires_in",DEPIN_CHAINED_CHALLENGE_TIMEOUT); }
}
UniValue Message(const CDepinMessage& m)
{
    UniValue item(UniValue::VOBJ);item.pushKV("hash",m.GetHash().ToString());item.pushKV("token",m.token);
    item.pushKV("sender",m.senderAddress);item.pushKV("timestamp",m.timestamp);
    item.pushKV("message_type",m.messageType==1?"private":"group");
    item.pushKV("encrypted_payload_hex",HexStr(m.encryptedPayload));item.pushKV("signature_hex",HexStr(m.signature));return item;
}
UniValue Run(const DepinRpcRequest& r, const JSONRPCRequest& original)
{
    if (r.method=="depingetmsginfo" || r.method=="depinpoolstats" || r.method=="depinmcpstatus" || r.method=="depingetancestorrecipients") {
        JSONRPCRequest q=original;q.params=UniValue(UniValue::VARR);
        if (r.method=="depingetancestorrecipients") {
            q.params.push_back(r.token);q.params.push_back(r.args["max_results"]);q.params.push_back(r.args["stop_at"]);
            return depingetancestorrecipients(q);
        }
        if (r.method=="depingetmsginfo") {
            auto info=depingetmsginfo(q);const auto id=GetDepinRpcIdentity();
            info.pushKV("network",id.network);info.pushKV("instance_id",id.instance);info.pushKV("server_time_ms",DepinRequestClockMillis());
            UniValue versions(UniValue::VARR);versions.push_back(DEPIN_RPC_PROTOCOL_VERSION);
            info.pushKV("accepted_protocols",versions);return info;
        }
        return r.method=="depinpoolstats"?depinpoolstats(q):depinmcpstatus(q);
    }
    Enabled();Ready();
    if (r.method=="depinchallenge") {
        CPubKey key;std::string error;
        const auto type=r.args["type"].get_str()=="admin"?DepinChallengeType::ADMIN:DepinChallengeType::RECEIVE;
        if (!CheckDepinChallengeRequest(r.token,r.address,type,r.target.root,key,error)) throw JSONRPCError(RPC_INVALID_REQUEST,error);
        if (!CheckDepinRpcReplay(r,error)) throw JSONRPCError(RPC_INVALID_REQUEST,error);
        if (!g_depinRateLimiter.Allow("challenge|"+r.address,GetTime())) throw JSONRPCError(RPC_MISC_ERROR,"Rate limited: too many challenges for this address");
        Remember(r);
        const auto nonce=g_depinChallenges.Issue(r.token,r.address,type,error);
        if (nonce.empty()) throw JSONRPCError(RPC_MISC_ERROR,error);
        UniValue result(UniValue::VOBJ);result.pushKV("challenge",nonce);result.pushKV("expires_in",DEPIN_CHALLENGE_TIMEOUT);result.pushKV("type",DepinChallengeTypeName(type));return result;
    }
    if (r.method=="depinsubmitmsg") {
        CKey key;CPubKey pub;std::string error;
        if (!GetDepinPoolKey(key,pub)) throw JSONRPCError(RPC_MISC_ERROR,"DePIN pool key unavailable");
        CECIESEncryptedMessage envelope;const auto poolId=pub.GetID();
        if (!DecodeDepinECIES(ParseHex(r.args["encrypted"].get_str()),MAX_DEPIN_MESSAGE_WIRE_BYTES*2,1,envelope,error,&poolId)) throw JSONRPCError(RPC_DESERIALIZATION_ERROR,error);
        std::string inner;
        if (!ECIESDecryptMessage(envelope,key,EncodeDestination(poolId),inner,error)) throw JSONRPCError(RPC_VERIFY_ERROR,"Failed to decrypt outer privacy shell: "+error);
        if (inner.empty() || inner.size()>MAX_DEPIN_MESSAGE_WIRE_BYTES*2 || !IsHex(inner)) throw JSONRPCError(RPC_INVALID_PARAMETER,"Message must be bounded hex");
        CDepinMessage message;
        if (!DecodeDepinMessage(ParseHex(inner),message,error)) throw JSONRPCError(RPC_DESERIALIZATION_ERROR,error);
        if (message.senderAddress!=r.address) throw JSONRPCError(RPC_INVALID_PARAMETER,"Envelope sender does not match signed message sender");
        if (!VerifyDepinMessageSignature(message)) throw JSONRPCError(RPC_VERIFY_ERROR,"Invalid message signature");
        CPubKey sender;
        if (!CheckAddressHasPublicKey(r.address,sender,error)) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,error);
        if (!HasDepinSectionAccess(r.address,message.token,r.target.root,error)) throw JSONRPCError(RPC_VERIFY_ERROR,error);
        // A valid sender cannot use replay to bypass quotas. A refused later
        // admission may burn this operation ID; it never burns someone else's.
        if (!CheckDepinRpcReplay(r,error)) throw JSONRPCError(RPC_INVALID_REQUEST,error);
        if (!g_depinRateLimiter.Allow("submit|"+r.address,GetTime())) throw JSONRPCError(RPC_MISC_ERROR,"Rate limited: too many messages from this address");
        Remember(r);
        DepinAdmissionError admission;
        if (!pDepinMsgPool->AddMessage(message,error,false,&admission))
            throw JSONRPCError(admission==DepinAdmissionError::RECIPIENT_NOT_AUTHORIZED?RPC_VERIFY_REJECTED:RPC_MISC_ERROR,error);
        UniValue result(UniValue::VOBJ);result.pushKV("result","success");result.pushKV("hash",message.GetHash().ToString());result.pushKV("timestamp",message.timestamp);return result;
    }
    if (r.method=="depinlistsections") {
        if (r.kind) Access(r);
        std::vector<std::string> sections;std::string error;
        if (!pDepinMsgPool->GetSections(sections,error)) throw JSONRPCError(RPC_MISC_ERROR,error);
        UniValue entries(UniValue::VARR);
        for (const auto& section:sections) {
            if (r.kind && !IsDepinSectionOrRoot(section,r.token)) continue;
            const auto label=GetDepinSectionLabel(section,r.target.root);UniValue entry(UniValue::VOBJ);
            entry.pushKV("name",section);entry.pushKV("label",label);entry.pushKV("depth",label.empty()?0:int(1+std::count(label.begin(),label.end(),'/')));
            if (r.kind) {
                const bool access=HasDepinSectionAccess(r.address,section,r.target.root,error);entry.pushKV("access",UniValue(access));
                if (access) entry.pushKV("messages",int64_t(pDepinMsgPool->CountMessagesInScope(section,GetTime())));
            }
            entries.push_back(entry);
        }
        UniValue result(UniValue::VOBJ);result.pushKV("sections",entries);
        if (r.kind) { Consume(r);Chain(result,r); }return result;
    }
    Access(r);
    if (r.method=="depinclearmsg") {
        const auto mode=r.args["mode"].get_str();const auto hours=r.args["hours"].get_int64();
        Consume(r);size_t removed=0;std::string error;
        if (!pDepinMsgPool->Purge(r.token==r.target.root?"":r.token,GetTime(),mode=="all",
                                 mode=="expired"?pDepinMsgPool->GetMessageExpiryTime():hours*3600,removed,error))
            throw JSONRPCError(RPC_DATABASE_ERROR,error);
        UniValue result(UniValue::VOBJ);result.pushKV("removed",int64_t(removed));result.pushKV("remaining",int64_t(pDepinMsgPool->Size()));return result;
    }
    UniValue messages(UniValue::VARR),result(UniValue::VOBJ);std::string error;bool more=false;
    if (r.method=="depinreceivemsg") {
        std::vector<CDepinMessage> page;auto timestamp=r.args["timestamp"].get_int64();if (timestamp) --timestamp;
        if (!pDepinMsgPool->GetLegacyPage(r.address,r.token,timestamp,r.args["after_hash"].get_str(),size_t(r.args["limit"].get_int64()),page,more,error)) throw JSONRPCError(RPC_INVALID_PARAMETER,error);
        for (const auto& m:page) messages.push_back(Message(m));
    } else {
        const auto& cursor=r.args["cursor"];const auto stream=cursor.isNull()?pDepinMsgPool->GetStreamId():uint256S(cursor["stream_id"].get_str());
        const auto after=cursor.isNull()?0:uint64_t(cursor["after_seq"].get_int64());CDepinSequencePage page;
        if (!pDepinMsgPool->GetSequencePage(r.address,r.token,stream,after,size_t(r.args["limit"].get_int64()),r.args["from_timestamp"].get_int64(),page,error)) throw JSONRPCError(RPC_INVALID_PARAMETER,error);
        for (const auto& m:page.messages) { auto entry=Message(m.message);entry.pushKV("sequence",int64_t(m.sequence));messages.push_back(entry); }
        UniValue next(UniValue::VOBJ);next.pushKV("version",1);next.pushKV("stream_id",page.stream.ToString());next.pushKV("after_seq",int64_t(page.after));
        next.pushKV("scope",r.token);next.pushKV("address",r.address);next.pushKV("from_timestamp",r.args["from_timestamp"]);result.pushKV("cursor",next);more=page.hasMore;
    }
    Consume(r);result.pushKV("messages",messages);result.pushKV("has_more",UniValue(more));Chain(result,r);return result;
}

UniValue DepinRpcV3(const JSONRPCRequest& request)
{
    if (request.fHelp) throw std::runtime_error(request.strMethod+" request\nDePIN protocol 3. One JSON object; legacy signatures are rejected.\nSee doc/depin-request-signatures.md. Use depinsignrpc method request on the signing wallet.\n");
    if (request.params.size()!=1 || !request.params[0].isObject()) throw DepinRpcError(RPC_INVALID_PARAMETER,"unsupported_protocol","DePIN unsupported_protocol: one protocol 3 request object required");
    const auto r=ParseDepinRpcRequest(request.strMethod,request.params[0]);
    LOCK(cs_main);const auto now=DepinRequestClockMillis();ObserveDepinRpcClock(now);const auto identity=GetDepinRpcIdentity();
    // Readiness precedes asset/public-key index work. Early unavailability is
    // a transport error: it cannot be encrypted without consulting that index.
    if (r.kind || r.method=="depinlistsections" || r.method=="depingetancestorrecipients") { Enabled();Ready(); }
    CPubKey client;
    // Error bodies for addressed requests are encrypted too. No on-chain key
    // lookup is needed to sign a public query or to disclose a parse failure.
    if (r.kind) { std::string error;if (!CheckAddressHasPublicKey(r.address,client,error))
        throw DepinRpcError(RPC_INVALID_ADDRESS_OR_KEY,"public_key_unavailable","Address has no revealed public key: "+error); }
    try {
        if (!r.bootstrap && (r.target.network!=identity.network || r.target.poolKey!=identity.poolKey || r.target.root!=identity.root || r.target.instance!=identity.instance))
            throw JSONRPCError(RPC_INVALID_REQUEST,"service_mismatch: network, pool or instance changed");
        if (r.kind && ((r.timestamp>now && r.timestamp-now>DEPIN_REQUEST_WINDOW_MS) || (now>=r.timestamp && now-r.timestamp>DEPIN_REQUEST_WINDOW_MS)))
            throw JSONRPCError(RPC_INVALID_REQUEST,"request_expired: timestamp outside accepted window");
        if (r.kind) {
            std::string error;
            if (r.kind>=2 && !g_depinChallenges.Matches(r.nonce,r.token,r.address,r.kind==3?DepinChallengeType::ADMIN:DepinChallengeType::RECEIVE,error,now/1000)) throw JSONRPCError(RPC_INVALID_REQUEST,error);
            if (!VerifyDepinChallengeSignature(r.address,r.signature,r.Preimage(),error)) throw JSONRPCError(RPC_INVALID_REQUEST,"signature_invalid: "+error);
            if (!client.IsFullyValid()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,"Address has no revealed public key");
        }
        return FinishDepinRpcResponse(Run(r,request),r,r.kind?&client:nullptr);
    } catch (const UniValue& error) {
        // Syntax errors preceding a request hash remain JSON-RPC transport
        // errors. Every correlatable operation error has the pool signature.
        auto detail=error;
        if (!detail.exists("data")) {
            const auto code=detail["code"].get_int();const auto message=detail["message"].get_str();
            std::string reason="operation_failed";
            for (const auto* candidate:{"service_mismatch","request_expired","signature_invalid","request_replayed","replay_capacity"})
                if (message.find(candidate)==0) reason=candidate;
            if (message.find("Challenge")!=std::string::npos) reason="challenge_invalid";
            else if (message.find("Rate limited")==0) reason="rate_limited";
            else if (code==RPC_CLIENT_IN_INITIAL_DOWNLOAD) reason="service_not_ready";
            else if (code==RPC_DATABASE_ERROR) reason="storage_failure";
            else if (code==RPC_INVALID_PARAMETER) reason="invalid_parameters";
            detail=DepinRpcError(code,reason,message);
        }
        UniValue result(UniValue::VOBJ);result.pushKV("error",detail);
        return FinishDepinRpcResponse(result,r,client.IsFullyValid()?&client:nullptr);
    }
}

#ifdef ENABLE_WALLET
UniValue DepinSignRpc(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size()!=2) throw std::runtime_error("depinsignrpc method request\nSign a complete protocol 3 request for the explicit remote destination. Returns request, preimage and request_hash.\n");
    auto* wallet=GetWalletForJSONRPCRequest(request);if (!EnsureWalletIsAvailable(wallet,request.fHelp)) return NullUniValue;
    const auto method=request.params[0].get_str();const auto object=request.params[1];const auto parsed=ParseDepinRpcRequest(method,object);
    if (!parsed.kind) throw JSONRPCError(RPC_INVALID_PARAMETER,"Public requests do not need a user signature");
    LOCK2(cs_main,wallet->cs_wallet);EnsureWalletIsUnlocked(wallet);
    const auto dest=DecodeDestination(parsed.address);const auto* id=boost::get<CKeyID>(&dest);CKey key;
    if (!id || !wallet->GetKey(*id,key)) throw JSONRPCError(RPC_WALLET_ERROR,"Legacy private key unavailable");
    std::string sig,error;if (!SignDepinChallengePreimage(key,parsed.Preimage(),sig,error)) throw JSONRPCError(RPC_WALLET_ERROR,error);
    UniValue signedRequest(UniValue::VOBJ);
    for (size_t n=0;n<object.size();++n) signedRequest.pushKV(object.getKeys()[n],object.getKeys()[n]=="signature"?UniValue(sig):object.getValues()[n]);
    UniValue result(UniValue::VOBJ);result.pushKV("request",signedRequest);result.pushKV("preimage",parsed.Preimage());result.pushKV("request_hash",parsed.Hash());return result;
}
#endif
}

void RegisterDepinRPCCommands(CRPCTable& table)
{
    static const CRPCCommand commands[]={
        {"depin messaging","depingetmsginfo",&DepinRpcV3,{"request"}},
        {"depin messaging","depinchallenge",&DepinRpcV3,{"request"}},
        {"depin messaging","depinpoolstats",&DepinRpcV3,{"request"}},
        {"depin messaging","depinsubmitmsg",&DepinRpcV3,{"request"}},
        {"depin messaging","depinreceiveseq",&DepinRpcV3,{"request"}},
        {"depin messaging","depinreceivemsg",&DepinRpcV3,{"request"}},
        {"depin messaging","depinmcpstatus",&DepinRpcV3,{"request"}},
        {"depin messaging","depingetancestorrecipients",&DepinRpcV3,{"request"}},
        {"depin messaging","depinlistsections",&DepinRpcV3,{"request"}},
        {"depin messaging","depinclearmsg",&DepinRpcV3,{"request"}},
#ifdef ENABLE_WALLET
        {"depin messaging","depinsignrpc",&DepinSignRpc,{"method","request"}},
#endif
    };
    for (const auto& command:commands) table.appendCommand(command.name,&command);
}
