// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#include "depinaddress.h"
#include "depinrpc.h"
#include "base58.h"
#include "chainparams.h"
#include "crypto/sha256.h"
#include "depinchallenge.h"
#include "depinecies.h"
#include "depinmsgpool.h"
#include "depinpoolkey.h"
#include "random.h"
#include "rpc/protocol.h"
#include "streams.h"
#include "sync.h"
#include "utilstrencodings.h"
#include "version.h"
#include "validation.h"
#include <climits>
#include <algorithm>
#include <limits>
#include <map>
#include <set>

namespace {
using Bytes = std::vector<unsigned char>;
void Number(Bytes& out, uint64_t value, unsigned width) { for (unsigned i=0;i<width;++i) out.push_back(value>>(8*i)); }
void Blob(Bytes& out, const Bytes& bytes) { Number(out,bytes.size(),4);out.insert(out.end(),bytes.begin(),bytes.end()); }
void Text(Bytes& out, const std::string& text) { Blob(out,Bytes(text.begin(),text.end())); }
void Fixed(Bytes& out, const std::string& hex) { const auto b=ParseHex(hex);out.insert(out.end(),b.begin(),b.end()); }
std::string Digest(const Bytes& bytes) { unsigned char hash[32];CSHA256().Write(bytes.data(),bytes.size()).Finalize(hash);return HexStr(hash,hash+32); }
[[noreturn]] void Bad(const std::string& reason)
{
    throw DepinRpcError(RPC_INVALID_PARAMETER,reason.find("unsupported_protocol")==0?"unsupported_protocol":"invalid_parameters","DePIN v5: "+reason);
}
void Keys(const UniValue& o, const std::set<std::string>& allowed, const std::set<std::string>& required = {})
{
    if (!o.isObject()) Bad("expected object");
    std::set<std::string> seen;
    for (const auto& key:o.getKeys()) if (!allowed.count(key) || !seen.insert(key).second) Bad("unknown or duplicate field: "+key.substr(0,64));
    for (const auto& key:required) if (!o.exists(key) || o[key].isNull()) Bad("required field: "+key);
}
std::string String(const UniValue& v, size_t maximum)
{
    if (!v.isStr() || v.get_str().size()>maximum) Bad("invalid string type or size budget exceeded");
    const auto& s=v.get_str();
    for (unsigned char c:s) if (c<0x20 || c>0x7e) Bad("text must be printable ASCII");
    return s;
}
int64_t Integer(const UniValue& v)
{
    if (!v.isNum()) Bad("expected integer JSON number");
    const auto s=v.getValStr();int64_t number;
    if (!ParseInt64(s,&number) || s.empty() || s.find_first_of(".eE+")!=std::string::npos) Bad("expected integer JSON number");
    return number;
}
int64_t OptionalInt(const UniValue& o, const std::string& key, int64_t fallback, int64_t minimum, int64_t maximum)
{
    const int64_t n=o.exists(key) && !o[key].isNull()?Integer(o[key]):fallback;
    if (n<minimum || n>maximum) Bad(key+" is outside its allowed range");return n;
}
std::string Hex(const UniValue& v, size_t size, bool empty = false)
{
    const std::string s=String(v,2*size);
    if (empty && s.empty()) return s;
    if (s.size()!=2*size || !IsHex(s) || std::any_of(s.begin(),s.end(),[](char c){return c>='A' && c<='F';})) Bad("expected fixed-size lowercase hex");
    return s;
}
std::string OptionalString(const UniValue& o, const std::string& key, const std::string& fallback, size_t maximum)
{
    return o.exists(key) && !o[key].isNull()?String(o[key],maximum):fallback;
}
CCriticalSection cs_rpcState;
std::string instance;
int64_t lastWall = -1;
std::map<std::string,int64_t> replay;
std::multimap<int64_t,std::string> replayExpiry;
std::string RandomId() { unsigned char bytes[32];GetStrongRandBytes(bytes,32);return HexStr(bytes,bytes+32); }
}

UniValue DepinRpcError(int code, const std::string& reason, const std::string& message)
{
    auto error=JSONRPCError(code,message);UniValue data(UniValue::VOBJ);
    data.pushKV("depin_error",reason);data.pushKV("expected_protocol",DEPIN_RPC_PROTOCOL_VERSION);error.pushKV("data",data);return error;
}

std::vector<unsigned char> DepinRpcRequest::Bytes() const
{
    std::vector<unsigned char> out;
    Text(out,"Neurai/DePIN/RPC/request");Number(out,DEPIN_RPC_PROTOCOL_VERSION,2);Text(out,method);Number(out,kind,1);
    Fixed(out,target.network);Blob(out,ParseHex(target.poolKey));Text(out,target.root);Fixed(out,target.instance);Fixed(out,target.membership.revision);
    Fixed(out,id);Number(out,uint64_t(timestamp),8);Text(out,token);Text(out,address);Blob(out,ParseHex(nonce));Blob(out,argumentBytes);
    return out;
}
std::string DepinRpcRequest::Hash() const { return Digest(Bytes()); }
std::string DepinRpcRequest::Preimage() const { return "DEPIN-RPC-REQUEST-v5|"+Hash(); }

DepinRpcRequest ParseDepinRpcRequest(const std::string& method, const UniValue& o)
{
    DepinRpcRequest r;r.method=method;
    if (!o.isObject() || !o.exists("protocol") || !o["protocol"].isNum() || Integer(o["protocol"])!=DEPIN_RPC_PROTOCOL_VERSION)
        Bad("unsupported_protocol: protocol 5 required; legacy signatures are not accepted");
    if (method=="depingetmsginfo") {
        Keys(o,{"protocol","request_id","timestamp_ms"},{"protocol","request_id","timestamp_ms"});
        r.bootstrap=true;r.target.network=r.target.instance=r.target.membership.revision=std::string(64,'0');
    } else {
        Keys(o,{"protocol","network","pool_pubkey","pool_root","instance_id","membership_revision","request_id","timestamp_ms","token","address","challenge","args","signature"},
               {"protocol","network","pool_pubkey","pool_root","instance_id","membership_revision","request_id","timestamp_ms","token","address","challenge","args","signature"});
        r.target.network=Hex(o["network"],32);r.target.instance=Hex(o["instance_id"],32);
        r.target.membership.revision=Hex(o["membership_revision"],32);
        r.target.poolKey=Hex(o["pool_pubkey"],33);const auto key=ParseHex(r.target.poolKey);
        if (!CPubKey(key).IsFullyValid() || !CPubKey(key).IsCompressed()) Bad("invalid pool public key");
        r.target.root=String(o["pool_root"],128);r.token=String(o["token"],128);r.address=String(o["address"],64);
        r.nonce=Hex(o["challenge"],32,true);r.signature=String(o["signature"],128);
        if (!o["args"].isObject()) Bad("args must be an object");
    }
    r.id=Hex(o["request_id"],32);r.timestamp=Integer(o["timestamp_ms"]);if (r.timestamp<0) Bad("negative timestamp_ms");
    if (r.bootstrap) return r;
    const UniValue& a=o["args"];auto& b=r.argumentBytes;
    if (method=="depinchallenge") {
        r.kind=1;Keys(a,{"type"});const auto type=OptionalString(a,"type","receive",7);
        if (type!="receive" && type!="admin") Bad("type must be receive or admin");
        r.args.pushKV("type",type);Number(b,type=="admin",1);
    } else if (method=="depinreceivemsg") {
        r.kind=2;Keys(a,{"timestamp","after_hash","limit"});
        const auto time=OptionalInt(a,"timestamp",0,0,INT64_MAX),limit=OptionalInt(a,"limit",0,0,1000);
        const auto after=OptionalString(a,"after_hash","",64);if (!after.empty()) Hex(UniValue(after),32);
        r.args.pushKV("timestamp",time);r.args.pushKV("after_hash",after);r.args.pushKV("limit",limit);
        Number(b,time,8);Blob(b,ParseHex(after));Number(b,limit,8);
    } else if (method=="depinreceiveseq") {
        r.kind=2;Keys(a,{"cursor","limit","from_timestamp"});
        const auto limit=OptionalInt(a,"limit",100,1,1000),from=OptionalInt(a,"from_timestamp",0,0,INT64_MAX);
        const bool continuation=a.exists("cursor") && !a["cursor"].isNull();
        std::string stream(64,'0');int64_t after=0;
        if (continuation) {
            const auto& c=a["cursor"];
            Keys(c,{"version","stream_id","after_seq","scope","address","from_timestamp"},
                   {"version","stream_id","after_seq","scope","address","from_timestamp"});
            if (Integer(c["version"])!=1 || String(c["scope"],128)!=r.token || String(c["address"],64)!=r.address || Integer(c["from_timestamp"])!=from) Bad("cursor does not match scope, address, version or filter");
            stream=Hex(c["stream_id"],32);after=Integer(c["after_seq"]);if (after<0) Bad("negative after_seq");
            r.args.pushKV("cursor",c);
        } else r.args.pushKV("cursor",NullUniValue);
        r.args.pushKV("limit",limit);r.args.pushKV("from_timestamp",from);
        Number(b,continuation,1);Fixed(b,stream);Number(b,after,8);Number(b,limit,8);Number(b,from,8);
    } else if (method=="depinclearmsg") {
        r.kind=3;Keys(a,{"mode","hours"});
        const auto mode=OptionalString(a,"mode","expired",7);
        if (mode!="expired" && mode!="all" && mode!="hours") Bad("mode must be expired, all or hours");
        if (mode!="hours" && a.exists("hours") && !a["hours"].isNull()) Bad("hours only valid for hours mode");
        if (mode=="hours" && (!a.exists("hours") || a["hours"].isNull())) Bad("hours required");
        const int64_t hours=mode=="hours"?OptionalInt(a,"hours",0,0,INT64_MAX/3600):0;
        if (r.token.empty()) r.token=r.target.root;
        r.args.pushKV("mode",mode);r.args.pushKV("hours",hours);Number(b,mode=="hours"?2:mode=="all"?1:0,1);Number(b,hours,8);
    } else if (method=="depinsubmitmsg") {
        r.kind=1;Keys(a,{"encrypted"},{"encrypted"});
        if (!r.token.empty()) Bad("submit token must remain inside the encrypted envelope");
        const size_t maximum=DepinECIESWireLimit(MAX_DEPIN_MESSAGE_WIRE_BYTES*2,1);
        const auto encrypted=String(a["encrypted"],maximum*2);
        if (encrypted.empty() || !IsHex(encrypted) || std::any_of(encrypted.begin(),encrypted.end(),[](char c){return c>='A' && c<='F';})) Bad("invalid encrypted envelope hex");
        r.args.pushKV("encrypted",encrypted);Blob(b,ParseHex(encrypted));
    } else if (method=="depingetancestorrecipients") {
        Keys(a,{"max_results","stop_at"});
        const auto limit=OptionalInt(a,"max_results",DEFAULT_DEPIN_ANCESTOR_RECIPIENTS_LIMIT,1,MAX_DEPIN_ANCESTOR_RECIPIENTS_HARD_CAP);
        const auto stop=OptionalString(a,"stop_at",r.target.root,128);
        const auto effective=stop.empty()?r.target.root:stop;
        r.args.pushKV("max_results",limit);r.args.pushKV("stop_at",effective);Number(b,limit,8);Text(b,effective);
    } else if (method=="depinlistsections") { r.kind=r.address.empty()?0:2;Keys(a,{}); }
    else if (method=="depinpoolstats" || method=="depinmcpstatus") { Keys(a,{}); }
    else Bad("unknown method");
    if (!r.kind) {
        if (!r.address.empty() || !r.nonce.empty() || !r.signature.empty()) Bad("public query must not contain authentication fields");
        if (method!="depingetancestorrecipients" && r.token!=r.target.root) Bad("public query requires pool root");
    } else {
        DepinRecipient recipient;if (!DepinRecipient::FromAddress(r.address,recipient)) Bad("address must be canonical Legacy P2PKH or strict ECDSA");
        if (r.kind>=2 && r.nonce.empty()) Bad("challenge required");
        if (r.kind==1 && !r.nonce.empty()) Bad("timestamp request must not contain a challenge");
        if (method!="depinsubmitmsg" && !IsDepinSectionOrRoot(r.token,r.target.root)) Bad("token is outside pool scope");
    }
    return r;
}

UniValue MakeDepinRpcRequest(const std::string& method, const DepinRpcIdentity& t, const std::string& token,
                            const std::string& address, const std::string& nonce, const UniValue& args,
                            const std::string& id, int64_t timestamp)
{
    UniValue o(UniValue::VOBJ);o.pushKV("protocol",DEPIN_RPC_PROTOCOL_VERSION);
    if (method!="depingetmsginfo") {
        o.pushKV("network",t.network);o.pushKV("pool_pubkey",t.poolKey);o.pushKV("pool_root",t.root);o.pushKV("instance_id",t.instance);o.pushKV("membership_revision",t.membership.revision);
        o.pushKV("token",token);o.pushKV("address",address);o.pushKV("challenge",nonce);o.pushKV("args",args);o.pushKV("signature","");
    }
    o.pushKV("request_id",id.empty()?RandomId():id);o.pushKV("timestamp_ms",timestamp<0?DepinRequestClockMillis():timestamp);
    return o;
}
UniValue MakeDepinRpcBootstrap() { return MakeDepinRpcRequest("depingetmsginfo",{},"","","",UniValue(UniValue::VOBJ)); }

void ResetDepinRpcInstance() { LOCK(cs_main);ResetDepinMembershipContext();LOCK(cs_rpcState);instance.clear();lastWall=-1;replay.clear();replayExpiry.clear();g_depinChallenges.Clear(); }
void ObserveDepinRpcClock(int64_t nowMs)
{
    LOCK(cs_rpcState);
    if (nowMs<0) Bad("clock unavailable");
    if (lastWall>=0 && nowMs<lastWall) { instance=RandomId();replay.clear();replayExpiry.clear();g_depinChallenges.Clear(); }
    lastWall=nowMs;
    while (!replayExpiry.empty() && replayExpiry.begin()->first<nowMs) {
        replay.erase(replayExpiry.begin()->second);replayExpiry.erase(replayExpiry.begin());
    }
    if (instance.empty()) instance=RandomId();
}
DepinRpcIdentity GetDepinRpcIdentity()
{
    LOCK(cs_main);
    const auto membership=GetDepinMembershipContext();
    CKey key;CPubKey pub;
    if (!GetDepinPoolKey(key,pub)) throw JSONRPCError(RPC_MISC_ERROR,"DePIN pool key unavailable");
    const auto root=pDepinMsgPool?pDepinMsgPool->GetActiveToken():"";
    LOCK(cs_rpcState);if (instance.empty()) instance=RandomId();
    return {GetParams().GetConsensus().hashGenesisBlock.ToString(),HexStr(pub.begin(),pub.end()),root,instance,membership};
}
bool CheckDepinRpcReplay(const DepinRpcRequest& r, std::string& error)
{
    LOCK(cs_rpcState);
    if (replay.count(r.Hash())) { error="request_replayed: Request already used";return false; }
    if (replay.size()>=10000) { error="replay_capacity: Too many pending requests";return false; }
    return true;
}
bool RememberDepinRpcRequest(const DepinRpcRequest& r, std::string& error)
{
    LOCK(cs_rpcState);const auto hash=r.Hash();
    if (replay.count(hash)) { error="request_replayed: Request already used";return false; }
    if (replay.size()>=10000) { error="replay_capacity: Too many pending requests";return false; }
    const auto deadline=r.timestamp>INT64_MAX-DEPIN_REQUEST_WINDOW_MS?INT64_MAX:r.timestamp+DEPIN_REQUEST_WINDOW_MS;
    replay.emplace(hash,deadline);
    try { replayExpiry.emplace(deadline,hash); } catch (...) { replay.erase(hash);throw; }
    return true;
}
size_t DepinRpcReplaySize() { LOCK(cs_rpcState);return replay.size(); }

std::string DepinRpcResponsePreimage(const DepinRpcIdentity& i, const std::string& method, const std::string& requestHash,
                                     uint8_t kind, const std::vector<unsigned char>& body)
{
    Bytes q;Text(q,"Neurai/DePIN/RPC/response");Number(q,DEPIN_RPC_PROTOCOL_VERSION,2);Text(q,method);
    Fixed(q,i.network);Blob(q,ParseHex(i.poolKey));Text(q,i.root);Fixed(q,i.instance);Fixed(q,i.membership.revision);Number(q,uint64_t(i.membership.height),8);Fixed(q,i.membership.block);Fixed(q,requestHash);Number(q,kind,1);Blob(q,body);
    return "DEPIN-RPC-RESPONSE-v5|"+Digest(q);
}
UniValue FinishDepinRpcResponse(const UniValue& result, const DepinRpcRequest& r, const CPubKey* clientKey)
{
    const auto identity=GetDepinRpcIdentity();const auto plain=result.write();
    if (plain.size()>MAX_DEPIN_REPLY_PLAINTEXT) throw JSONRPCError(RPC_INVALID_PARAMETER,"DePIN response exceeds 4 MiB plaintext budget");
    Bytes body;std::string error;
    if (clientKey) {
        CECIESEncryptedMessage e;
        if (!ECIESEncryptMessage(plain,{{r.address,*clientKey}},e,error)) throw JSONRPCError(RPC_INTERNAL_ERROR,error);
        CDataStream stream(SER_NETWORK,PROTOCOL_VERSION);stream<<e;body.assign(stream.begin(),stream.end());
    } else body.assign(plain.begin(),plain.end());
    CKey key;CPubKey pub;if (!GetDepinPoolKey(key,pub)) throw JSONRPCError(RPC_MISC_ERROR,"DePIN pool key unavailable");
    std::string sig;if (!SignDepinChallengePreimage(key,DepinRpcResponsePreimage(identity,r.method,r.Hash(),clientKey?1:0,body),sig,error)) throw JSONRPCError(RPC_INTERNAL_ERROR,error);
    UniValue out(UniValue::VOBJ);out.pushKV("protocol",DEPIN_RPC_PROTOCOL_VERSION);out.pushKV("network",identity.network);
    out.pushKV("pool_pubkey",identity.poolKey);out.pushKV("pool_root",identity.root);out.pushKV("instance_id",identity.instance);
    out.pushKV("membership_revision",identity.membership.revision);out.pushKV("membership_height",identity.membership.height);out.pushKV("membership_blockhash",identity.membership.block);
    out.pushKV("request_hash",r.Hash());out.pushKV("body_kind",clientKey?1:0);out.pushKV(clientKey?"encrypted":"body",HexStr(body));out.pushKV("poolsig",sig);return out;
}
bool VerifyDepinRpcResponse(const UniValue& o, const DepinRpcRequest& r, const CPubKey& pinned, std::string& error)
{
    try {
        if (!pinned.IsFullyValid() || !pinned.IsCompressed()) Bad("invalid pinned pool key");
        if (!o.isObject() || !o.exists("body_kind")) Bad("invalid response wrapper");
        const auto kind=Integer(o["body_kind"]);if (kind!=0 && kind!=1) Bad("invalid body_kind");
        const std::string field=kind?"encrypted":"body";
        Keys(o,{"protocol","network","pool_pubkey","pool_root","instance_id","membership_revision","membership_height","membership_blockhash","request_hash","body_kind",field,"poolsig"},
               {"protocol","network","pool_pubkey","pool_root","instance_id","membership_revision","membership_height","membership_blockhash","request_hash","body_kind",field,"poolsig"});
        if (Integer(o["protocol"])!=DEPIN_RPC_PROTOCOL_VERSION || Hex(o["request_hash"],32)!=r.Hash()) Bad("response request mismatch");
        DepinRpcIdentity i{Hex(o["network"],32),Hex(o["pool_pubkey"],33),String(o["pool_root"],128),Hex(o["instance_id"],32)};
        i.membership={Hex(o["membership_revision"],32),Hex(o["membership_blockhash"],32),Integer(o["membership_height"])};
        if (i.membership.height < -1 || i.membership.height > INT_MAX) Bad("invalid membership height");
        if (i.poolKey!=HexStr(pinned.begin(),pinned.end())) Bad("response pool key mismatch");
        if (!r.bootstrap && (i.network!=r.target.network || i.poolKey!=r.target.poolKey || i.root!=r.target.root || i.instance!=r.target.instance)) Bad("response service mismatch");
        if ((r.kind!=0)!=(kind!=0)) Bad("response confidentiality mismatch");
        const auto hex=String(o[field],2*DepinECIESWireLimit(MAX_DEPIN_REPLY_PLAINTEXT,MAX_DEPIN_RECIPIENTS));
        if (hex.empty() || !IsHex(hex) || std::any_of(hex.begin(),hex.end(),[](char c){return c>='A' && c<='F';})) Bad("invalid response body");
        return VerifyDepinChallengeSignature(EncodeDestination(pinned.GetID()),String(o["poolsig"],128),DepinRpcResponsePreimage(i,r.method,r.Hash(),kind,ParseHex(hex)),error);
    } catch (const UniValue& e) { error=e.write();return false; } catch (const std::exception& e) { error=e.what();return false; }
}
