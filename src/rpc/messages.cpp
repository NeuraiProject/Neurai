// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assets/assets.h"
#include "assets/assetdb.h"
#include "assets/messages.h"
#include "assets/myassetsdb.h"
#include <map>
#include <set>
#include <limits>
#include <algorithm>
#include <cctype>
#include "tinyformat.h"

#include "amount.h"
#include "base58.h"
#include "chain.h"
#include "chainparams.h"
#include "hash.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "httpserver.h"
#include "validation.h"
#include "net.h"
#include "policy/feerate.h"
#include "policy/fees.h"
#include "policy/policy.h"
#include "policy/rbf.h"
#include "depinchallenge.h"
#include "depinrpc.h"
#include "depinmcpworker.h"
#include "rpc/mining.h"
#include "rpc/safemode.h"
#include "rpc/server.h"
#include "script/sign.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "wallet/coincontrol.h"
#include "wallet/feebumper.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "depinecies.h"
#include "depinmsgpool.h"
#include "depinpoolkey.h"
#ifdef ENABLE_WALLET
#include "wallet/depinpoolkeyload.h"
#endif

static void EnsureDepinServiceReady()
{
    std::string error;
    if (!CheckDepinServiceReady(error)) {
        throw JSONRPCError(RPC_CLIENT_IN_INITIAL_DOWNLOAD, error);
    }
}

std::string MessageActivationWarning()
{
    return AreMessagesDeployed() ? "" : "\nTHIS COMMAND IS NOT YET ACTIVE!\nhttps://github.com/NeuraiProject/rips/blob/master/rip-0005.mediawiki\n";
}

UniValue viewallmessages(const JSONRPCRequest& request) {
    if (request.fHelp || !AreMessagesDeployed() || request.params.size() != 0)
        throw std::runtime_error(
                "viewallmessages \n"
                + MessageActivationWarning() +
                "\nView all messages that the wallet contains\n"

                "\nResult:\n"
                "\"Asset Name:\"                     (string) The name of the asset the message was sent on\n"
                "\"Message:\"                        (string) The IPFS hash of the message\n"
                "\"Time:\"                           (Date) The time as a date in the format (YY-mm-dd Hour-minute-second)\n"
                "\"Block Height:\"                   (number) The height of the block the message was included in\n"
                "\"Status:\"                         (string) Status of the message (READ, UNREAD, ORPHAN, EXPIRED, SPAM, HIDDEN, ERROR)\n"
                "\"Expire Time:\"                    (Date, optional) If the message had an expiration date assigned, it will be shown here in the format (YY-mm-dd Hour-minute-second)\n"
                "\"Expire UTC Time:\"                (Date, optional) If the message contains an expire date that is too large, the UTC number will be displayed\n"


                "\nExamples:\n"
                + HelpExampleCli("viewallmessages", "")
                + HelpExampleRpc("viewallmessages", "")
        );

    if (!fMessaging) {
        UniValue ret(UniValue::VSTR);
        ret.push_back("Messaging is disabled. To enable messaging, run the wallet without -disablemessaging or remove disablemessaging from your neurai.conf");
        return ret;
    }

    if (!pMessagesCache || !pmessagedb) {
        UniValue ret(UniValue::VSTR);
        ret.push_back("Messaging database and cache are having problems (a wallet restart might fix this issue)");
        return ret;
    }

    std::set<CMessage> setMessages;

    pmessagedb->LoadMessages(setMessages);

    for (auto pair : mapDirtyMessagesOrphaned) {
        CMessage message = pair.second;
        message.status = MessageStatus::ORPHAN;
        if (setMessages.count(message))
            setMessages.erase(message);
        setMessages.insert(message);
    }

    for (auto out : setDirtyMessagesRemove) {
        CMessage message;
        message.out = out;
        setMessages.erase(message);
    }

    for (auto pair : mapDirtyMessagesAdd) {
        setMessages.erase(pair.second);
        setMessages.insert(pair.second);
    }

    UniValue messages(UniValue::VARR);

    for (auto message : setMessages) {
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("Asset Name", message.strName));
        obj.push_back(Pair("Message", EncodeAssetData(message.ipfsHash)));
        obj.push_back(Pair("Time", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", message.time)));
        obj.push_back(Pair("Block Height", message.nBlockHeight));
        obj.push_back(Pair("Status", MessageStatusToString(message.status)));
        try {
            std::string date = DateTimeStrFormat("%Y-%m-%d %H:%M:%S", message.nExpiredTime);
            if (message.nExpiredTime)
                obj.push_back(Pair("Expire Time", date));
        } catch (...) {
            obj.push_back(Pair("Expire UTC Time", message.nExpiredTime));
        }

        messages.push_back(obj);
    }


    return messages;
}

UniValue viewallmessagechannels(const JSONRPCRequest& request) {
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
                "viewallmessagechannels \n"
                + MessageActivationWarning() +
                "\nView all message channels the wallet is subscribed to\n"

                "\nResult:[\n"
                "\"Asset Name\"                      (string) The asset channel name\n"
                "\n]\n"
                "\nExamples:\n"
                + HelpExampleCli("viewallmessagechannels", "")
                + HelpExampleRpc("viewallmessagechannels", "")
        );

    if (!fMessaging) {
        UniValue ret(UniValue::VSTR);
        ret.push_back("Messaging is disabled. To enable messaging, run the wallet without -disablemessaging or remove disablemessaging from your neurai.conf");
        return ret;
    }

    if (!pMessageSubscribedChannelsCache || !pmessagechanneldb) {
        UniValue ret(UniValue::VSTR);
        ret.push_back("Messaging channel database and cache are having problems (a wallet restart might fix this issue)");
        return ret;
    }

    std::set<std::string> setChannels;

    pmessagechanneldb->LoadMyMessageChannels(setChannels);

    LogPrintf("%s: Checking caches removeSize:%u, addSize:%u\n", __func__, setDirtyChannelsRemove.size(), setDirtyChannelsAdd.size());

    for (auto name : setDirtyChannelsRemove) {
        setChannels.erase(name);
    }

    for (auto name : setDirtyChannelsAdd) {
        setChannels.insert(name);
    }

    UniValue channels(UniValue::VARR);

    for (auto name : setChannels) {
        channels.push_back(name);
    }

    return channels;
}

UniValue subscribetochannel(const JSONRPCRequest& request) {
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "subscribetochannel \n"
                + MessageActivationWarning() +
                "\nSubscribe to a certain message channel\n"

                "\nArguments:\n"
                "1. \"channel_name\"            (string, required) The channel name to subscribe to, it must end with '!' or have an '~' in the name\n"

                "\nResult:[\n"
                "\n]\n"
                "\nExamples:\n"
                + HelpExampleCli("subscribetochannel", "\"ASSET_NAME!\"")
                + HelpExampleRpc("subscribetochannel", "\"ASSET_NAME!\"")
        );

    if (!fMessaging) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Messaging is disabled. To enable messaging, run the wallet without -disablemessaging or remove disablemessaging from your neurai.conf");
    }

    if (!pMessageSubscribedChannelsCache || !pmessagechanneldb) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Message database isn't setup");
    }

    std::string channel_name = request.params[0].get_str();

    AssetType type;
    if (!IsAssetNameValid(channel_name, type))
        throw JSONRPCError(
                RPC_INVALID_PARAMETER, "Channel Name is not valid.");

    // if the given asset name is a root of sub asset, subscribe to that assets owner token
    if (type == AssetType::ROOT || type == AssetType::SUB) {
        channel_name += "!";
        if (!IsAssetNameValid(channel_name, type))
        throw JSONRPCError(
                RPC_INVALID_PARAMETER, "Channel Name is not valid.");
    }

    if (type != AssetType::OWNER && type != AssetType::MSGCHANNEL)
        throw JSONRPCError(
                RPC_INVALID_PARAMETER, "Channel Name must be a owner asset, or a message channel asset e.g OWNER!, MSG_CHANNEL~123.");

    AddChannel(channel_name);

    return "Subscribed to channel: " + channel_name;
}


UniValue unsubscribefromchannel(const JSONRPCRequest& request) {
    if (request.fHelp || !AreMessagesDeployed() || request.params.size() != 1)
        throw std::runtime_error(
                "unsubscribefromchannel \n"
                + MessageActivationWarning() +
                "\nUnsubscribe from a certain message channel\n"

                "\nArguments:\n"
                "1. \"channel_name\"            (string, required) The channel name to unsubscribe from, must end with '!' or have an '~' in the name\n"

                "\nResult:[\n"
                "\n]\n"
                "\nExamples:\n"
                + HelpExampleCli("unsubscribefromchannel", "\"ASSET_NAME!\"")
                + HelpExampleRpc("unsubscribefromchannel", "\"ASSET_NAME!\"")
        );

    if (!fMessaging) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Messaging is disabled. To enable messaging, run the wallet without -disablemessaging or remove disablemessaging from your neurai.conf");
    }

    if (!pMessageSubscribedChannelsCache || !pmessagechanneldb) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Message database isn't setup");
    }

    std::string channel_name = request.params[0].get_str();

    AssetType type;
    if (!IsAssetNameValid(channel_name, type))
        throw JSONRPCError(
                RPC_INVALID_PARAMETER, "Channel Name is not valid.");

    // if the given asset name is a root of sub asset, subscribe to that assets owner token
    if (type == AssetType::ROOT || type == AssetType::SUB) {
        channel_name += "!";

        if (!IsAssetNameValid(channel_name, type))
        throw JSONRPCError(
                RPC_INVALID_PARAMETER, "Channel Name is not valid.");
    }

    if (type != AssetType::OWNER && type != AssetType::MSGCHANNEL)
        throw JSONRPCError(
                RPC_INVALID_PARAMETER, "Channel Name must be a owner asset, or a message channel asset e.g OWNER!, MSG_CHANNEL~123.");

    RemoveChannel(channel_name);

    return "Unsubscribed from channel: " + channel_name;
}

UniValue clearmessages(const JSONRPCRequest& request) {
    if (request.fHelp || !AreMessagesDeployed() || request.params.size() != 0)
        throw std::runtime_error(
                "clearmessages \n"
                + MessageActivationWarning() +
                "\nDelete current database of messages\n"

                "\nResult:[\n"
                "\n]\n"
                "\nExamples:\n"
                + HelpExampleCli("clearmessages", "")
                + HelpExampleRpc("clearmessages", "")
        );

    if (!fMessaging) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Messaging is disabled. To enable messaging, run the wallet without -disablemessaging or remove disablemessaging from your neurai.conf");
    }

    if (!pMessagesCache || !pmessagedb) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Message database isn't setup");
    }

    int count = 0;
    count += mapDirtyMessagesAdd.size();

    pMessagesCache->Clear();
    setDirtyMessagesRemove.clear();
    mapDirtyMessagesAdd.clear();
    mapDirtyMessagesOrphaned.clear();
    pmessagedb->EraseAllMessages(count);

    return "Erased " + std::to_string(count) + " Messages from the database and cache";
}

#ifdef ENABLE_WALLET
UniValue sendmessage(const JSONRPCRequest& request) {
    if (request.fHelp || !AreMessagesDeployed() || request.params.size() < 2 || request.params.size() > 3)
        throw std::runtime_error(
                "sendmessage \"channel_name\" \"ipfs_hash\" (expire_time)\n"
                + MessageActivationWarning() +
                "\nCreates and broadcasts a message transaction to the network for a channel this wallet owns"

                "\nArguments:\n"
                "1. \"channel_name\"             (string, required) Name of the channel that you want to send a message with (message channel, administrator asset), if a non administrator asset name is given, the administrator '!' will be added to it\n"
                "2. \"ipfs_hash\"                (string, required) The IPFS hash of the message\n"
                "3. \"expire_time\"              (numeric, optional) UTC timestamp of when the message expires\n"

                "\nResult:[\n"
                "txid\n"
                "]\n"

                "\nExamples:\n"
                + HelpExampleCli("sendmessage", "\"ASSET_NAME!\" \"QmTqu3Lk3gmTsQVtjU7rYYM37EAW4xNmbuEAp2Mjr4AV7E\" 15863654")
                + HelpExampleCli("sendmessage", "\"ASSET_NAME!\" \"QmTqu3Lk3gmTsQVtjU7rYYM37EAW4xNmbuEAp2Mjr4AV7E\" 15863654")
        );

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    ObserveSafeMode();
    LOCK2(cs_main, pwallet->cs_wallet);

    EnsureWalletIsUnlocked(pwallet);

    std::string asset_name = request.params[0].get_str();
    std::string ipfs_hash = request.params[1].get_str();

    int64_t expire_time = 0;
    if (request.params.size() > 2) {
        expire_time = request.params[2].get_int64();
    }

    CheckIPFSTxidMessage(ipfs_hash, expire_time);

    AssetType type;
    std::string strNameError;
    if (!IsAssetNameValid(asset_name, type, strNameError))
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid asset_name: ") + strNameError);

    if (type != AssetType::MSGCHANNEL && type != AssetType::OWNER && type != AssetType::ROOT && type != AssetType::SUB && type != AssetType::RESTRICTED) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid asset_name: Only message channels, root, sub, restricted, and owner assets are allowed"));
    }

    if (type == AssetType::ROOT || type == AssetType::SUB || type == AssetType::RESTRICTED)
        asset_name += OWNER_TAG;

    std::pair<int, std::string> error;
    std::vector< std::pair<CAssetTransfer, std::string> >vTransfers;

    std::map<std::string, std::vector<COutput> > mapAssetCoins;
    pwallet->AvailableAssets(mapAssetCoins);

    if (!mapAssetCoins.count(asset_name)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Wallet doesn't own the asset_name: " + asset_name));
    }

    // Get the address that the coin resides in, because to send a valid message. You need to send it to the same address that it currently resides in.
    CTxDestination dest;
    ExtractDestination(mapAssetCoins.at(asset_name)[0].tx->tx->vout[mapAssetCoins.at(asset_name)[0].i].scriptPubKey, dest);
    std::string address = EncodeDestination(dest);

    vTransfers.emplace_back(std::make_pair(CAssetTransfer(asset_name, OWNER_ASSET_AMOUNT, DecodeAssetData(ipfs_hash), expire_time), address));
    CReserveKey reservekey(pwallet);
    CWalletTx transaction;
    CAmount nRequiredFee;

    CCoinControl ctrl;

    // Create the Transaction
    if (!CreateTransferAssetTransaction(pwallet, ctrl, vTransfers, "", error, transaction, reservekey, nRequiredFee))
        throw JSONRPCError(error.first, error.second);

    // Send the Transaction to the network
    std::string txid;
    if (!SendAssetTransaction(pwallet, transaction, reservekey, error, txid))
        throw JSONRPCError(error.first, error.second);

    // Display the transaction id
    UniValue result(UniValue::VARR);
    result.push_back(txid);
    return result;
}

UniValue viewmytaggedaddresses(const JSONRPCRequest& request) {
    if (request.fHelp || !AreRestrictedAssetsDeployed() || request.params.size() != 0)
        throw std::runtime_error(
                "viewmytaggedaddresses \n"
                + MessageActivationWarning() +
                "\nView all addresses this wallet owns that have been tagged\n"

                "\nResult:\n"
                "{\n"
                "\"Address:\"                        (string) The address that was tagged\n"
                "\"Tag Name:\"                       (string) The asset name\n"
                "\"[Assigned|Removed]:\"             (Date) The UTC datetime of the assignment or removal of the tag in the format (YY-mm-dd HH:MM:SS)\n"
                "                                         (Only the most recent tagging/untagging event will be returned for each address)\n"
                "}...\n"

                "\nExamples:\n"
                + HelpExampleCli("viewmytaggedaddresses", "")
                + HelpExampleRpc("viewmytaggedaddresses", "")
        );

    std::vector<std::tuple<std::string, std::string, bool, uint32_t> > myTaggedAddresses;

    if (!pmyrestricteddb)
        throw JSONRPCError(RPC_DATABASE_ERROR, "My restricted database is not available");

    pmyrestricteddb->LoadMyTaggedAddresses(myTaggedAddresses);
    UniValue myTags(UniValue::VARR);

    for (auto item : myTaggedAddresses) {
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("Address", std::get<0>(item)));
        obj.push_back(Pair("Tag Name", std::get<1>(item)));
        if (std::get<2>(item))
            obj.push_back(Pair("Assigned", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", std::get<3>(item))));
        else
            obj.push_back(Pair("Removed", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", std::get<3>(item))));

        myTags.push_back(obj);
    }

    return myTags;
}

UniValue viewmyrestrictedaddresses(const JSONRPCRequest& request) {
    if (request.fHelp || !AreRestrictedAssetsDeployed() || request.params.size() != 0)
        throw std::runtime_error(
                "viewmyrestrictedaddresses \n"
                + MessageActivationWarning() +
                "\nView all addresses this wallet owns that have been restricted\n"

                "\nResult:\n"
                "{\n"
                "\"Address:\"                        (string) The address that was restricted\n"
                "\"Asset Name:\"                     (string) The asset that the restriction applies to\n"
                "\"[Restricted|Derestricted]:\"      (Date) The UTC datetime of the restriction or derestriction in the format (YY-mm-dd HH:MM:SS))\n"
                "                                         (Only the most recent restriction/derestriction event will be returned for each address)\n"
                "}...\n"

                "\nExamples:\n"
                + HelpExampleCli("viewmyrestrictedaddresses", "")
                + HelpExampleRpc("viewmyrestrictedaddresses", "")
        );

    std::vector<std::tuple<std::string, std::string, bool, uint32_t> > myRestrictedAddresses;

    if (!pmyrestricteddb)
        throw JSONRPCError(RPC_DATABASE_ERROR, "My restricted database is not available");

    pmyrestricteddb->LoadMyRestrictedAddresses(myRestrictedAddresses);
    UniValue myRestricted(UniValue::VARR);

    for (auto item : myRestrictedAddresses) {
        UniValue obj(UniValue::VOBJ);

        obj.push_back(Pair("Address", std::get<0>(item)));
        obj.push_back(Pair("Asset Name", std::get<1>(item)));
        if (std::get<2>(item))
            obj.push_back(Pair("Restricted", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", std::get<3>(item))));
        else
            obj.push_back(Pair("Derestricted", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", std::get<3>(item))));

        myRestricted.push_back(obj);
    }

    return myRestricted;
}

#endif

#include "depinmsgpool.h"

#ifdef ENABLE_WALLET
class CWallet;
class CPubKey;
class CKey;
#endif

UniValue depingetmsginfo(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
                "depingetmsginfo\n"
                "\nReturns information about the DePIN messaging system\n"
                "\nResult:\n"
                "{\n"
                "  \"enabled\": true|false,        (boolean) Whether DePIN messaging is enabled\n"
                "  \"token\": \"name\",              (string) Active token name\n"
                "  \"cipher\": \"name\",            (string) Encryption cipher used by the pool\n"
                "  \"maxrecipients\": n,           (numeric) Maximum recipients per message\n"
                "  \"maxmessagesize\": n,          (numeric) Maximum message size in bytes\n"
                "  \"messageexpiryhours\": n,      (numeric) Message expiry time in hours\n"
                "  \"maxpoolsizemb\": n,           (numeric) Maximum pool size in MB\n"
                "  \"messages\": n,                (numeric) Number of messages in mempool\n"
                "  \"memoryusage\": n,             (numeric) Memory usage in bytes\n"
                "  \"memoryusagemb\": n,           (numeric) Memory usage in MB\n"
                "  \"oldestmessage\": \"time\",      (string) Timestamp of oldest message\n"
                "  \"newestmessage\": \"time\"       (string) Timestamp of newest message\n"
                "  \"ready\": true|false,          (boolean) Whether current-chain service is available\n"
                "  \"not_ready_reason\": \"text\",   (string) Reason when not ready\n"
                "  \"authorization_height\": n,     (numeric) Active connected-chain height\n"
                "  \"known_headers\": n,            (numeric) Best known header height\n"
                "  \"tip_age_seconds\": n,          (numeric) Active-tip age\n"
                "  \"maxtipage\": n,                (numeric) Configured age bound in seconds\n"
                "  \"maxheaderlag\": n,             (numeric) Configured header lead bound\n"
                "  \"protocol\": 3,                  (numeric) DePIN RPC protocol version\n"
                "  \"depinpoolpkey\": \"hex\",        (string) Pool public key: pin it on first use; encrypt depinsubmitmsg envelopes for it; verifies poolsig\n"
                "  \"depinpoolkeyaddress\": \"addr\", (string) P2PKH address of the pool key (verifymessage-compatible)\n"


                "  \"depinwallet\": \"file\",        (string) Wallet the pool key is derived from\n"
                "  \"poolsig\": \"base64\"           (string) Pool-key signature over this response (see depinreceivemsg help)\n"
                "}\n"
                "\nExamples:\n"
                + HelpExampleCli("depingetmsginfo", "")
                + HelpExampleRpc("depingetmsginfo", "")
        );

    if (!pDepinMsgPool) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "DePIN messaging pool not initialized");
    }

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("enabled", pDepinMsgPool->IsEnabled()));
    obj.push_back(Pair("token", pDepinMsgPool->GetActiveToken()));
    obj.push_back(Pair("cipher", pDepinMsgPool->GetEncryptionCipher()));
    obj.push_back(Pair("maxrecipients", (int)pDepinMsgPool->GetMaxRecipients()));
    obj.push_back(Pair("maxmessagesize", (int)pDepinMsgPool->GetMaxMessageSize()));
    obj.push_back(Pair("messageexpiryhours", (int)pDepinMsgPool->GetMessageExpiryHours()));
    obj.push_back(Pair("maxpoolsizemb", (int)pDepinMsgPool->GetMaxPoolSizeMB()));
    obj.push_back(Pair("messages", (int)pDepinMsgPool->Size()));

    size_t memoryUsage = pDepinMsgPool->DynamicMemoryUsage();
    obj.push_back(Pair("memoryusage", (int)memoryUsage));
    obj.push_back(Pair("memoryusagemb", (double)memoryUsage / (1024.0 * 1024.0)));

    int64_t oldest = pDepinMsgPool->GetOldestMessageTime();
    int64_t newest = pDepinMsgPool->GetNewestMessageTime();

    if (newest > 0)
        obj.push_back(Pair("newestmessage", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", newest)));

    // The service identity: the pool public key and which wallet it came
    // from. Clients pin depinpoolpkey on first use; nothing served here is
    // trusted on its own.
    const CDepinServiceStatus status = GetDepinServiceStatus();
    obj.push_back(Pair("ready", status.ready));
    obj.push_back(Pair("not_ready_reason", status.reason));
    obj.push_back(Pair("authorization_height", status.height));
    obj.push_back(Pair("known_headers", status.headers));
    obj.push_back(Pair("tip_age_seconds", status.tipAge));
    obj.push_back(Pair("maxtipage", gArgs.GetArg("-depinmaxtipage", DEFAULT_DEPIN_MAX_TIP_AGE)));
    obj.push_back(Pair("maxheaderlag", gArgs.GetArg("-depinmaxheaderlag", DEFAULT_DEPIN_MAX_HEADER_LAG)));
    obj.push_back(Pair("stream_id", pDepinMsgPool->GetStreamId().ToString()));
    obj.push_back(Pair("admission_sequence", int64_t(pDepinMsgPool->GetHighWater())));
    obj.push_back(Pair("tombstones", int64_t(pDepinMsgPool->GetTombstoneCount())));
    obj.push_back(Pair("state_format", 2));
    obj.push_back(Pair("sequence_rpc", "depinreceiveseq"));
    obj.push_back(Pair("max_message_wire_bytes", int64_t(MAX_DEPIN_MESSAGE_WIRE_BYTES)));
    obj.push_back(Pair("max_reply_plaintext_bytes", int64_t(MAX_DEPIN_REPLY_PLAINTEXT)));
    obj.push_back(Pair("protocol", DEPIN_RPC_PROTOCOL_VERSION));
    CKey poolKey;
    CPubKey poolPubKey;
    if (GetDepinPoolKey(poolKey, poolPubKey)) {
        obj.push_back(Pair("depinpoolpkey", HexStr(poolPubKey.begin(), poolPubKey.end())));
        obj.push_back(Pair("depinpoolkeyaddress", EncodeDestination(poolPubKey.GetID())));
        obj.push_back(Pair("depinwallet", GetDepinPoolKeyWalletName()));
    }

    return obj;
}

#ifdef ENABLE_WALLET
UniValue depinsendmsg(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw std::runtime_error(
                "depinsendmsg \"token\" \"message\" \"fromaddress\"\n"
                "\nEncrypt, sign and add a message to this node's DePIN pool\n"
                "\nThe pool must be enabled on this node (-depinmsg) and the wallet must hold\n"
                "the token, or one of its ancestors, at fromaddress. To publish through a\n"
                "remote node, prepare the message client-side and call its depinsubmitmsg.\n"
                "\nArguments:\n"
                "1. \"token\"        (string, required) Token name. May be a section (sub-asset) such as\n"
                "                  \"&TOKEN/GENERAL\": recipients are the active holders of the section\n"
                "                  and of every ancestor up to the pool root; sending is authorized by\n"
                "                  holding the section or any ancestor.\n"
                "2. \"message\"      (string, required) Message to send (max 1KB)\n"
                "3. \"fromaddress\"  (string, required) Wallet address used for signing/encryption\n"
                "\nResult:\n"
                "{\n"
                "  \"result\": \"success\",          (string) Status\n"
                "  \"hash\": \"hash\",                (string) Message hash\n"
                "  \"token\": \"name\",               (string) Token/section the message was sent to\n"
                "  \"ancestors\": [...],           (array) Ancestor chain whose holders form the recipient set\n"
                "  \"recipients\": n,              (numeric) Number of recipients\n"
                "  \"skipped_no_pubkey\": n,       (numeric) Holders skipped for lacking a revealed public key\n"
                "  \"skipped_restricted\": n,      (numeric) Holders skipped as frozen or self-revoked\n"
                "  \"timestamp\": n                (numeric) Message timestamp\n"
                "}\n"
                "\nExamples:\n"
                + HelpExampleCli("depinsendmsg", "\"&MYTOKEN\" \"Hello team!\" \"NXsender...\"")
                + HelpExampleRpc("depinsendmsg", "\"&MYTOKEN\", \"Hello team!\", \"NXsender...\"")
        );

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    const std::string token = request.params[0].get_str();
    const std::string message = request.params[1].get_str();
    const std::string senderAddress = request.params[2].get_str();
    if (senderAddress.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "fromaddress is required");
    }

    if (message.size() > MAX_DEPIN_MESSAGE_SIZE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                          strprintf("Message size (%d) exceeds maximum (%d)",
                                   message.size(), MAX_DEPIN_MESSAGE_SIZE));
    }

    if (!pDepinMsgPool || !pDepinMsgPool->IsEnabled()) {
        throw JSONRPCError(RPC_MISC_ERROR, "DePIN messaging pool is not enabled");
    }

    // The token must be the pool root or a section inside its subtree.
    // AddMessage would refuse anything else, but failing here avoids resolving
    // recipients and encrypting for nothing.
    if (!IsDepinSectionOrRoot(token, pDepinMsgPool->GetActiveToken())) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                          strprintf("Token '%s' is not configured token '%s' or a section inside it",
                                   token, pDepinMsgPool->GetActiveToken()));
    }

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureDepinServiceReady();
    EnsureWalletIsUnlocked(pwallet);

    {
        const CTxDestination dest = DecodeDestination(senderAddress);
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                              strprintf("Invalid address: %s", senderAddress));
        }
        if (!IsMine(*pwallet, dest)) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                              strprintf("Address %s is not part of this wallet", senderAddress));
        }
    }

    std::map<std::string, std::vector<COutput>> mapAssetCoins;
    pwallet->AvailableAssets(mapAssetCoins);

    // Sections: sending to "&TEST/GENERAL" is authorized by holding the section
    // OR any of its ancestors ("&TEST" grants the whole branch), so the wallet
    // check walks the ancestor chain instead of demanding the exact token.
    std::string ancestorsError;
    std::vector<std::string> tokenAncestors;
    if (!DeriveDepinAncestors(token, "", tokenAncestors, ancestorsError)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, ancestorsError);
    }

    bool walletHasBranchToken = false;
    for (const std::string& ancestor : tokenAncestors) {
        if (!mapAssetCoins.count(ancestor)) {
            continue;
        }
        for (const auto& out : mapAssetCoins[ancestor]) {
            CTxDestination dest;
            if (ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, dest) &&
                EncodeDestination(dest) == senderAddress) {
                walletHasBranchToken = true;
                break;
            }
        }
        if (walletHasBranchToken) break;
    }
    if (!walletHasBranchToken) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                          strprintf("Wallet does not own %s or any of its ancestor tokens at %s",
                                   token, senderAddress));
    }

    // Recipients: the ACTIVE holders of the token and of every ancestor UP TO
    // THE POOL'S ROOT, resolved by GetDepinAncestorRecipients -- exact reads,
    // no flush, freeze/self-revoke respected, missing pubkeys skipped and
    // counted. Deriving past the pool root would encrypt for holders the pool
    // does not serve, and an extra recipientKeys entry is an extra reader.
    // The limit is never zero: Initialize() rejects maxRecipients == 0.
    const std::string recipientsStopAt = pDepinMsgPool->GetActiveToken();
    const size_t recipientsLimit = std::min<size_t>(pDepinMsgPool->GetMaxRecipients(), MAX_DEPIN_RECIPIENTS);

    std::string error;
    CDepinAncestorRecipients branchRecipients;
    if (!GetDepinAncestorRecipients(token, recipientsLimit, branchRecipients, error,
                                    recipientsStopAt)) {
        throw JSONRPCError(RPC_MISC_ERROR, strprintf("Failed to get token holders: %s", error));
    }

    // The messaging limit is a hard error, never a silent cut: sending to the
    // first N of an unknown set would misrepresent who received the message.
    if (branchRecipients.truncated) {
        std::string ancestorList;
        for (const std::string& ancestor : branchRecipients.ancestors) {
            if (!ancestorList.empty()) ancestorList += ", ";
            ancestorList += ancestor;
        }
        throw JSONRPCError(RPC_MISC_ERROR,
                          strprintf("Section '%s' resolves to more than %u eligible recipients "
                                   "(the serving pool's limit is %u). The recipient set is the "
                                   "union of holders of: %s.",
                                   token, (unsigned int)recipientsLimit,
                                   (unsigned int)recipientsLimit, ancestorList));
    }

    std::vector<std::string> holders;
    for (const CDepinRecipient& recipient : branchRecipients.recipients) {
        holders.push_back(recipient.address);
    }

    if (holders.empty()) {
        throw JSONRPCError(RPC_MISC_ERROR,
                          strprintf("No eligible recipients for '%s': every holder is restricted "
                                   "or has no revealed public key", token));
    }

    // Create message
    CDepinMessage chatMsg;
    chatMsg.token = token;
    chatMsg.senderAddress = senderAddress;
    chatMsg.timestamp = GetTime();

    // Encrypt ONCE for ALL holders (ECIES hybrid encryption)
    // This creates a shared AES-encrypted message + encrypted AES keys for each holder
    if (!EncryptMessageForAllRecipients(message, holders, chatMsg.encryptedPayload, error)) {
        throw JSONRPCError(RPC_MISC_ERROR,
                          strprintf("Failed to encrypt message: %s", error));
    }

    LogPrintf("depinsendmsg: Encrypted message for %d recipients, total size: %d bytes\n",
              holders.size(), chatMsg.encryptedPayload.size());

    // The sender always signs; the pool re-verifies the signature on insert.
    if (!SignDepinMessage(chatMsg, senderAddress)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign message");
    }

    DepinAdmissionError admissionError;
    if (!pDepinMsgPool->AddMessage(chatMsg, error, /*skipSignatureCheck=*/false, &admissionError)) {
        throw JSONRPCError(admissionError == DepinAdmissionError::RECIPIENT_NOT_AUTHORIZED
                          ? RPC_VERIFY_REJECTED : RPC_MISC_ERROR,
                          strprintf("Failed to add message: %s", error));
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("result", "success"));
    result.push_back(Pair("hash", chatMsg.GetHash().ToString()));
    result.push_back(Pair("token", chatMsg.token));
    UniValue ancestorsArr(UniValue::VARR);
    for (const std::string& ancestor : branchRecipients.ancestors) {
        ancestorsArr.push_back(ancestor);
    }
    result.push_back(Pair("ancestors", ancestorsArr));
    result.push_back(Pair("recipients", (int)holders.size()));
    // Surface what was dropped: an address without a revealed public key is
    // silently unreachable otherwise, and "the root sees everything" only holds
    // for holders with a revealed key.
    result.push_back(Pair("skipped_no_pubkey", (int)branchRecipients.skippedNoPubKey));
    result.push_back(Pair("skipped_restricted", (int)branchRecipients.skippedRestricted));
    result.push_back(Pair("timestamp", chatMsg.timestamp));

    return result;
}
#endif // ENABLE_WALLET


#ifdef ENABLE_WALLET


UniValue depindecrypt(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
                "depindecrypt \"address\" \"encrypted\"\n"
                "\nOpen an encrypted DePIN reply (depinchallenge, depinreceivemsg, ...) with a\n"
                "wallet key: the client half of the transport layer, for scripting with\n"
                "neurai-cli. Verify the reply's poolsig first; this RPC does not.\n"
                "\nArguments:\n"
                "1. \"address\"    (string, required) Wallet address the reply was encrypted for\n"
                "2. \"encrypted\"  (string, required) The reply's \"encrypted\" hex\n"
                "\nResult:\n"
                "The decrypted JSON value (a string if the plaintext is not JSON)\n"
                "\nExamples:\n"
                + HelpExampleCli("depindecrypt", "\"NXholder...\" \"<hex>\"")
                + HelpExampleRpc("depindecrypt", "\"NXholder...\", \"<hex>\"")
        );

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    const std::string address = request.params[0].get_str();
    const std::string& encryptedHex = request.params[1].get_str();

    const CTxDestination dest = DecodeDestination(address);
    const CKeyID* keyID = boost::get<CKeyID>(&dest);
    if (!IsValidDestination(dest) || !keyID) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }
    if (encryptedHex.size() > 2 * DepinECIESWireLimit(MAX_DEPIN_REPLY_PLAINTEXT, MAX_DEPIN_RECIPIENTS) ||
        !IsHex(encryptedHex)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "encrypted exceeds budget or is not hex");
    }

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);

    CKey key;
    if (!pwallet->GetKey(*keyID, key)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Private key for %s not in wallet", address));
    }

    CECIESEncryptedMessage ecies;
    std::string formatError;
    const uint160 recipientID = *keyID;
    if (!DecodeDepinECIES(ParseHex(encryptedHex), MAX_DEPIN_REPLY_PLAINTEXT, MAX_DEPIN_RECIPIENTS,
                          ecies, formatError, &recipientID))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, formatError);

    std::string plaintext;
    std::string error;
    if (!ECIESDecryptMessage(ecies, key, address, plaintext, error)) {
        throw JSONRPCError(RPC_VERIFY_ERROR, strprintf("Failed to decrypt: %s", error));
    }

    UniValue decoded;
    if (!decoded.read(plaintext)) {
        return UniValue(plaintext);
    }
    return decoded;
}
#endif // ENABLE_WALLET

// New secure endpoint: receives pre-encrypted and signed messages

// New non-wallet endpoint: retrieves encrypted pool messages (no decryption)



#ifdef ENABLE_WALLET
#endif

#ifdef ENABLE_WALLET
UniValue depingetmsg(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
                "depingetmsg \"token\" ( \"fromaddress\" )\n"
                "\nRetrieve and decrypt this node's pool messages for your wallet addresses\n"
                "\nReads the local pool only (-depinmsg must be enabled on this node). To read\n"
                "a remote pool, query its depinreceivemsg and decrypt client-side.\n"
                "\nArguments:\n"
                "1. \"token\"        (string, required) Token name. May be a section (sub-asset) such as\n"
                "                    \"&TOKEN/GENERAL\"; only that section's subtree is returned\n"
                "2. \"fromaddress\"  (string, optional) Decrypt only with this wallet address\n"
                "\nResult:\n"
                "[\n"
                "  {\n"
                "    \"recipient\": \"address\",      (string) Recipient address (your address)\n"
                "    \"sender\": \"address\",         (string) Sender address\n"
                "    \"token\": \"name\",             (string) Token/section the message belongs to\n"
                "    \"message\": \"text\",           (string) Decrypted message\n"
                "    \"message_type\": \"private|group\", (string) Message type (private=1-to-1, group=broadcast)\n"
                "    \"timestamp\": n,              (numeric) Unix timestamp\n"
                "    \"date\": \"YYYY-MM-DD HH:MM:SS\", (string) Formatted date\n"
                "    \"expires\": \"YYYY-MM-DD HH:MM:SS\" (string) Expiration date\n"
                "  },\n"
                "  ...\n"
                "]\n"
                "\nExamples:\n"
                + HelpExampleCli("depingetmsg", "\"&MYTOKEN\"") + " (all wallet addresses)\n"
                + HelpExampleCli("depingetmsg", "\"&MYTOKEN\" \"NXyouraddress...\"") + " (specific address)\n"
                + HelpExampleRpc("depingetmsg", "\"&MYTOKEN\"")
        );

    std::string token = request.params[0].get_str();

    // isNull() as well as size(): a named call that skips fromaddress leaves a
    // JSON null here, not a missing slot.
    std::string specificAddress;
    if (request.params.size() >= 2 && !request.params[1].isNull() &&
        !request.params[1].get_str().empty()) {
        specificAddress = request.params[1].get_str();
    }

    if (!specificAddress.empty()) {
        CTxDestination dest = DecodeDestination(specificAddress);
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                              strprintf("Invalid fromaddress: %s", specificAddress));
        }
    }

    // Local query
    if (!pDepinMsgPool || !pDepinMsgPool->IsEnabled()) {
        throw JSONRPCError(RPC_MISC_ERROR, "DePIN messaging pool is not enabled");
    }

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureDepinServiceReady();

    // The token may be a section inside the configured subtree; it then acts
    // as the tab scope for the loop below.
    if (!IsDepinSectionOrRoot(token, pDepinMsgPool->GetActiveToken())) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                          strprintf("Token '%s' is not configured token '%s' or a section inside it",
                                   token, pDepinMsgPool->GetActiveToken()));
    }

    // Get all wallet addresses that own a token of the branch: the requested
    // token, any of its ancestors (they grant the subtree), or any section
    // inside it (their holders can decrypt their own section's messages).
    std::set<std::string> myAddresses;
    auto assetInBranch = [&token](const std::string& name) {
        return IsDepinSectionOrRoot(name, token) || IsDepinSectionOrRoot(token, name);
    };

    {
        std::map<std::string, std::vector<COutput>> mapAssetCoins;
        pwallet->AvailableAssets(mapAssetCoins);

        std::set<std::string> branchAddresses;
        for (const auto& assetEntry : mapAssetCoins) {
            if (!assetInBranch(assetEntry.first)) {
                continue;
            }
            for (const auto& out : assetEntry.second) {
                CTxDestination dest;
                if (ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, dest)) {
                    branchAddresses.insert(EncodeDestination(dest));
                }
            }
        }

        if (!specificAddress.empty()) {
            if (!branchAddresses.count(specificAddress)) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                                  strprintf("Address %s does not own %s or any related branch token",
                                           specificAddress, token));
            }
            myAddresses.insert(specificAddress);
        } else {
            myAddresses = branchAddresses;
            if (myAddresses.empty()) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                                  strprintf("Wallet does not own any %s tokens", token));
            }
        }
    }

    UniValue result(UniValue::VARR);

    // Unexpired pool snapshot; address filtering happens during decryption.
    std::vector<CDepinMessage> allMessages = pDepinMsgPool->GetAllMessages(/*includeExpired=*/false);
    std::set<uint256> processedMessages;  // To avoid duplicates

    for (const CDepinMessage& msg : allMessages) {
        // Tab scope: only the requested token's subtree.
        if (!IsDepinSectionOrRoot(msg.token, token)) {
            continue;
        }

        // Avoid processing the same message multiple times
        uint256 msgHash = msg.GetHash();
        if (processedMessages.count(msgHash)) {
            continue;
        }

        // Try to decrypt with each owned address
        bool decrypted = false;
        for (const std::string& myAddress : myAddresses) {
            std::string accessError;
            if (!HasDepinSectionAccess(myAddress, msg.token, pDepinMsgPool->GetActiveToken(), accessError)) {
                continue;
            }
            std::string decryptedMessage;
            std::string error;

            // ECIES shared message contains an AES key encrypted for each holder
            // DecryptMessageForAddress will find and decrypt the key for myAddress
            if (DecryptMessageForAddress(msg.encryptedPayload, myAddress, decryptedMessage, error)) {
                UniValue msgObj(UniValue::VOBJ);
                msgObj.push_back(Pair("recipient", myAddress));
                msgObj.push_back(Pair("sender", msg.senderAddress));
                msgObj.push_back(Pair("token", msg.token));
                msgObj.push_back(Pair("message", decryptedMessage));
                std::string msgTypeStr = (msg.messageType == 0x01) ? "private" : "group";
                msgObj.push_back(Pair("message_type", msgTypeStr));
                msgObj.push_back(Pair("timestamp", msg.timestamp));
                msgObj.push_back(Pair("date", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", msg.timestamp)));
                msgObj.push_back(Pair("expires", DateTimeStrFormat("%Y-%m-%d %H:%M:%S",
                                                                   msg.timestamp + pDepinMsgPool->GetMessageExpiryTime())));
                result.push_back(msgObj);
                processedMessages.insert(msgHash);
                decrypted = true;
                break;  // Only add once per message
            }
        }
    }

    return result;
}
#endif // ENABLE_WALLET


UniValue depinpoolstats(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 0)
        throw std::runtime_error(
            "depinpoolstats\n"
            "\nGet statistical analysis of the DePIN message pool.\n"
            "\nResult:\n"
            "{\n"
            "  \"enabled\": true|false,\n"
            "  \"token\": \"string\",\n"
            "  \"total_messages\": n,\n"
            "  \"total_size_bytes\": n,\n"
            "  \"memory_usage_bytes\": n,\n"
            "  \"oldest_message\": \"YYYY-MM-DD HH:MM:SS\",\n"
            "  \"newest_message\": \"YYYY-MM-DD HH:MM:SS\",\n"
            "  \"messages_by_age\": {\n"
            "    \"last_hour\": n,\n"
            "    \"last_day\": n,\n"
            "    \"last_week\": n\n"
            "  },\n"
            "  \"unique_senders\": n,\n"
            "  \"unique_recipients\": n,\n"
            "  \"avg_recipients_per_message\": n.nn,\n"
            "  \"avg_message_size\": n,\n"
            "  \"expiring_in_24h\": n\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("depinpoolstats", "")
            + HelpExampleRpc("depinpoolstats", "")
        );

    // Check if DePIN pool is enabled
    if (!pDepinMsgPool || !pDepinMsgPool->IsEnabled()) {
        throw JSONRPCError(RPC_MISC_ERROR, "DePIN message pool is not enabled");
    }

    // Get all messages
    std::vector<CDepinMessage> messages = pDepinMsgPool->GetAllMessages();

    // Calculate statistics
    int64_t now = GetTime();
    int64_t oldest = std::numeric_limits<int64_t>::max();
    int64_t newest = 0;
    size_t totalSize = 0;
    int totalRecipients = 0;
    int messagesLastHour = 0;
    int messagesLastDay = 0;
    int messagesLastWeek = 0;
    int expiringIn24h = 0;

    std::set<std::string> uniqueSenders;
    std::set<std::string> uniqueRecipients;

    for (const auto& msg : messages) {
        // Track time range
        if (msg.timestamp < oldest) oldest = msg.timestamp;
        if (msg.timestamp > newest) newest = msg.timestamp;

        // Count by age
        int64_t age = now - msg.timestamp;
        if (age < 3600) messagesLastHour++;
        if (age < 86400) messagesLastDay++;
        if (age < 604800) messagesLastWeek++;

        // Count expiring soon
        int64_t timeToExpiry = (msg.timestamp + pDepinMsgPool->GetMessageExpiryTime()) - now;
        if (timeToExpiry < 86400 && timeToExpiry > 0) expiringIn24h++;

        // Track senders
        uniqueSenders.insert(msg.senderAddress);

        // With ECIES shared encryption, we can't determine individual recipients
        // Count the message payload size instead
        totalSize += msg.signature.size();
        totalSize += msg.encryptedPayload.size();
    }

    // Note: totalRecipients and uniqueRecipients are not available with ECIES shared encryption
    totalRecipients = 0;  // Not determinable without decryption

    // Build result
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("enabled", pDepinMsgPool->IsEnabled()));
    result.push_back(Pair("token", pDepinMsgPool->GetActiveToken()));
    result.push_back(Pair("total_messages", (int)messages.size()));
    result.push_back(Pair("total_size_bytes", (int)totalSize));
    result.push_back(Pair("memory_usage_bytes", (int)pDepinMsgPool->DynamicMemoryUsage()));

    if (messages.size() > 0) {
        result.push_back(Pair("oldest_message", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", oldest)));
        result.push_back(Pair("newest_message", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", newest)));

        UniValue byAge(UniValue::VOBJ);
        byAge.push_back(Pair("last_hour", messagesLastHour));
        byAge.push_back(Pair("last_day", messagesLastDay));
        byAge.push_back(Pair("last_week", messagesLastWeek));
        result.push_back(Pair("messages_by_age", byAge));

        result.push_back(Pair("unique_senders", (int)uniqueSenders.size()));
        result.push_back(Pair("unique_recipients", "N/A (ECIES shared encryption)"));
        result.push_back(Pair("avg_recipients_per_message", "N/A (ECIES shared encryption)"));

        result.push_back(Pair("avg_message_size", (int)(totalSize / messages.size())));
        result.push_back(Pair("expiring_in_24h", expiringIn24h));
    } else {
        result.push_back(Pair("oldest_message", ""));
        result.push_back(Pair("newest_message", ""));
        result.push_back(Pair("unique_senders", 0));
        result.push_back(Pair("unique_recipients", 0));
        result.push_back(Pair("avg_recipients_per_message", 0));
        result.push_back(Pair("avg_message_size", 0));
        result.push_back(Pair("expiring_in_24h", 0));
    }

    return result;
}

UniValue depinmcpstatus(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
                "depinmcpstatus\n"
                "\nGet status information about the DePIN MCP (AI) worker\n"
                "\nResult:\n"
                "{\n"
                "  \"enabled\": true|false,         (boolean) Whether MCP worker is enabled\n"
                "  \"running\": true|false,         (boolean) Whether MCP worker is running\n"
                "  \"mcp_url\": \"url\",              (string) MCP server URL\n"
                "  \"model_name\": \"name\",          (string) Name of the loaded AI model\n"
                "  \"command_key\": \"key\",          (string) Command prefix (e.g. /ai)\n"
                "  \"depin_token\": \"token\",        (string) DePIN token being monitored\n"
                "  \"poll_interval\": n,            (numeric) Polling interval in seconds\n"
                "  \"commands_processed\": n,       (numeric) Total commands processed\n"
                "  \"total_errors\": n,             (numeric) Total errors encountered\n"
                "  \"rate_limited\": n,             (numeric) Commands rejected by rate limiting\n"
                "  \"concurrency\": n,              (numeric) Number of parallel task threads\n"
                "  \"tasks_in_flight\": n,          (numeric) AI requests currently being processed\n"
                "  \"processed_cache\": n,          (numeric) Size of the processed-message dedup cache\n"
                "  \"context_sessions\": n,         (numeric) Active conversation contexts\n"
                "  \"last_poll_time\": n            (numeric) Unix timestamp of last poll\n"
                "}\n"
                "\nExamples:\n"
                + HelpExampleCli("depinmcpstatus", "")
                + HelpExampleRpc("depinmcpstatus", "")
        );

    UniValue result(UniValue::VOBJ);

    if (!g_depinMCPWorker) {
        result.push_back(Pair("enabled", false));
        result.push_back(Pair("running", false));
        return result;
    }

    result.push_back(Pair("enabled", true));
    result.push_back(Pair("running", g_depinMCPWorker->IsRunning()));
    result.push_back(Pair("mcp_url", g_depinMCPWorker->GetMCPUrl()));
    result.push_back(Pair("model_name", g_depinMCPWorker->GetModelName()));
    result.push_back(Pair("command_key", g_depinMCPWorker->GetCommandKey()));
    result.push_back(Pair("depin_token", g_depinMCPWorker->GetDepinToken()));
    result.push_back(Pair("node_address", g_depinMCPWorker->GetNodeAddress()));
    result.push_back(Pair("poll_interval", g_depinMCPWorker->GetPollInterval()));
    result.push_back(Pair("commands_processed", (uint64_t)g_depinMCPWorker->GetCommandsProcessed()));
    result.push_back(Pair("total_errors", (uint64_t)g_depinMCPWorker->GetTotalErrors()));
    result.push_back(Pair("rate_limited", (uint64_t)g_depinMCPWorker->GetRateLimited()));
    result.push_back(Pair("concurrency", g_depinMCPWorker->GetConcurrency()));
    result.push_back(Pair("tasks_in_flight", g_depinMCPWorker->GetTasksInFlight()));
    result.push_back(Pair("processed_cache", (uint64_t)g_depinMCPWorker->GetProcessedCacheSize()));
    result.push_back(Pair("context_sessions", (uint64_t)g_depinMCPWorker->GetContextSessions()));
    result.push_back(Pair("last_poll_time", g_depinMCPWorker->GetLastPollTime()));

    if (g_depinMCPWorker->GetLastPollTime() > 0) {
        result.push_back(Pair("last_poll_time_str", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", g_depinMCPWorker->GetLastPollTime())));
    }

    return result;
}

UniValue depingetancestorrecipients(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3)
        throw std::runtime_error(
                "depingetancestorrecipients \"token\" ( max_results ) ( \"stop_at\" )\n"
                "\nList the active holders of a DEPIN branch: the deduplicated union of the\n"
                "holders of the given token and of every one of its '/'-separated ancestors,\n"
                "each with the public key it has revealed on chain.\n"
                "\nActive means: positive balance, public key revealed, and not blocked by an\n"
                "owner freeze or by self-revocation. Restriction is per (asset, address), so an\n"
                "address that is active in at least one ancestor is returned even if it revoked\n"
                "itself in another -- holding the root already grants visibility over the branch.\n"
                "\nThe query is exact: '&TEST' returns holders of '&TEST' only, never of\n"
                "'&TEST/APPLE', '&TESTING' or '&TEST.FOO'. Every derived ancestor must exist; a\n"
                "missing intermediate level is an error rather than something skipped.\n"
                "\nThis command is informational. It does not know about -depinmsgmaxusers, does\n"
                "not decide whether a message fits in a pool, and a truncated result must not be\n"
                "treated as a complete recipient set.\n"
                "\nRequires -assetindex and -pubkeyindex.\n"
                "\nArguments:\n"
                "1. \"token\"        (string, required) DEPIN token, e.g. \"&TEST/APPLE/GOLDEN\"\n"
                "2. max_results   (numeric, optional, default=" + std::to_string(DEFAULT_DEPIN_ANCESTOR_RECIPIENTS_LIMIT) + ") Maximum recipients to return\n"
                "                 (1.." + std::to_string(MAX_DEPIN_ANCESTOR_RECIPIENTS_HARD_CAP) + ")\n"
                "3. \"stop_at\"      (string, optional) Stop deriving ancestors at this token,\n"
                "                 inclusive. Must be the token itself or one of its ancestors.\n"
                "                 Omitted: derive up to the absolute root.\n"
                "\nResult:\n"
                "{\n"
                "  \"token\": \"name\",                    (string) Token queried\n"
                "  \"stop_at\": \"name\",                  (string) Where derivation stopped (\"\" = root)\n"
                "  \"ancestors\": [\"name\", ...],         (array) Token first, then each ancestor\n"
                "  \"recipients\": [                     (array) Active holders, ordered by address\n"
                "    {\n"
                "      \"address\": \"address\",           (string) Holder address\n"
                "      \"pubkey\": \"hex\"                 (string) Public key revealed on chain\n"
                "    }, ...\n"
                "  ],\n"
                "  \"returned\": n,                      (numeric) Number of recipients returned\n"
                "  \"max_results\": n,                   (numeric) Limit applied\n"
                "  \"truncated\": true|false,            (boolean) True if more eligible recipients exist\n"
                "  \"skipped_no_pubkey\": n,             (numeric) Addresses dropped for lacking a usable\n"
                "                                       revealed public key\n"
                "  \"skipped_no_pubkey_complete\": bool, (boolean) False when truncated: the count then\n"
                "                                       covers only the addresses examined\n"
                "  \"skipped_restricted\": n,            (numeric) Addresses dropped as frozen or\n"
                "                                       self-revoked in every ancestor they hold\n"
                "  \"skipped_restricted_complete\": bool (boolean) Same rule as above\n"
                "}\n"
                "\nExamples:\n"
                + HelpExampleCli("depingetancestorrecipients", "\"&TEST/APPLE/GOLDEN\"")
                + HelpExampleCli("depingetancestorrecipients", "\"&TEST/APPLE/GOLDEN\" 50 \"&TEST/APPLE\"")
                + HelpExampleRpc("depingetancestorrecipients", "\"&TEST/APPLE/GOLDEN\", 50, \"&TEST/APPLE\"")
        );

    const std::string token = request.params[0].get_str();

    size_t maxResults = DEFAULT_DEPIN_ANCESTOR_RECIPIENTS_LIMIT;
    if (request.params.size() > 1 && !request.params[1].isNull()) {
        const int64_t requested = request.params[1].get_int64();
        if (requested <= 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "max_results must be at least 1");
        }
        if (requested > (int64_t)MAX_DEPIN_ANCESTOR_RECIPIENTS_HARD_CAP) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               strprintf("max_results must not exceed %u",
                                         (unsigned int)MAX_DEPIN_ANCESTOR_RECIPIENTS_HARD_CAP));
        }
        maxResults = (size_t)requested;
    }

    std::string stopAt;
    if (request.params.size() > 2 && !request.params[2].isNull()) {
        stopAt = request.params[2].get_str();
    }

    LOCK(cs_main);
    EnsureDepinServiceReady();

    // The helper also checks freshness for non-RPC callers.
    // RPC_MISC_ERROR rather than RPC_INVALID_PARAMETER: the function reports
    // missing indexes and databases through the same channel as a bad token, so
    // the code cannot honestly claim the caller's parameters were at fault.
    CDepinAncestorRecipients recipients;
    std::string error;
    if (!GetDepinAncestorRecipients(token, maxResults, recipients, error, stopAt)) {
        throw JSONRPCError(RPC_MISC_ERROR, error);
    }

    UniValue ancestors(UniValue::VARR);
    for (const std::string& ancestor : recipients.ancestors) {
        ancestors.push_back(ancestor);
    }

    UniValue entries(UniValue::VARR);
    for (const CDepinRecipient& recipient : recipients.recipients) {
        UniValue entry(UniValue::VOBJ);
        entry.push_back(Pair("address", recipient.address));
        entry.push_back(Pair("pubkey", HexStr(recipient.pubkey.begin(), recipient.pubkey.end())));
        entries.push_back(entry);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("token", recipients.token));
    result.push_back(Pair("stop_at", recipients.stopAt));
    result.push_back(Pair("ancestors", ancestors));
    result.push_back(Pair("recipients", entries));
    result.push_back(Pair("returned", (uint64_t)recipients.recipients.size()));
    result.push_back(Pair("max_results", (uint64_t)recipients.maxResults));
    result.push_back(Pair("truncated", recipients.truncated));
    result.push_back(Pair("skipped_no_pubkey", (uint64_t)recipients.skippedNoPubKey));
    result.push_back(Pair("skipped_no_pubkey_complete", recipients.skippedNoPubKeyComplete));
    result.push_back(Pair("skipped_restricted", (uint64_t)recipients.skippedRestricted));
    result.push_back(Pair("skipped_restricted_complete", recipients.skippedRestrictedComplete));

    return result;
}


#ifdef ENABLE_WALLET
UniValue depinpoolpkey(const JSONRPCRequest& request)
{
    // Define BIP32 hardened key limit constant
    const uint32_t BIP32_HARDENED_KEY_LIMIT = 0x80000000;

    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
                "depinpoolpkey\n"
                "\nReturns the public key of the DePIN pool address from the internal wallet.\n"
                "This command only works if the wallet is loaded and unlocked at node startup.\n"
                "\nDerived path:\n"
                "  Mainnet:  m/44'/1900'/200'/0/0\n"
                "  Testnet:  m/44'/1'/200'/1/0\n"
                "  Regtest:  m/44'/1'/200'/0/0\n"
                "\nResult:\n"
                "{\n"
                "  \"pubkey\": \"hex\",           (string) Public key in hex format\n"
                "  \"address\": \"address\",      (string) Corresponding Neurai address\n"
                "  \"path\": \"derivation_path\"  (string) BIP44 derivation path used\n"
                "}\n"
                "\nExamples:\n"
                + HelpExampleCli("depinpoolpkey", "")
                + HelpExampleRpc("depinpoolpkey", "")
        );

    // Check wallet availability
    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Wallet is not loaded or available");
    }

    CPubKey pubkey;
    CKey privKey;
    std::string derivationPath;
    std::string error;

    if (!DeriveDepinPoolKeys(pwallet, privKey, pubkey, derivationPath, error)) {
        throw JSONRPCError(RPC_WALLET_ERROR, error);
    }

    // Get the address
    CKeyID keyID = pubkey.GetID();
    CTxDestination dest = keyID;
    std::string address = EncodeDestination(dest);

    // Build result
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("pubkey", HexStr(pubkey.begin(), pubkey.end())));
    result.push_back(Pair("address", address));
    result.push_back(Pair("path", derivationPath));

    return result;
}
#endif

static const CRPCCommand commands[] =
    {           //  category    name                          actor (function)             argNames
                //  ----------- ------------------------      -----------------------      ----------
            { "messages",       "viewallmessages",            &viewallmessages,            {}},
            { "messages",       "viewallmessagechannels",     &viewallmessagechannels,     {}},
            { "messages",       "subscribetochannel",         &subscribetochannel,         {"channel_name"}},
            { "messages",       "unsubscribefromchannel",     &unsubscribefromchannel,     {"channel_name"}},
#ifdef ENABLE_WALLET
            { "messages",       "sendmessage",                &sendmessage,                {"channel", "ipfs_hash", "expire_time"}},
            {"restricted",        "viewmytaggedaddresses",      &viewmytaggedaddresses,       {}},
            {"restricted",        "viewmyrestrictedaddresses",  &viewmyrestrictedaddresses,   {}},
#endif
            { "messages",       "clearmessages",              &clearmessages,              {}},
            // DePIN Messaging Commands
#ifdef ENABLE_WALLET
            { "depin messaging",          "depinpoolpkey",              &depinpoolpkey,              {}},
            { "depin messaging",          "depindecrypt",               &depindecrypt,               {"address", "encrypted"}},
            // Local pool + this node's wallet; never reachable through a proxy.
            { "depin messaging",          "depinsendmsg",               &depinsendmsg,               {"token", "message", "fromaddress"}},
            { "depin messaging",          "depingetmsg",                &depingetmsg,                {"token", "fromaddress"}},
#endif
    };

void RegisterMessageRPCCommands(CRPCTable &t)
{
    RegisterDepinRPCCommands(t);
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
