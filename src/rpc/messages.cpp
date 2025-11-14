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
#include "consensus/validation.h"
#include "core_io.h"
#include "httpserver.h"
#include "validation.h"
#include "net.h"
#include "policy/feerate.h"
#include "policy/fees.h"
#include "policy/policy.h"
#include "policy/rbf.h"
#include "depinmsgpoolnet.h"
#include "rpc/mining.h"
#include "rpc/safemode.h"
#include "rpc/server.h"
#include "script/sign.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "wallet/coincontrol.h"
#include "wallet/feebumper.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"

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

// DePIN Messaging RPC Commands
#include "depinmsgpool.h"

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
                "  \"port\": n,                    (numeric) Listening port\n"
                "  \"maxrecipients\": n,           (numeric) Maximum recipients per message\n"
                "  \"messages\": n,                (numeric) Number of messages in mempool\n"
                "  \"memoryusage\": n,             (numeric) Memory usage in bytes\n"
                "  \"oldestmessage\": \"time\",      (string) Timestamp of oldest message\n"
                "  \"newestmessage\": \"time\"       (string) Timestamp of newest message\n"
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
    obj.push_back(Pair("port", (int)pDepinMsgPool->GetPort()));
    obj.push_back(Pair("maxrecipients", (int)pDepinMsgPool->GetMaxRecipients()));
    obj.push_back(Pair("messages", (int)pDepinMsgPool->Size()));
    obj.push_back(Pair("memoryusage", (int)pDepinMsgPool->DynamicMemoryUsage()));

    int64_t oldest = pDepinMsgPool->GetOldestMessageTime();
    int64_t newest = pDepinMsgPool->GetNewestMessageTime();

    if (oldest > 0)
        obj.push_back(Pair("oldestmessage", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", oldest)));
    if (newest > 0)
        obj.push_back(Pair("newestmessage", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", newest)));

    return obj;
}

#ifdef ENABLE_WALLET
UniValue depinsendmsg(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 5)
        throw std::runtime_error(
                "depinsendmsg \"token\" \"ip[:port]\" \"message\" \"fromaddress\" (port)\n"
                "\nSend an encrypted message through a remote DePIN gateway (challenge/response)\n"
                "\nArguments:\n"
                "1. \"token\"        (string, required) Token name\n"
                "2. \"ip[:port]\"    (string, required) Target node address (optional :port to contact remote gateway)\n"
                "3. \"message\"      (string, required) Message to send (max 1KB)\n"
                "4. \"fromaddress\" (string, required) Wallet address used for signing/encryption\n"
                "5. port           (numeric, optional) Destination message port (defaults to 19002). Only used when specified after fromaddress\n"
                "\nResult:\n"
                "{\n"
                "  \"result\": \"success\",          (string) Status\n"
                "  \"hash\": \"hash\",                (string) Message hash\n"
                "  \"recipients\": n,              (numeric) Number of recipients\n"
                "  \"timestamp\": n                (numeric) Message timestamp\n"
                "}\n"
                "\nExamples:\n"
                + HelpExampleCli("depinsendmsg", "\"MYTOKEN\" \"192.168.1.100\" \"Hello team!\" \"NXsender...\"")
                + HelpExampleCli("depinsendmsg", "\"MYTOKEN\" \"192.168.1.100:19005\" \"Hello team!\" \"NXsender...\" 19005")
                + HelpExampleRpc("depinsendmsg", "\"MYTOKEN\", \"192.168.1.100\", \"Hello team!\", \"NXsender...\"")
        );

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);

    std::string token = request.params[0].get_str();
    std::string destinationParam = request.params[1].get_str();
    std::string message = request.params[2].get_str();
    std::string senderAddress = request.params.size() >= 4 ? request.params[3].get_str() : "";
    if (senderAddress.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "fromaddress is required for remote send");
    }

    int paramIndex = 4;

    int destinationPort = DEFAULT_DEPIN_MSG_PORT;
    bool destinationPortProvided = false;
    if (request.params.size() >= paramIndex + 1) {
        destinationPort = request.params[paramIndex].get_int();
        if (destinationPort <= 0 || destinationPort > 65535) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid destination port");
        }
        destinationPortProvided = true;
    }

    auto parseHostPort = [](const std::string& input, std::string& hostOut, int& portOut) {
        hostOut = input;
        portOut = DEFAULT_DEPIN_MSG_PORT;
        size_t pos = input.rfind(':');
        if (pos != std::string::npos && pos + 1 < input.size()) {
            std::string portStr = input.substr(pos + 1);
            bool numeric = !portStr.empty() && std::all_of(portStr.begin(), portStr.end(), [](unsigned char c) {
                return std::isdigit(c);
            });
            if (numeric) {
                hostOut = input.substr(0, pos);
                portOut = atoi(portStr.c_str());
            }
        }
    };

    // If called from DePIN server (pre-authenticated), force local processing
    bool localPoolActive = request.fSkipWalletCheck;

    std::string gatewayHost;
    int gatewayPortFromAddress = DEFAULT_DEPIN_MSG_PORT;
    parseHostPort(destinationParam, gatewayHost, gatewayPortFromAddress);
    if (!destinationPortProvided) {
        destinationPort = gatewayPortFromAddress;
    }
    if (gatewayPortFromAddress <= 0 || gatewayPortFromAddress > 65535) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid gateway port");
    }

    std::string targetHost = gatewayHost;
    int targetPort = destinationPort;
    if (targetPort <= 0 || targetPort > 65535) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid destination port");
    }
    std::string ipAddress = targetHost;

    if (message.size() > MAX_DEPIN_MESSAGE_SIZE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                          strprintf("Message size (%d) exceeds maximum (%d)",
                                   message.size(), MAX_DEPIN_MESSAGE_SIZE));
    }

    auto ensureWalletOwnsAddress = [&](const std::string& addr, bool enforceTokenOwnership) {
        CTxDestination dest = DecodeDestination(addr);
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                              strprintf("Invalid address: %s", addr));
        }

        // Debug logging
        isminetype mine = IsMine(*pwallet, dest);
        LogPrintf("DEBUG depinsendmsg: Checking address %s, IsMine result: %d, wallet name: %s\n",
                  addr, mine, pwallet->GetName());

        if (!mine) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                              strprintf("Address %s is not part of this wallet", addr));
        }
        if (!enforceTokenOwnership) {
            return;
        }
    };

    // Determine if this is a local or remote operation
    // Local if: no gateway host specified OR server-authenticated request
    localPoolActive = localPoolActive || gatewayHost.empty();

    std::map<std::string, std::vector<COutput>> mapAssetCoins;
    pwallet->AvailableAssets(mapAssetCoins);

    auto walletHasTokenAtAddress = [&](const std::string& addr) {
        if (!mapAssetCoins.count(token)) {
            return false;
        }
        for (const auto& out : mapAssetCoins[token]) {
            CTxDestination dest;
            if (ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, dest)) {
                if (EncodeDestination(dest) == addr) {
                    return true;
                }
            }
        }
        return false;
    };

    auto requireAddressWithTokens = [&](const std::string& addr) {
        // Only check wallet ownership if NOT called from DePIN server
        if (!request.fSkipWalletCheck) {
            ensureWalletOwnsAddress(addr, false);
        }
        if (!walletHasTokenAtAddress(addr)) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                              strprintf("Wallet does not own any %s tokens at %s", token, addr));
        }
    };

    // ========== PREPARE MESSAGE (always local, regardless of destination) ==========

    // Verify sender owns address and has token (not needed if server-authenticated)
    if (!request.fSkipWalletCheck) {
        requireAddressWithTokens(senderAddress);
        if (!walletHasTokenAtAddress(senderAddress)) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                              strprintf("Wallet does not own any %s tokens at %s", token, senderAddress));
        }
    }

    // Get token holders (needed for encryption)
    std::string error;
    std::vector<std::string> holders = GetTokenHolders(token, MAX_DEPIN_RECIPIENTS, error);

    if (holders.empty()) {
        throw JSONRPCError(RPC_MISC_ERROR, strprintf("Failed to get token holders: %s", error));
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

    // ALWAYS sign the message (security requirement)
    // Client must always sign, even for remote sends
    if (!request.fSkipWalletCheck) {
        if (!SignDepinMessage(chatMsg, senderAddress)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign message");
        }
        LogPrintf("depinsendmsg: Message signed by %s\n", senderAddress);
    } else {
        // Server-authenticated path: signature already validated via challenge/response
        // Use empty signature to indicate pre-authentication
        chatMsg.signature.resize(65, 0);
        LogPrintf("depinsendmsg: Using pre-authenticated signature (server path)\n");
    }

    // ========== DELIVER MESSAGE (local or remote) ==========

    if (localPoolActive) {
        // LOCAL: Add directly to pool
        // Verify pool is available for local operations
        if (!pDepinMsgPool || !pDepinMsgPool->IsEnabled()) {
            throw JSONRPCError(RPC_MISC_ERROR, "DePIN messaging pool is not enabled");
        }

        LogPrintf("depinsendmsg: Adding to local pool\n");
        if (!pDepinMsgPool->AddMessage(chatMsg, error, request.fSkipWalletCheck)) {
            throw JSONRPCError(RPC_MISC_ERROR, strprintf("Failed to add message: %s", error));
        }
    } else {
        // REMOTE: Send serialized message to remote node
        LogPrintf("depinsendmsg: Sending to remote node %s:%d\n", gatewayHost, gatewayPortFromAddress);

        // Serialize the complete message
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << chatMsg;
        std::vector<unsigned char> serializedMsg(ss.begin(), ss.end());
        std::string hexMsg = HexStr(serializedMsg);

        // Send to remote node (already authenticated)
        UniValue remoteResult;
        if (!CDepinMsgPoolClient::SubmitSerializedMessage(gatewayHost, gatewayPortFromAddress,
                                                          hexMsg, remoteResult, error)) {
            throw JSONRPCError(RPC_MISC_ERROR, strprintf("Failed to submit to remote: %s", error));
        }

        LogPrintf("depinsendmsg: Successfully submitted to remote node\n");
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("result", "success"));
    result.push_back(Pair("hash", chatMsg.GetHash().ToString()));
    result.push_back(Pair("recipients", (int)holders.size()));
    result.push_back(Pair("timestamp", chatMsg.timestamp));
    result.push_back(Pair("destination", localPoolActive ? "local" : gatewayHost));

    return result;
}

// New secure endpoint: receives pre-encrypted and signed messages
UniValue depinsubmitmsg(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "depinsubmitmsg \"hexmessage\"\n"
                "\nSubmit a pre-encrypted and signed DePIN message to the pool\n"
                "\nThis is the secure protocol where the client prepares the complete message\n"
                "(encryption + signature) and the server only validates and stores it.\n"
                "\nArguments:\n"
                "1. \"hexmessage\"   (string, required) Hex-encoded serialized CDepinMessage\n"
                "\nResult:\n"
                "{\n"
                "  \"result\": \"success\",           (string) Status\n"
                "  \"hash\": \"hash\",                (string) Message hash\n"
                "  \"timestamp\": n                  (numeric) Unix timestamp\n"
                "}\n"
                "\nNote: This endpoint is typically called by remote nodes after challenge/response authentication.\n"
                "\nExamples:\n"
                + HelpExampleCli("depinsubmitmsg", "\"0a3f2e...\"")
                + HelpExampleRpc("depinsubmitmsg", "\"0a3f2e...\"")
        );

    if (!pDepinMsgPool || !pDepinMsgPool->IsEnabled()) {
        throw JSONRPCError(RPC_MISC_ERROR, "DePIN messaging pool is not enabled");
    }

    std::string hexMessage = request.params[0].get_str();

    // Decode hex
    if (!IsHex(hexMessage)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Message must be hex-encoded");
    }

    std::vector<unsigned char> msgData = ParseHex(hexMessage);
    if (msgData.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Empty message data");
    }

    // Deserialize CDepinMessage
    CDepinMessage chatMsg;
    try {
        CDataStream ss(msgData, SER_NETWORK, PROTOCOL_VERSION);
        ss >> chatMsg;
    } catch (const std::exception& e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR,
                          strprintf("Failed to deserialize message: %s", e.what()));
    }

    // Verify token matches pool configuration
    if (chatMsg.token != pDepinMsgPool->GetActiveToken()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                          strprintf("Token '%s' does not match configured token '%s'",
                                   chatMsg.token, pDepinMsgPool->GetActiveToken()));
    }

    // ALWAYS verify signature (critical security check)
    if (!VerifyDepinMessageSignature(chatMsg)) {
        throw JSONRPCError(RPC_VERIFY_ERROR, "Invalid message signature");
    }

    // Verify sender owns the token
    std::string error;
    if (!CheckTokenOwnership(chatMsg.senderAddress, chatMsg.token, error)) {
        throw JSONRPCError(RPC_VERIFY_ERROR,
                          strprintf("Sender verification failed: %s", error));
    }

    // Add to pool (no signature skip - always verify)
    if (!pDepinMsgPool->AddMessage(chatMsg, error, false)) {
        throw JSONRPCError(RPC_MISC_ERROR, strprintf("Failed to add message: %s", error));
    }

    LogPrintf("depinsubmitmsg: Added message from %s, hash=%s\n",
              chatMsg.senderAddress, chatMsg.GetHash().ToString());

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("result", "success"));
    result.push_back(Pair("hash", chatMsg.GetHash().ToString()));
    result.push_back(Pair("timestamp", chatMsg.timestamp));

    return result;
}

UniValue depingetmsg(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3)
        throw std::runtime_error(
                "depingetmsg \"token\" (\"ip\") (port)\n"
                "\nRetrieve and decrypt DePIN messages for your addresses\n"
                "\nArguments:\n"
                "1. \"token\"        (string, required) Token name\n"
                "2. \"ip\"           (string, optional) IP address of remote node (default: local)\n"
                "3. port           (numeric, optional) Port of remote DePIN messaging server (default: 19002)\n"
                "\nResult:\n"
                "[\n"
                "  {\n"
                "    \"sender\": \"address\",         (string) Sender address\n"
                "    \"message\": \"text\",           (string) Decrypted message\n"
                "    \"timestamp\": n,              (numeric) Unix timestamp\n"
                "    \"date\": \"YYYY-MM-DD HH:MM:SS\", (string) Formatted date\n"
                "    \"expires\": \"YYYY-MM-DD HH:MM:SS\" (string) Expiration date\n"
                "  },\n"
                "  ...\n"
                "]\n"
                "\nExamples:\n"
                + HelpExampleCli("depingetmsg", "\"MYTOKEN\"")
                + HelpExampleCli("depingetmsg", "\"MYTOKEN\" \"192.168.1.78\"")
                + HelpExampleCli("depingetmsg", "\"MYTOKEN\" \"192.168.1.78\" 19002")
                + HelpExampleRpc("depingetmsg", "\"MYTOKEN\"")
        );

    std::string token = request.params[0].get_str();
    std::string ipAddress;
    int port = DEFAULT_DEPIN_MSG_PORT;
    bool isRemoteQuery = false;

    // Check if this is a remote query
    if (request.params.size() >= 2) {
        ipAddress = request.params[1].get_str();
        isRemoteQuery = true;

        if (request.params.size() >= 3) {
            port = request.params[2].get_int();
            if (port <= 0 || port > 65535) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid port number");
            }
        }
    }

    // Si es consulta remota, hacer petición al nodo remoto
    if (isRemoteQuery) {
        CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
        if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
            return NullUniValue;
        }

        LOCK2(cs_main, pwallet->cs_wallet);
        EnsureWalletIsUnlocked(pwallet);

        // Get local addresses that own the token
        std::set<std::string> myAddresses;
        std::map<std::string, std::vector<COutput>> mapAssetCoins;
        pwallet->AvailableAssets(mapAssetCoins);

        if (mapAssetCoins.count(token)) {
            for (const auto& out : mapAssetCoins[token]) {
                CTxDestination dest;
                if (ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, dest)) {
                    myAddresses.insert(EncodeDestination(dest));
                }
            }
        }

        if (myAddresses.empty()) {
            throw JSONRPCError(RPC_WALLET_ERROR,
                              strprintf("Wallet does not own any %s tokens", token));
        }

        // Query remote node
        std::vector<CDepinMessage> remoteMessages;
        std::string error;
        std::vector<std::string> addressList(myAddresses.begin(), myAddresses.end());

        if (!QueryRemoteDepinMsgPool(pwallet, ipAddress, port, token, addressList, remoteMessages, error)) {
            throw JSONRPCError(RPC_MISC_ERROR, error);
        }

        // Decrypt received messages
        UniValue result(UniValue::VARR);

        for (const CDepinMessage& msg : remoteMessages) {
            // Try to decrypt with each owned address
            bool decrypted = false;
            for (const std::string& myAddress : myAddresses) {
                std::string decryptedMessage;
                std::string decryptError;

                // ECIES shared message contains an AES key encrypted for each holder
                // DecryptMessageForAddress will find and decrypt the key for myAddress
                if (DecryptMessageForAddress(msg.encryptedPayload, myAddress, decryptedMessage, decryptError)) {
                    UniValue msgObj(UniValue::VOBJ);
                    msgObj.push_back(Pair("recipient", myAddress));
                    msgObj.push_back(Pair("sender", msg.senderAddress));
                    msgObj.push_back(Pair("message", decryptedMessage));
                    msgObj.push_back(Pair("timestamp", msg.timestamp));
                    msgObj.push_back(Pair("date", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", msg.timestamp)));
                    msgObj.push_back(Pair("expires", DateTimeStrFormat("%Y-%m-%d %H:%M:%S",
                                                                       msg.timestamp + DEPIN_MESSAGE_EXPIRY_TIME)));
                    result.push_back(msgObj);
                    decrypted = true;
                    break;  // Only add once per message
                }
            }
            if (!decrypted) {
                LogPrintf("Warning: Could not decrypt message from %s with any owned address\n", msg.senderAddress);
            }
        }

        return result;
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

    // Verify token
    if (token != pDepinMsgPool->GetActiveToken()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                          strprintf("Token '%s' does not match configured token '%s'",
                                   token, pDepinMsgPool->GetActiveToken()));
    }

    // Get all wallet addresses that own the token
    std::set<std::string> myAddresses;
    std::map<std::string, std::vector<COutput>> mapAssetCoins;
    pwallet->AvailableAssets(mapAssetCoins);

    if (mapAssetCoins.count(token)) {
        for (const auto& out : mapAssetCoins[token]) {
            CTxDestination dest;
            if (ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, dest)) {
                myAddresses.insert(EncodeDestination(dest));
            }
        }
    }

    if (myAddresses.empty()) {
        throw JSONRPCError(RPC_WALLET_ERROR,
                          strprintf("Wallet does not own any %s tokens", token));
    }

    UniValue result(UniValue::VARR);

    // Get ALL messages from pool (we no longer need to filter by address)
    std::vector<CDepinMessage> allMessages = pDepinMsgPool->GetAllMessages();
    std::set<uint256> processedMessages;  // To avoid duplicates

    for (const CDepinMessage& msg : allMessages) {
        // Avoid processing the same message multiple times
        uint256 msgHash = msg.GetHash();
        if (processedMessages.count(msgHash)) {
            continue;
        }

        // Try to decrypt with each owned address
        bool decrypted = false;
        for (const std::string& myAddress : myAddresses) {
            std::string decryptedMessage;
            std::string error;

            // ECIES shared message contains an AES key encrypted for each holder
            // DecryptMessageForAddress will find and decrypt the key for myAddress
            if (DecryptMessageForAddress(msg.encryptedPayload, myAddress, decryptedMessage, error)) {
                UniValue msgObj(UniValue::VOBJ);
                msgObj.push_back(Pair("recipient", myAddress));
                msgObj.push_back(Pair("sender", msg.senderAddress));
                msgObj.push_back(Pair("message", decryptedMessage));
                msgObj.push_back(Pair("timestamp", msg.timestamp));
                msgObj.push_back(Pair("date", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", msg.timestamp)));
                msgObj.push_back(Pair("expires", DateTimeStrFormat("%Y-%m-%d %H:%M:%S",
                                                                   msg.timestamp + DEPIN_MESSAGE_EXPIRY_TIME)));
                result.push_back(msgObj);
                processedMessages.insert(msgHash);
                decrypted = true;
                break;  // Only add once per message
            }
        }
    }

    return result;
}

UniValue depinclearmsg(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
                "depinclearmsg\n"
                "\nRemove all expired messages from DePIN messaging system\n"
                "\nResult:\n"
                "{\n"
                "  \"removed\": n,        (numeric) Number of messages removed\n"
                "  \"remaining\": n       (numeric) Number of messages remaining\n"
                "}\n"
                "\nExamples:\n"
                + HelpExampleCli("depinclearmsg", "")
                + HelpExampleRpc("depinclearmsg", "")
        );

    if (!pDepinMsgPool || !pDepinMsgPool->IsEnabled()) {
        throw JSONRPCError(RPC_MISC_ERROR, "DePIN messaging pool is not enabled");
    }

    size_t sizeBefore = pDepinMsgPool->Size();
    pDepinMsgPool->RemoveExpiredMessages(GetTime());
    size_t sizeAfter = pDepinMsgPool->Size();

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("removed", (int)(sizeBefore - sizeAfter)));
    result.push_back(Pair("remaining", (int)sizeAfter));

    return result;
}
#endif // ENABLE_WALLET

UniValue depingetpoolcontent(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 7)
        throw std::runtime_error(
            "depingetpoolcontent ( verbose sender_address recipient_address start_time end_time limit offset )\n"
            "\nInspect the contents of the DePIN message pool.\n"
            "\nArguments:\n"
            "1. verbose           (boolean, \"all\", or \"raw\", optional, default=false) Show detailed message structure. Use \"all\" for all messages, \"raw\" to show encrypted hex data\n"
            "2. sender_address    (string, optional) Filter by sender address\n"
            "3. recipient_address (string, optional) Filter by recipient address\n"
            "4. start_time        (numeric, optional) Filter messages after timestamp\n"
            "5. end_time          (numeric, optional) Filter messages before timestamp\n"
            "6. limit             (numeric, optional, default=100) Maximum messages to return\n"
            "7. offset            (numeric, optional, default=0) Skip first N messages\n"
            "\nResult (verbose=false):\n"
            "[\n"
            "  {\n"
            "    \"hash\": \"hex\",\n"
            "    \"sender\": \"address\",\n"
            "    \"timestamp\": n,\n"
            "    \"date\": \"YYYY-MM-DD HH:MM:SS\",\n"
            "    \"expires\": \"YYYY-MM-DD HH:MM:SS\",\n"
            "    \"recipients\": n,\n"
            "    \"size\": n\n"
            "  },\n"
            "  ...\n"
            "]\n"
            "\nResult (verbose=true):\n"
            "[\n"
            "  {\n"
            "    \"hash\": \"hex\",\n"
            "    \"sender\": \"address\",\n"
            "    \"timestamp\": n,\n"
            "    \"date\": \"YYYY-MM-DD HH:MM:SS\",\n"
            "    \"expires\": \"YYYY-MM-DD HH:MM:SS\",\n"
            "    \"recipients\": [\n"
            "      {\n"
            "        \"address\": \"address\",\n"
            "        \"encrypted_size\": n\n"
            "      },\n"
            "      ...\n"
            "    ],\n"
            "    \"signature_size\": n,\n"
            "    \"total_encrypted_size\": n,\n"
            "    \"total_size\": n\n"
            "  },\n"
            "  ...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("depingetpoolcontent", "")
            + HelpExampleCli("depingetpoolcontent", "true")
            + HelpExampleCli("depingetpoolcontent", "all")
            + HelpExampleCli("depingetpoolcontent", "raw")
            + HelpExampleCli("depingetpoolcontent", "false \"NXXaddress...\"")
            + HelpExampleRpc("depingetpoolcontent", "true")
        );

    // Check if DePIN pool is enabled
    if (!pDepinMsgPool || !pDepinMsgPool->IsEnabled()) {
        throw JSONRPCError(RPC_MISC_ERROR, "DePIN message pool is not enabled");
    }

    // Parse parameters
    bool fVerbose = false;
    bool fShowAll = false;
    bool fShowRaw = false;
    std::string senderFilter = "";
    std::string recipientFilter = "";
    int64_t startTime = 0;
    int64_t endTime = std::numeric_limits<int64_t>::max();
    int limit = 100;
    int offset = 0;

    if (request.params.size() > 0 && !request.params[0].isNull()) {
        if (request.params[0].isBool()) {
            fVerbose = request.params[0].get_bool();
        } else if (request.params[0].isNum()) {
            fVerbose = request.params[0].get_int() != 0;
        } else if (request.params[0].isStr()) {
            std::string val = request.params[0].get_str();
            if (val == "all") {
                fVerbose = true;
                fShowAll = true;
                limit = std::numeric_limits<int>::max();
            } else if (val == "raw") {
                fVerbose = true;
                fShowRaw = true;
            } else {
                fVerbose = (val == "true" || val == "1");
            }
        }
    }
    if (request.params.size() > 1) senderFilter = request.params[1].get_str();
    if (request.params.size() > 2) recipientFilter = request.params[2].get_str();
    if (request.params.size() > 3) startTime = request.params[3].get_int64();
    if (request.params.size() > 4) endTime = request.params[4].get_int64();
    if (request.params.size() > 5 && !fShowAll) limit = request.params[5].get_int();
    if (request.params.size() > 6 && !fShowAll) offset = request.params[6].get_int();

    // Validate limits (unless showing all)
    if (!fShowAll) {
        if (limit < 1) limit = 1;
        if (limit > 1000) limit = 1000;
    }
    if (offset < 0) offset = 0;

    // Get all messages from pool
    std::vector<CDepinMessage> messages = pDepinMsgPool->GetAllMessages();

    // Apply filters and build result
    UniValue result(UniValue::VARR);
    int skipped = 0;
    int added = 0;

    for (const auto& msg : messages) {
        // Filter by sender
        if (!senderFilter.empty() && msg.senderAddress != senderFilter)
            continue;

        // Note: Recipient filtering not available with ECIES shared encryption
        // All holders can potentially decrypt, we can't determine recipients without decryption
        if (!recipientFilter.empty()) {
            // Skip this filter since we use shared ECIES encryption
            LogPrint(BCLog::RPC, "Warning: Recipient filtering not supported with ECIES shared encryption\n");
        }

        // Filter by time range
        if (msg.timestamp < startTime || msg.timestamp > endTime)
            continue;

        // Apply offset
        if (skipped < offset) {
            skipped++;
            continue;
        }

        // Apply limit
        if (added >= limit)
            break;

        // Build message object
        UniValue msgObj(UniValue::VOBJ);
        msgObj.push_back(Pair("hash", msg.GetHash().GetHex()));
        msgObj.push_back(Pair("sender", msg.senderAddress));
        msgObj.push_back(Pair("timestamp", msg.timestamp));
        msgObj.push_back(Pair("date", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", msg.timestamp)));
        msgObj.push_back(Pair("expires", DateTimeStrFormat("%Y-%m-%d %H:%M:%S",
                                                    msg.timestamp + DEPIN_MESSAGE_EXPIRY_TIME)));

        if (fVerbose) {
            // Verbose mode: show ECIES shared encryption details
            msgObj.push_back(Pair("encryption_type", "ECIES_shared"));
            msgObj.push_back(Pair("encrypted_payload_size", (int)msg.encryptedPayload.size()));
            msgObj.push_back(Pair("signature_size", (int)msg.signature.size()));

            // If raw mode, show the encrypted payload and signature in hex
            if (fShowRaw) {
                msgObj.push_back(Pair("encrypted_payload_hex", HexStr(msg.encryptedPayload)));
                msgObj.push_back(Pair("signature_hex", HexStr(msg.signature)));
            }

            size_t totalSize = msg.encryptedPayload.size() + msg.signature.size();
            msgObj.push_back(Pair("total_size", (int)totalSize));
        } else {
            // Simple mode: just size
            msgObj.push_back(Pair("encryption_type", "ECIES_shared"));
            size_t totalSize = msg.encryptedPayload.size() + msg.signature.size();
            msgObj.push_back(Pair("size", (int)totalSize));
        }

        result.push_back(msgObj);
        added++;
    }

    return result;
}

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
        int64_t timeToExpiry = (msg.timestamp + DEPIN_MESSAGE_EXPIRY_TIME) - now;
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
            { "depin",          "depingetmsginfo",            &depingetmsginfo,            {}},
            { "depin",          "depingetpoolcontent",        &depingetpoolcontent,        {}},
            { "depin",          "depinpoolstats",             &depinpoolstats,             {}},
            { "depin",          "depinsubmitmsg",             &depinsubmitmsg,             {"hexmessage"}},
#ifdef ENABLE_WALLET
            { "depin",          "depinsendmsg",               &depinsendmsg,               {"token", "ip", "message", "fromaddress", "port"}},
            { "depin",          "depingetmsg",                &depingetmsg,                {"token"}},
            { "depin",          "depinclearmsg",              &depinclearmsg,              {}},
#endif
    };

void RegisterMessageRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
