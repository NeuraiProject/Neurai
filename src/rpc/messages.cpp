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
#include "depinchallenge.h"
#include "depinmcpworker.h"
#include "rpc/mining.h"
#include "rpc/safemode.h"
#include "rpc/server.h"
#include "script/sign.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h" // ParseInt64, used by ParseFlexibleInt64
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

/**
 * Read an integer that may arrive as a JSON number or as a string.
 *
 * neurai-cli hands every argument over as a string unless the method is listed
 * in vRPCConvertParams (rpc/client.cpp). One DePIN parameter cannot be listed
 * there -- depinclearmsg's `mode` accepts a word ("all") as well as a number,
 * and the conversion layer throws on any argument that is not valid JSON -- so
 * its numeric form has to be recognised here instead.
 *
 * Acceptance is strict: ParseInt64() rejects empty strings, padding, embedded
 * NULs and trailing characters, so "7x", " 7" and "1.5" stay errors rather than
 * silently becoming 7. Callers decide what a rejection means; this function
 * only reports it.
 */
static bool ParseFlexibleInt64(const UniValue& value, int64_t& out)
{
    if (value.isNum()) {
        out = value.get_int64();
        return true;
    }
    if (value.isStr()) {
        return ParseInt64(value.get_str(), &out);
    }
    return false;
}

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
                "  \"protocol\": 2,                  (numeric) DePIN RPC protocol version\n"
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
    obj.push_back(Pair("protocol", DEPIN_RPC_PROTOCOL_VERSION));
    CKey poolKey;
    CPubKey poolPubKey;
    if (GetDepinPoolKey(poolKey, poolPubKey)) {
        obj.push_back(Pair("depinpoolpkey", HexStr(poolPubKey.begin(), poolPubKey.end())));
        obj.push_back(Pair("depinpoolkeyaddress", EncodeDestination(poolPubKey.GetID())));
        obj.push_back(Pair("depinwallet", GetDepinPoolKeyWalletName()));
    }

    return FinishDepinResponse(obj, "depingetmsginfo", pDepinMsgPool->GetActiveToken(), "", "", nullptr);
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
    // one flush, freeze/self-revoke respected, missing pubkeys skipped and
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

    if (!pDepinMsgPool->AddMessage(chatMsg, error, /*skipSignatureCheck=*/false)) {
        throw JSONRPCError(RPC_MISC_ERROR, strprintf("Failed to add message: %s", error));
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

UniValue depinchallenge(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 4 || request.params.size() > 5)
        throw std::runtime_error(
                "depinchallenge \"token\" \"address\" timestamp \"signature\" ( \"type\" )\n"
                "\nIssue a single-use challenge proving control of a holder's address to the\n"
                "authenticated DePIN RPCs (depinreceivemsg, depinlistsections, depinclearmsg).\n"
                "\nThe request itself is signed by the address, over the current time in\n"
                "milliseconds:\n"
                "  \"DEPIN-REQ|receive|<token>|<address>|<timestamp>\"   (or \"admin\")\n"
                "with signmessage, or depinsignrequest on a node holding the key. Accepted only\n"
                "within " + std::to_string(DEPIN_REQUEST_WINDOW_MS / 1000) + " s of the node's clock and never twice: a request forged in\n"
                "someone else's name is refused before it touches that address's quota or\n"
                "its live challenges.\n"
                "\nThe reply is encrypted for the address's revealed public key, so only its\n"
                "owner can read the nonce. Within " + std::to_string(DEPIN_CHALLENGE_TIMEOUT) + " seconds, sign\n"
                "  \"DEPIN-GET|<token>|<address>|<nonce>\"    (type receive)\n"
                "  \"DEPIN-CLEAR|<token>|<address>|<nonce>\"  (type admin)\n"
                "(signmessage or depinsignchallenge) and pass nonce and signature to the RPC.\n"
                "A nonce is bound to token, address and type, is consumed by its first valid\n"
                "use, and expires otherwise. Only a holder gets one: the access checks run\n"
                "before anything is issued. Issuance is limited per address and minute\n"
                "(-depinratelimit), counting only the address's own signed requests.\n"
                "Authenticated replies carry a next_challenge, so a client that keeps reading\n"
                "needs this call only once.\n"
                "\nArguments:\n"
                "1. \"token\"      (string, required) Pool root or a section inside it\n"
                "2. \"address\"    (string, required) Holder address (P2PKH with its public key revealed on chain)\n"
                "3. timestamp    (numeric, required) Unix time in MILLISECONDS the request was signed at\n"
                "4. \"signature\"  (string, required) Base64 signature of \"DEPIN-REQ|<type>|<token>|<address>|<timestamp>\"\n"
                "5. \"type\"       (string, optional, default=receive) \"receive\": holder of the token or an ancestor;\n"
                "                 \"admin\": owner of the token or an ancestor (for depinclearmsg)\n"
                "\nResult (encrypted for the address, plus poolsig; decrypted content):\n"
                "{\n"
                "  \"challenge\": \"hex\",    (string) 64-hex nonce\n"
                "  \"expires_in\": n,        (numeric) Seconds until it expires\n"
                "  \"type\": \"receive\"      (string) Challenge type\n"
                "}\n"
                "\nExamples:\n"
                + HelpExampleCli("depinchallenge", "\"&MYTOKEN/SEC\" \"NXholder...\" 1730000000000 \"<signature>\"")
                + HelpExampleCli("depinchallenge", "\"&MYTOKEN\" \"NXowner...\" 1730000000000 \"<signature>\" \"admin\"")
                + HelpExampleRpc("depinchallenge", "\"&MYTOKEN/SEC\", \"NXholder...\", 1730000000000, \"<signature>\"")
        );

    if (!pDepinMsgPool || !pDepinMsgPool->IsEnabled()) {
        throw JSONRPCError(RPC_MISC_ERROR, "DePIN messaging pool is not enabled");
    }

    const std::string token = request.params[0].get_str();
    const std::string address = request.params[1].get_str();
    const int64_t timestamp = request.params[2].get_int64();
    const std::string requestSignature = request.params[3].get_str();
    DepinChallengeType type = DepinChallengeType::RECEIVE;
    if (request.params.size() >= 5 && !request.params[4].isNull() && !request.params[4].get_str().empty()) {
        if (!ParseDepinChallengeType(request.params[4].get_str(), type)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "type must be \"receive\" or \"admin\"");
        }
    }

    // 1. The requester proves it IS the address, without touching state:
    //    window and signature.
    std::string error;
    if (!CheckDepinChallengeRequestAuth(type, token, address, timestamp, requestSignature,
                                        DepinRequestClockMillis(), error)) {
        throw JSONRPCError(RPC_INVALID_REQUEST, strprintf("Request authentication failed: %s", error));
    }

    // 2. Validate the revealed key and access before recording the request:
    //    otherwise arbitrary valid signatures from non-holders could fill the
    //    global replay guard and deny service to real holders.
    CPubKey pubkey;
    if (!CheckDepinChallengeRequest(token, address, type, pDepinMsgPool->GetActiveToken(), pubkey, error)) {
        throw JSONRPCError(RPC_INVALID_REQUEST, error);
    }

    // 3. Atomically reject a replay only after it is a request a holder could
    //    actually use. A duplicate cannot reach the quota or evict a nonce.
    if (!g_depinRequestGuard.Remember(requestSignature, DepinRequestClockMillis(),
                                      2 * DEPIN_REQUEST_WINDOW_MS, error)) {
        throw JSONRPCError(RPC_INVALID_REQUEST, strprintf("Request authentication failed: %s", error));
    }

    // 4. Count, 5. issue.
    if (!g_depinRateLimiter.Allow("challenge|" + address, GetTime())) {
        throw JSONRPCError(RPC_MISC_ERROR,
                           strprintf("Rate limited: more than %u challenges for this address in the last minute",
                                     g_depinRateLimiter.GetLimit()));
    }

    const std::string nonce = g_depinChallenges.Issue(token, address, type, error);
    if (nonce.empty()) {
        throw JSONRPCError(RPC_MISC_ERROR, error);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("challenge", nonce));
    result.push_back(Pair("expires_in", (int)DEPIN_CHALLENGE_TIMEOUT));
    result.push_back(Pair("type", DepinChallengeTypeName(type)));
    return FinishDepinResponse(result, "depinchallenge", token, address, "", &pubkey);
}

#ifdef ENABLE_WALLET
UniValue depinsignchallenge(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 4)
        throw std::runtime_error(
                "depinsignchallenge \"address\" \"token\" \"challenge\" ( \"type\" )\n"
                "\nSign a DePIN challenge with a wallet key: the client half of depinchallenge.\n"
                "Equivalent to signmessage over \"DEPIN-GET|token|address|challenge\" (receive)\n"
                "or \"DEPIN-CLEAR|token|address|challenge\" (admin).\n"
                "\nArguments:\n"
                "1. \"address\"    (string, required) Wallet address the challenge was issued to\n"
                "2. \"token\"      (string, required) Token the challenge was issued for\n"
                "3. \"challenge\"  (string, required) The nonce (decrypted depinchallenge reply)\n"
                "4. \"type\"       (string, optional, default=receive) \"receive\" or \"admin\"\n"
                "\nResult:\n"
                "{\n"
                "  \"signature\": \"base64\",  (string) Compact signature to pass to the RPC\n"
                "  \"preimage\": \"text\"      (string) What was signed\n"
                "}\n"
                "\nExamples:\n"
                + HelpExampleCli("depinsignchallenge", "\"NXholder...\" \"&MYTOKEN/SEC\" \"<nonce>\"")
                + HelpExampleRpc("depinsignchallenge", "\"NXowner...\", \"&MYTOKEN\", \"<nonce>\", \"admin\"")
        );

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    const std::string address = request.params[0].get_str();
    const std::string token = request.params[1].get_str();
    const std::string challenge = request.params[2].get_str();
    DepinChallengeType type = DepinChallengeType::RECEIVE;
    if (request.params.size() >= 4 && !request.params[3].isNull() && !request.params[3].get_str().empty()) {
        if (!ParseDepinChallengeType(request.params[3].get_str(), type)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "type must be \"receive\" or \"admin\"");
        }
    }

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);

    std::string signature;
    std::string error;
    if (!SignDepinChallenge(pwallet, address, token, challenge, signature, error, type)) {
        throw JSONRPCError(RPC_WALLET_ERROR, error);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("signature", signature));
    result.push_back(Pair("preimage", DepinChallengePreimage(type, token, address, challenge)));
    return result;
}

UniValue depinsignrequest(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
        throw std::runtime_error(
                "depinsignrequest \"address\" \"token\" ( \"type\" )\n"
                "\nSign a depinchallenge request with a wallet key, over the current time in\n"
                "milliseconds: the client half of asking for a challenge. Equivalent to\n"
                "signmessage over \"DEPIN-REQ|<type>|<token>|<address>|<timestamp>\".\n"
                "\nArguments:\n"
                "1. \"address\"  (string, required) Wallet address to request the challenge for\n"
                "2. \"token\"    (string, required) Token the challenge will be bound to\n"
                "3. \"type\"     (string, optional, default=receive) \"receive\" or \"admin\"\n"
                "\nResult:\n"
                "{\n"
                "  \"timestamp\": n,          (numeric) Unix ms signed (pass it to depinchallenge)\n"
                "  \"signature\": \"base64\",  (string) Compact signature to pass to depinchallenge\n"
                "  \"preimage\": \"text\"      (string) What was signed\n"
                "}\n"
                "\nExamples:\n"
                + HelpExampleCli("depinsignrequest", "\"NXholder...\" \"&MYTOKEN/SEC\"")
                + HelpExampleRpc("depinsignrequest", "\"NXowner...\", \"&MYTOKEN\", \"admin\"")
        );

    CWallet * const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    const std::string address = request.params[0].get_str();
    const std::string token = request.params[1].get_str();
    DepinChallengeType type = DepinChallengeType::RECEIVE;
    if (request.params.size() >= 3 && !request.params[2].isNull() && !request.params[2].get_str().empty()) {
        if (!ParseDepinChallengeType(request.params[2].get_str(), type)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "type must be \"receive\" or \"admin\"");
        }
    }

    const CTxDestination dest = DecodeDestination(address);
    const CKeyID* keyID = boost::get<CKeyID>(&dest);
    if (!IsValidDestination(dest) || !keyID) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);

    CKey key;
    if (!pwallet->GetKey(*keyID, key)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Private key for %s not in wallet", address));
    }

    const int64_t timestamp = DepinRequestClockMillis();
    const std::string preimage = DepinChallengeRequestPreimage(type, token, address, timestamp);
    std::string signature;
    std::string error;
    if (!SignDepinChallengePreimage(key, preimage, signature, error)) {
        throw JSONRPCError(RPC_WALLET_ERROR, error);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("timestamp", timestamp));
    result.push_back(Pair("signature", signature));
    result.push_back(Pair("preimage", preimage));
    return result;
}

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
    const std::string encryptedHex = request.params[1].get_str();

    const CTxDestination dest = DecodeDestination(address);
    const CKeyID* keyID = boost::get<CKeyID>(&dest);
    if (!IsValidDestination(dest) || !keyID) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }
    if (!IsHex(encryptedHex)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "encrypted must be hex");
    }

    LOCK2(cs_main, pwallet->cs_wallet);
    EnsureWalletIsUnlocked(pwallet);

    CKey key;
    if (!pwallet->GetKey(*keyID, key)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Private key for %s not in wallet", address));
    }

    CECIESEncryptedMessage ecies;
    try {
        CDataStream ss(ParseHex(encryptedHex), SER_NETWORK, PROTOCOL_VERSION);
        ss >> ecies;
    } catch (const std::exception& e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Failed to deserialize encrypted reply: %s", e.what()));
    }

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
UniValue depinsubmitmsg(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
                "depinsubmitmsg {\"sender\":\"...\",\"encrypted\":\"...\"}\n"
                "\nSubmit a pre-encrypted and signed DePIN message to the pool\n"
                "\nThe client prepares the complete message (recipient encryption + signature),\n"
                "serializes it and wraps the hex in an ECIES envelope for the pool key\n"
                "(depingetmsginfo.depinpoolpkey); the node opens the envelope, validates and\n"
                "stores. The envelope is mandatory: there is no bare-hex form. The sender must\n"
                "have revealed its public key on chain, and the reply is encrypted for it.\n"
                "\nArguments:\n"
                "1. {                  (json object, required) Wrapped encrypted message\n"
                "     \"sender\": \"...\", (string, required) Sender address\n"
                "     \"encrypted\": \"...\" (string, required) Hex-encoded ECIES wrapper\n"
                "   }\n"
                "\nResult:\n"
                "{\n"
                "  \"encrypted\": \"hex\",            (string) ECIES blob for the sender's revealed public key\n"
                "  \"poolsig\": \"base64\"            (string) Pool-key signature over the encrypted hex\n"
                "}\n"
                "Decrypted, \"encrypted\" contains:\n"
                "{\n"
                "  \"result\": \"success\",           (string) Status\n"
                "  \"hash\": \"hash\",                (string) Message hash\n"
                "  \"timestamp\": n                  (numeric) Unix timestamp\n"
                "}\n"
                "\nExamples:\n"
                + HelpExampleCli("depinsubmitmsg", "'{\"sender\":\"NX...\",\"encrypted\":\"...\"}'")
                + HelpExampleRpc("depinsubmitmsg", "{\"sender\":\"NX...\",\"encrypted\":\"...\"}")
        );

    if (!pDepinMsgPool || !pDepinMsgPool->IsEnabled()) {
        throw JSONRPCError(RPC_MISC_ERROR, "DePIN messaging pool is not enabled");
    }

    // Only the wrapped form exists: the serialized message travels inside an
    // ECIES envelope for the pool key, so an RPC proxy in between sees neither
    // the sender's recipient list nor the payload.
    if (!request.params[0].isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                          "depinsubmitmsg expects {\"sender\": address, \"encrypted\": hex}: wrap the "
                          "serialized message for the pool key (depingetmsginfo.depinpoolpkey)");
    }
    const UniValue& wrapped = request.params[0].get_obj();
    if (!wrapped.exists("sender") || !wrapped.exists("encrypted")) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Wrapped message must contain 'sender' and 'encrypted'");
    }
    const std::string wrappedSender = wrapped["sender"].get_str();
    const std::string encryptedHex = wrapped["encrypted"].get_str();

    CKey poolPrivKey;
    CPubKey poolPubKey;
    if (!GetDepinPoolKey(poolPrivKey, poolPubKey)) {
        throw JSONRPCError(RPC_MISC_ERROR, "DePIN pool key not loaded: the service is not available on this node");
    }

    if (!IsHex(encryptedHex)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Encrypted data must be hex-encoded");
    }

    CECIESEncryptedMessage eciesMsg;
    try {
        CDataStream ss(ParseHex(encryptedHex), SER_NETWORK, PROTOCOL_VERSION);
        ss >> eciesMsg;
    } catch (const std::exception& e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, strprintf("Failed to deserialize ECIES wrapper: %s", e.what()));
    }

    std::string hexMessage;
    std::string decryptError;
    if (!ECIESDecryptMessage(eciesMsg, poolPrivKey, EncodeDestination(poolPubKey.GetID()), hexMessage, decryptError)) {
        throw JSONRPCError(RPC_VERIFY_ERROR, strprintf("Failed to decrypt outer privacy shell: %s", decryptError));
    }

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

    // Verify the token is the configured token or a section inside its
    // subtree. Exact equality here used to reject section messages before they
    // ever reached AddMessage; the subtree check keeps the fast rejection for
    // foreign tokens without blocking sections.
    if (!IsDepinSectionOrRoot(chatMsg.token, pDepinMsgPool->GetActiveToken())) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                          strprintf("Token '%s' is not configured token '%s' or a section inside it",
                                   chatMsg.token, pDepinMsgPool->GetActiveToken()));
    }

    // The envelope's sender is who the reply is encrypted for; it must be the
    // address that signed the message inside.
    if (wrappedSender != chatMsg.senderAddress) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                          strprintf("Envelope sender %s does not match the signed message sender %s",
                                   wrappedSender, chatMsg.senderAddress));
    }

    // The reply is encrypted for the sender, so the sender must have revealed
    // its public key (the signature check below needs it anyway). Refused
    // here, before anything is verified or stored: there is no plaintext
    // fallback.
    CPubKey senderPubKey;
    std::string pubkeyError;
    if (!CheckAddressHasPublicKey(chatMsg.senderAddress, senderPubKey, pubkeyError)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                          strprintf("Sender has no revealed public key, and responses are always encrypted: %s",
                                   pubkeyError));
    }

    // ALWAYS verify signature (critical security check)
    if (!VerifyDepinMessageSignature(chatMsg)) {
        throw JSONRPCError(RPC_VERIFY_ERROR,
                          strprintf("Invalid message signature for sender %s. "
                                   "Check debug.log for details.",
                                   chatMsg.senderAddress));
    }

    // Verify sender has active inherited access to the message's token (a
    // balance-only check would let frozen or self-revoked holders through).
    // AddMessage repeats this authoritatively; this pre-check exists to return
    // a verification-class error instead of a generic pool failure.
    std::string error;
    if (!HasDepinSectionAccess(chatMsg.senderAddress, chatMsg.token,
                               pDepinMsgPool->GetActiveToken(), error)) {
        throw JSONRPCError(RPC_VERIFY_ERROR,
                          strprintf("Sender verification failed: %s", error));
    }

    // Rate limit only now, with key, signature and access verified: anyone
    // can build an envelope for the pool key that names a victim as sender,
    // and counting it earlier would let that forgery spend the victim's quota.
    if (!g_depinRateLimiter.Allow("submit|" + chatMsg.senderAddress, GetTime())) {
        throw JSONRPCError(RPC_MISC_ERROR,
                           strprintf("Rate limited: more than %u messages from this address in the last minute",
                                     g_depinRateLimiter.GetLimit()));
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

    // Encrypted for the sender, whose key was resolved above.
    return FinishDepinResponse(result, "depinsubmitmsg", chatMsg.token, chatMsg.senderAddress, "", &senderPubKey);
}

// New non-wallet endpoint: retrieves encrypted pool messages (no decryption)
UniValue depinreceivemsg(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 4 || request.params.size() > 7)
        throw std::runtime_error(
                "depinreceivemsg \"token\" \"address\" \"challenge\" \"signature\" ( timestamp \"after_hash\" limit )\n"
                "\nRetrieve a holder's DePIN messages from the pool, with optional pagination\n"
                "\nThe caller proves control of the address with a challenge from depinchallenge\n"
                "(type receive) signed by that address. The reply is always encrypted for the\n"
                "address's revealed public key and signed with the pool key (poolsig over\n"
                "\"DEPIN-RESP|depinreceivemsg|<token>|<address>|<challenge>|<sha256 of the encrypted hex>\").\n"
                "\nArguments:\n"
                "1. \"token\"      (string, required) Token name (pool root or a section inside it)\n"
                "2. \"address\"    (string, required) Holder address (access selector and encryption target)\n"
                "3. \"challenge\"  (string, required) Nonce from depinchallenge, issued for this token and address\n"
                "4. \"signature\"  (string, required) Base64 signature of \"DEPIN-GET|<token>|<address>|<challenge>\"\n"
                "5. timestamp    (numeric, optional) Unix time. Return only messages with timestamp >= (timestamp-1 if timestamp>0)\n"
                "6. \"after_hash\" (string, optional) Hash of last received message for pagination. Empty \"\" starts from beginning\n"
                "7. limit        (numeric, optional) Maximum messages to return. 0 or omitted = no limit (return all)\n"
                "\nResult (decrypted content of \"encrypted\"):\n"
                "{\n"
                "  \"messages\": [                   (array) Messages, oldest first\n"
                "  {\n"
                "    \"hash\": \"...\",                 (string) Message hash\n"
                "    \"token\": \"...\",                (string) Token\n"
                "    \"sender\": \"...\",               (string) Sender address\n"
                "    \"timestamp\": n,                 (numeric) Unix timestamp\n"
                "    \"message_type\": \"private|group\", (string) Message type (private=1-to-1, group=broadcast)\n"
                "    \"encrypted_payload_hex\": \"...\", (string) Encrypted payload (hex)\n"
                "    \"signature_hex\": \"...\"         (string) Message signature (hex)\n"
                "  },\n"
                "  ...\n"
                "  ],\n"
                "  \"has_more\": true|false,         (boolean) More messages available (only meaningful with limit)\n"
                "  \"next_challenge\": \"hex\",       (string) Next nonce for this token and address, valid " + std::to_string(DEPIN_CHAINED_CHALLENGE_TIMEOUT) + " s:\n"
                "                                   sign it for the next call instead of calling depinchallenge\n"
                "  \"next_expires_in\": n            (numeric) Seconds the next challenge lives\n"
                "}\n"
                "\nThe reply itself is {\"encrypted\": hex, \"poolsig\": base64}: the object above is\n"
                "what \"encrypted\" decrypts to with the address's key.\n"
                "\nExamples:\n"
                + HelpExampleCli("depinreceivemsg", "\"&TOKEN\" \"NXaddress\" \"<challenge>\" \"<signature>\"")
                + HelpExampleCli("depinreceivemsg", "\"&TOKEN\" \"NXaddress\" \"<challenge>\" \"<signature>\" 0 \"\" 5")
                + HelpExampleRpc("depinreceivemsg", "\"&TOKEN\", \"NXaddress\", \"<challenge>\", \"<signature>\", 0, \"\", 5")
        );

    if (!pDepinMsgPool || !pDepinMsgPool->IsEnabled()) {
        throw JSONRPCError(RPC_MISC_ERROR, "DePIN messaging pool is not enabled");
    }

    const std::string token = request.params[0].get_str();
    const std::string address = request.params[1].get_str();

    // The token may be a section inside the configured subtree; it then acts
    // as the tab scope below. The challenge proves control of the address;
    // what the address can actually read is fixed cryptographically by
    // recipientKeys + ECIES regardless.
    if (!IsDepinSectionOrRoot(token, pDepinMsgPool->GetActiveToken())) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                          strprintf("Token '%s' is not configured token '%s' or a section inside it",
                                   token, pDepinMsgPool->GetActiveToken()));
    }

    // Validate address (network + base58)
    const CTxDestination dest = DecodeDestination(address);
    if (!IsValidDestination(dest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    // Responses are always encrypted for the requesting address, so it must
    // have revealed its public key on chain (the same condition it needs to
    // receive messages at all).
    CPubKey clientPubKey;
    std::string pubkeyError;
    if (!CheckAddressHasPublicKey(address, clientPubKey, pubkeyError)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                          strprintf("Address has no revealed public key, and responses are always encrypted: %s",
                                   pubkeyError));
    }

    // Proof of control: form, existence, signature, access re-check, consume
    // (in that order; see CheckDepinChallengeAuth).
    const std::string challenge = request.params[2].get_str();
    const std::string signature = request.params[3].get_str();
    std::string authError;
    if (!CheckDepinChallengeAuth(DepinChallengeType::RECEIVE, token, address, challenge, signature,
                                 pDepinMsgPool->GetActiveToken(), authError)) {
        throw JSONRPCError(RPC_INVALID_REQUEST, strprintf("Challenge authentication failed: %s", authError));
    }

    int64_t fromTimestamp = 0;
    if (request.params.size() >= 5 && !request.params[4].isNull()) {
        fromTimestamp = request.params[4].get_int64();
        if (fromTimestamp < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "timestamp must be >= 0");
        }
        if (fromTimestamp > 0) {
            fromTimestamp -= 1;
        }
    }

    // Parse after_hash parameter (cursor for pagination)
    std::string afterHash = "";
    if (request.params.size() >= 6 && !request.params[5].isNull()) {
        afterHash = request.params[5].get_str();
        // Validate hash format (64 hex chars)
        if (!afterHash.empty() && !IsHex(afterHash)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "after_hash must be a valid hex string");
        }
        if (!afterHash.empty() && afterHash.length() != 64) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "after_hash must be 64 characters (256-bit hash)");
        }
    }

    // Parse limit parameter
    int64_t limit = 0;  // 0 = no limit
    if (request.params.size() >= 7 && !request.params[6].isNull()) {
        limit = request.params[6].get_int64();
        if (limit < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "limit must be >= 0");
        }
        // Limit maximum to prevent abuse
        if (limit > 1000) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "limit cannot exceed 1000");
        }
    }

    // Fetch pool contents with filtering. Both message types (group and private)
    // are filtered by recipientKeys membership; the sender always sees their own
    // messages. The requested token is the scope: asking for a section returns
    // only that section's subtree, asking for the root returns everything.
    std::vector<CDepinMessage> messages = pDepinMsgPool->GetMessagesForAddress(address, token);

    UniValue resultArray(UniValue::VARR);
    bool foundAnchor = afterHash.empty();  // If no hash, start from beginning
    int64_t totalAvailable = 0;

    // Convert afterHash string to uint256 if provided
    uint256 afterHashObj;
    if (!afterHash.empty()) {
        afterHashObj.SetHex(afterHash);
    }

    for (const CDepinMessage& msg : messages) {
        // Filter 1: Timestamp (existing logic)
        if (msg.timestamp < fromTimestamp) {
            continue;
        }

        totalAvailable++;  // Count messages that pass timestamp filter

        // Filter 2: Pagination cursor (after_hash)
        if (!foundAnchor) {
            if (msg.GetHash() == afterHashObj) {
                foundAnchor = true;  // Found the anchor, NEXT messages go to result
            }
            continue;  // Skip this message and all previous ones
        }

        // Filter 3: Limit (pagination size)
        if (limit > 0 && resultArray.size() >= (size_t)limit) {
            break;  // Already have enough messages
        }

        // Build message JSON object (existing logic)
        UniValue msgObj(UniValue::VOBJ);
        msgObj.push_back(Pair("hash", msg.GetHash().ToString()));
        msgObj.push_back(Pair("token", msg.token));
        msgObj.push_back(Pair("sender", msg.senderAddress));
        msgObj.push_back(Pair("timestamp", msg.timestamp));
        std::string msgTypeStr = (msg.messageType == 0x01) ? "private" : "group";
        msgObj.push_back(Pair("message_type", msgTypeStr));
        msgObj.push_back(Pair("encrypted_payload_hex", HexStr(msg.encryptedPayload)));
        msgObj.push_back(Pair("signature_hex", HexStr(msg.signature)));
        resultArray.push_back(msgObj);
    }

    // Validate that after_hash was found if specified
    if (!afterHash.empty() && !foundAnchor) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("after_hash '%s' not found in available messages", afterHash));
    }

    // Build the response: always an object, so the chained challenge has a
    // place to ride. has_more is only meaningful with a limit.
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("messages", resultArray));
    bool hasMore = false;
    if (limit > 0) {
            // Calculate if there are more messages available
            bool hasMore = false;
            if (resultArray.size() == (size_t)limit) {
                // We filled the limit, check if there's at least one more
                size_t processed = 0;
                bool countingAfterAnchor = afterHash.empty();
                for (const CDepinMessage& msg : messages) {
                    if (msg.timestamp < fromTimestamp) continue;
                    if (!countingAfterAnchor) {
                        if (msg.GetHash() == afterHashObj) {
                            countingAfterAnchor = true;
                        }
                        continue;
                    }
                    processed++;
                    if (processed > (size_t)limit) {
                        hasMore = true;
                        break;
                    }
                }
            }
    }
    result.push_back(Pair("has_more", hasMore));

    // Nonce chaining: the next challenge for exactly these bindings travels
    // inside the encrypted reply, with a longer life, so a client that keeps
    // reading never calls depinchallenge again -- and still signs every
    // request. Access was re-validated by CheckDepinChallengeAuth above.
    {
        std::string nextNonce;
        std::string chainError;
        nextNonce = g_depinChallenges.Issue(token, address, DepinChallengeType::RECEIVE, chainError,
                                            DEPIN_CHAINED_CHALLENGE_TIMEOUT);
        if (!nextNonce.empty()) {
            result.push_back(Pair("next_challenge", nextNonce));
            result.push_back(Pair("next_expires_in", (int)DEPIN_CHAINED_CHALLENGE_TIMEOUT));
        }
    }

    // Transport layer: the whole result encrypted for the address's revealed
    // public key, then signed with the pool key (encrypt-then-sign).
    return FinishDepinResponse(result, "depinreceivemsg", token, address, challenge, &clientPubKey);
}

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

    // Get ALL messages from pool (we no longer need to filter by address)
    std::vector<CDepinMessage> allMessages = pDepinMsgPool->GetAllMessages();
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

UniValue depinclearmsg(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 4 || request.params.size() > 5)
        throw std::runtime_error(
                "depinclearmsg \"scope\" \"address\" \"challenge\" \"signature\" ( \"all\" | hours )\n"
                "\nRemove messages from the DePIN pool: an owner-level operation.\n"
                "\nThe caller proves it owns the scope's token (or an ancestor's) with an\n"
                "admin challenge from depinchallenge, issued for exactly `scope` (\"\" means\n"
                "the pool root, and the challenge is requested for the root by name). A\n"
                "challenge for one section never authorises a wider or a sibling purge.\n"
                "\nArguments:\n"
                "1. \"scope\"      (string, required) Section token whose subtree is purged; \"\" for the whole pool\n"
                "2. \"address\"    (string, required) Owner address the challenge was issued to\n"
                "3. \"challenge\"  (string, required) Nonce from depinchallenge (type admin) for (scope, address)\n"
                "4. \"signature\"  (string, required) Base64 signature of \"DEPIN-CLEAR|<scope>|<address>|<challenge>\"\n"
                "5. mode         (string or numeric, optional) Cleanup mode:\n"
                "                - omitted: Remove only expired messages (default)\n"
                "                - \"all\": Remove ALL messages of the scope\n"
                "                - <hours>: Remove messages older than specified hours (numeric)\n"
                "\nResult:\n"
                "{\n"
                "  \"removed\": n,        (numeric) Number of messages removed\n"
                "  \"remaining\": n       (numeric) Number of messages remaining\n"
                "}\n"
                "\nExamples:\n"
                + HelpExampleCli("depinclearmsg", "\"\" \"NXowner...\" \"<challenge>\" \"<signature>\"")
                + HelpExampleCli("depinclearmsg", "\"&TOKEN/GENERAL\" \"NXowner...\" \"<challenge>\" \"<signature>\" \"all\"")
                + HelpExampleCli("depinclearmsg", "\"\" \"NXowner...\" \"<challenge>\" \"<signature>\" 7")
                + HelpExampleRpc("depinclearmsg", "\"&TOKEN/GENERAL\", \"NXowner...\", \"<challenge>\", \"<signature>\", \"all\"")
        );

    if (!pDepinMsgPool || !pDepinMsgPool->IsEnabled()) {
        throw JSONRPCError(RPC_MISC_ERROR, "DePIN messaging pool is not enabled");
    }

    const std::string poolRoot = pDepinMsgPool->GetActiveToken();

    // Scope first, normalised before anything is authenticated: "" is the
    // pool root, and the challenge was issued for the root by its name.
    std::string scopeToken = request.params[0].isNull() ? std::string() : request.params[0].get_str();
    if (scopeToken.empty()) {
        scopeToken = poolRoot;
    } else if (!IsDepinSectionOrRoot(scopeToken, poolRoot)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                          strprintf("Scope '%s' is not configured token '%s' or a section inside it",
                                   scopeToken, poolRoot));
    }
    // The root's subtree is the whole pool; keep the pool-wide primitives.
    const bool wholePool = (scopeToken == poolRoot);

    const std::string address = request.params[1].get_str();
    const std::string challenge = request.params[2].get_str();
    const std::string signature = request.params[3].get_str();
    const UniValue modeParam = request.params.size() >= 5 ? request.params[4] : NullUniValue;

    // The mode is validated BEFORE the challenge is consumed: a typo must not
    // burn a nonce. Only an absent or null mode means the default; an empty
    // string stays an error.
    enum { MODE_EXPIRED, MODE_ALL, MODE_HOURS } mode = MODE_EXPIRED;
    int64_t hoursThreshold = 0;
    if (!modeParam.isNull()) {
        if (modeParam.isStr() && modeParam.get_str() == "all") {
            mode = MODE_ALL;
        } else if (ParseFlexibleInt64(modeParam, hoursThreshold)) {
            // Accepts the number sent over JSON-RPC and the string neurai-cli
            // produces; anything that is not a strict integer is an error
            // rather than being coerced.
            if (hoursThreshold < 0) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Hours threshold must be positive");
            }
            // The multiplication below overflows for absurd inputs. A
            // threshold past the pool's own expiry already removes everything,
            // so capping is not a loss of function.
            const int64_t maxHours = std::numeric_limits<int64_t>::max() / 3600;
            if (hoursThreshold > maxHours) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   strprintf("Hours threshold must not exceed %d", maxHours));
            }
            mode = MODE_HOURS;
        } else {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter. Use \"all\" or a numeric value for hours");
        }
    }

    CPubKey clientPubKey;
    std::string pubkeyError;
    if (!CheckAddressHasPublicKey(address, clientPubKey, pubkeyError)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                          strprintf("Address has no revealed public key, and responses are always encrypted: %s",
                                   pubkeyError));
    }

    // Owner-level proof for exactly this scope, consumed here.
    std::string authError;
    if (!CheckDepinChallengeAuth(DepinChallengeType::ADMIN, scopeToken, address, challenge, signature,
                                 poolRoot, authError)) {
        throw JSONRPCError(RPC_INVALID_REQUEST, strprintf("Challenge authentication failed: %s", authError));
    }

    const size_t sizeBefore = pDepinMsgPool->Size();
    const int64_t currentTime = GetTime();
    const std::string purgeScope = wholePool ? std::string() : scopeToken;

    if (mode == MODE_EXPIRED) {
        pDepinMsgPool->RemoveExpiredMessages(currentTime, purgeScope);
    } else if (mode == MODE_ALL) {
        if (wholePool) {
            pDepinMsgPool->Clear();
        } else {
            pDepinMsgPool->ClearScope(scopeToken);
        }
    } else {
        pDepinMsgPool->RemoveMessagesOlderThan(currentTime, hoursThreshold * 3600, purgeScope);
    }

    const size_t sizeAfter = pDepinMsgPool->Size();

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("removed", (int)(sizeBefore - sizeAfter)));
    result.push_back(Pair("remaining", (int)sizeAfter));

    return FinishDepinResponse(result, "depinclearmsg", scopeToken, address, challenge, &clientPubKey);
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

    return FinishDepinResponse(result, "depinpoolstats", pDepinMsgPool ? pDepinMsgPool->GetActiveToken() : std::string(), "", "", nullptr);
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
        return FinishDepinResponse(result, "depinmcpstatus", pDepinMsgPool ? pDepinMsgPool->GetActiveToken() : std::string(), "", "", nullptr);
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

    return FinishDepinResponse(result, "depinmcpstatus", pDepinMsgPool ? pDepinMsgPool->GetActiveToken() : std::string(), "", "", nullptr);
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

    // No lock or flush here on purpose: GetDepinAncestorRecipients() owns that
    // contract so every caller gets it, not only this one.
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

    return FinishDepinResponse(result, "depingetancestorrecipients", request.params[0].get_str(), "", "", nullptr);
}

UniValue depinlistsections(const JSONRPCRequest& request)
{
    if (request.fHelp || (request.params.size() != 0 && request.params.size() != 4))
        throw std::runtime_error(
                "depinlistsections ( \"address\" \"scope\" \"challenge\" \"signature\" )\n"
                "\nList the sections (sub-assets) of the pool's active token, for UI tabs.\n"
                "The list is served from a per-tip snapshot; section names are public on\n"
                "chain, so with no arguments the names are listed for anyone. Access and\n"
                "message counters are personal: the address mode takes all four arguments,\n"
                "proves control of the address with a challenge (depinchallenge, type\n"
                "receive, issued for `scope`), is limited to the subtree of `scope`, and is\n"
                "answered encrypted for the address. Nothing in between (one to three\n"
                "arguments) is accepted.\n"
                "\nArguments:\n"
                "1. \"address\"    (string, optional) Report this address's access per section\n"
                "2. \"scope\"      (string, required with address) Pool root or a section: the challenge's token and the\n"
                "                  subtree reported\n"
                "3. \"challenge\"  (string, required with address) Nonce from depinchallenge for (scope, address)\n"
                "4. \"signature\"  (string, required with address) Base64 signature of \"DEPIN-GET|<scope>|<address>|<challenge>\"\n"
                "\nResult: { \"sections\": [...], \"poolsig\": \"base64\" } (encrypted for the address in address mode)\n"
                "[\n"
                "  {\n"
                "    \"name\": \"&TOKEN/GENERAL\",   (string) Full section token\n"
                "    \"label\": \"GENERAL\",         (string) Name relative to the pool root (\"\" = root)\n"
                "    \"depth\": n,                 (numeric) Levels below the pool root (0 = root)\n"
                "    \"access\": true|false,       (boolean, only with address) Active inherited access\n"
                "    \"messages\": n               (numeric, only with address and access) Messages in\n"
                "                                 this section's subtree\n"
                "  },\n"
                "  ...\n"
                "]\n"
                "\nExamples:\n"
                + HelpExampleCli("depinlistsections", "")
                + HelpExampleCli("depinlistsections", "\"NXyouraddress...\" \"&TOKEN/GENERAL\" \"<challenge>\" \"<signature>\"")
                + HelpExampleRpc("depinlistsections", "")
        );

    if (!pDepinMsgPool || !pDepinMsgPool->IsEnabled()) {
        throw JSONRPCError(RPC_MISC_ERROR, "DePIN messaging pool is not enabled");
    }

    std::string address;
    std::string scope;
    std::string challenge;
    std::string signature;
    CPubKey clientPubKey;
    if (request.params.size() == 4) {
        address = request.params[0].get_str();
        scope = request.params[1].get_str();
        challenge = request.params[2].get_str();
        signature = request.params[3].get_str();
        if (address.empty() || scope.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "address and scope are required in address mode");
        }
        CTxDestination dest = DecodeDestination(address);
        if (!IsValidDestination(dest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
        }
        if (!IsDepinSectionOrRoot(scope, pDepinMsgPool->GetActiveToken())) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                              strprintf("Scope '%s' is not configured token '%s' or a section inside it",
                                       scope, pDepinMsgPool->GetActiveToken()));
        }
        std::string pubkeyError;
        if (!CheckAddressHasPublicKey(address, clientPubKey, pubkeyError)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                              strprintf("Address has no revealed public key, and responses are always encrypted: %s",
                                       pubkeyError));
        }
        // Distinguish "cannot answer" from "no access" up front: after this,
        // a false from HasDepinSectionAccess means no access, not a missing
        // database answered with a false reason.
        if (!fAssetIndex) {
            throw JSONRPCError(RPC_MISC_ERROR,
                              "Asset index is required but not enabled. Restart with -assetindex and -reindex");
        }
        if (!passetsdb) {
            throw JSONRPCError(RPC_MISC_ERROR, "Asset database not available");
        }
        if (!prestricteddb) {
            throw JSONRPCError(RPC_MISC_ERROR, "Restricted asset database not available");
        }

        // Proof of control over `address` for `scope`, consumed here.
        std::string authError;
        if (!CheckDepinChallengeAuth(DepinChallengeType::RECEIVE, scope, address, challenge, signature,
                                     pDepinMsgPool->GetActiveToken(), authError)) {
            throw JSONRPCError(RPC_INVALID_REQUEST, strprintf("Challenge authentication failed: %s", authError));
        }
    }

    std::vector<std::string> sections;
    std::string error;
    if (!pDepinMsgPool->GetSections(sections, error)) {
        throw JSONRPCError(RPC_MISC_ERROR, error);
    }

    const std::string activeToken = pDepinMsgPool->GetActiveToken();

    UniValue result(UniValue::VARR);
    for (const std::string& section : sections) {
        // Address mode reports the challenge's subtree only: a holder of one
        // section proves nothing about its siblings.
        if (!scope.empty() && !IsDepinSectionOrRoot(section, scope)) {
            continue;
        }
        const std::string label = GetDepinSectionLabel(section, activeToken);

        int depth = 0;
        if (!label.empty()) {
            depth = 1 + (int)std::count(label.begin(), label.end(), '/');
        }

        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("name", section));
        obj.push_back(Pair("label", label));
        obj.push_back(Pair("depth", depth));

        if (!address.empty()) {
            std::string accessError;
            const bool hasAccess = HasDepinSectionAccess(address, section, activeToken, accessError);
            obj.push_back(Pair("access", hasAccess));
            if (hasAccess) {
                obj.push_back(Pair("messages", (uint64_t)pDepinMsgPool->CountMessagesInScope(section)));
            }
        }

        result.push_back(obj);
    }

    UniValue wrapped(UniValue::VOBJ);
    wrapped.push_back(Pair("sections", result));
    if (!address.empty()) {
        // Nonce chaining, as in depinreceivemsg: the next challenge for
        // (scope, address) rides inside the encrypted reply.
        std::string nextNonce;
        std::string chainError;
        nextNonce = g_depinChallenges.Issue(scope, address, DepinChallengeType::RECEIVE, chainError,
                                            DEPIN_CHAINED_CHALLENGE_TIMEOUT);
        if (!nextNonce.empty()) {
            wrapped.push_back(Pair("next_challenge", nextNonce));
            wrapped.push_back(Pair("next_expires_in", (int)DEPIN_CHAINED_CHALLENGE_TIMEOUT));
        }
        return FinishDepinResponse(wrapped, "depinlistsections", scope, address, challenge, &clientPubKey);
    }
    return FinishDepinResponse(wrapped, "depinlistsections", pDepinMsgPool->GetActiveToken(), "", "", nullptr);
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
                "  Mainnet:  m/44'/0'/200'/0/0\n"
                "  Testnet:  m/44'/0'/200'/1/0\n"
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
            { "depin messaging",          "depingetmsginfo",            &depingetmsginfo,            {}},
            { "depin messaging",          "depinchallenge",             &depinchallenge,             {"token", "address", "timestamp", "signature", "type"}},
            { "depin messaging",          "depinpoolstats",             &depinpoolstats,             {}},
            { "depin messaging",          "depinsubmitmsg",             &depinsubmitmsg,             {"message"}},
            { "depin messaging",          "depinreceivemsg",            &depinreceivemsg,            {"token", "address", "challenge", "signature", "timestamp", "after_hash", "limit"}},
            { "depin messaging",          "depinmcpstatus",             &depinmcpstatus,             {}},
            { "depin messaging",          "depingetancestorrecipients", &depingetancestorrecipients, {"token", "max_results", "stop_at"}},
            { "depin messaging",          "depinlistsections",          &depinlistsections,          {"address", "scope", "challenge", "signature"}},
            { "depin messaging",          "depinclearmsg",              &depinclearmsg,              {"scope", "address", "challenge", "signature", "mode"}},
#ifdef ENABLE_WALLET
            { "depin messaging",          "depinpoolpkey",              &depinpoolpkey,              {}},
            { "depin messaging",          "depinsignchallenge",         &depinsignchallenge,         {"address", "token", "challenge", "type"}},
            { "depin messaging",          "depinsignrequest",           &depinsignrequest,           {"address", "token", "type"}},
            { "depin messaging",          "depindecrypt",               &depindecrypt,               {"address", "encrypted"}},
            // Local pool + this node's wallet; never reachable through a proxy.
            { "depin messaging",          "depinsendmsg",               &depinsendmsg,               {"token", "message", "fromaddress"}},
            { "depin messaging",          "depingetmsg",                &depingetmsg,                {"token", "fromaddress"}},
#endif
    };

void RegisterMessageRPCCommands(CRPCTable &t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
