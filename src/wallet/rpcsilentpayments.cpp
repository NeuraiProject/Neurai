// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// NIP-047 Silent Payments RPC commands.

#include "base58.h"
#include "chain.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "net.h"
#include "policy/fees.h"
#include "rpc/mining.h"
#include "rpc/server.h"
#include "script/standard.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "validation.h"
#include "wallet/coincontrol.h"
#include "wallet/rpcwallet.h"
#include "silentpayments.h"
#include "wallet/wallet.h"

#include <univalue.h>

namespace {

std::string NetworkName(uint8_t networkId)
{
    switch (networkId) {
    case silentpayments::MAINNET: return "main";
    case silentpayments::TESTNET: return "test";
    default: return "regtest";
    }
}

UniValue CodeToJSON(const silentpayments::PaymentCode& code)
{
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("code", silentpayments::EncodeCode(code)));
    obj.push_back(Pair("network", NetworkName(code.networkId)));
    obj.push_back(Pair("scan_pubkey", HexStr(code.scanKey)));
    obj.push_back(Pair("spend_pubkey", HexStr(code.spendKey)));
    return obj;
}

} // namespace

UniValue getsilentpaymentcode(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getsilentpaymentcode\n"
            "\nReturns the reusable silent payment code of this wallet (NIP-047).\n"
            "Every payment to the code lands on a new strict ECDSA (witness v3) output\n"
            "that only this wallet can link to the code.\n"
            "\nResult:\n"
            "{\n"
            "  \"code\": \"str\",          (string) payment code (nsp1... / tnsp1...)\n"
            "  \"network\": \"str\",       (string) main, test or regtest\n"
            "  \"scan_pubkey\": \"hex\",   (string) B_scan\n"
            "  \"spend_pubkey\": \"hex\",  (string) B_spend\n"
            "  \"view_only\": true|false (boolean) imported view key: payments are detected, not spendable\n"
            "  \"verified\": true        (boolean) checked against the wallet seed in this session. An encrypted\n"
            "                           wallet shows its code only after one unlock in the session\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getsilentpaymentcode", "")
            + HelpExampleRpc("getsilentpaymentcode", ""));

    LOCK2(cs_main, pwallet->cs_wallet);
    silentpayments::PaymentCode code;
    std::string error;
    if (!pwallet->HasSilentPaymentIdentity()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Silent payments need a strict ECDSA wallet (-addresstype=ecdsa) or an imported view key");
    }
    bool verified = false;
    if (!pwallet->GetSilentPaymentCode(code, error, &verified)) {
        const bool locked = pwallet->IsLocked() && pwallet->GetSilentPaymentIdentityError().empty();
        throw JSONRPCError(locked ? RPC_WALLET_UNLOCK_NEEDED : RPC_WALLET_ERROR, error);
    }
    UniValue obj = CodeToJSON(code);
    obj.push_back(Pair("view_only", pwallet->IsSilentPaymentViewOnly()));
    obj.push_back(Pair("verified", verified));
    return obj;
}

UniValue decodesilentpaymentcode(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "decodesilentpaymentcode \"code\"\n"
            "\nValidates a silent payment code for this network and returns its keys.\n"
            "\nArguments:\n"
            "1. \"code\"       (string, required) payment code\n"
            "\nResult:\n"
            "{\n"
            "  \"isvalid\": true|false,  (boolean)\n"
            "  \"error\": \"str\",         (string) reason when invalid\n"
            "  \"network\", \"scan_pubkey\", \"spend_pubkey\" when valid\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("decodesilentpaymentcode", "\"tnsp1q...\""));

    silentpayments::PaymentCode code;
    std::string error;
    UniValue obj(UniValue::VOBJ);
    if (!silentpayments::DecodeCode(request.params[0].get_str(), silentpayments::LocalNetworkId(), code, error)) {
        obj.push_back(Pair("isvalid", false));
        obj.push_back(Pair("error", error));
        return obj;
    }
    obj.push_back(Pair("isvalid", true));
    obj.pushKVs(CodeToJSON(code));
    return obj;
}

UniValue sendsilentpayments(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 3)
        throw std::runtime_error(
            "sendsilentpayments [{\"code\":\"str\",\"amount\":x},...] ( conf_target \"estimate_mode\" )\n"
            "\nPays one or more silent payment codes from strict ECDSA (v3) coins only.\n"
            "Several payments to the same code are allowed (up to 16 per code); the change\n"
            "returns to a new internal v3 address."
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nArguments:\n"
            "1. payments        (array, required) [{\"code\": payment code, \"amount\": amount in " + CURRENCY_UNIT + "}, ...]\n"
            "2. conf_target     (numeric, optional) Confirmation target (in blocks)\n"
            "3. \"estimate_mode\" (string, optional, default=UNSET) UNSET, ECONOMICAL or CONSERVATIVE\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\": \"hex\",\n"
            "  \"fee\": x.xxx,\n"
            "  \"payments\": [{\"code\": \"str\", \"amount\": x.xxx, \"vout\": n, \"k\": n}, ...]\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("sendsilentpayments", "'[{\"code\":\"tnsp1q...\",\"amount\":1.5}]'"));

    LOCK2(cs_main, pwallet->cs_wallet);

    const UniValue& payments = request.params[0].get_array();
    if (payments.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "No payments");
    }
    std::vector<silentpayments::Recipient> recipients;
    std::vector<std::string> codeStrings;
    std::map<std::vector<unsigned char>, uint32_t> nextIndex;
    std::vector<uint32_t> indexes;
    for (size_t i = 0; i < payments.size(); ++i) {
        const UniValue& entry = payments[i].get_obj();
        RPCTypeCheckObj(entry, {{"code", UniValueType(UniValue::VSTR)}, {"amount", UniValueType()}}, false, true);
        silentpayments::Recipient recipient;
        std::string error;
        if (!silentpayments::DecodeCode(entry["code"].get_str(), silentpayments::LocalNetworkId(), recipient.code, error)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid silent payment code (" + error + "): " + entry["code"].get_str());
        }
        recipient.amount = AmountFromValue(entry["amount"]);
        if (recipient.amount <= 0) {
            throw JSONRPCError(RPC_TYPE_ERROR, "Invalid amount for send");
        }
        const std::vector<unsigned char> scan(recipient.code.scanKey.begin(), recipient.code.scanKey.end());
        indexes.push_back(nextIndex[scan]++);
        recipients.push_back(recipient);
        codeStrings.push_back(silentpayments::EncodeCode(recipient.code));
    }

    CCoinControl coin_control;
    if (!request.params[1].isNull()) {
        coin_control.m_confirm_target = ParseConfirmTarget(request.params[1]);
    }
    if (!request.params[2].isNull()) {
        if (!FeeModeFromString(request.params[2].get_str(), coin_control.m_fee_mode)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid estimate_mode parameter");
        }
    }

    EnsureWalletIsUnlocked(pwallet);

    CWalletTx wtx;
    CReserveKey reservekey(pwallet);
    CAmount nFee = 0;
    std::vector<unsigned int> positions;
    std::string error;
    if (!pwallet->CreateSilentPaymentTransaction(recipients, wtx, reservekey, nFee, positions, error, coin_control)) {
        throw JSONRPCError(RPC_WALLET_ERROR, error);
    }
    CValidationState state;
    if (!pwallet->CommitTransaction(wtx, reservekey, g_connman.get(), state)) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Transaction commit failed:: %s", state.GetRejectReason()));
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("txid", wtx.GetHash().GetHex()));
    result.push_back(Pair("fee", ValueFromAmount(nFee)));
    UniValue list(UniValue::VARR);
    for (size_t i = 0; i < recipients.size(); ++i) {
        UniValue p(UniValue::VOBJ);
        p.push_back(Pair("code", codeStrings[i]));
        p.push_back(Pair("amount", ValueFromAmount(recipients[i].amount)));
        p.push_back(Pair("vout", (int)positions[i]));
        p.push_back(Pair("k", (int)indexes[i]));
        list.push_back(p);
    }
    result.push_back(Pair("payments", list));
    return result;
}

UniValue listsilentpayments(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "listsilentpayments ( include_spent )\n"
            "\nLists the silent payments received by this wallet.\n"
            "\nArguments:\n"
            "1. include_spent   (boolean, optional, default=true)\n"
            "\nResult:\n"
            "[{\n"
            "  \"txid\": \"hex\", \"vout\": n, \"k\": n, \"amount\": x.xxx, \"address\": \"str\",\n"
            "  \"status\": \"pending|unconfirmed|confirmed|spent|conflicted|abandoned|other_chain|unknown\",\n"
            "  \"confirmations\": n, \"blockhash\": \"hex\", \"height\": n, \"view_only\": true|false\n"
            "}, ...]\n"
            "\nExamples:\n"
            + HelpExampleCli("listsilentpayments", ""));

    const bool includeSpent = request.params[0].isNull() || request.params[0].get_bool();

    LOCK2(cs_main, pwallet->cs_wallet);
    UniValue result(UniValue::VARR);
    for (const auto& entry : pwallet->mapSilentPayments) {
        const COutPoint& outpoint = entry.first;
        const silentpayments::PaymentRecord& record = entry.second;
        int depth = 0;
        const std::string status = pwallet->GetSilentPaymentStatus(outpoint, record, depth);
        if (!includeSpent && status == "spent") continue;
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("txid", outpoint.hash.GetHex()));
        obj.push_back(Pair("vout", (int)outpoint.n));
        obj.push_back(Pair("k", (int)record.k));
        auto it = pwallet->mapWallet.find(outpoint.hash);
        if (it != pwallet->mapWallet.end() && outpoint.n < it->second.tx->vout.size()) {
            obj.push_back(Pair("amount", ValueFromAmount(it->second.tx->vout[outpoint.n].nValue)));
        }
        CTxDestination dest;
        if (ExtractDestination(silentpayments::PaymentScript(record.key), dest)) {
            obj.push_back(Pair("address", EncodeDestination(dest)));
        }
        obj.push_back(Pair("status", status));
        obj.push_back(Pair("confirmations", depth));
        if (!record.blockHash.IsNull()) {
            obj.push_back(Pair("blockhash", record.blockHash.GetHex()));
            obj.push_back(Pair("height", record.height));
        }
        obj.push_back(Pair("view_only", record.viewOnly));
        result.push_back(obj);
    }
    return result;
}

UniValue getsilentpaymentinfo(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "getsilentpaymentinfo\n"
            "\nReturns the silent payment scanning state of this wallet.\n"
            "\nResult:\n"
            "{\n"
            "  \"enabled\": true|false,     (boolean) the wallet has an identity (own or view key)\n"
            "  \"view_only\": true|false,\n"
            "  \"code\": \"str\",             (string) once checked against the seed in this session and while\n"
            "                                the identity is sound\n"
            "  \"code_verified\": true|false,(boolean) code checked against the seed in this session\n"
            "  \"identity_error\": \"str\",   (string) damaged identity: the code must not be used\n"
            "  \"paused\": true|false,      (boolean) locked wallet: scanning waits for walletpassphrase\n"
            "  \"scanned_height\": n,       (numeric) last block really scanned (-1: none)\n"
            "  \"scanned_hash\": \"hex\",\n"
            "  \"tip_height\": n,\n"
            "  \"blocks_behind\": n,\n"
            "  \"error\": \"str\",            (string) why scanning stopped (missing block or undo data)\n"
            "  \"payments\": n\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getsilentpaymentinfo", ""));

    LOCK2(cs_main, pwallet->cs_wallet);
    UniValue obj(UniValue::VOBJ);
    const bool enabled = pwallet->HasSilentPaymentIdentity();
    obj.push_back(Pair("enabled", enabled));
    if (!enabled) return obj;
    obj.push_back(Pair("view_only", pwallet->IsSilentPaymentViewOnly()));
    silentpayments::PaymentCode code;
    std::string error;
    bool verified = false;
    if (pwallet->GetSilentPaymentCode(code, error, &verified)) {
        obj.push_back(Pair("code", silentpayments::EncodeCode(code)));
    }
    obj.push_back(Pair("code_verified", verified));
    if (!pwallet->GetSilentPaymentIdentityError().empty()) {
        obj.push_back(Pair("identity_error", pwallet->GetSilentPaymentIdentityError()));
    }
    uint256 hash;
    const int height = pwallet->GetSilentPaymentCursor(&hash);
    obj.push_back(Pair("paused", pwallet->SilentPaymentsPaused()));
    obj.push_back(Pair("scanned_height", height));
    if (height >= 0) obj.push_back(Pair("scanned_hash", hash.GetHex()));
    obj.push_back(Pair("tip_height", chainActive.Height()));
    obj.push_back(Pair("blocks_behind", std::max(0, chainActive.Height() - height)));
    if (!pwallet->GetSilentPaymentError().empty()) obj.push_back(Pair("error", pwallet->GetSilentPaymentError()));
    obj.push_back(Pair("payments", (int)pwallet->mapSilentPayments.size()));
    return obj;
}

UniValue rescansilentpayments(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "rescansilentpayments ( start_height )\n"
            "\nScans the active chain again for silent payments, from start_height to the tip.\n"
            "Reads blocks and their undo data; -txindex is not needed. Scanning stops, without\n"
            "advancing past it, at the first block whose data is not available (pruned node).\n"
            "\nArguments:\n"
            "1. start_height    (numeric, optional, default=0)\n"
            "\nResult:\n"
            "{\n"
            "  \"start_height\": n, \"scanned_height\": n, \"found\": n\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("rescansilentpayments", "100"));

    const int start = request.params[0].isNull() ? 0 : request.params[0].get_int();
    int found = 0;
    std::string error;
    // Scans in chunks and releases cs_main between them: no lock held here.
    if (!pwallet->RescanSilentPayments(start, found, error)) {
        LOCK(pwallet->cs_wallet);
        throw JSONRPCError(pwallet->SilentPaymentsPaused() ? RPC_WALLET_UNLOCK_NEEDED : RPC_MISC_ERROR, error);
    }
    LOCK(pwallet->cs_wallet);
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("start_height", start));
    obj.push_back(Pair("scanned_height", pwallet->GetSilentPaymentCursor()));
    obj.push_back(Pair("found", found));
    return obj;
}

UniValue exportsilentpaymentviewkey(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "exportsilentpaymentviewkey \"acknowledge\"\n"
            "\nReturns the view key (b_scan and B_spend) of this wallet's silent payment code.\n"
            "Whoever holds it can find and link every payment to the code, but cannot spend them.\n"
            "Never combine it with an exported payment private key: together they reveal the spend key.\n"
            "The result is a secret: from a shell, prefer a terminal that is not recorded or logged."
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nArguments:\n"
            "1. \"acknowledge\"   (string, required) must be \"reveal view key\"\n"
            "\nResult:\n"
            "{\n"
            "  \"scan_private_key\": \"hex\", \"spend_pubkey\": \"hex\", \"network\": \"str\"\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("exportsilentpaymentviewkey", "\"reveal view key\""));

    if (request.params[0].get_str() != "reveal view key") {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "The view key is only exported with the acknowledge text \"reveal view key\"");
    }
    LOCK2(cs_main, pwallet->cs_wallet);
    if (!pwallet->HasSilentPaymentIdentity()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "This wallet has no silent payment identity");
    }
    EnsureWalletIsUnlocked(pwallet);
    CKey scan;
    CPubKey spend;
    std::string error;
    if (!pwallet->GetSilentPaymentViewKey(scan, spend, error)) {
        throw JSONRPCError(RPC_WALLET_ERROR, error);
    }
    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("scan_private_key", HexStr(scan.begin(), scan.end())));
    obj.push_back(Pair("spend_pubkey", HexStr(spend)));
    obj.push_back(Pair("network", NetworkName(silentpayments::LocalNetworkId())));
    return obj;
}

UniValue importsilentpaymentviewkey(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3)
        throw std::runtime_error(
            "importsilentpaymentviewkey \"scan_private_key\" \"spend_pubkey\" ( start_height )\n"
            "\nTurns this wallet into a watch wallet of a silent payment code: payments are\n"
            "detected and shown as watch-only, never spendable. Only for an unencrypted wallet\n"
            "without its own silent payment identity (or whose stored view key is damaged); the wallet\n"
            "can no longer be encrypted. Pass the secret with \"neurai-cli -stdin importsilentpaymentviewkey\"\n"
            "(one argument per line) so it stays out of the shell history and the process list.\n"
            "\nArguments:\n"
            "1. \"scan_private_key\" (string, required) hex b_scan\n"
            "2. \"spend_pubkey\"     (string, required) hex B_spend\n"
            "3. start_height        (numeric, optional, default=0) first block to scan\n"
            "\nResult:\n"
            "{\n"
            "  \"code\": \"str\", \"scanned_height\": n, \"found\": n\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("importsilentpaymentviewkey", "\"<hex>\" \"<hex>\" 0"));

    const std::vector<unsigned char> scanBytes = ParseHexV(request.params[0], "scan_private_key");
    const std::vector<unsigned char> spendBytes = ParseHexV(request.params[1], "spend_pubkey");
    if (scanBytes.size() != 32 || spendBytes.size() != 33) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid view key length");
    }
    CKey scan;
    scan.Set(scanBytes.begin(), scanBytes.end(), true);
    const CPubKey spend(spendBytes.begin(), spendBytes.end());
    const int start = request.params[2].isNull() ? 0 : request.params[2].get_int();

    std::string error;
    {
        LOCK2(cs_main, pwallet->cs_wallet);
        if (start < 0 || start > chainActive.Height()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid start_height");
        }
        if (!pwallet->ImportSilentPaymentViewKey(scan, spend, error)) {
            throw JSONRPCError(RPC_WALLET_ERROR, error);
        }
    }
    int found = 0;
    if (!pwallet->RescanSilentPayments(start, found, error)) {
        throw JSONRPCError(RPC_MISC_ERROR, error);
    }
    LOCK(pwallet->cs_wallet);
    silentpayments::PaymentCode code;
    UniValue obj(UniValue::VOBJ);
    if (pwallet->GetSilentPaymentCode(code, error)) {
        obj.push_back(Pair("code", silentpayments::EncodeCode(code)));
    }
    obj.push_back(Pair("scanned_height", pwallet->GetSilentPaymentCursor()));
    obj.push_back(Pair("found", found));
    return obj;
}

UniValue repairsilentpaymentidentity(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }
    if (request.fHelp || request.params.size() != 0)
        throw std::runtime_error(
            "repairsilentpaymentidentity\n"
            "\nRewrites the silent payment code of this wallet from its seed after an identity failure\n"
            "(\"stored silent payment code does not match the wallet seed\"). Payments sent to the\n"
            "replaced code did not reach this wallet: check your backups before repairing."
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nResult:\n"
            "{\n"
            "  \"previous_code\": \"str\",  (string) the code that was stored (do not use it)\n"
            "  \"code\": \"str\"            (string) the code derived from the seed\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("repairsilentpaymentidentity", ""));

    UniValue obj(UniValue::VOBJ);
    {
        LOCK2(cs_main, pwallet->cs_wallet);
        EnsureWalletIsUnlocked(pwallet);
        silentpayments::PaymentCode previous, code;
        std::string error;
        if (!pwallet->RepairSilentPaymentIdentity(previous, code, error)) {
            throw JSONRPCError(RPC_WALLET_ERROR, error);
        }
        if (previous.scanKey.IsValid()) obj.push_back(Pair("previous_code", silentpayments::EncodeCode(previous)));
        obj.push_back(Pair("code", silentpayments::EncodeCode(code)));
    }
    pwallet->ResumeSilentPayments();
    return obj;
}

static const CRPCCommand commands[] =
{ //  category              name                            actor (function)               argNames
    //  --------------------- ------------------------------ ------------------------------ ----------
    { "wallet",             "getsilentpaymentcode",         &getsilentpaymentcode,         {} },
    { "wallet",             "decodesilentpaymentcode",      &decodesilentpaymentcode,      {"code"} },
    { "wallet",             "sendsilentpayments",           &sendsilentpayments,           {"payments", "conf_target", "estimate_mode"} },
    { "wallet",             "listsilentpayments",           &listsilentpayments,           {"include_spent"} },
    { "wallet",             "getsilentpaymentinfo",         &getsilentpaymentinfo,         {} },
    { "wallet",             "rescansilentpayments",         &rescansilentpayments,         {"start_height"} },
    { "wallet",             "exportsilentpaymentviewkey",   &exportsilentpaymentviewkey,   {"acknowledge"} },
    { "wallet",             "importsilentpaymentviewkey",   &importsilentpaymentviewkey,   {"scan_private_key", "spend_pubkey", "start_height"} },
    { "wallet",             "repairsilentpaymentidentity",  &repairsilentpaymentidentity,  {} },
};

void RegisterSilentPaymentsRPCCommands(CRPCTable& t)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        t.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
