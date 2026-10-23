// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "privacy/c6_config.h"

#include "privacy/c6_world.h"
#include "privacy/c7.h"
#include "privacy/publication.h"

#include <univalue.h>

#include <algorithm>
#include <functional>

namespace privacy {
namespace {

const char* const PROFILE = "C6-XNA-TEST-J2-v2";
const char* const PROFILE_C7 = "C7-XNA-TEST-v1";

/** C7 instances pinned in this build (plan C7 section 5.1): a config for any
 *  other instance loads unpinned, and the wallet decides whether to accept it.
 *  Hashes in display order, as the deployment report prints them. */
struct C7Pin {
    const char* network;
    const char* identity;
    const char* emission; //!< "txid:vout"
    const char* commitment;
};
const std::vector<C7Pin>& C7Pins()
{
    static const std::vector<C7Pin> pins = {
        // Born on testnet at height 75836, birth 8336537aab139fa78e9a219affaefa7f2c86eb8787c36600c6a270babd8763fa.
        {"testnet", "C7TEST1023A#POOL", "8bc6445bb44d6adb2e9c5d59b5ed1e7f6971662a8a571888bc1120060901e3a2:3",
         "a90ce546a03d4b6a83ba8d7680eced7f8adaf1ff7cf71c4fa9f35badcd158be2"},
    };
    return pins;
}

/** Parses "txid:vout" with the txid in display order. */
bool ParseOutpoint(const std::string& point, Bytes32& txid, uint32_t& vout);
const char* const OPERATIONS[] = {"D", "T1", "T2", "T3", "W", "J2"};

int Nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

/** Canonical lower-case hex of any length. */
bool ParseHexBytes(const std::string& text, Bytes& out)
{
    if (text.size() % 2) return false;
    out.clear();
    out.reserve(text.size() / 2);
    for (size_t i = 0; i < text.size(); i += 2) {
        const int high = Nibble(text[i]), low = Nibble(text[i + 1]);
        if (high < 0 || low < 0) return false;
        out.push_back(static_cast<uint8_t>(high << 4 | low));
    }
    return true;
}

bool Hex32Reversed(const std::string& text, Bytes32& out)
{
    if (!ParseHex32(text, out)) return false;
    std::reverse(out.begin(), out.end());
    return true;
}

Bytes Compact(size_t n)
{
    if (n < 253) return {static_cast<uint8_t>(n)};
    if (n <= 0xffff) return {253, static_cast<uint8_t>(n), static_cast<uint8_t>(n >> 8)};
    Bytes out = {254};
    Append(out, U32LE(static_cast<uint32_t>(n)));
    return out;
}

Bytes Push(const std::string& text)
{
    Bytes out = {static_cast<uint8_t>(text.size())};
    Append(out, text);
    return out;
}

/** Builds the MAST of the leaves sorted by form name, as c6-transaction.js does,
 *  and fills each leaf's control block. Returns the tree root. */
Bytes32 BuildMast(std::vector<C6Leaf>& leaves)
{
    std::vector<size_t> order(leaves.size());
    for (size_t i = 0; i < order.size(); ++i) order[i] = i;
    std::sort(order.begin(), order.end(), [&](size_t a, size_t b) { return leaves[a].form < leaves[b].form; });
    std::vector<std::vector<Bytes32>> paths(leaves.size());
    std::function<Bytes32(size_t, size_t)> tree = [&](size_t begin, size_t end) -> Bytes32 {
        if (end - begin == 1) {
            const C6Leaf& leaf = leaves[order[begin]];
            Bytes data = {1};
            Append(data, Compact(leaf.script.size()));
            Append(data, leaf.script);
            return TaggedHash("NeuraiAuthLeaf", data);
        }
        size_t cut = 1;
        while (cut * 2 < end - begin) cut *= 2;
        const Bytes32 a = tree(begin, begin + cut), b = tree(begin + cut, end);
        for (size_t i = begin; i < begin + cut; ++i) paths[order[i]].push_back(b);
        for (size_t i = begin + cut; i < end; ++i) paths[order[i]].push_back(a);
        Bytes data;
        Append(data, a < b ? a : b);
        Append(data, a < b ? b : a);
        return TaggedHash("NeuraiAuthBranch", data);
    };
    const Bytes32 root = tree(0, leaves.size());
    for (size_t i = 0; i < leaves.size(); ++i) {
        leaves[i].control = {1};
        for (const Bytes32& node : paths[i]) Append(leaves[i].control, node);
    }
    return root;
}

bool Str(const UniValue& object, const std::string& key, std::string& out)
{
    const UniValue& value = find_value(object, key);
    if (!value.isStr()) return false;
    out = value.get_str();
    return true;
}

bool ParseOutpoint(const std::string& point, Bytes32& txid, uint32_t& vout)
{
    if (point.size() < 66 || point.size() > 75 || point[64] != ':' || !Hex32Reversed(point.substr(0, 64), txid) ||
        !std::all_of(point.begin() + 65, point.end(), ::isdigit)) {
        return false;
    }
    const unsigned long n = std::stoul(point.substr(65));
    if (n > 0xffffffffUL) return false;
    vout = static_cast<uint32_t>(n);
    return true;
}

} // namespace

Bytes32 TaggedHash(const std::string& tag, const Bytes& data)
{
    Bytes tagBytes;
    Append(tagBytes, tag);
    const Bytes32 tagHash = Sha256(tagBytes);
    Bytes message;
    Append(message, tagHash);
    Append(message, tagHash);
    Append(message, data);
    return Sha256(message);
}

const C6Leaf* C6Config::Leaf(const std::string& form) const
{
    for (const C6Leaf& leaf : leaves) {
        if (leaf.form == form) return &leaf;
    }
    return nullptr;
}

Bytes C6Config::StateScript(const Bytes& opening) const
{
    Bytes script(anchorScript.begin(), anchorScript.end() - 33);
    Append(script, PoseidonBytes(opening));
    script.push_back(0x75); // OP_DROP
    return script;
}

Bytes C6Config::ReserveGuard() const
{
    Bytes guard = {0x00, 0x52, 0xc4, 0x20};
    Append(guard, commitment);
    Append(guard, Bytes{0x88, 0x00, 0x51, 0xcf});
    Append(guard, Push(identity));
    Append(guard, Bytes{0x88, 0x00, 0x51, 0xce});
    Append(guard, Push(identity));
    Append(guard, Bytes{0x88, 0x00, 0xd5, 0x00, 0x52, 0xc4, 0x88, 0x51});
    return guard;
}

Bytes C6Config::ReserveScript() const
{
    Bytes data = {1, 0};
    Append(data, Sha256(ReserveGuard()));
    Bytes script = {0x51, 0x20};
    Append(script, TaggedHash("NeuraiAuthScript", data));
    return script;
}

bool LoadC6Config(const std::string& json, C6Config& config, std::string& error)
{
    UniValue root;
    if (!root.read(json) || !root.isObject()) {
        error = "privacy pool config is not valid JSON";
        return false;
    }
    const UniValue& c = find_value(root, "config").isObject() ? find_value(root, "config") : root;
    const UniValue& manifest = find_value(c, "manifest");
    const UniValue& deployment = find_value(c, "deployment");
    if (!manifest.isObject() || !deployment.isObject()) {
        error = "privacy pool config lacks manifest or deployment";
        return false;
    }
    config = C6Config{};
    std::string text, genesisDisplay, expectedGenesis, expectedCommitment, deploymentCommitment, kind;
    if (!Str(manifest, "profile", config.profile) || (config.profile != PROFILE && config.profile != PROFILE_C7) ||
        !Str(deployment, "kind", kind) || kind != "xna") {
        error = "unsupported privacy pool profile";
        return false;
    }
    if (!Str(manifest, "identity", config.identity) || config.identity.empty() || config.identity.size() > 64 ||
        !Str(c, "network", config.network) || !Str(manifest, "network", text) || !ParseHex32(text, config.genesis) ||
        !Str(c, "expectedGenesis", expectedGenesis) || expectedGenesis != text ||
        !Str(deployment, "genesis", genesisDisplay) || !Str(manifest, "commitment", text) ||
        !ParseHex32(text, config.commitment) || !Str(c, "expectedCommitment", expectedCommitment) ||
        expectedCommitment != text || !Str(deployment, "commitment", deploymentCommitment) ||
        deploymentCommitment != text || !Str(manifest, "context", text) || !ParseHex32(text, config.context) ||
        !Str(c, "domain", text) || !ParseHex32(text, config.domain) || !Str(c, "assetId", text) ||
        !ParseHex32(text, config.assetId)) {
        error = "privacy pool config pins are missing or inconsistent";
        return false;
    }
    Bytes32 genesis;
    if (!Hex32Reversed(genesisDisplay, genesis) || genesis != config.genesis) {
        error = "privacy pool genesis pins disagree";
        return false;
    }
    Bytes32 ctx;
    if (!PoolContext(config.domain, config.assetId, 1, ctx, error) || ctx != config.context) {
        error = "privacy pool context does not match domain and asset";
        return false;
    }
    config.c7 = config.profile == PROFILE_C7;
    if (config.c7) {
        // The instance is derived, not trusted: genesis, emission and name give the domain.
        std::string emission;
        Bytes32 domain;
        if (!Str(deployment, "emission", emission) || !ParseOutpoint(emission, config.emissionTxid, config.emissionVout) ||
            !c7::PoolDomain(config.genesis, config.emissionTxid, config.emissionVout, config.identity, domain) ||
            domain != config.domain || config.assetId != c7::XnaAssetId()) {
            error = "C7 pool domain or asset does not derive from its genesis, emission and name";
            return false;
        }
        for (const C7Pin& pin : C7Pins()) {
            if (config.network == pin.network && config.identity == pin.identity && emission == pin.emission &&
                Hex(config.commitment) == pin.commitment) {
                config.pinned = true;
            }
        }
    }

    const UniValue& vks = find_value(manifest, "vks");
    const UniValue& digests = find_value(manifest, "vk_sha256");
    const UniValue& fees = find_value(manifest, "fees");
    for (const char* op : OPERATIONS) {
        Bytes vk;
        Bytes32 digest;
        if (!Str(vks, op, text) || !ParseHexBytes(text, vk) || vk.empty() || !Str(digests, op, text) ||
            !ParseHex32(text, digest) || Sha256(vk) != digest) {
            error = std::string("verifying key of ") + op + " does not match its pin";
            return false;
        }
        config.vks[op] = std::move(vk);
        const UniValue& levels = find_value(fees, op);
        if (!levels.isArray() || levels.empty()) {
            error = std::string("missing fee levels for ") + op;
            return false;
        }
        for (size_t i = 0; i < levels.size(); ++i) {
            const std::string level = levels[i].getValStr();
            if (level.empty() || level.size() > 19 || !std::all_of(level.begin(), level.end(), ::isdigit)) {
                error = "invalid fee level";
                return false;
            }
            config.fees[op].push_back(std::stoull(level));
        }
    }

    const UniValue& anchor = find_value(deployment, "anchor");
    std::string point;
    if (!anchor.isObject() || !find_value(anchor, "height").isNum() || !Str(anchor, "hash", text) ||
        !Hex32Reversed(text, config.anchorHash) || !Str(anchor, "outpoint", point) || !Str(anchor, "opening", text) ||
        !ParseHexBytes(text, config.anchorOpening) || config.anchorOpening.size() != 145 ||
        !Str(anchor, "script", text) || !ParseHexBytes(text, config.anchorScript) || config.anchorScript.size() < 34) {
        error = "invalid pool birth";
        return false;
    }
    config.anchorHeight = find_value(anchor, "height").get_int();
    const size_t colon = point.find(':');
    if (colon != 64 || !Hex32Reversed(point.substr(0, 64), config.anchorTxid) || point.size() < 66 ||
        !std::all_of(point.begin() + 65, point.end(), ::isdigit) || point.size() > 75) {
        error = "invalid pool birth outpoint";
        return false;
    }
    config.anchorVout = static_cast<uint32_t>(std::stoul(point.substr(65)));
    if (config.StateScript(config.anchorOpening) != config.anchorScript) {
        error = "pool birth script does not commit to its opening";
        return false;
    }

    const UniValue& leaves = find_value(deployment, "leaves");
    if (!leaves.isArray() || leaves.size() != 9) {
        error = "pool contract must have nine leaves";
        return false;
    }
    for (size_t i = 0; i < leaves.size(); ++i) {
        C6Leaf leaf;
        const UniValue& args = find_value(leaves[i], "args");
        if (!Str(leaves[i], "form", leaf.form) || C6FormIndex(leaf.form) < 0 || config.Leaf(leaf.form) ||
            !Str(leaves[i], "script", text) || !ParseHexBytes(text, leaf.script) || leaf.script.empty() || !args.isArray()) {
            error = "invalid pool contract leaf";
            return false;
        }
        for (size_t a = 0; a < args.size(); ++a) leaf.args.push_back(args[a].getValStr());
        config.leaves.push_back(std::move(leaf));
    }
    Bytes data = {4, 0};
    Append(data, BuildMast(config.leaves));
    if (TaggedHash("NeuraiAuthScript", data) != config.commitment) {
        error = "pool contract leaves do not match the pinned commitment";
        return false;
    }

    const UniValue& artifacts = find_value(c, "artifacts");
    const UniValue& forms = find_value(artifacts, "forms");
    const UniValue& files = find_value(artifacts, "files");
    for (const char* op : OPERATIONS) {
        const UniValue& form = find_value(forms, op);
        C6Artifact artifact;
        if (!Str(form, "wasm", artifact.wasm) || !Str(form, "zkey", artifact.zkey)) continue;
        const UniValue& wasm = find_value(files, artifact.wasm);
        const UniValue& zkey = find_value(files, artifact.zkey);
        std::string wasmHash, zkeyHash;
        if (!Str(wasm, "sha256", wasmHash) || !ParseHex32(wasmHash, artifact.wasmSha256) || !Str(zkey, "sha256", zkeyHash) ||
            !ParseHex32(zkeyHash, artifact.zkeySha256) || !find_value(wasm, "bytes").isNum() ||
            !find_value(zkey, "bytes").isNum()) {
            error = std::string("missing artifact pins for ") + op;
            return false;
        }
        artifact.wasmBytes = find_value(wasm, "bytes").get_int64();
        artifact.zkeyBytes = find_value(zkey, "bytes").get_int64();
        config.artifacts[op] = artifact;
    }
    return true;
}

} // namespace privacy
