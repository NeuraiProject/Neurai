// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/silentpayments.h"

#include "bech32.h"
#include "chainparams.h"
#include "crypto/sha256.h"
#include "hash.h"
#include "random.h"
#include "script/standard.h"
#include "support/cleanse.h"

#include <secp256k1.h>
#include <secp256k1_ecdh.h>

#include <cassert>
#include <cstring>
#include <map>
#include <mutex>
#include <set>

namespace silentpayments {
namespace {

const char* const TAG_INPUTS = "NeuraiSilentPayments/v0/Inputs";
const char* const TAG_SHARED = "NeuraiSilentPayments/v0/SharedSecret";
const uint32_t HARDENED = 0x80000000;
const uint32_t BECH32M_CONST = 0x2bc830a3;
const char* const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

typedef std::vector<unsigned char, secure_allocator<unsigned char>> SecretBytes;

// Secret operands only reach constant-time paths: ECDH (ecmult_const),
// pubkey_create (ecmult_gen) and seckey_* scalar arithmetic. The
// pubkey_tweak_mul/tweak_add APIs are variable time and never see a secret.
secp256k1_context* Ctx()
{
    static secp256k1_context* ctx = nullptr;
    static std::once_flag once;
    std::call_once(once, [] {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        unsigned char seed[32];
        GetRandBytes(seed, sizeof(seed));
        bool randomized = secp256k1_context_randomize(ctx, seed);
        memory_cleanse(seed, sizeof(seed));
        assert(randomized);
    });
    return ctx;
}

int EcdhCompressed(unsigned char* output, const unsigned char* x32, const unsigned char* y32, void*)
{
    output[0] = 0x02 | (y32[31] & 1);
    memcpy(output + 1, x32, 32);
    return 1;
}

bool ParsePub(const CPubKey& key, secp256k1_pubkey& out)
{
    return key.IsValid() && key.IsCompressed() && secp256k1_ec_pubkey_parse(Ctx(), &out, key.begin(), key.size());
}

CPubKey SerializePub(const secp256k1_pubkey& point)
{
    unsigned char buf[33];
    size_t len = sizeof(buf);
    secp256k1_ec_pubkey_serialize(Ctx(), buf, &len, &point, SECP256K1_EC_COMPRESSED);
    return CPubKey(buf, buf + len);
}

bool ValidScalar(const unsigned char* b32) { return secp256k1_ec_seckey_verify(Ctx(), b32) == 1; }

/** SEC1 compressed point of scalar * point, computed in constant time. */
bool Ecdh(const CPubKey& point, const unsigned char* scalar, SecretBytes& out)
{
    secp256k1_pubkey parsed;
    if (!ParsePub(point, parsed)) return false;
    out.assign(33, 0);
    return secp256k1_ecdh(Ctx(), out.data(), &parsed, scalar, EcdhCompressed, nullptr) == 1;
}

void AppendOutpoint(std::vector<unsigned char>& v, const COutPoint& o)
{
    v.insert(v.end(), o.hash.begin(), o.hash.end());
    for (int i = 0; i < 4; ++i) v.push_back((o.n >> (8 * i)) & 0xff);
}

bool InputHash(const std::vector<unsigned char>& context, const std::vector<COutPoint>& outpoints,
               const CPubKey& sum, uint256& h)
{
    if (outpoints.empty()) return false;
    std::vector<unsigned char> smallest;
    for (const COutPoint& o : outpoints) {
        std::vector<unsigned char> s;
        AppendOutpoint(s, o);
        if (smallest.empty() || s < smallest) smallest = s; // unsigned lexicographic order
    }
    std::vector<unsigned char> msg(context);
    msg.insert(msg.end(), smallest.begin(), smallest.end());
    msg.insert(msg.end(), sum.begin(), sum.end());
    h = TaggedHash(TAG_INPUTS, msg);
    return ValidScalar(h.begin());
}

/** Tagged hash of secret data: the SHA-256 state is wiped after use. */
uint256 SecretTaggedHash(const char* tag, const SecretBytes& msg)
{
    unsigned char tagHash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(reinterpret_cast<const unsigned char*>(tag), strlen(tag)).Finalize(tagHash);
    CSHA256 hasher;
    hasher.Write(tagHash, sizeof(tagHash)).Write(tagHash, sizeof(tagHash)).Write(msg.data(), msg.size());
    uint256 result;
    hasher.Finalize(result.begin());
    memory_cleanse(&hasher, sizeof(hasher));
    return result;
}

bool SharedTweak(const std::vector<unsigned char>& context, const SecretBytes& shared, uint32_t k, uint256& t)
{
    // N || serP(S) || BE32(k) in secure memory sized up front: no reallocation
    // leaves an unwiped copy of S behind.
    SecretBytes msg;
    msg.reserve(context.size() + shared.size() + 4);
    msg.insert(msg.end(), context.begin(), context.end());
    msg.insert(msg.end(), shared.begin(), shared.end());
    for (int i = 3; i >= 0; --i) msg.push_back((k >> (8 * i)) & 0xff);
    t = SecretTaggedHash(TAG_SHARED, msg);
    return ValidScalar(t.begin());
}

/** P_k = B_spend + t_k*G; t_k*G through pubkey_create (constant time). */
bool PaymentKey(const CPubKey& spendPub, const uint256& tweak, CPubKey& out)
{
    secp256k1_pubkey spend, tg, sum;
    if (!ParsePub(spendPub, spend) || !secp256k1_ec_pubkey_create(Ctx(), &tg, tweak.begin())) return false;
    const secp256k1_pubkey* points[2] = {&spend, &tg};
    if (!secp256k1_ec_pubkey_combine(Ctx(), &sum, points, 2)) return false;
    out = SerializePub(sum);
    return true;
}

std::vector<uint8_t> ExpandHrp(const std::string& hrp)
{
    std::vector<uint8_t> v;
    for (char c : hrp) v.push_back(c >> 5);
    v.push_back(0);
    for (char c : hrp) v.push_back(c & 31);
    return v;
}

uint32_t PolyMod(const std::vector<uint8_t>& values)
{
    static const uint32_t GEN[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    uint32_t chk = 1;
    for (uint8_t v : values) {
        uint32_t top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (int i = 0; i < 5; ++i) {
            if ((top >> i) & 1) chk ^= GEN[i];
        }
    }
    return chk;
}

std::string Hrp(uint8_t networkId) { return networkId == MAINNET ? "nsp" : "tnsp"; }

} // namespace

uint8_t LocalNetworkId()
{
    const std::string& id = GetParams().NetworkIDString();
    if (id == "main") return MAINNET;
    if (id == "test") return TESTNET;
    return REGTEST;
}

std::vector<unsigned char> Context(uint8_t networkId, const uint256& genesisHash)
{
    std::vector<unsigned char> v{networkId};
    for (int i = 31; i >= 0; --i) v.push_back(genesisHash.begin()[i]); // display order
    v.push_back(PROFILE_VERSION);
    v.push_back(WITNESS_FAMILY);
    return v;
}

std::vector<unsigned char> LocalContext()
{
    return Context(LocalNetworkId(), GetParams().GetConsensus().hashGenesisBlock);
}

std::string EncodeCode(const PaymentCode& code)
{
    std::vector<uint8_t> payload{code.networkId};
    payload.insert(payload.end(), code.scanKey.begin(), code.scanKey.end());
    payload.insert(payload.end(), code.spendKey.begin(), code.spendKey.end());
    std::vector<uint8_t> data{PROFILE_VERSION};
    bech32::ConvertBits<8, 5, true>(payload, data);
    return bech32::Encode(Hrp(code.networkId), data, bech32::Encoding::BECH32M);
}

bool DecodeCode(const std::string& in, uint8_t localNetworkId, PaymentCode& code, std::string& error)
{
    // Dedicated decoder: the address parser keeps its 90 character limit.
    if (in.size() < 8 || in.size() > 200) { error = "length"; return false; }
    bool lower = false, upper = false;
    for (char c : in) {
        if (c < 33 || c > 126) { error = "charset"; return false; }
        if (c >= 'a' && c <= 'z') lower = true;
        if (c >= 'A' && c <= 'Z') upper = true;
    }
    if (lower && upper) { error = "mixed case"; return false; }
    std::string str;
    for (char c : in) str += (c >= 'A' && c <= 'Z') ? (c - 'A' + 'a') : c;
    size_t pos = str.rfind('1');
    if (pos == std::string::npos || pos < 1 || pos + 7 > str.size()) { error = "separator"; return false; }
    const std::string hrp = str.substr(0, pos);
    std::vector<uint8_t> values;
    for (size_t i = pos + 1; i < str.size(); ++i) {
        const char* p = strchr(CHARSET, str[i]);
        if (!p || !*p) { error = "charset"; return false; }
        values.push_back(p - CHARSET);
    }
    std::vector<uint8_t> check = ExpandHrp(hrp);
    check.insert(check.end(), values.begin(), values.end());
    if (PolyMod(check) != BECH32M_CONST) { error = "checksum"; return false; }
    if (hrp != "nsp" && hrp != "tnsp") { error = "hrp"; return false; }
    values.resize(values.size() - 6);
    if (values.empty() || values[0] != PROFILE_VERSION) { error = "version"; return false; }
    std::vector<uint8_t> payload;
    if (!bech32::ConvertBits<5, 8, false>(std::vector<uint8_t>(values.begin() + 1, values.end()), payload)) {
        error = "padding";
        return false;
    }
    if (payload.size() != CODE_PAYLOAD_SIZE) { error = "payload length"; return false; }
    const uint8_t networkId = payload[0];
    if (networkId > REGTEST || (hrp == "nsp") != (networkId == MAINNET)) { error = "hrp/network_id"; return false; }
    if (networkId != localNetworkId) { error = "network"; return false; }
    CPubKey scan(payload.begin() + 1, payload.begin() + 34), spend(payload.begin() + 34, payload.end());
    secp256k1_pubkey a, b;
    if (!ParsePub(scan, a) || !ParsePub(spend, b)) { error = "point"; return false; }
    if (std::equal(scan.begin() + 1, scan.end(), spend.begin() + 1)) { error = "scan equals +-spend"; return false; }
    code.networkId = networkId;
    code.scanKey = scan;
    code.spendKey = spend;
    return true;
}

bool DeriveAccountKeys(const SecureVector& seed, uint8_t networkId, AccountKeys& keys)
{
    if (seed.size() < 32 || networkId > REGTEST) return false;
    const uint32_t coinType = networkId == MAINNET ? 1900 : 1;
    CExtKey node;
    node.SetSeed(seed.data(), seed.size());
    for (uint32_t index : {PURPOSE, coinType, (uint32_t)networkId, 0u}) {
        CExtKey child;
        if (!node.Derive(child, index | HARDENED)) return false; // an invalid child fails explicitly
        node = child;
    }
    CExtKey role, leaf;
    if (!node.Derive(role, 0 | HARDENED) || !role.Derive(leaf, 0 | HARDENED)) return false;
    keys.spend = leaf.key;
    if (!node.Derive(role, 1 | HARDENED) || !role.Derive(leaf, 0 | HARDENED)) return false;
    keys.scan = leaf.key;
    keys.spendPub = keys.spend.GetPubKey();
    keys.scanPub = keys.scan.GetPubKey();
    return keys.spend.IsValid() && keys.scan.IsValid() && keys.spendPub.IsCompressed() && keys.scanPub.IsCompressed();
}

CScript PaymentScript(const CPubKey& key)
{
    WitnessStrictAuthScript dest;
    if (!GetStrictAuthScriptDestinationForPubKey(key, dest) || dest.version != WITNESS_FAMILY) return CScript();
    return GetScriptForDestination(dest);
}

bool IsNativeV3Script(const CScript& script)
{
    return script.size() == 34 && script[0] == OP_3 && script[1] == 0x20;
}

bool MayBeEligible(const CTransaction& tx)
{
    if (tx.IsCoinBase() || tx.nVersion != 2 || tx.vin.empty()) return false;
    for (const CTxIn& in : tx.vin) {
        const std::vector<std::vector<unsigned char>>& stack = in.scriptWitness.stack;
        if (stack.size() != 4 || stack[0] != std::vector<unsigned char>{0x02} ||
            stack[3] != std::vector<unsigned char>{OP_TRUE} || stack[2].size() != 33) return false;
    }
    return true;
}

bool GetEligibleInputs(const CTransaction& tx, const std::vector<CTxOut>& spent,
                       std::vector<CPubKey>& pubkeys, std::vector<COutPoint>& outpoints)
{
    pubkeys.clear();
    outpoints.clear();
    if (!MayBeEligible(tx) || spent.size() != tx.vin.size()) return false;
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        // The prevout script decides the family: a v1 AuthScript spend with an
        // ECDSA key and OP_TRUE has the same witness shape as v3.
        if (!IsNativeV3Script(spent[i].scriptPubKey)) return false;
        const std::vector<std::vector<unsigned char>>& stack = tx.vin[i].scriptWitness.stack;
        CPubKey pubkey(stack[2].begin(), stack[2].end());
        if (!pubkey.IsFullyValid() || PaymentScript(pubkey) != spent[i].scriptPubKey) return false;
        pubkeys.push_back(pubkey);
        outpoints.push_back(tx.vin[i].prevout);
    }
    return true;
}

bool SumPublicKeys(const std::vector<CPubKey>& keys, CPubKey& sum)
{
    if (keys.empty()) return false;
    std::vector<secp256k1_pubkey> parsed(keys.size());
    std::vector<const secp256k1_pubkey*> ptrs;
    for (size_t i = 0; i < keys.size(); ++i) {
        if (!ParsePub(keys[i], parsed[i])) return false;
        ptrs.push_back(&parsed[i]);
    }
    secp256k1_pubkey out;
    // One call with the full list: intermediate cancellations are fine.
    if (!secp256k1_ec_pubkey_combine(Ctx(), &out, ptrs.data(), ptrs.size())) return false;
    sum = SerializePub(out);
    return true;
}

bool SumPrivateKeys(const std::vector<CKey>& keys, CKey& sum)
{
    SecretBytes acc(32), next(32);
    bool have = false;
    for (const CKey& key : keys) {
        if (!key.IsValid()) return false;
        if (!have) {
            std::copy(key.begin(), key.end(), acc.begin());
            have = true;
            continue;
        }
        std::copy(acc.begin(), acc.end(), next.begin());
        if (secp256k1_ec_seckey_tweak_add(Ctx(), next.data(), key.begin())) {
            acc.swap(next);
        } else {
            have = false; // the key is valid, so the only failure is a zero sum
        }
    }
    if (!have) return false;
    sum.Set(acc.begin(), acc.end(), true);
    return sum.IsValid();
}

bool CreateOutputs(const std::vector<unsigned char>& context, const std::vector<CKey>& inputKeys,
                   const std::vector<COutPoint>& outpoints, const std::vector<Recipient>& recipients,
                   std::vector<CTxOut>& outputs, std::string& error)
{
    outputs.clear();
    if (inputKeys.empty() || inputKeys.size() != outpoints.size()) { error = "inputs and keys differ"; return false; }
    if (recipients.empty()) { error = "no recipients"; return false; }
    CKey sum;
    if (!SumPrivateKeys(inputKeys, sum)) { error = "input keys sum to zero"; return false; }
    uint256 h;
    if (!InputHash(context, outpoints, sum.GetPubKey(), h)) { error = "invalid input hash"; return false; }
    SecretBytes ha(sum.begin(), sum.end());
    if (!secp256k1_ec_seckey_tweak_mul(Ctx(), ha.data(), h.begin())) { error = "invalid input scalar"; return false; }

    std::map<std::vector<unsigned char>, SecretBytes> shared;
    std::map<std::vector<unsigned char>, CPubKey> spendOf;
    std::map<std::vector<unsigned char>, uint32_t> next;
    std::set<CScript> seen;
    for (const Recipient& r : recipients) {
        const std::vector<unsigned char> scan(r.code.scanKey.begin(), r.code.scanKey.end());
        if (!shared.count(scan)) {
            if (!Ecdh(r.code.scanKey, ha.data(), shared[scan])) { error = "invalid scan key"; return false; }
            spendOf[scan] = r.code.spendKey;
        } else if (spendOf[scan] != r.code.spendKey) {
            error = "codes with the same scan key and different spend keys";
            return false;
        }
        const uint32_t k = next[scan]++;
        if (k >= MAX_PAYMENTS_PER_GROUP) { error = "more than 16 payments to one code"; return false; }
        uint256 t;
        CPubKey pk;
        if (!SharedTweak(context, shared[scan], k, t) || !PaymentKey(r.code.spendKey, t, pk)) {
            error = "payment key derivation failed";
            return false;
        }
        memory_cleanse(t.begin(), t.size());
        CScript script = PaymentScript(pk);
        if (script.empty() || !seen.insert(script).second) { error = "duplicated destination"; return false; }
        outputs.emplace_back(r.amount, script);
    }
    return true;
}

std::vector<Match> ScanTransaction(const std::vector<unsigned char>& context, const CTransaction& tx,
                                   const std::vector<CPubKey>& pubkeys, const std::vector<COutPoint>& outpoints,
                                   const CKey& scanKey, const CPubKey& spendPub)
{
    std::vector<Match> matches;
    std::map<CScript, std::vector<uint32_t>> candidates;
    for (uint32_t n = 0; n < tx.vout.size(); ++n) {
        if (IsNativeV3Script(tx.vout[n].scriptPubKey)) candidates[tx.vout[n].scriptPubKey].push_back(n);
    }
    if (candidates.empty()) return matches; // no possible payment: skip the ECDH
    matches.reserve(tx.vout.size()); // no reallocation leaves stale copies of t_k
    CPubKey sum;
    uint256 h;
    if (!scanKey.IsValid() || !SumPublicKeys(pubkeys, sum) || !InputHash(context, outpoints, sum, h)) return matches;
    SecretBytes bh(scanKey.begin(), scanKey.end());
    SecretBytes shared;
    if (!secp256k1_ec_seckey_tweak_mul(Ctx(), bh.data(), h.begin()) || !Ecdh(sum, bh.data(), shared)) return matches;
    for (uint32_t k = 0; k < MAX_PAYMENTS_PER_GROUP; ++k) {
        uint256 t;
        CPubKey pk;
        if (!SharedTweak(context, shared, k, t) || !PaymentKey(spendPub, t, pk)) {
            memory_cleanse(t.begin(), t.size());
            break;
        }
        auto it = candidates.find(PaymentScript(pk));
        if (it == candidates.end()) { // the sequence ends at the first missing k
            memory_cleanse(t.begin(), t.size());
            break;
        }
        for (uint32_t n : it->second) matches.push_back(Match{n, k, t, pk});
        memory_cleanse(t.begin(), t.size());
    }
    return matches;
}

bool PaymentPrivateKey(const CKey& spendKey, const uint256& tweak, CKey& out)
{
    if (!spendKey.IsValid()) return false;
    SecretBytes d(spendKey.begin(), spendKey.end());
    if (!secp256k1_ec_seckey_tweak_add(Ctx(), d.data(), tweak.begin())) return false;
    out.Set(d.begin(), d.end(), true);
    return out.IsValid();
}

} // namespace silentpayments
