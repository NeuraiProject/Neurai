// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-035 §6.1 acceptance bench. The opcode counts as one
// sigop-equivalent; v1 acceptance target is that one
// OP_CHECKSIG_ED25519 verification stays within 5x of one equivalent
// OP_CHECKMULTISIG verification on the same hardware. Run alongside
// the verify_script bench (which times ECDSA / Schnorr CHECKSIG paths)
// to compute the 5x ratio.
//
// Three regimes:
//   - Ed25519Verify_KAT1_empty_msg  : RFC 8032 §7.1 test 1, message = "".
//                                     Pure crypto cost; the 32-B
//                                     SHA-512 + double-scalarmult lower
//                                     bound.
//   - Ed25519Verify_KAT4_64B_msg    : RFC 8032 SHA(abc) test, 64-B msg.
//                                     Adds one extra SHA-512 block to
//                                     the input hash.
//   - Ed25519Verify_3072B_msg       : Synthetic full-MAX_PQ_SCRIPT_ELEMENT
//                                     message under the wider witness
//                                     gate. Models a Cosmos light-client
//                                     header signed under §4.4.
//
// Plus structural-rejection benches at the bottom: ValidatePubkey and
// ValidateSignature on canonical inputs (these are the cheapest paths
// that the script handler exercises before reaching the verify
// equation, and they bound the cost of the underflow / malformed
// gating rejections).

#include <vector>

#include "bench.h"
#include "crypto/ed25519.h"
#include "utilstrencodings.h"

namespace {

// RFC 8032 §7.1 test 1 (empty message).
const std::string KAT1_PK =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const std::string KAT1_SIG =
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

// RFC 8032 §7.1 test SHA(abc) (64-byte message).
const std::string KAT4_PK =
    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf";
const std::string KAT4_SIG =
    "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704";
const std::string KAT4_MSG =
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

void RunVerify(benchmark::State& state,
               const std::string& pk_hex,
               const std::string& sig_hex,
               const std::vector<unsigned char>& msg)
{
    auto pk  = ParseHex(pk_hex);
    auto sig = ParseHex(sig_hex);
    while (state.KeepRunning()) {
        // The result is forced into a side effect to defeat dead-code
        // elimination at -O2/-O3.
        volatile bool r = crypto::ed25519::VerifyStrict(
            pk.data(), pk.size(),
            sig.data(), sig.size(),
            msg.data(), msg.size());
        (void)r;
    }
}

} // namespace

static void Ed25519Verify_KAT1_empty_msg(benchmark::State& state)
{
    RunVerify(state, KAT1_PK, KAT1_SIG, {});
}

static void Ed25519Verify_KAT4_64B_msg(benchmark::State& state)
{
    auto msg = ParseHex(KAT4_MSG);
    RunVerify(state, KAT4_PK, KAT4_SIG, msg);
}

static void Ed25519Verify_3072B_msg(benchmark::State& state)
{
    // Synthetic large-message regime: KAT1 keys/sig won't *verify* over
    // a 3072 B message (signature was generated for an empty message),
    // but the verification cost is dominated by SHA-512(R || A || msg)
    // and the double-scalarmult, both of which run identically whether
    // the equation eventually matches or not. The volatile sink in
    // RunVerify defeats short-circuiting on the false return.
    std::vector<unsigned char> msg(3072);
    for (size_t i = 0; i < msg.size(); ++i) msg[i] = (unsigned char)(i & 0xff);
    RunVerify(state, KAT1_PK, KAT1_SIG, msg);
}

static void Ed25519ValidatePubkey_canonical(benchmark::State& state)
{
    auto pk = ParseHex(KAT1_PK);
    while (state.KeepRunning()) {
        volatile auto r = crypto::ed25519::ValidatePubkey(pk.data(), pk.size());
        (void)r;
    }
}

static void Ed25519ValidateSignature_canonical(benchmark::State& state)
{
    auto sig = ParseHex(KAT1_SIG);
    while (state.KeepRunning()) {
        volatile auto r = crypto::ed25519::ValidateSignature(sig.data(), sig.size());
        (void)r;
    }
}

BENCHMARK(Ed25519Verify_KAT1_empty_msg);
BENCHMARK(Ed25519Verify_KAT4_64B_msg);
BENCHMARK(Ed25519Verify_3072B_msg);
BENCHMARK(Ed25519ValidatePubkey_canonical);
BENCHMARK(Ed25519ValidateSignature_canonical);
