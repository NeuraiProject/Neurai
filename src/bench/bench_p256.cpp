// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-060 §4.6 cost bench. Every P-256 case times the whole path a node runs
// for one OP_CHECKSIG_P256: public key parsing and decompression, signature
// parsing, SHA-256 of the message and the verification equation. The cost
// formula is
//
//   M_P256  = max median of {valid, invalid well-formed} x {32 B, 72 B msg}
//   M_ECDSA = median of EcdsaSecp256k1Verify (compressed key + DER verify)
//   P256_SIGOP_COST = max(1, ceil(M_P256 / M_ECDSA))
//
// The empty-signature case (key decompression only) is reported but does not
// enter the formula. 72 bytes is the size of the NIP-060 §5 message
// (TXHASH || spent scriptPubKey || amount) for a P2PKH-sized script.

#include <vector>

#include "bench.h"
#include "crypto/p256.h"
#include "hash.h"
#include "key.h"
#include "pubkey.h"
#include "utilstrencodings.h"

namespace {

// Deterministic RFC 6979 signatures (test_framework/key_p256.py) by the key
// SHA-256("NIP-XX bench key") mod n (the provisional label of NIP-060, kept
// so the constants below stay reproducible) over messages of N bytes equal to N.
const std::string PUB = "02d4eb1b9c3d12421f795b4802310427332c1bafac91db538cdc9d142c344bcee4";
const std::string SIG32 =
    "f4bd19d0d18f648f613a87ba1a6f18a704b4119956a40157b43d2d010a1cff50"
    "53a52c17391af7d266f8a42e38683209a5a1341fbab220761e834457e23adae2";
const std::string SIG72 =
    "68f1011f7c30538cbe51281f2906dba31f8a8cc74e1214cc42f68ab73d173677"
    "5ce18dfc9cd55cca2523f07954eaed0df9870dc7f148f421766d51e3ce77945c";

enum class Case { VALID, INVALID, EMPTY };

void RunP256(benchmark::State& state, size_t msglen, const std::string& sighex, Case c)
{
    const auto pub = ParseHex(PUB);
    auto sig = ParseHex(sighex);
    if (c == Case::INVALID) sig[3] ^= 1; // well formed, r still in range
    if (c == Case::EMPTY) sig.clear();
    const std::vector<unsigned char> msg(msglen, static_cast<unsigned char>(msglen));
    const bool expected = c == Case::VALID;
    while (state.KeepRunning()) {
        bool valid = false;
        const auto res = crypto::p256::VerifyStrict(pub.data(), pub.size(), sig.data(), sig.size(),
                                                    msg.data(), msg.size(), valid);
        if (res != crypto::p256::StructuralResult::OK || valid != expected) {
            throw std::runtime_error("P-256 bench: unexpected verification result");
        }
    }
}

void P256Verify_32B_valid(benchmark::State& s) { RunP256(s, 32, SIG32, Case::VALID); }
void P256Verify_32B_invalid(benchmark::State& s) { RunP256(s, 32, SIG32, Case::INVALID); }
void P256Verify_32B_empty(benchmark::State& s) { RunP256(s, 32, SIG32, Case::EMPTY); }
void P256Verify_72B_valid(benchmark::State& s) { RunP256(s, 72, SIG72, Case::VALID); }
void P256Verify_72B_invalid(benchmark::State& s) { RunP256(s, 72, SIG72, Case::INVALID); }

// Reference for M_ECDSA: what OP_CHECKSIG / CSFS pay per signature, a
// compressed secp256k1 key parsed from bytes and a DER signature over a
// 32-byte digest.
void EcdsaSecp256k1Verify(benchmark::State& state)
{
    CKey key;
    const std::vector<unsigned char> secret(32, 0x42);
    key.Set(secret.begin(), secret.end(), true);
    const uint256 hash = Hash(secret.begin(), secret.end());
    std::vector<unsigned char> sig;
    if (!key.Sign(hash, sig)) throw std::runtime_error("ECDSA bench: signing failed");
    const CPubKey pubkey = key.GetPubKey();
    const std::vector<unsigned char> pubbytes(pubkey.begin(), pubkey.end());
    while (state.KeepRunning()) {
        const CPubKey parsed(pubbytes);
        if (!parsed.Verify(hash, sig)) throw std::runtime_error("ECDSA bench: verification failed");
    }
}

} // namespace

BENCHMARK(P256Verify_32B_valid);
BENCHMARK(P256Verify_32B_invalid);
BENCHMARK(P256Verify_32B_empty);
BENCHMARK(P256Verify_72B_valid);
BENCHMARK(P256Verify_72B_invalid);
BENCHMARK(EcdsaSecp256k1Verify);
