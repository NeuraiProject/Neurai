// Copyright (c) 2025 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-036 §3.7 / §5 Phase 4 — DoS bench for OP_POSEIDON.
//
// Two regimes that the activation NIP must quote:
//   - 520 B per call: 17 chunks → 9 sponge permutations.
//   - 3072 B per call: 100 chunks → 50 permutations.
//
// Plus the per-call breakdown for each padding-boundary case from the
// §3.5 worked-examples table, so a reviewer can see how cost scales
// with chunk count.
//
// The synthetic "201 calls of OP_POSEIDON" worst case (1809 perms in
// the 520 B regime, 10050 perms in the 3072 B regime) is exercised by
// looping the per-call bench. NIP §3.7 makes clear the 3072 B × 201
// figure is *bench-only* — not transaction-feasible — so the goal here
// is to time the synthetic upper bound, not to imitate a real script.

#include <vector>

#include "bench.h"
#include "crypto/poseidon_bn254.h"

namespace {

void RunPoseidon(benchmark::State& state, size_t input_len)
{
    std::vector<unsigned char> in(input_len);
    // Deterministic content; the §3.6 vectors use byte[i] = i mod 256 for
    // the 520 B and 3072 B cases, so we follow the same convention.
    for (size_t i = 0; i < input_len; ++i) in[i] = (unsigned char)(i & 0xff);

    unsigned char hash[32];
    while (state.KeepRunning()) {
        crypto::PoseidonBN254(in.data(), in.size(), hash);
    }
}

void RunPoseidon_201Calls(benchmark::State& state, size_t input_len)
{
    // Synthetic upper bound: MAX_OPS_PER_SCRIPT calls of OP_POSEIDON on
    // the same input. Not transaction-feasible (see NIP §3.7) — this
    // measurement is the per-call cost × 201 directly.
    std::vector<unsigned char> in(input_len);
    for (size_t i = 0; i < input_len; ++i) in[i] = (unsigned char)(i & 0xff);

    unsigned char hash[32];
    while (state.KeepRunning()) {
        for (int i = 0; i < 201; ++i) {
            crypto::PoseidonBN254(in.data(), in.size(), hash);
        }
    }
}

} // namespace

// Per-call cost across the §3.5 worked-examples and the two §3.7
// regimes. Each one corresponds to a distinct (padded chunks N,
// permutations) tuple; reviewers can read off the cost-per-perm from
// the differences.

static void Poseidon_Empty(benchmark::State& state)    { RunPoseidon(state, 0); }
static void Poseidon_30B(benchmark::State& state)      { RunPoseidon(state, 30); }
static void Poseidon_31B(benchmark::State& state)      { RunPoseidon(state, 31); }
static void Poseidon_61B(benchmark::State& state)      { RunPoseidon(state, 61); }
static void Poseidon_62B(benchmark::State& state)      { RunPoseidon(state, 62); }
static void Poseidon_92B(benchmark::State& state)      { RunPoseidon(state, 92); }
static void Poseidon_93B(benchmark::State& state)      { RunPoseidon(state, 93); }
static void Poseidon_520B(benchmark::State& state)     { RunPoseidon(state, 520); }
static void Poseidon_3072B(benchmark::State& state)    { RunPoseidon(state, 3072); }

// §3.7 DoS gate: synthetic 201-call worst case in each regime.
static void Poseidon_520B_x201(benchmark::State& state)  { RunPoseidon_201Calls(state, 520); }
static void Poseidon_3072B_x201(benchmark::State& state) { RunPoseidon_201Calls(state, 3072); }

BENCHMARK(Poseidon_Empty);
BENCHMARK(Poseidon_30B);
BENCHMARK(Poseidon_31B);
BENCHMARK(Poseidon_61B);
BENCHMARK(Poseidon_62B);
BENCHMARK(Poseidon_92B);
BENCHMARK(Poseidon_93B);
BENCHMARK(Poseidon_520B);
BENCHMARK(Poseidon_3072B);
BENCHMARK(Poseidon_520B_x201);
BENCHMARK(Poseidon_3072B_x201);
