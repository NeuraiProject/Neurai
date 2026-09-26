// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#include "crypto/mcl_backend.h"
#include <mcl/bn.hpp>
#include <mutex>

namespace {
bool CheckBackend()
{
    using namespace mcl;
    initPairing(BN_SNARK1);
    // Public EIP-196/197 generators, Fp2 in real, imaginary order.
    G1 p;
    bool valid = false;
    p.set(&valid, Fp(1), Fp(2), false);
    if (!valid || !p.isValidOrder()) return false;
    Fp2 x, y;
    x.a.setStr("10857046999023057135944570762232829481370756359578518086990519993285655852781");
    x.b.setStr("11559732032986387107991004021392285783925812861821192530917403151452391805634");
    y.a.setStr("8495653923123431417604973247489272438418190587263600148770280649306958101930");
    y.b.setStr("4082367875863433681332203403145435568316851327593401208105741076214120093531");
    G2 q;
    q.set(&valid, x, y, false);
    if (!valid || !q.isValidOrder()) return false;
    G1 twice;
    G1::dbl(twice, p);
    twice.normalize();
    if (twice.x.getStr() != "1368015179489954701390400359078579693043519447331113978918064868415326638035" ||
        twice.y.getStr() != "9918110051302171585080402603319702774565515993150576347155970296011118125764") return false;
    Fp12 e;
    pairing(e, p, q);
    if (e.isOne() || e.isZero()) return false;
    G2 twice_q;
    G2::dbl(twice_q, q);
    G1 ps[2] = {twice, -p};
    G2 qs[2] = {q, twice_q};
    Fp12 product, result;
    millerLoopVec(product, ps, qs, 2);
    finalExp(result, product);
    return result.isOne();
}
}

bool MCL_InitSanityCheck() noexcept
{
    static std::once_flag once;
    static bool ready = false;
    try {
        std::call_once(once, [] {
            // Catch inside call_once so failed initialization is never retried.
            try { ready = CheckBackend(); } catch (...) { ready = false; }
        });
        return ready;
    } catch (...) { return false; }
}
