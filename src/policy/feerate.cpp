// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "feerate.h"

#include "tinyformat.h"

const std::string CURRENCY_UNIT = "XNA";

namespace {
//! a * b / c with a 128-bit intermediate product, saturated to int64: with
//! Neurai's MAX_MONEY (1000 times Bitcoin's) the 64-bit product overflows.
int64_t MulDiv(int64_t a, int64_t b, int64_t c)
{
    const __int128 r = static_cast<__int128>(a) * b / c;
    if (r > std::numeric_limits<int64_t>::max()) return std::numeric_limits<int64_t>::max();
    if (r < std::numeric_limits<int64_t>::min()) return std::numeric_limits<int64_t>::min();
    return static_cast<int64_t>(r);
}
} // namespace

CFeeRate::CFeeRate(const CAmount& nFeePaid, size_t nBytes_)
{
    assert(nBytes_ <= uint64_t(std::numeric_limits<int64_t>::max()));
    int64_t nSize = int64_t(nBytes_);

    if (nSize > 0)
        nSatoshisPerK = MulDiv(nFeePaid, 1000, nSize);
    else
        nSatoshisPerK = 0;
}

CAmount CFeeRate::GetFee(size_t nBytes_) const
{
    assert(nBytes_ <= uint64_t(std::numeric_limits<int64_t>::max()));
    int64_t nSize = int64_t(nBytes_);

    CAmount nFee = MulDiv(nSatoshisPerK, nSize, 1000);

    if (nFee == 0 && nSize != 0) {
        if (nSatoshisPerK > 0)
            nFee = CAmount(1);
        if (nSatoshisPerK < 0)
            nFee = CAmount(-1);
    }

    return nFee;
}

std::string CFeeRate::ToString() const
{
    return strprintf("%d.%08d %s/kB", nSatoshisPerK / COIN, nSatoshisPerK % COIN, CURRENCY_UNIT);
}
