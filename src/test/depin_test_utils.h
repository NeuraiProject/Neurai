// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#ifndef NEURAI_TEST_DEPIN_TEST_UTILS_H
#define NEURAI_TEST_DEPIN_TEST_UTILS_H

#include "chain.h"
#include "utiltime.h"
#include "validation.h"

// Database-only fixtures do not mine blocks. Give their synthetic chain index
// a current time, restoring the original metadata before TestingSetup tears
// down. Production has no regtest exemption from freshness checks. Functional
// and wallet integration tests use actual mined blocks instead.
inline void RefreshDepinTestTipTime()
{
    LOCK(cs_main);
    if (chainActive.Tip()) chainActive.Tip()->nTime = GetTime();
}

struct ScopedDepinTestTipTime {
    CBlockIndex* tip;
    uint32_t oldTime;
    ScopedDepinTestTipTime() : tip(chainActive.Tip()), oldTime(tip ? tip->nTime : 0)
    {
        RefreshDepinTestTipTime();
    }
    ~ScopedDepinTestTipTime()
    {
        LOCK(cs_main);
        if (tip) tip->nTime = oldTime;
    }
};
#endif
