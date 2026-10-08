// Copyright (c) 2014-2016 The Bitcoin Core developers
// Copyright (c) 2019-2022 The Ravencoin developers
// Copyright (c) 2023 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/neurai-config.h"
#endif

#include "timedata.h"

#include "netaddress.h"
#include "sync.h"
#include "ui_interface.h"
#include "util.h"
#include "utilstrencodings.h"
#include "warnings.h"

#include <limits>


static CCriticalSection cs_nTimeOffset;
static TimeOffsetData g_time_data GUARDED_BY(cs_nTimeOffset);

/**
 * "Never go to sea with two chronometers; take one or three."
 * Our three time sources are:
 *  - System clock
 *  - Median of other nodes clocks
 *  - The user (asking the user to fix the system clock if the first two disagree)
 */
int64_t GetTimeOffset()
{
    LOCK(cs_nTimeOffset);
    return g_time_data.Offset();
}

int64_t GetAdjustedTime()
{
    return GetTime() + GetTimeOffset();
}

int64_t GetTimeOffsetSample(int64_t peer_time, int64_t local_time)
{
    if (local_time > 0 && peer_time < std::numeric_limits<int64_t>::min() + local_time)
        return std::numeric_limits<int64_t>::min();
    if (local_time < 0 && peer_time > std::numeric_limits<int64_t>::max() + local_time)
        return std::numeric_limits<int64_t>::max();
    return peer_time - local_time;
}

bool TimeOffsetData::AddSample(const CNetAddr& ip, int64_t nOffsetSample, int64_t max_adjustment)
{
    bool warn = false;
    // Ignore duplicates
    if (m_known.size() == MAX_SAMPLES)
        return false;
    if (!m_known.insert(ip).second)
        return false;

    // Add data
    m_samples.input(nOffsetSample);
    LogPrint(BCLog::NET,"added time data, samples %d, offset %+d (%+d minutes)\n", m_samples.size(), nOffsetSample, nOffsetSample/60);

    // There is a known issue here (see issue #4521):
    //
    // - The structure m_samples contains up to 200 elements, after which
    // any new element added to it will not increase its size, replacing the
    // oldest element.
    //
    // - The condition to update m_offset includes checking whether the
    // number of elements in m_samples is odd, which will never happen after
    // there are 200 elements.
    //
    // But in this case the 'bug' is protective against some attacks, and may
    // actually explain why we've never seen attacks which manipulate the
    // clock offset.
    //
    // So we should hold off on fixing this and clean it up as part of
    // a timing cleanup that strengthens it in a number of other ways.
    //
    if (m_samples.size() >= 5 && m_samples.size() % 2 == 1)
    {
        int64_t nMedian = m_samples.median();
        std::vector<int64_t> vSorted = m_samples.sorted();
        // Only let other nodes change our time by so much
        const int64_t limit = std::max<int64_t>(0, max_adjustment);
        if (nMedian >= -limit && nMedian <= limit)
        {
            m_offset = nMedian;
        }
        else
        {
            m_offset = 0;

            if (!m_warned)
            {
                // If nobody has a time different than ours but within 5 minutes of ours, give a warning
                bool fMatch = false;
                for (int64_t nOffset : vSorted)
                    if (nOffset != 0 && nOffset > -5 * 60 && nOffset < 5 * 60)
                        fMatch = true;

                if (!fMatch)
                {
                    m_warned = true;
                    warn = true;
                }
            }
        }

        if (LogAcceptCategory(BCLog::NET)) {
            for (int64_t n : vSorted) {
                LogPrint(BCLog::NET, "%+d  ", n);
            }
            LogPrint(BCLog::NET, "|  ");

            LogPrint(BCLog::NET, "nTimeOffset = %+d  (%+d minutes)\n", m_offset, m_offset/60);
        }
    }
    return warn;
}

void AddTimeData(const CNetAddr& ip, int64_t sample)
{
    LOCK(cs_nTimeOffset);
    if (g_time_data.AddSample(ip, sample, gArgs.GetArg("-maxtimeadjustment", DEFAULT_MAX_TIME_ADJUSTMENT))) {
        const std::string message = strprintf(_("Please check that your computer's date and time are correct! If your clock is wrong, %s will not work properly."), _(PACKAGE_NAME));
        SetMiscWarning(message);
        uiInterface.ThreadSafeMessageBox(message, "", CClientUIInterface::MSG_WARNING);
    }
}
