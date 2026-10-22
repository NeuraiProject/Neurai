// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#ifndef NEURAI_TEST_SCOPED_BLOCK_NETWORK_H
#define NEURAI_TEST_SCOPED_BLOCK_NETWORK_H

#include "primitives/block.h"
#include <string>

// Construct before TestingSetup, destroy after its chain is torn down.
// SelectParams alone intentionally leaves bNetwork untouched. Wallet tests
// using the real testnet parameters must also select its SHA256d block path.
class ScopedTestBlockNetwork {
    const BlockNetwork previous;
    const uint32_t previousActivation;
public:
    explicit ScopedTestBlockNetwork(const std::string& network)
        : previous(bNetwork), previousActivation(nKAWPOWActivationTime)
    {
        bNetwork = BlockNetwork();
        bNetwork.SetNetwork(network);
    }
    ~ScopedTestBlockNetwork()
    {
        bNetwork = previous;
        nKAWPOWActivationTime = previousActivation;
    }
    ScopedTestBlockNetwork(const ScopedTestBlockNetwork&) = delete;
    ScopedTestBlockNetwork& operator=(const ScopedTestBlockNetwork&) = delete;
};
#endif
