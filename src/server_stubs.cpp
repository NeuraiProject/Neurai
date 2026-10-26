// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Placeholders for LIBNEURAI_SERVER functions that LIBNEURAI_COMMON references,
// for programs that link LIBNEURAI_COMMON without the server (neurai-tx). They
// are ordinary definitions compiled only into those programs: weak symbols in
// a static library do not resolve references on every platform (MinGW).

#include "validation.h"
#include "assets/assets.h"
#include "assets/messages.h"
#include "consensus/consensus.h"

// assets/messages.cpp
void AddAddressSeen(const std::string& /*address*/) {}

// validation.cpp
bool AreAssetsDeployed() { return false; }

// consensus/consensus.cpp
unsigned int GetMaxBlockWeight() { return 8000000u; }

// assets/assets.cpp
bool CAssetsCache::TrySpendCoin(const COutPoint& /*out*/, const CTxOut& /*coin*/) { return true; }
