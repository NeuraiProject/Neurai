// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_CRYPTO_PQ_SANITY_H
#define NEURAI_CRYPTO_PQ_SANITY_H

/** Check ML-DSA-44 key derivation and signing/verification using public test data.
 *  Does not access wallets or change the RNG. Returns false on failure,
 *  including exceptions. Run once during startup, after the RNG sanity check.
 */
bool PQ_InitSanityCheck() noexcept;

#endif // NEURAI_CRYPTO_PQ_SANITY_H
