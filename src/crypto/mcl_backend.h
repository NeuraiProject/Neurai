// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#ifndef NEURAI_CRYPTO_MCL_BACKEND_H
#define NEURAI_CRYPTO_MCL_BACKEND_H

/** Initialize the private BN_SNARK1 instance once and check public test vectors.
 * Immutable after startup; failures are sticky. No wallet data or randomness.
 * This does not implement or activate OP_ZKVERIFY.
 */
bool MCL_InitSanityCheck() noexcept;
#endif
