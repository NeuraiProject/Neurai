// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#ifndef NEURAI_CRYPTO_BACKEND_ERROR_H
#define NEURAI_CRYPTO_BACKEND_ERROR_H
#include <exception>
/** Local infrastructure failure, never a cryptographic rejection verdict.
 * Deliberately fixed text: do not include witness data or backend diagnostics.
 */
class CryptoBackendError final : public std::exception {
public:
    const char* what() const noexcept override { return "local cryptographic backend failure"; }
};
#endif
