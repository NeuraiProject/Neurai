// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#ifndef NEURAI_CRYPTO_MCL_CONFIG_H
#define NEURAI_CRYPTO_MCL_CONFIG_H
// Private to the backend target. Fail closed if global build flags override
// its baseline CPU configuration (Automake may append user CXXFLAGS).
#if !defined(__x86_64__) && !defined(_M_X64)
#error "The NIP-018 backend currently supports x86-64 only"
#endif
#if defined(__BMI__) || defined(__BMI2__) || defined(__ADX__) || defined(__AVX__) || defined(__AVX2__) || defined(__AVX512F__)
#error "The NIP-018 baseline backend must not require BMI, ADX or AVX"
#endif
#if MCL_FP_BIT != 256 || MCL_FR_BIT != 256 || MCL_BINT_ASM != 0 || MCL_MSM != 0
#error "Inconsistent NIP-018 backend configuration"
#endif
#if !defined(MCL_DONT_USE_XBYAK) || defined(MCL_USE_LLVM) || defined(MCL_USE_GMP)
#error "The NIP-018 baseline backend requires no JIT, LLVM or external GMP"
#endif
#endif
