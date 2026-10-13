// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#ifndef NEURAI_CRYPTO_MCL_CONFIG_H
#define NEURAI_CRYPTO_MCL_CONFIG_H
// Private to the backend target. Fail closed if global build flags override
// its baseline CPU configuration (Automake may append user CXXFLAGS).
#if defined(__x86_64__) || defined(_M_X64)
#if defined(__BMI__) || defined(__BMI2__) || defined(__ADX__) || defined(__AVX__) || defined(__AVX2__) || defined(__AVX512F__)
#error "The NIP-018 baseline backend must not require BMI, ADX or AVX"
#endif
#elif defined(__aarch64__) || defined(_M_ARM64)
#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "The NIP-018 ARM64 backend requires little-endian byte order"
#endif
#if !defined(__ARM_ARCH) || __ARM_ARCH != 8 || defined(__ARM_FEATURE_SVE) || defined(__ARM_FEATURE_SVE2)
#error "The NIP-018 ARM64 baseline must target ARMv8-A without SVE"
#endif
#if defined(__ARM_FEATURE_ATOMICS) || defined(__ARM_FEATURE_CRC32) || defined(__ARM_FEATURE_CRYPTO) || defined(__ARM_FEATURE_DOTPROD) || defined(__ARM_FEATURE_FP16_VECTOR_ARITHMETIC)
#error "The NIP-018 ARM64 baseline must not require optional ARM extensions"
#endif
#else
#error "The NIP-018 backend supports x86-64 and little-endian ARM64 only"
#endif
#if MCL_FP_BIT != 256 || MCL_FR_BIT != 256 || MCL_BINT_ASM != 0 || MCL_MSM != 0
#error "Inconsistent NIP-018 backend configuration"
#endif
#if !defined(MCL_DONT_USE_XBYAK) || defined(MCL_USE_LLVM) || defined(MCL_USE_GMP)
#error "The NIP-018 baseline backend requires no JIT, LLVM or external GMP"
#endif
#endif
