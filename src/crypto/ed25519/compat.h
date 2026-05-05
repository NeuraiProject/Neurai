// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// NIP-035: minimal compatibility shim that lets us compile the
// libsodium ref10 Ed25519 verifier (vendored under src/crypto/ed25519/)
// inside the Neurai tree without dragging in the rest of libsodium.
//
// This header replaces the libsodium private headers that the ref10
// sources expect:
//
//   private/common.h    -> LOAD64_LE / STORE64_LE / COMPILER_ASSERT / ACQUIRE_FENCE
//   private/quirks.h    -> empty (we do not need libsodium's compiler shims)
//   utils.h             -> sodium_is_zero / sodium_memzero / crypto_verify_32
//   crypto_verify_32.h  -> crypto_verify_32
//
// Only the symbols actually referenced by the verify-only path are
// implemented; the rest are deliberately omitted.
//
// The strict NIP-035 §4.4 profile is enforced by a wrapper layer in
// src/crypto/ed25519.cpp on top of these primitives. This shim just
// provides the low-level glue.

#ifndef NEURAI_CRYPTO_ED25519_COMPAT_H
#define NEURAI_CRYPTO_ED25519_COMPAT_H

#include <stdint.h>
#include <string.h>

// =====================================================================
// Platform selection.
//
// HAVE_TI_MODE forces ref10 onto the radix-2^51 / 5-limb field
// representation, which is what we want on x86_64 (and any other 64-bit
// target with __int128 support — every supported Neurai build target).
// =====================================================================
#ifndef HAVE_TI_MODE
#define HAVE_TI_MODE 1
#endif

// libsodium uses __int128 spelled as uint128_t; provide that typedef.
typedef unsigned __int128 uint128_t;

// HAVE_AMD64_ASM enables some inline-asm helpers in fe_51/fe.h. We do
// not vendor that path to keep the build portable; leaving the macro
// undefined selects the C99 reference implementation.

// =====================================================================
// Byte-load / byte-store macros expected by ref10's fe_51 code.
//
// ref10's macros assume a 64-bit little-endian load is just a
// dereference; we use memcpy to be safe against alignment and strict
// aliasing. memcpy of a constant-sized aligned buffer is a single MOV
// on optimised builds.
// =====================================================================
static inline uint64_t neurai_ed25519_load64_le(const unsigned char *p)
{
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

static inline void neurai_ed25519_store64_le(unsigned char *p, uint64_t v)
{
    memcpy(p, &v, 8);
}

#define LOAD64_LE(p)      (neurai_ed25519_load64_le((const unsigned char *)(p)))
#define STORE64_LE(p, v)  (neurai_ed25519_store64_le((unsigned char *)(p), (v)))

// =====================================================================
// libsodium's "private/common.h" macros that ref10.c references.
// =====================================================================

// COMPILER_ASSERT(cond): static assertion. C++ has static_assert; for
// .c files we use a sizeof-based trick that compiles on any C99.
#ifdef __cplusplus
#define COMPILER_ASSERT(X) static_assert((X), #X)
#else
#define COMPILER_ASSERT(X) typedef char neurai_compiler_assert_##__LINE__[(X) ? 1 : -1]
#endif

// ACQUIRE_FENCE: libsodium uses this to harden against speculative
// execution side channels around input loads. For our verify-only
// consensus path the inputs (pubkey, signature, message) are public, so
// a no-op is correct. Defining it as an empty statement preserves
// upstream layout while letting us avoid a real fence.
#define ACQUIRE_FENCE() ((void)0)

// =====================================================================
// libsodium "utils" helpers used by ref10.
//
// Only sodium_is_zero is referenced (in ref10_fe_51_inline.h's
// fe25519_frombytes_strict path). crypto_verify_32 is referenced once
// in ref10.c. Both are constant-time in libsodium; we provide simple
// constant-time-ish versions because:
//   - the strict-profile verifier never branches on secret data
//     (the message, pubkey, and signature are all public consensus
//     inputs);
//   - leaking timing information about a public input does not affect
//     consensus determinism.
// =====================================================================
static inline int sodium_is_zero(const unsigned char *n, size_t nlen)
{
    unsigned char d = 0;
    for (size_t i = 0; i < nlen; ++i) {
        d |= n[i];
    }
    return 1 & ((d - 1) >> 8);
}

static inline int crypto_verify_32(const unsigned char *x, const unsigned char *y)
{
    unsigned char d = 0;
    for (size_t i = 0; i < 32; ++i) {
        d |= (unsigned char)(x[i] ^ y[i]);
    }
    return (1 & ((d - 1) >> 8)) - 1;
}

// sodium_memzero is referenced indirectly through the inline header but
// only on signing paths we never link; provide a memset-based stub for
// completeness. The compiler is allowed to elide this; that is fine for
// verify-only.
static inline void sodium_memzero(void *pnt, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)pnt;
    while (len--) {
        *p++ = 0;
    }
}

#endif // NEURAI_CRYPTO_ED25519_COMPAT_H
