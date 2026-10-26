# SPH hash compatibility

Introduced in `1320936`. It fixes misaligned accesses and shifts of negative
values in the SPH hash code (used by X16R/X16RV2), found by UBSan. All hash
outputs are preserved byte for byte, including the mainnet genesis hash. No
consensus rule, DePIN format, signature, key, RPC or persistence format changes,
and the KAWPOW code and parameters are unchanged.

## Changes

- `src/algo/sph_types.h` and its identical copy `src/crypto/sph_types.h` load
  and store integer representations through `memcpy`. The swaps, endian branches
  and byte-wise fallbacks are retained. This removes dereferences of cast
  pointers with incompatible alignment or effective type, also in the
  `_aligned` helpers; output sizes and bytes do not change.
- `src/algo/simd.c` replaces the 14 shifts of potentially negative values in
  FFT16 with bounded multiplications. The FFT8 bounds give
  `|d2_i * 2^i| <= 554496`, within `s32`. REDS1/REDS2 express the former
  arithmetic right shift as a division rounding towards negative infinity,
  without negating the minimum integer. Masks are applied to unsigned values.
  Nothing depends on C's shift of a negative value.
- The `depin_sections_wallet_tests` and `depin_selfrevoke_wallet_tests`
  fixtures explicitly select the testnet SHA256d path before constructing
  `TestingSetup`, and restore the network flags and the KAWPOW activation when
  destroyed. `SelectParams` alone intentionally leaves those flags untouched in
  tests. Production network selection and algorithm activation do not change.

## Independent reference

The expected values come from the **Java** implementation by the SPH author,
[sphlib](https://github.com/pornin/sphlib), pinned to commit
`15b6b8d8f3e4a43c58ba102d712fa6b8a3317035`. The Java code does not share the C
helpers being fixed, and the expected values were frozen from Java, not from
the fixed C code. The original node C/C++ code was compared with Java before the
fix was applied.

The reproducible corpus has 4516 cases: the 16 X16 components, edge lengths and
random messages, long SIMD/Fugue inputs, every X16R/X16RV2 selector, mixed
compositions and the historical genesis header. 50 Java cases are kept in
`src/test/data/sph_compat.json` for the regular test suite. The checked mainnet
genesis hash is
`00000044d33c0c0ba019be5c0249730424a69cb4c222153322f68c6104484806`. The node
computes it through the X16RV2 path (its `nTime` is after the X16RV2
activation); with a null `hashPrevBlock` every selector is BLAKE and X16R gives
the same value, as both vectors check.

The Java adaptation reproduces the X16 composition and the zero padding after
Tiger in X16RV2; its cryptographic components are independent. The published
bit-length vectors of sphlib give a second check for the 224, 256, 384 and
512-bit SIMD/Fugue variants.

## Testing

The tools and commands are in [contrib/devtools/sph](../contrib/devtools/sph/README.md).
Besides the corpus comparison, run:

- the `sph_tests` unit suite (unaligned streaming outputs, the 50 frozen Java
  vectors and scoped restoration of wallet test network globals);
- the complete unit suite, also with `--enable-debug` (`DEBUG_LOCKORDER`);
- the DePIN functional tests `feature_depin_pool_state.py` and
  `feature_depin_messaging_permissions.py` on regtest.

The fix was checked with GCC and Clang at several optimization levels, with
ASan/UBSan (`UBSAN_OPTIONS=halt_on_error=1`, without excluding SPH or the shift
and alignment checks), with `SPH_UNALIGNED=0` and `SPH_NO_ASM=1`, and with an
ARM64 executable under QEMU; every configuration matched all 4516 cases.

## Limits

ARM64 was checked by emulating the hash executable; no complete ARM64 node was
built and no physical ARM or big-endian hardware was tested. The historical
genesis and the existing KAWPOW and header suites were verified, but the
complete historical chain was not replayed. The corpus and sanitizers give
reproducible evidence and regressions, not an exhaustive proof over every
possible input. In microbenchmarks the fixed code changed SIMD/Fugue medians
by between -1.6% and +0.9%, X16R by +5.4% and X16RV2 by +0.4%; these are
diagnostic and do not measure real mining throughput.
