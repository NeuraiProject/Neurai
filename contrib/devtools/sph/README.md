# SPH hash compatibility checks

These tools compare the actual C/C++ algorithms used by `HashX16R` and
`HashX16RV2` with the separate Java implementation from the SPH author. They
have no RPC, wallet, mining thread, or network access. Run them in a disposable
build environment with the node's usual dependencies and a configured source
tree (`src/config/neurai-config.h` must exist).

Reference: <https://github.com/pornin/sphlib>, commit
`15b6b8d8f3e4a43c58ba102d712fa6b8a3317035`. The archive from
<https://codeload.github.com/pornin/sphlib/tar.gz/15b6b8d8f3e4a43c58ba102d712fa6b8a3317035>
has SHA-256
`d89412f9e757c76e41e35d0038dbbdecb88f3a40267c399606bf30da51095acd`.
Verify the archive before extracting it. These scripts do not fetch dependencies
or update the reference automatically. The upstream source retains its own
license.

## Independent reference and differential corpus

From the configured Neurai root, with `upstream` pointing to the verified sphlib
source directory and `out` to a new scratch directory:

```sh
python3 contrib/devtools/sph/generate_corpus.py "$out"
mkdir -p "$out/java"
javac --release 8 -d "$out/java" "$upstream"/java/fr/cryptohash/*.java contrib/devtools/sph/SphReference.java
java -cp "$out/java" SphReference < "$out/corpus.txt" > "$out/reference.txt"
python3 contrib/devtools/sph/build_compat.py "$PWD" "$out/gcc-O2"
"$out/gcc-O2/sph-compat" < "$out/corpus.txt" > "$out/gcc-O2.txt"
cmp "$out/reference.txt" "$out/gcc-O2.txt"
```

The fixed corpus has 4,516 cases: all 16 X16 component hashes, 44 boundary
lengths, zero/ones/pattern inputs, seeded random data, long SIMD/Fugue messages,
every repeated X16 selector, mixed selectors, and the mainnet genesis header.
`corpus.json` records the seed, input SHA-256 and case descriptions. Java computes
the expected digests independently; the C++ runner calls the production X16
functions. X16RV2's Tiger output is padded to 64 bytes with zeros before the
selected component. X16 outputs use displayed network byte order; individual
512-bit digests use their normal byte order.

Repeat with separate output directories and compare **every** output byte:

| Variant | Builder options |
|---|---|
| GCC debug / optimized | `--opt=-O0`, `--opt=-O2`, `--opt=-O3` |
| Portable byte access | `--portable` |
| GCC ASan + UBSan | `--sanitize --opt=-O1` |
| Clang optimized | `--cc clang-14 --cxx clang++-14 --opt=-O2` or `-O3` |
| Clang ASan + UBSan | `--cc clang-14 --cxx clang++-14 --sanitize --opt=-O1` |
| ARM64 executable | `--cc aarch64-linux-gnu-gcc --cxx aarch64-linux-gnu-g++` |

Run sanitizer variants with
`ASAN_OPTIONS=handle_segv=0:detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`.
The Linux sanitizer executables are linked without PIE. These options reproduce
the isolated test environment; leak checking is outside this report. No SPH
sanitizer is disabled. ARM64 can run with
`qemu-aarch64 -L /usr/aarch64-linux-gnu "$out/arm64/sph-compat"`.
This tests the ARM64 hash executable under emulation, not an ARM64 node build.
The builder retains compiler commands and logs, and enables strict aliasing.

For a before/after comparison, build the runner against the unchanged base
algorithms in a separate checkout **before** applying the patch. Preserve that
binary, its source hashes and outputs. Expected vectors must come from the Java
reference, never from the newly patched C implementation.

## Published bit vectors and alignment

```sh
python3 contrib/devtools/sph/check_nist.py "$PWD" "$upstream" "$out/nist"
gcc -std=c11 -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie -no-pie -Isrc contrib/devtools/sph/check_types.c -o "$out/types"
ASAN_OPTIONS=handle_segv=0:detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 "$out/types"
```

`check_nist.py` runs the upstream C tests against this tree's SIMD/Fugue and
`algo/sph_types.h`: 8,192 published bit-length vectors per algorithm (224, 256,
384 and 512-bit variants), plus the upstream type tests. Each vector is checked
with aligned and unaligned input. It uses GCC, GCC ASan/UBSan and Clang. The copied
upstream harness has one compatibility fix: avoid `memcpy(dst, NULL, 0)` for the
empty vector. Expected hashes and production code are unchanged. The initial
harness sanitizer failure must not be confused with a production algorithm
failure or suppressed globally.

`check_types.c` makes 20,800 byte-order/alignment/canary checks. Also compile with
`-DSPH_TYPES_HEADER='"crypto/sph_types.h"'` to check the second header copy, with
Clang sanitizers, and with ARM64 default and portable options. The committed
`sph_tests` unit suite additionally checks unaligned streaming outputs, 50 frozen
Java vectors and scoped restoration of wallet test network globals. Run the
full node tests and the DePIN functional tests as described in
[the compatibility report](../../../doc/sph-hash-compatibility.md).

## Performance and limits

`sph-compat --bench` reports microseconds, input size, iterations, and a digest
guard. Compare the preserved base and patched GCC `-O2` binaries in alternating
rounds after other builds/tests finish. Guards must match. Timings from a shared
Docker host are diagnostic, not a mining throughput guarantee.

The historical mainnet genesis has a fixed expected X16R hash. Subsequent mainnet
blocks use KAWPOW, whose code and activation are unchanged. Synthetic headers
exercise X16R/X16RV2 compositions; they are not a replay of the historical chain.
