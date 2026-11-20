# Differential fuzzer for the P-256 verifier

`p256_diff_fuzz.cpp` checks `src/crypto/p256.cpp` (NIP-060, consensus code)
against OpenSSL with libFuzzer. For every input both sides must agree on the
structural result and its precedence (public key before signature), on the
decompressed point and on the verification result; any disagreement aborts and
leaves the input as an artifact. Half of the inputs are raw bytes; the other
half are valid signatures built with OpenSSL and then mutated (bit flips, high
S, r or s at their bounds, the negated key, truncations).

Rerun it after any change to the verifier.

## Build (Debian 12: `clang`, `libssl-dev`)

From the repository root, after `./configure` (for `src/config/neurai-config.h`):

```
clang++ -std=c++17 -O1 -g -DHAVE_CONFIG_H -fsanitize=fuzzer,address,undefined \
  -fno-sanitize-recover=undefined -Wno-deprecated-declarations \
  -Isrc -Isrc/config contrib/p256/fuzz/p256_diff_fuzz.cpp \
  src/crypto/p256.cpp src/crypto/sha256.cpp src/crypto/sha256_sse4.cpp \
  -lcrypto -o p256_diff_fuzz
python3 contrib/p256/fuzz/make_seeds.py src/test/data/p256_vectors.json seeds
mkdir -p corpus
./p256_diff_fuzz -fork=8 -max_total_time=10800 corpus seeds
```

On kernels with `vm.mmap_rnd_bits = 32` the ASan runtimes of GCC 12 and
clang 14 hang or crash at start in about a third of the runs. Run the fuzzer
(and any sanitizer build) with ASLR disabled for the process,
`setarch x86_64 -R ./p256_diff_fuzz ...`; inside Docker that needs
`--security-opt seccomp=unconfined`.
