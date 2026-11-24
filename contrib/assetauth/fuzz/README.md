# Fuzzer for OP_CHECKASSETAUTH (NIP-054)

`assetauth_fuzz.cpp` checks `src/script/assetauth.cpp`, policy versions 1 and
2, with libFuzzer. The first input byte picks a mode:

- **decode**: an arbitrary stack goes through `DecodeAssetAuthCall` and
  through an independent decoder written from the NIP; both must return the
  same error and, on success, the same call.
- **evaluate**: a transaction is built from a small vocabulary of inputs,
  outputs and referenced outputs whose meaning the harness knows (family,
  asset, owner name, message, signature type). An abstract model of the rules,
  written from the NIP and blind to scripts, predicts the exact error, whether
  the call went asynchronous and the work `W`. The implementation must match
  all three. A budget of `W` must pass with `W` charged and one of `W - 1`
  must fail with the budget error. The call must give the same result through
  `VerifyScript` as a real custody script. For version 2, reordering the vote
  references must not change the result.

Any disagreement aborts and leaves the input as an artifact. Rerun it after
any change to the evaluator.

## Build (Debian 12: `clang`)

The harness links against the static libraries of a configured and built
tree; only `assetauth.cpp` and the harness are instrumented. From the
repository root, with `D` the depends prefix:

```
FLAGS="-std=c++20 -O1 -g -DHAVE_CONFIG_H -D__STDC_FORMAT_MACROS -DBOOST_SP_USE_STD_ATOMIC \
  -DBOOST_AC_USE_STD_ATOMIC -pthread -Isrc -Isrc/config -Isrc/obj -I$D/include \
  -Isrc/leveldb/include -Isrc/secp256k1/include -Isrc/univalue/include"
SAN="-fsanitize=address,undefined -fno-sanitize-recover=undefined"
clang++ $FLAGS $SAN -fsanitize=fuzzer -c contrib/assetauth/fuzz/assetauth_fuzz.cpp -o assetauth_fuzz.o
clang++ $FLAGS $SAN -fsanitize=fuzzer-no-link -c src/script/assetauth.cpp -o assetauth_instr.o
cd src && clang++ $SAN -fsanitize=fuzzer -pthread ../assetauth_fuzz.o ../assetauth_instr.o \
  -Wl,--start-group libneurai_server.a libneurai_wallet.a privacy/libneurai_privacy.a \
  libneurai_common.a libneurai_util.a libneurai_zmq.a libneurai_consensus.a \
  crypto/libneurai_crypto.a crypto/libneurai_mcl.a univalue/.libs/libunivalue.a \
  leveldb/libleveldb.a leveldb/libleveldb_sse42.a leveldb/libmemenv.a \
  secp256k1/.libs/libsecp256k1.a -Wl,--end-group \
  -L$D/lib -lboost_system-mt-x64 -lboost_filesystem-mt-x64 -lboost_program_options-mt-x64 \
  -lboost_thread-mt-x64 -lboost_chrono-mt-x64 -levent_pthreads -levent -lssl -lcrypto -loqs \
  -lzmq -lminiupnpc -L/root/db4/lib -ldb_cxx-4.8 -lrt -ldl -lm -o ../assetauth_fuzz
```

## Run

```
mkdir -p corpus artifacts
setarch x86_64 -R ./assetauth_fuzz -fork=8 -max_total_time=3600 -artifact_prefix=artifacts/ corpus
```

As with the P-256 fuzzer, ASan processes may crash at start on kernels with
`vm.mmap_rnd_bits = 32`, and `-fork` gives up on the first one: disable ASLR
for the process with `setarch x86_64 -R`, which inside Docker needs
`--security-opt seccomp=unconfined`.

## Results

2026-11-24, after policy version 2: one hour with `-fork=8`, about 37 million
executions, no disagreement and no sanitizer report.
