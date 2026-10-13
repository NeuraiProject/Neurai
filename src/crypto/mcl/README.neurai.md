# Neurai BN254 backend source pin

Upstream: https://github.com/herumi/mcl
Commit: cbb18eb08b86129cf936a6436b5e6c68a2ce8ddf

`UPSTREAM.json` records the source archive hash and SHA-256 of every upstream
file included here. `include/`, `src/`, COPYRIGHT and readme.md are preserved
byte-for-byte. Only `src/fp.cpp` is compiled. Other source files include generated
headers and implementation templates required by it; assembly and generators are
retained for provenance but not invoked by the Neurai build. No network fetch or
upstream Makefile execution is needed. Generated upstream headers are frozen.

License: BSD-3-Clause, see COPYRIGHT and individual source notices. Upstream
also credits xbyak, cybozulib and Lifted-ElGamal; retain these notices when
redistributing sources or binaries, including when JIT is disabled.

Build: src/Makefile.mcl.include. Required static library, Fp/Fr capacity 256/256,
BN_SNARK1 only, no Xbyak/JIT, LLVM, BINT assembly, specialized MSM or external
GMP. The same portable implementation targets baseline x86-64 or little-endian
ARMv8-A; incompatible user ISA flags fail in mcl_config.h. Compiler flags are
selected from the configured host CPU in configure.ac. Other architectures
remain outside the integration scope. ARM64 functional validation runs the
existing differential corpus and concurrent-initialization test under Linux
QEMU with UBSan. Cross-compilation does not establish macOS runtime validation.

Both compiled translation units use private `neurai_mcl_detail` and
`neurai_cybozu_detail` namespaces through target-local preprocessing. Public
headers never expose upstream types. Do not include these headers from arbitrary
node translation units or change curve/global modes after initialization. Future
BLS integration must use separately isolated state; it must not call initPairing
on this instance. The namespace prefix prevents accidental reuse of ordinary
upstream C++ symbols, not deliberate access to private implementation details.

The public wrapper currently only initializes and checks the backend once. It is
called during node startup and from tests; failures are sticky and abort startup.
The checks use public EIP generators, fixed G1 doubling coordinates, a nontrivial
pairing and a bilinear identity. They do not constitute a full cryptographic
audit. No OP_ZKVERIFY implementation or activation is introduced in this stage.

Before changing this pin/configuration, repeat the external differential corpus,
primitive vectors, instrumentation, build and node startup checks. The existing
ASan/UBSan evidence predates this namespace/build integration; the integrated
build has separate functional evidence in the review report.
