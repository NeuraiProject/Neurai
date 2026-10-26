Benchmarking
============

Neurai has an internal benchmarking framework (`src/bench/`). It is built by
default; `./configure --disable-bench` skips it. It covers, among others:

- hashing (`crypto_hash.cpp`: RIPEMD160, SHA1, SHA256, SHA512, ...) and Base58
- the rolling bloom filter, prevector, the locked memory pool and check queues
- script verification (`verify_script.cpp`), `OP_CHECKSIGADD`
  (`bench_checksigadd.cpp`), Ed25519 (`bench_ed25519.cpp`) and Poseidon
  (`bench_poseidon.cpp`)
- block checks (`checkblock.cpp`), coins cache (`ccoins_caching.cpp`), mempool
  eviction and wallet coin selection

After compiling Neurai, the benchmarks can be run with:
`src/bench/bench_neurai`

The output is CSV, one line per benchmark:
```
#Benchmark,count,min,max,average,min_cycles,max_cycles,average_cycles
RIPEMD160,448,0.001245033173334,0.002638196945190,0.002461894814457,...
SHA256,256,0.002209486499909,0.008500099182129,0.004300644621253,...
...
```

Times are in seconds; the cycle columns are filled in only where the platform
provides a cycle counter.
