# Cost of reference inputs when a block connects (NIP-014)

`vrefin_block_cost.py` builds blocks on regtest whose transactions reference
outputs (NIP-014) and measures how long the node takes to connect each one and
how much its peak resident memory grows while it does. A reference costs 36
bytes of block space and the node copies the whole referenced output, up to
10,000 bytes of scriptPubKey, for every transaction that references it.

Blocks:

| Block | What it measures |
| --- | --- |
| baseline | 780 transactions without references |
| adversarial | 780 standard transactions of 64 references each, all to the same 64 outputs of 10,000 bytes: about 500 MB of copies |
| distinct | 19,200 references to different small outputs: the lookup of each reference |
| slow checks | 360 transactions whose script runs `OP_POSEIDON` close to the block budget, without references |
| slow checks + references | the same with the 64 references of the adversarial block |

Each block is measured when it is submitted, and again after
`invalidateblock`, a restart (cold UTXO cache, fresh peak memory) and
`reconsiderblock`, with `-par=0` (automatic script check threads), `-par=1`
(none) and `-par=2` (one, as on a two-core node).

## Run

From the repository root, after building `neuraid`:

```
taskset -c 0-15 python3 contrib/nip014/vrefin_block_cost.py
```

On hybrid CPUs pin the run to one kind of core. It takes about a minute.

## Results (2026-11-24, i9-14900K, P-cores, after `3c347f4`)

| Block | `-par=0` | `-par=1` | `-par=2` |
| --- | --- | --- | --- |
| baseline | 0.011 s, +1 MB | 0.033 s, +1 MB | 0.020 s, +1 MB |
| adversarial | 0.671 s, +4 MB | 0.695 s, +4 MB | 0.669 s, +4 MB |
| distinct, 19,200 references | 0.017 s, +4 MB | 0.028 s, +4 MB | 0.017 s, +4 MB |
| slow checks | 0.261 s, +1 MB | 1.955 s, +1 MB | 0.987 s, +1 MB |
| slow checks + references | 0.362 s, +9 MB | 2.281 s, +3 MB | 1.200 s, +204 MB |

- Looking a reference up costs about 1 µs, with the UTXO database in the page
  cache.
- Copying the referenced outputs costs about 0.7 s per 2 MB block in the
  adversarial case, against 0.02 s without references.
- The copies stay in memory while their transaction waits in the script check
  queue. When checks are slower than the copies and there are few check
  threads, the queue keeps almost all of them: 204 MB of the 230 MB the block
  copies.
