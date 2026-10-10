# Internal mining and historical chain behavior

## Internal CPU miner

With wallet support enabled and a loaded wallet able to reserve a mining key,
`setgenerate true 1` starts one internal mining thread. `setgenerate false`
interrupts and joins all mining threads before returning. Another start command
replaces the previous workers, and a processor limit of zero stops mining.
`getgenerate` reports the requested setting, not evidence of accepted blocks:
check the block count and logs for progress or local errors.

The internal miner searches the nonce used by the active hash algorithm:
64-bit `nNonce64` for KAWPOW, and 32-bit `nNonce` for legacy X16R/X16Rv2
(and SHA256d in branches that support it). It stores the successful KAWPOW mix
hash in the submitted block. Searches yield after a bounded number of attempts,
check thread interruption between hashes, and rebuild the template when the
nonce space is exhausted. A context construction or one hash computation can
still delay cancellation; there is no fixed wall-clock stop guarantee.

The miner is useful for development and isolated network tests. This repair
does not make CPU KAWPOW mining competitive with external GPU miners. It does
not change external mining RPC protocols, block validity rules, or difficulty.
Regtest uses `generate`/`generatetoaddress` instead of the `setgenerate` RPC.
See [Mining clocks](mining-time.md) for pool clock configuration.

## Historical mainnet rewards

`GetBlockSubsidy` retains its original floating-point expression
`50000 * COIN * pow(0.95, halvings)` followed by conversion to `CAmount` for
mainnet heights below 518400 (the first 36 intervals of 14400 blocks). Later
intervals use fixed integer rewards. Branches with different testnet subsidy
schedules must be reviewed separately; the mainnet height does not describe
those schedules.

The old expression still matters when replaying historical blocks during
initial synchronization, import, or reindexing. Replacing it with a seemingly
equivalent integer calculation or rounded table can change the reward by
individual base units. Any such replacement needs exact comparison against
the historical results. This maintenance change preserves the expression and
all reward rules.

## Deep reorganizations

Mainnet's default maximum reorganization depth is 60 blocks, subject to a
minimum of six connected peers and an active tip no more than twelve hours
old. The check is conditional on the connection manager and uses local state;
`-maxreorg`, `-minreorgpeers`, and `-minreorgage` can override its parameters.
Other networks or activation rules may use different defaults.

This is a local restriction, not a guarantee of network-wide finality. Nodes
with different tips, peer counts, or settings can disagree about admitting a
deep alternative chain even when it has more accumulated work. When diagnosing
`bad-fork-prior-to-maxreorgdepth`, compare chain tips, work, peer connectivity,
and configuration before taking recovery action. There is no blanket
recommendation here to disable the protection. Its behavior is unchanged.

## DGW and block timestamps

Dark Gravity Wave derives the next target from previous targets and block
timestamps. An adversary able to influence enough of the mined blocks can
influence those inputs. Timestamp validity checks and the peer-clock hardening
reduce distinct risks; they do not establish that DGW is immune to timestamp
manipulation.

This document records the inherited design limitation without changing the
retarget algorithm. A proposed mitigation needs separate consensus review,
historical replay tests and, where necessary, an explicit activation.
Historical regression vectors preserve the existing target limits and
256-bit retarget arithmetic. Changing either requires a separate consensus
proposal; the difficulty admission checks do not change their results.

## Difficulty admission

Incoming full blocks must have a known parent and the exact difficulty required
by that parent before full proof-of-work and transaction checks run. The check
also applies to forced submissions and uses the candidate branch, not the active
tip. New headers are checked for the same difficulty before full proof-of-work.

A full block whose parent is unavailable is deferred without penalizing its
sender or recording permanent invalidity. It can be submitted again once its
parent is available. Import and reindex retain their handling of blocks stored
out of order. This admission step does not change target limits, the retarget
algorithm, or the proof-of-work and transaction checks required for acceptance.

The standalone regression can exercise each network against a built daemon:

```sh
python3 test/functional/standalone/block_work_admission.py \
  --neuraid src/neuraid --network main --tmpdir /tmp/neurai-work-test
```

Use a new empty output directory for each run. Repeat with `--network test` and
`--network regtest` when validating either maintained branch.
