# Clock configuration for nodes and mining pools

Keep the operating system clock synchronized and monitor its offset independently
of Neurai. Neurai's peer time adjustment does not synchronize the system clock.

By default, Neurai accepts a median adjustment of at most **300 seconds** in either
direction, using samples from persistent outbound connections. Inbound peers,
feeler probes and one-shot address discovery connections do not contribute.
Their individual offsets remain visible in `getpeerinfo` for diagnostics.

An out-of-range median resets the adjustment to zero; it is not clamped to the
limit. The existing minimum sample count, per-address deduplication and bounded
sample history are retained. With too few eligible samples, the initial adjustment
is zero. Outbound peers are not trusted time servers: monitor the system clock
rather than relying on them to repair it.

For a pool with a correctly synchronized system clock, disable peer adjustment:

```ini
# neurai.conf
maxtimeadjustment=0
```

The equivalent command-line option is `-maxtimeadjustment=0`. Restart the node
after changing its startup configuration. This option is also available in older
releases. Verify `getnetworkinfo.timeoffset` is zero; individual peer offsets in
`getpeerinfo` can still be nonzero. Continue monitoring the host clock when this
option is used.

An explicit positive `-maxtimeadjustment=<seconds>` overrides the default; a
negative value is treated as zero, as before. Values above 300 increase exposure
to peer clock manipulation and can exceed the block future-time allowance.

This changes local time policy, not block timestamp consensus rules or their
activation heights. It can change whether a near-future block is temporarily
accepted. For the 720-second DGW allowance, two nodes at opposite default
adjustments differ by at most 600 seconds due to peers alone; actual system-clock
errors consume the remaining margin. Mining templates still respect median time
past as well as adjusted time. A well-synchronized system clock remains necessary.
