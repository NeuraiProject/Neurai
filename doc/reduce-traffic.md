Reduce Traffic
==============

Some node operators need to deal with bandwidth caps imposed by their ISPs.

By default, neuraid allows up to 256 connections to different peers, 12 of
which are outbound. You can therefore have at most 244 inbound connections.

The default settings can result in relatively significant traffic consumption.

Ways to reduce traffic:

## 1. Use `-maxuploadtarget=<MiB per day>`

A major component of the traffic is caused by serving historic blocks to other nodes
during the initial blocks download phase (syncing up a new node).
This option can be specified in MiB per day and is turned off by default.
This is *not* a hard limit; only a threshold to minimize the outbound
traffic. When the limit is about to be reached, the uploaded data is cut by no
longer serving historic blocks (blocks older than one week).
Keep in mind that new nodes require other nodes that are willing to serve
historic blocks.

Whitelisted peers (`-whitelist`) will never be disconnected, although their traffic counts for
calculating the target.

## 2. Disable "listening" (`-listen=0`)

Disabling listening will result in fewer nodes connected (remember the maximum of 12
outbound peers). Fewer nodes will result in less traffic usage as you are relaying
blocks and transactions to fewer nodes.

## 3. Reduce maximum connections (`-maxconnections=<num>`)

Reducing the maximum connected nodes to a minimum could be desirable if traffic
limits are tiny. Keep in mind that neurai's trustless model works best if you are
connected to a handful of nodes.

## 4. Turn off transaction relay (`-blocksonly`)

Forwarding transactions to peers increases the P2P traffic. To only sync blocks
with other peers, you can disable transaction relay.

Be reminded of the effects of this setting.

- Fee estimation will no longer work.
- It does not change `-walletbroadcast`: the wallet still broadcasts its own
  transactions, which then stand out because the node relays no others. Set
  `-walletbroadcast=0` yourself if privacy matters.
- It sets `-whitelistrelay=0` unless set explicitly; peers whitelisted with
  `-whitelistforcerelay` still have their transactions received and relayed.
- It makes block propagation slower because compact block relay can only be
  used when transaction relay is enabled.
