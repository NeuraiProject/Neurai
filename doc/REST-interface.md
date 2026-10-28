Unauthenticated REST Interface
==============================

The REST API can be enabled with the `-rest` option.

The interface runs on the same port as the JSON-RPC interface, by default port 19001 for mainnet, port 19101 for
testnet and port 19201 for regtest.

REST Interface consistency guarantees
-------------------------------------

The [same guarantees as for the RPC Interface](JSON-RPC-interface.md#rpc-consistency-guarantees)
apply.

Supported API
-------------

#### Transactions
`GET /rest/tx/<TX-HASH>.<bin|hex|json>`

Given a transaction hash: returns a transaction in binary, hex-encoded binary, or JSON formats.

By default, this endpoint will only search the mempool.
For full TX query capability, one must enable the transaction index via "txindex=1" command line / configuration option.

#### Blocks
`GET /rest/block/<BLOCK-HASH>.<bin|hex|json>`
`GET /rest/block/notxdetails/<BLOCK-HASH>.<bin|hex|json>`

Given a block hash: returns a block, in binary, hex-encoded binary or JSON formats.
Responds with 404 if the block doesn't exist.

The HTTP request and response are both handled entirely in-memory, thus making maximum memory usage at least 24 MB (8 MB max serialized block, plus hex encoding) per request.

With the /notxdetails/ option JSON response will only contain the transaction hash instead of the complete transaction details. The option only affects the JSON response.

#### Blockheaders
`GET /rest/headers/<COUNT>/<BLOCK-HASH>.<bin|hex|json>`

Given a block hash: returns <COUNT> amount of blockheaders in upward direction (at most 2000).
Returns empty if the block doesn't exist or it isn't in the active chain.

#### Chaininfos
`GET /rest/chaininfo.json`

Returns various state info regarding block chain processing: the same object as the `getblockchaininfo` RPC.
Only supports JSON as output format.
* chain : (string) current network name (main, test, regtest)
* blocks : (numeric) the current number of blocks processed in the server
* asset_marker : (string) marker required for new asset outputs in the next block ("rvn" or "xna")
* zk_public_tree, zk_portable_tree : (object) activation of the privacy pool profiles: activation_height (null when unscheduled), active_at_tip, active_for_next_block
* headers : (numeric) the current number of headers we have validated
* bestblockhash : (string) the hash of the currently best block
* difficulty : (numeric) the current difficulty
* difficulty_algorithm : (string) "DGW-180", or "BTC" before DGW activation (then DGW_activation_height is also present)
* mediantime : (numeric) the median time of the 11 blocks before the most recent block on the blockchain
* verificationprogress : (numeric) estimate of verification progress [0..1]
* chainwork : (string) total amount of work in active chain, in hexadecimal
* size_on_disk : (numeric) the estimated size of the block and undo files on disk
* pruned : (boolean) if the blocks are subject to pruning
* pruneheight : (numeric) lowest-height complete block stored (only present if pruning is enabled)
* automatic_pruning, prune_target_size : pruning settings (only present if pruning is enabled)
* softforks : (array) status of softforks in progress
* bip9_softforks : (object) status of BIP9 softforks in progress
* warnings : (string) any network and blockchain warnings

#### Query UTXO set
`GET /rest/getutxos/<checkmempool>/<txid>-<n>/<txid>-<n>/.../<txid>-<n>.<bin|hex|json>`

The getutxo command allows querying of the UTXO set given a set of outpoints (at most 15 per request).
See BIP64 for input and output serialisation:
https://github.com/bitcoin/bips/blob/master/bip-0064.mediawiki

Example on testnet (an output still in the mempool has height 2147483647):
```
$ curl localhost:19101/rest/getutxos/checkmempool/4d6f7e3a1c2b5a8d9e0f1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7-0.json 2>/dev/null | json_pp
{
   "chainHeight" : 70123,
   "chaintipHash" : "000000d6b2c08bcb8a7e4b4a2a7a1e3f6c2d0b9e8f7a6b5c4d3e2f1a0b9c8d7e",
   "bitmap" : "1",
   "utxos" : [
      {
         "height" : 2147483647,
         "value" : 8.8687,
         "scriptPubKey" : {
            "asm" : "OP_DUP OP_HASH160 1c7cebb529b86a04c683dfa87be49de35bcf589e OP_EQUALVERIFY OP_CHECKSIG",
            "hex" : "76a9141c7cebb529b86a04c683dfa87be49de35bcf589e88ac",
            "reqSigs" : 1,
            "type" : "pubkeyhash",
            "addresses" : [
               "t9XEconFHDitovkAr5ExeS8STCpMP9CKJS"
            ]
         }
      }
   ]
}
```

#### Memory pool
`GET /rest/mempool/info.json`

Returns various information about the TX mempool.
Only supports JSON as output format.
* size : (numeric) the number of transactions in the TX mempool
* bytes : (numeric) size of the TX mempool in bytes
* usage : (numeric) total TX mempool memory usage
* maxmempool : (numeric) maximum memory usage for the mempool in bytes
* mempoolminfee : (numeric) minimum feerate (XNA per KB) for tx to be accepted

`GET /rest/mempool/contents.json`

Returns transactions in the TX mempool.
Only supports JSON as output format.

#### Silent payment index (NIP-047 light clients)
Requires `-silentpaymentindex`. The data is the same as the RPC calls `getsilentpaymentindexinfo`,
`getsilentpaymenttweaks` and `getsilentpaymenttweaksrange`: for each block, every eligible transaction with a
native v3 output, its public tweak and all its native v3 outputs, plus every native v3 output the block spends.
Every client downloads the same data, so the server does not learn which payments belong to whom. It can omit
data, though: compare the `digest` of each block with other servers or with a recomputation from
`getblock <hash> 3`.

`GET /rest/spindexinfo.json`

State of the index (enabled, complete, height reached, missing ranges). Not cached.

`GET /rest/sptweaks/v1/<BLOCK-HASH>.<bin|hex|json>`

The record of one block. Its content never changes for a block hash, so the response is sent with
`Cache-Control: public, max-age=31536000, immutable`; it does not say whether the block is in the active chain.

`GET /rest/sptweaksrange/v1/<HEIGHT>/<COUNT>.<bin|hex|json>?anchor=<BLOCK-HASH>`

Consecutive blocks of the active chain from `<HEIGHT>`, whole blocks only (at least one, at most 1000 blocks and
4 MB). `anchor` is the hash the client has at `<HEIGHT> - 1`; if that block left the active chain the answer is
HTTP 409 with `{"reorg": true, "fork_height": n}` in JSON, and the client continues from `fork_height + 1`.
`next_height` and `status` tell how to continue: `more` (ask again now), `tip` (wait for a new block) or
`incomplete` (the index lacks data from `next_height`).

Binary format 1: a message starts with `"NSPT"`, the format (1), the type (1 block, 2 range) and the 35-byte
NIP-047 context. A block is `hash[32] prev[32] height:u32 n_entries entry* n_spent spent*`, with
`entry = txid[32] tweak[33] n_out (vout commitment[32] value:i64)*` and `spent = txid[32] vout`; counters and
`vout` are minimal CompactSize, hashes in internal byte order and integers little-endian. A range adds
`snapshot_height:u32 snapshot_hash[32] synced_height:u32 next_height:u32 status:u8 n_blocks` before its blocks.
Test vectors: `src/test/data/silentpayment_index_vectors.json`.

#### Channel messages (NIP-048)
`GET /rest/channelmessages/<FROM-HEIGHT>/<CHANNEL>.json`

Needs `-channelmessageindex`. The messages of an owner token (`NAME!`) or message channel (`NAME~CHANNEL`) from
`<FROM-HEIGHT>` to the tip, in chain order, as `getchannelmessages "<CHANNEL>" {"from_height": <FROM-HEIGHT>}`
returns them: expired messages are left out, judged against the median time past of the tip. At most 1000
messages are returned, without splitting a block; `next_from_height` is the `<FROM-HEIGHT>` of the next page, or
null at the end. The channel goes last because sub-asset names contain `/`. HTTP 503 when the index is disabled.

Risks
-------------
Running a web browser on the same node with a REST enabled neuraid can be a risk. Accessing prepared XSS websites could read out tx/block data of your node by placing links like `<script src="http://127.0.0.1:19001/rest/tx/1234567890.json">` which might break the nodes privacy.
