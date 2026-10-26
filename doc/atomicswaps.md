# HOWTO: Atomic Swaps

__Or, trading apples for bananas.__


## The Problem

> The addresses and txids below are illustrative values from an old example;
> use your own testnet addresses and UTXOs.

_Andy has some apples.  Barb has some bananas.  Andy agrees to give Barb two apples in exchange for one banana.  In order to make sure both parties hold up their end of the deal they need to create a single transaction that sends assets both directions._

## The Inputs

We'll need to find 3 UTXOs to use as inputs.  Andy's apples, Barb's bananas and some Neurai to pay the network fee (Andy will pay).

Andy uses `listunspent` to find a suitable `txid` and `vout`:

```
﻿{
  "txid": "631cf1566165803f0b89fbfb169d8f0c89129ec3f8536a48e4c4f0f3c4081cff",
  "vout": 0,
  "address": "mh8mmbCPqnxCNqJq547NG99pauTHqvvYjA",
  "scriptPubKey": "21027e1fde02d2cbfac3629aeaf669abd156d0c4dfbf52f6a5e4dd6664e81a621045ac",
  "amount": 4.88281250,
  "confirmations": 3088,
  "spendable": true,
  "solvable": true,
  "safe": true
}
```

Then each party uses `listmyassets` with `verbose=true` to find asset UTXOs:

Andy:
`listmyassets APPLES true`:

```
{
  "APPLES": {
    "balance": 1000,
    "outpoints": [
      {
        "txid": "744c61abe6d237939c3567bc44b912ff4c375984229908c964be44f36dec79e3",
        "vout": 3,
        "amount": 1000
      }
    ]
  }
}
```

Barb:
`listmyassets BANANAS true`:

```
{
  "BANANAS": {
    "balance": 1000,
    "outpoints": [
      {
        "txid": "8468ef5193b1f5d6a7bd501f5f8ef5aec7c3d86fa87cec5a0b6f6d86fba78a4f",
        "vout": 3,
        "amount": 1000
      }
    ]
  }
}
```

Extracting the txids and vouts gives us our raw inputs:
`'[{"txid":"631cf1566165803f0b89fbfb169d8f0c89129ec3f8536a48e4c4f0f3c4081cff","vout":0}, \
   {"txid":"744c61abe6d237939c3567bc44b912ff4c375984229908c964be44f36dec79e3","vout":3}, \
   {"txid":"8468ef5193b1f5d6a7bd501f5f8ef5aec7c3d86fa87cec5a0b6f6d86fba78a4f","vout":3}]'`

## The Outputs

We'll be using 5 new Neurai addresses:

Andy's Neurai change address:
`mvGfeg4uZA8XvjVDUywdgYE6TAyz77o5gB`

Andy's banana receive address:
`msXQpCK8UexfgtMbUGwnKjDfE6vqJ4JUPF`

Barb's banana change address:
`mjyoMtEtoxw9edgzpNnEVTH7jqSqiQ529N`

Barb's apple receive address:
`mzPe6rUPYcbDbqnxRc5mcvKkASCAS9JBzL`

Andy's apple change address:
`mzct8GQ5zdaCvbrnRDrR8T87ZuZxkRYNwL`

All asset transfers have to be balanced.  Since we have 1000 APPLES coming in, we have to have 1000 going out.  So Andy will send 2 to Barb's receive address and the rest (998) to his change address.  The Neurai will pay 0.0001 for the network fee as normal.

`'{"mvGfeg4uZA8XvjVDUywdgYE6TAyz77o5gB":4.8827125, \
  "msXQpCK8UexfgtMbUGwnKjDfE6vqJ4JUPF":{"transfer":{"BANANAS":1}}, \
  "mjyoMtEtoxw9edgzpNnEVTH7jqSqiQ529N":{"transfer":{"BANANAS":999}}, \
  "mzPe6rUPYcbDbqnxRc5mcvKkASCAS9JBzL":{"transfer":{"APPLES":2}}, \
  "mzct8GQ5zdaCvbrnRDrR8T87ZuZxkRYNwL":{"transfer":{"APPLES":998}}}'`

## Creating The Transaction

Andy can now use `createrawtransaction`, passing in the inputs and outputs and receiving the transaction hex:

```
createrawtransaction '[{"txid":"631cf1566165803f0b89fbfb169d8f0c89129ec3f8536a48e4c4f0f3c4081cff","vout":0},{"txid":"744c61abe6d237939c3567bc44b912ff4c375984229908c964be44f36dec79e3","vout":3},{"txid":"8468ef5193b1f5d6a7bd501f5f8ef5aec7c3d86fa87cec5a0b6f6d86fba78a4f","vout":3}]' '{"mvGfeg4uZA8XvjVDUywdgYE6TAyz77o5gB":4.8827125,"msXQpCK8UexfgtMbUGwnKjDfE6vqJ4JUPF":{"transfer":{"BANANAS":1}},"mjyoMtEtoxw9edgzpNnEVTH7jqSqiQ529N":{"transfer":{"BANANAS":999}},"mzPe6rUPYcbDbqnxRc5mcvKkASCAS9JBzL":{"transfer":{"APPLES":2}},"mzct8GQ5zdaCvbrnRDrR8T87ZuZxkRYNwL":{"transfer":{"APPLES":998}}}'
```

It returns the unsigned transaction hex. Each asset output script ends with
the asset marker (`OP_XNA_ASSET`) and its payload; since NIP-040 the payload
starts with the `xna` prefix (older examples and pre-NIP-040 UTXOs show
`rvn`).

## Signing The Transaction

Ok, the structure of the transaction is set.  Now each party needs to sign it in order to unlock the inputs.  Here are the steps:

* Andy signs it using `signrawtransaction`.  This will alter the hex, using his wallet to insert the signatures.

> **Note:** Since Andy doesn't have the keys for all of the inputs he will see an error: `"Unable to sign input, invalid stack size (possibly missing key)" This is normal and expected.`

* Andy sends the signed hex to Barb.
* Barb uses `signrawtransaction` to sign the rest of the inputs.  Again capture the hex output.

## Submit The Transaction

Almost there.  Barb now passes the fully signed hex to `sendrawtransaction`!  It will be communicated to the network and put into the next block.
