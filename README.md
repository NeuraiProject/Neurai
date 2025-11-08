Neurai - DePIN Messaging Experimental
=====================================


![Title](img/neurai-title.jpg)

https://neurai.org

To see how to run Neurai, please read the respective files in [the doc folder](doc)


What is Neurai?
----------------
Neurai is a decentralized open source protocol optimized to transfer cryptoassets from one party to another on Layer1. The project aims to integrate NFT and Tokens with IoT and artificial intelligence applications.

What is DePIN Messaging?
----------------
Is a private and temporary messaging system for Neurai that enables encrypted communication between holders of a specific token. 


- **Does not write to blockchain**:no fees, no permanence.
- **Encrypted messages**: only readable by token holders.
- **Direct communication**: between nodes via TCP or relay Nodes with same configuration.
- **Temporal message**: with max 7-day expiration, custom time or all read msg check.
- **Token ownership verification**: to send/receive.
- **Integrated TCP server**: for remote queries.

```
┌─────────────────────────────────────────────────────────────┐
│               Neurai Node with DePIN Messaging              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐        ┌──────────────┐                   │
│  │ RPC Server   │────────│ DePIN MsgPool│                   │
│  │ (neurai-cli) │        │   Manager    │                   │
│  └──────────────┘        └──────┬───────┘                   │
│                                 │                           │
│                         ┌───────┴─────────┐                 │
│                         │                 │                 │
│                    ┌────▼────┐      ┌─────▼──────┐          │
│                    │ Message │      │ Network    │          │
│                    │ Storage │      │ Listener   │          │
│                    │ (7 days)│      │(Port 19002)│          │
│                    └────┬────┘      └─────┬──────┘          │
│                         │                 │                 │
│                    ┌────▼─────────────────▼─────┐           │
│                    │   Asset Index (-assetindex)│           │
│                    │   Token Holder Lookup      │           │
│                    └────────────────────────────┘           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

More about this  [Here](doc/README.md)

Network Details
----------------
```
Network Name: Neurai
Network Abbreviation: XNA
Mining Algorithm:  KAWPOW Proof-of-work
Block Time: 1 minute
Initial Block Size: 8 MB
Block Reward Schedule: 50,000 XNA per block
Block Reward Micro-halvening: 10 days (5%)
Maximum Supply: 21,000,000,000 XNA
Decimal Places: 8
Launch Date: 2023-04-17 08:40 UTC
Genesis: Fortune 16/April/2023  Elon Musk agrees A.I. will hit people like an asteroid 

Main Network: 19000
Main RPC: 19001
Testnet Network: 19100
Testnet RPC: 19101
Regtest Network: 19200
Regtest RPC: 19201

MAIN NETWORK
BIP32 Derivation Path: m/44'/0'/0'/0
BIP32 private: 0x0488ade4
BIP32 public: 0x0488b21e

Special derivation path for HW like Onekey
BIP32 Derivation Path: m/44'/1900'/0'/0

private: 0x80
public: 0x35
scripthash: 0x75

TESTNET NETWORK
BIP32 Derivation Path: m/44'/0'/0'/1
BIP32 private: 0x043587cf
BIP32 public:  0x04358394

private: 0x80
public: 0x7f
scripthash: 0x75
```

Code Source
-------
The Neurai code comes from Ravencoin and Ravencoin comes from Bitcoin.

License
-------

Neurai is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.


