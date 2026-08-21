Neurai — DePIN Messaging (Experimental)
==============

## WARNING
This is an experimental, off-chain messaging system for holders of a DePIN
asset. It is currently intended for testnet and regtest. See
[`depinreceivemsg.md`](depinreceivemsg.md) for the stable client-facing
retrieval and decryption contract.


## DePIN Messaging

Is a private and temporary messaging system for Neurai that enables encrypted communication between holders of a specific token. This system:

- **Does not write to blockchain**: no fees, no permanence.
- **Encrypted messages**: readable only by public keys selected by the sender.
- **One port**: everything is served by the node's standard JSON-RPC
  interface, typically behind an RPC proxy such as `neurai-rpc-proxy`. There
  is no separate listener.
- **Temporal message**: with max 7-day expiration, custom time or all read msg check.
- **Token ownership verification**: for sending, and challenge/signature
  authentication for every read or purge bound to an address.
- **Signed, encrypted replies**: every DePIN RPC response is signed with the
  node's pool key (`poolsig`); replies bound to an address are encrypted for
  that address's revealed public key.
- **Dedicated service wallet**: the pool key is derived from a legacy BIP44
  wallet configured on the node; without it the service does not start.


## Key Features

### 1. Hybrid encryption

- Message content is encrypted once with a fresh symmetric key.
- The symmetric key is ECIES-wrapped once for every recipient public key.
- A recipient needs its private key and a matching wrapped key to decrypt the
  content. An address without a revealed public key cannot be included.
- Recipient keys are a snapshot at send time. A later holder cannot decrypt
  historic content that was not encrypted for that key.

### 2. No Transaction Costs
- No network fees required
- Does not consume blockchain space
- Completely off-chain operation

### 3. Recipient resolution
- The node or client library can resolve active holders and their revealed
  public keys with `depingetancestorrecipients`.
- A send to a section includes active holders of that section and its
  ancestors, up to the serving pool root.
- Resolution requires both the asset index (`-assetindex`) and the public-key
  index (`-pubkeyindex`).

### 4. Automatic Expiration
- Messages expire after 7 days
- Automatic mempool cleanup
- Prevents data accumulation

### 5. Token-based access control

- Sending is authorized by an active holding in the target section's ancestor
  chain.
- Reads (`depinreceivemsg`, `depinlistsections` with an address) require a
  single-use challenge from `depinchallenge`, signed by the address; purges
  (`depinclearmsg`) require an owner-level challenge.
- Decryption remains cryptographic: `recipientKeys` in the message is the
  final visibility boundary.

### 6. Hierarchical Sections

Sub-assets of the pool token act as chat **sections** with downward
visibility. With `-depinmsgtoken=&TEST`:

- `&TEST` is the root; `&TEST/GENERAL` and `&TEST/OTHERS` are sections
  (creating a sub-DEPIN requires the parent's owner token, so only the root
  owner can open sections).
- An **active** holder of `&TEST` reads and writes in the root and in every
  descendant section.
- A holder of only `&TEST/GENERAL` participates there and in its descendants,
  never in the root or in sibling sections.

"Active" means: positive balance, not frozen by the owner (`freezedepin`) and
not self-revoked (`selfrevokedepin`). Access is inherited per (asset, address)
pair: an address revoked in a section but still holding the active root keeps
access — the root grants the branch, a section-level revocation cannot take
that away.

**How it works**: the `token` parameter of `depinsendmsg`, `depingetmsg`,
`depinchallenge` and `depinreceivemsg` accepts a section name. Sending to a
section encrypts for the active holders of the section **and of every
ancestor up to the pool root**; reading with a section token returns only that
section's subtree (its "tab"). `depinlistsections` lists the sections for UI
tabs — names only without arguments; the address mode (per-address access and
message counters) takes a challenge issued for a `scope` and reports that
scope's subtree. `depinclearmsg` takes a scope so a section owner can purge
their subtree (never parents or siblings); its `admin` challenge is bound to
exactly that scope. The root's subtree is the whole pool.

**Recipient scope**: a client publishing through a service node resolves
recipients with the pool's root as `stop_at` (`depingetmsginfo` publishes it).
This is deliberate: every extra `recipientKeys` entry is an extra reader, and
encrypting up to the absolute root would include holders of ancestors the
pool does not even serve.

**Recipient limit**: a send **fails** (never silently truncates) when the
union of eligible holders across the ancestor chain exceeds
`MAX_DEPIN_RECIPIENTS` (50). A leaf section can hit the limit before the root
does, because it aggregates the holders of all its ancestors.

**Privacy limits** (read before relying on sections):

- Section names, the hierarchy (`&TEST/GENERAL` → `&TEST`) and token holdings
  are **public on chain**. Sections protect message *content* (ECIES), not
  membership. Opaque labels (`&TEST/K7M2Q`) hide meaning from casual
  observers, but not existence, hierarchy or holdings.
- "The root sees everything" only holds for holders with a **revealed public
  key**; holders that never spent from their address are skipped (reported as
  `skipped_no_pubkey` in `depinsendmsg`).
- `recipientKeys` is a snapshot chosen by the sender: sections compute the
  legitimate recipient set, but cannot prove a sender did not add an external
  public key. The pool caps the recipient *count* per message as hardening.
- The token filter in `depinreceivemsg` is a scope. The challenge proves
  control of the address; what an address can actually read is fixed
  cryptographically by `recipientKeys` + ECIES.
- A pool configured on a deep section (`-depinmsgtoken=&TEST/GENERAL`) serves
  only that subtree: holders of `&TEST` are outside it for that node.
  Configure the pool at the root of what it is meant to serve.

---

## Technical Architecture

### Main Components

```
┌─────────────────────────────────────────────────────────────┐
│               Neurai Node with DePIN Messaging              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐        ┌──────────────┐    ┌───────────┐  │
│  │ RPC Server   │────────│ DePIN MsgPool│────│ Pool key  │  │
│  │ (JSON-RPC)   │        │   Manager    │    │ (wallet)  │  │
│  └──────▲───────┘        └──────┬───────┘    └───────────┘  │
│         │                       │                           │
│         │                ┌──────▼──────┐                    │
│         │                │  Challenge  │                    │
│         │                │    store    │                    │
│         │                └──────┬──────┘                    │
│         │                       │                           │
│         │                ┌──────▼──────┐                    │
│         │                │   Message   │                    │
│         │                │   Storage   │                    │
│         │                │   (7 days)  │                    │
│         │                └──────┬──────┘                    │
│         │                       │                           │
│         │           ┌───────────▼────────────────┐          │
│         │           │   Asset Index (-assetindex)│          │
│         │           │   Pubkey Index             │          │
│         │           └────────────────────────────┘          │
└─────────┼───────────────────────────────────────────────────┘
          │
   neurai-rpc-proxy (whitelist) ◄──── holder wallets (hold their own keys)
```


### Authenticated RPC flow (protocol 2)

Every DePIN operation is a regular JSON-RPC method on the node's RPC port.
A service node is published through an RPC proxy that whitelists the DePIN
methods; holders never get node credentials. Instead, a holder proves control
of an address with a challenge:

1. **Pin the pool key** (first contact). `depingetmsginfo` answers
   `{"body": "<hex>", "poolsig": "<base64>"}`; decoded, `body` carries
   `depinpoolpkey` and `depinpoolkeyaddress`. On first contact store that key
   with the service's identity (trust on first use; a pin shipped with the
   application avoids even that); from then on verify `poolsig` over the
   `body` or `encrypted` string of every reply with the pinned key, and treat
   a changed key as an alert. Message content is never readable by the node
   or the proxy regardless; the pin is what makes withheld or altered replies
   detectable.
2. **Request a challenge.** The request is signed by the address over the
   current time in milliseconds, `signmessage`-compatible:
   `DEPIN-REQ|<type>|<token>|<address>|<timestamp>` (a node holding the key:
   `depinsignrequest "address" "token" ("type")`). The node accepts it within
   60 s of its clock and never twice, so nobody can spend a holder's quota or
   evict its live challenges by naming its address.
   ```bash
   depinchallenge "&MYTOKEN/SEC" "NXholder..." 1730000000000 "<signature>"          # type receive (default)
   depinchallenge "&MYTOKEN" "NXowner..." 1730000000000 "<signature>" "admin"       # for depinclearmsg
   ```
   The reply is encrypted for the address's revealed public key and signed
   with the pool key: `{"encrypted": "<hex>", "poolsig": "<base64>"}`.
   Decrypting it yields `{"challenge": "<64 hex>", "expires_in": 30,
   "type": "receive"}`. A challenge is bound to the token, the address and
   the type, is consumed by its first valid use and expires after 30 s. Only
   a holder (or, for `admin`, an owner) of the token or an ancestor gets one.
3. **Sign the preimage** with the address's key, `signmessage`-compatible:
   `DEPIN-GET|<token>|<address>|<challenge>` for `receive`,
   `DEPIN-CLEAR|<token>|<address>|<challenge>` for `admin`. A node that holds
   the key can use `depinsignchallenge "address" "token" "challenge" ("type")`.
4. **Call the RPC** with the challenge and signature:
   ```bash
   depinreceivemsg "&MYTOKEN/SEC" "NXholder..." "<challenge>" "<signature>" (timestamp "after_hash" limit)
   depinlistsections "NXholder..." "&MYTOKEN/SEC" "<challenge>" "<signature>"
   depinclearmsg "&MYTOKEN/SEC" "NXowner..." "<challenge>" "<signature>" ("all" | hours)
   ```
   A failed signature, a nonce issued for other bindings, or an address that
   lost access between issuance and use is refused — and the refusal never
   consumes the nonce, so nobody can burn someone else's challenge. Every
   authenticated reply carries `next_challenge` (valid 300 s) inside its
   encrypted body: sign it for the next call and `depinchallenge` is needed
   only once per conversation.
5. **Verify and decrypt the reply.** Every reply carries `poolsig`, the pool
   key's compact signature over
   `DEPIN-RESP|<method>|<token>|<address>|<challenge>|<sha256 hex of the body>`
   where the body is the `encrypted` hex string (replies bound to an address)
   or the `body` hex string (plain replies such as `depingetmsginfo`, which
   carry their JSON hex-encoded), hashed exactly as received. It is
   `verifymessage`-compatible against `depinpoolkeyaddress`. Verify first,
   then decrypt `encrypted` with the address's key or hex-decode `body`.

To publish a message through a service node, prepare it client-side: resolve
recipients (`depingetancestorrecipients` with the pool root as `stop_at`),
encrypt and sign the `CDepinMessage`, wrap the serialized hex in an ECIES
envelope for `depinpoolpkey`, and call
`depinsubmitmsg {"sender": "NXfrom...", "encrypted": "<hex>"}`. The bare hex
form no longer exists. The reply is encrypted for the sender.

`depingetpoolcontent` was removed: it exposed metadata of the whole pool and
had no identity to bind a challenge to. `depinpoolstats` keeps the aggregate
counters.

## System Requirements

### Mandatory Requirements

#### 1. Active Asset Index (`-assetindex`)
**REQUIRED** for DePIN messaging functionality.

```bash
# In neurai.conf
assetindex=1
```

**⚠️ Important**:
- If this is your first time activating `-assetindex`, you need to do a **full reindex**
- Reindexing can take several hours depending on blockchain size
- Increases disk usage by ~20-30%

**Reindex command**:
```bash
neuraid -reindex
```

#### 2. Revealed public-key index (`-pubkeyindex`)

**REQUIRED** for DePIN message encryption and recipient discovery.

```bash
# In neurai.conf
pubkeyindex=1
```

Changing this index requires rebuilding chainstate:

```bash
neuraid -reindex-chainstate
```

#### 3. Existing DEPIN Token
You must specify a valid **DEPIN** token (soulbound asset) that exists on the Neurai blockchain:
- Must be a **DEPIN** token, i.e. a name starting with `&` (e.g., `&MYTOKEN`)
- Can also be a **sub-DEPIN** token (e.g., `&MYTOKEN/DEVICE`)

Other asset types (ROOT, QUALIFIER `#`, RESTRICTED `$`, MSGCHANNEL, UNIQUE) are
**rejected**: the node will refuse to start with `Invalid -depinmsgtoken`.

**⚠️ Network availability**: DEPIN assets are currently only available on
**testnet and regtest**. Mainnet support will be added once the feature is
thoroughly tested, so DePIN messaging cannot be enabled on mainnet for now.


### Message Sending Flow

```
1. Client reads depingetmsginfo: pool root, recipient limit, depinpoolpkey
                                    ↓
2. Client verifies that FROM_ADDRESS holds the selected section or an ancestor
                                    ↓
3. Resolve active holders with public keys, stopping at the pool root
   (depingetancestorrecipients "TOKEN" limit "POOL_ROOT")
                                    ↓
4. Refuse the send if the complete recipient set exceeds the pool's limit
                                    ↓
5. Encrypt the content once; ECIES-wrap the content key for each recipient
                                    ↓
6. Sign the serialized message with FROM_ADDRESS
                                    ↓
7. Wrap the serialized hex in an ECIES envelope for depinpoolpkey and call
   depinsubmitmsg {"sender": FROM_ADDRESS, "encrypted": "<hex>"}
                                    ↓
8. Pool opens the envelope, verifies scope, sender access, signature and size
                                    ↓
9. Store in its temporary pool; messages expire according to pool policy
```

On a node that holds the sender's key and runs the pool itself,
`depinsendmsg "TOKEN_OR_SECTION" "MESSAGE" "FROM_ADDRESS"` performs steps 2-9
locally. It never contacts another node.

### Data Structure

#### CDepinMessage
```cpp
struct CDepinMessage {
    string token;                    // "&MYTOKEN"
    string senderAddress;            // "NXa1b2c3d4e5f6..."
    int64_t timestamp;               // 1699564800 (UNIX time)
    vector<unsigned char> signature; // Sender's ECDSA signature

    // One symmetric ciphertext plus one ECIES-wrapped content key per recipient
    vector<unsigned char> encryptedPayload;
};
```

#### CDepinMsgPool
```cpp
class CDepinMsgPool {
    string activeToken;                    // Configured token
    map<uint256, CDepinMessage> mapMessages; // Hash -> Message
    multimap<int64_t, uint256> mapByTime;  // Timestamp -> Hash

    unsigned int nMaxRecipients;           // Recipient limit
    unsigned int nPort;                    // Server port
};
```

---

## Configuration

### Basic Configuration

Edit `neurai.conf`:

```ini
# REQUIRED: Enable asset index
assetindex=1

# REQUIRED: Index revealed public keys used for recipient encryption
pubkeyindex=1

# Enable DePIN messaging
depinmsg=1

# Required DEPIN token for chat (must start with &, testnet/regtest only)
depinmsgtoken=&MYTOKEN

# Abuse control the node can apply by itself: challenges issued and messages
# accepted per address and minute (0 = unlimited). Per-IP limits belong to the
# RPC proxy in front of the node.
depinratelimit=20

# Only when more than one wallet is loaded: which one is the service wallet.
# It must be an unencrypted legacy (non-PQ) BIP44 wallet; keep it dedicated and
# empty of funds -- its key is hot for as long as the node serves.
# depinwallet=depin.dat

# Maximum recipients (optional, default: 20, hard maximum: 50; must be >= 1)
depinmsgmaxusers=20
```

### First-Time Configuration (Reindex Required)

If this is your first time activating `-assetindex` or `-pubkeyindex`:

```bash
# 1. Stop the node
neurai-cli stop

# 2. Edit neurai.conf and add assetindex=1 and pubkeyindex=1

# 3. A full reindex rebuilds both indexes
neuraid -reindex

# 4. Wait for reindex to complete (may take hours)
#    You can monitor progress with:
neurai-cli getblockchaininfo
```

### Configuration for Different Use Cases

#### Small Group (< 10 members)
```ini
assetindex=1
pubkeyindex=1
depinmsg=1
depinmsgtoken=&TEAM       # DEPIN (soulbound) token — testnet/regtest only
depinmsgmaxusers=10
```

#### Medium Community (10-20 members)
```ini
assetindex=1
pubkeyindex=1
depinmsg=1
depinmsgtoken=&COMMUNITY
depinmsgmaxusers=20
```

#### Large Group (20-50 members)
```ini
assetindex=1
pubkeyindex=1
depinmsg=1
depinmsgtoken=&MEMBERS
depinmsgmaxusers=50
```

# Verify DePIN messaging status
```ini
neurai-cli depingetmsginfo
```
# Shows: active token, port, number of messages, etc.


## Usage

### Available Commands

#### 1. Send Message (local wallet + local pool)

```bash
neurai-cli depinsendmsg "TOKEN_OR_SECTION" "MESSAGE" "FROM_ADDRESS"
```

**Parameters**:
- `TOKEN_OR_SECTION`: A pool root or section, for example `&MYTOKEN/GENERAL`.
- `MESSAGE`: Text to send (maximum 1KB)
- `FROM_ADDRESS`: Address in the local wallet used for signing. It is required
  and must actively hold the target token or one of its ancestors.

This RPC needs the wallet holding `FROM_ADDRESS` and the pool on the same
node. To publish through a remote service node, prepare the message
client-side and call its `depinsubmitmsg` (see [`depinreceivemsg.md`](depinreceivemsg.md)).

**Example**:
```bash
neurai-cli depinsendmsg "&MYTOKEN/GENERAL" "Hello team!" "NXspecificAddress..."
```

**Output**:
```json
{
  "result": "success",
  "hash": "a1b2c3d4e5f6...",
  "token": "&MYTOKEN/GENERAL",
  "ancestors": ["&MYTOKEN/GENERAL", "&MYTOKEN"],
  "recipients": 15,
  "skipped_no_pubkey": 1,
  "skipped_restricted": 0,
  "timestamp": 1699564800
}
```

#### 2. Read Messages

**Local wallet + local pool** (decrypts with the wallet's keys):
```bash
neurai-cli depingetmsg "TOKEN_OR_SECTION" ("FROM_ADDRESS")
```

- `TOKEN_OR_SECTION`: A root or section scope. A section includes its descendants.
- `FROM_ADDRESS`: Optional specific local wallet address to use. When omitted,
  the wallet tries all of its relevant branch addresses and de-duplicates by
  message hash.

**Any pool, any client** (the holder keeps its keys): `depinchallenge`, sign,
`depinreceivemsg`, verify `poolsig`, decrypt. The full contract is in
[`depinreceivemsg.md`](depinreceivemsg.md). From a node that holds the key:

```bash
# 1. sign the request, ask for the challenge (reply encrypted for the address), open it
neurai-cli depinsignrequest "NXyouraddress..." "&MYTOKEN/GENERAL"   # -> {"timestamp": ..., "signature": ...}
neurai-cli depinchallenge "&MYTOKEN/GENERAL" "NXyouraddress..." <timestamp> "<signature>"
neurai-cli depindecrypt "NXyouraddress..." "<encrypted>"        # -> {"challenge": ..., ...}
# 2. sign the nonce with the wallet key
neurai-cli depinsignchallenge "NXyouraddress..." "&MYTOKEN/GENERAL" "<challenge>"
# 3. read (reply encrypted for the address and signed by the pool key), then open it
neurai-cli depinreceivemsg "&MYTOKEN/GENERAL" "NXyouraddress..." "<challenge>" "<signature>"
neurai-cli depindecrypt "NXyouraddress..." "<encrypted>"
```

`contrib/depin/regtest_walkthrough.sh` runs this whole flow (bootstrap,
refused start without wallet, signed challenge request, read, chained read,
forged/replayed requests, rate limit, sections, purge) against a fresh
regtest node and checks every step.

**`depingetmsg` output**:
```json
[
  {
    "sender": "NXa1b2c3d4e5f6...",
    "token": "&MYTOKEN/GENERAL",
    "message": "Hello team!",
    "timestamp": 1699564800,
    "date": "2024-11-09 14:20:00",
    "expires": "2024-11-16 14:20:00"
  },
  {
    "sender": "NXz9y8x7w6v5...",
    "message": "Meeting at 3pm",
    "timestamp": 1699568400,
    "date": "2024-11-09 15:20:00",
    "expires": "2024-11-16 15:20:00"
  }
]
```

#### 3. DePIN Messaging Information

```bash
neurai-cli depingetmsginfo
```

**Output** (a signed plain body; `body` is the hex of the JSON below):
```json
{ "body": "7b22656e61626c6564223a747275652c...", "poolsig": "IMn3..." }
```
```json
{
  "enabled": true,
  "token": "&MYTOKEN",
  "maxrecipients": 20,
  "messages": 42,
  "memoryusage": 52428,
  "newestmessage": "2024-11-09 15:20:00",
  "protocol": 2,
  "depinpoolpkey": "02ab...",
  "depinpoolkeyaddress": "NXpool...",
  "depinwallet": "wallet.dat"
}
```

#### 4. Clear Expired Messages

```bash
neurai-cli depinclearmsg "SCOPE" "OWNER_ADDRESS" "CHALLENGE" "SIGNATURE" ("all"|HOURS)
```

`SCOPE` is a served section, or `""` for the whole pool. It clears that
section and its descendants only; it never clears a parent or sibling. The
challenge must be an `admin` challenge issued for exactly `SCOPE` (for `""`,
request it for the pool root by name) to an owner of that token or of an
ancestor. Automatic cleanup also removes expired messages without any call.

#### 5. List sections for a client UI

```bash
neurai-cli depinlistsections ("ADDRESS")
```

Without an address, this lists public section names, labels and depths. With
an address over node RPC, it also reports inherited active access and the
message count for readable sections. The unauthenticated DePIN port rejects
the address form and returns names only.

```json
[
  {"name":"&MYTOKEN", "label":"", "depth":0},
  {"name":"&MYTOKEN/GENERAL", "label":"GENERAL", "depth":1}
]
```

#### 6. Resolve recipient public keys

```bash
neurai-cli depingetancestorrecipients "&MYTOKEN/GENERAL" 100 "&MYTOKEN"
```

This informational RPC returns active recipient addresses and their revealed
public keys, plus `truncated` and skipped-holder metadata. It is useful to
external encrypting clients, but a truncated response is not a valid complete
recipient list. See [`depinreceivemsg.md`](depinreceivemsg.md) for its full
contract and security rules.

#### 7. Pool information

```bash
neurai-cli depingetmsginfo
```

A client publishing through this node reads `token` (the pool root, its
`stop_at` for recipient resolution), `maxrecipients` and `depinpoolpkey`
(the key to wrap `depinsubmitmsg` envelopes for) from here, and pins
`depinpoolpkey` as described in [`depinreceivemsg.md`](depinreceivemsg.md).

<!-- Legacy holder-list example retained below only as a blockchain index example. -->

#### Blockchain holder lookup

```bash
neurai-cli listaddressesbyasset "&MYTOKEN"
```

This is a raw asset-index query. It does not apply DePIN restrictions, public
key availability, hierarchy, or messaging recipient limits. Do not use it as
a DePIN recipient list.

**Example output**:
```json
{
  "NXa1b2c3d4e5f6...": 100.00000000,
  "NXb2c3d4e5f6g7...": 50.00000000,
  "NXc3d4e5f6g7h8...": 25.00000000
  // ... more addresses
}
```

---------------------


Setup
---------------------
Neurai is the original Neurai client and it builds the backbone of the network. It downloads and, by default, stores the entire history of Neurai transactions; depending on the speed of your computer and network connection, the synchronization process is typically complete in under an hour.

To download compiled binaries of the Neurai and wallet, visit the [GitHub release page](https://github.com/NeuraiProject/Neurai/releases).

Running
---------------------
The following are some helpful notes on how to run Neurai on your native platform.

### Linux

1) Download and extract binaries to desired folder.

2) Install distribution-specific dependencies listed below.

3) Run the GUI wallet or only the Neurai deamon

   a. GUI wallet:

   `./neurai-qt`

   b. Core deamon:

   `./neuraid -deamon`

#### Ubuntu 16.04, 17.04/17.10 and 18.04

Update apt cache and install general dependencies:

```
sudo apt update
sudo apt install libevent-dev libboost-all-dev libminiupnpc10 libzmq5 software-properties-common
```

The wallet requires version 4.8 of the Berkeley DB. The easiest way to get it is to build it with the script contrib/install_db4.sh


```

The GUI wallet requires the QR Code encoding library. Install with:

`sudo apt install libqrencode3`

#### Fedora 27

Install general dependencies:

`sudo dnf install zeromq libevent boost libdb4-cxx miniupnpc`

The GUI wallet requires the QR Code encoding library and Google's data interchange format Protocol Buffers. Install with:

`sudo dnf install qrencode protobuf`

#### CentOS 7

Add the EPEL repository and install general depencencies:

```
sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
sudo yum install zeromq libevent boost libdb4-cxx miniupnpc
```

The GUI wallet requires the QR Code encoding library and Google's data interchange format Protocol Buffers. Install with:

`sudo yum install qrencode protobuf`

### OS X

1) Download Neurai-Qt.dmg.

2) Double click the DMG to mount it.

3) Drag Neurai icon to the Applications Folder

![alt tag](https://i.imgur.com/GLhBFUV.png)

4) Open the Applications folder and Launch Neurai. The client will begin synchronizing with the network.

![alt tag](https://i.imgur.com/v3962qo.png)

Note: You may get the follow error on first launch:
```
Dyld Error Message:
  Library not loaded: @loader_path/libboost_system-mt.dylib
  Referenced from: /Applications/Neurai-Qt.app/Contents/Frameworks/libboost_thread-mt.dylib
  Reason: image not found
```
To resolve, you will need to copy libboost_system.dylib to libboost_system-mt.dylib in the /Applications/Neurai-Qt.app/Contents/Frameworks folder

### Windows

1) Download windows-x86_64.zip and unpack executables to desired folder.

2) Double click the neurai-qt.exe to launch it.

### Need Help?

- See the documentation at the [Neurai Wiki](https://neurai.wiki/wiki/Neurai_Wiki)
for help and more information.
- Ask for help on [Discord](https://discord.gg/DUkcBst), [Telegram](https://t.me/NeuraiDev) or [Reddit](https://www.reddit.com/r/Neurai/).

Building from source
---------------------
The following are developer notes on how to build the Neurai software on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [Dependencies](https://github.com/NeuraiProject/Neurai/tree/master/doc/dependencies.md)
- [OS X Build Notes](https://github.com/NeuraiProject/Neurai/tree/master/doc/build-osx.md)
- [Unix Build Notes](https://github.com/NeuraiProject/Neurai/tree/master/doc/build-unix.md)
- [Windows Build Notes](https://github.com/NeuraiProject/Neurai/tree/master/doc/build-windows.md)
- [OpenBSD Build Notes](https://github.com/NeuraiProject/Neurai/tree/master/doc/build-openbsd.md)
- [Gitian Building Guide](https://github.com/NeuraiProject/Neurai/tree/master/doc/gitian-building.md)

Development
---------------------
Neurai repo's [root README](https://github.com/NeuraiProject/Neurai/blob/master/README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](https://github.com/NeuraiProject/Neurai/blob/master/doc/developer-notes.md)
- [Release Notes](https://github.com/NeuraiProject/Neurai/blob/master/doc/release-notes.md)
- [Release Process](https://github.com/NeuraiProject/Neurai/blob/master/doc/release-process.md)
- [Source Code Documentation (External Link)](https://dev.visucore.com/neurai/doxygen/) -- 2018-05-11 -- Broken link
- [Translation Process](https://github.com/NeuraiProject/Neurai/blob/master/doc/translation_process.md)
- [Translation Strings Policy](https://github.com/NeuraiProject/Neurai/blob/master/doc/translation_strings_policy.md)
- [Travis CI](https://github.com/NeuraiProject/Neurai/blob/master/doc/travis-ci.md)
- [Unauthenticated REST Interface](https://github.com/NeuraiProject/Neurai/blob/master/doc/REST-interface.md)
- [Shared Libraries](https://github.com/NeuraiProject/Neurai/blob/master/doc/shared-libraries.md)
- [BIPS](https://github.com/NeuraiProject/Neurai/blob/master/doc/bips.md)
- [Dnsseed Policy](https://github.com/NeuraiProject/Neurai/blob/master/doc/dnsseed-policy.md)
- [Benchmarking](https://github.com/NeuraiProject/Neurai/blob/master/doc/benchmarking.md)

### Resources
- Discuss on chat [Discord](https://discord.gg/jn6uhur), [Telegram](https://t.me/NeuraiDev) or [Reddit](https://www.reddit.com/r/Neurai/).
- Find out more on the [Neurai Wiki](https://neurai.wiki/wiki/Neurai_Wiki)
- Visit the project home [Neurai.org](https://neurai.org)

### Miscellaneous
- [Assets Attribution](https://github.com/NeuraiProject/Neurai/blob/master/doc/assets-attribution.md)
- [Files](https://github.com/NeuraiProject/Neurai/blob/master/doc/files.md)
- [Fuzz-testing](https://github.com/NeuraiProject/Neurai/blob/master/doc/fuzzing.md)
- [Reduce Traffic](https://github.com/NeuraiProject/Neurai/blob/master/doc/reduce-traffic.md)
- [Tor Support](https://github.com/NeuraiProject/Neurai/blob/master/doc/tor.md)
- [Init Scripts (systemd/upstart/openrc)](https://github.com/NeuraiProject/Neurai/blob/master/doc/init.md)
- [ZMQ](https://github.com/NeuraiProject/Neurai/blob/master/doc/zmq.md)

License
---------------------
Distributed under the [MIT software license](https://github.com/NeuraiProject/Neurai/blob/master/COPYING).
This product includes software developed by the OpenSSL Project for use in the [OpenSSL Toolkit](https://www.openssl.org/). This product includes
cryptographic software written by Eric Young ([eay@cryptsoft.com](mailto:eay@cryptsoft.com)), and UPnP software written by Thomas Bernard.
