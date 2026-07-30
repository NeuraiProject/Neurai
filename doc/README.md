Neurai — DePIN Messaging (Experimental)
==============

## WARNING
This is an experimental, off-chain messaging system for holders of a DePIN
asset. It is currently intended for testnet and regtest. See
[`depinreceivemsg.md`](depinreceivemsg.md) for the stable client-facing
retrieval and decryption contract.


## DePIN Messaging

Is a private and temporary messaging system for Neurai that enables encrypted communication between holders of a specific token. This system:

- **Does not write to blockchain**:no fees, no permanence.
- **Encrypted messages**: readable only by public keys selected by the sender.
- **Direct communication**: between nodes via TCP or relay Nodes with same configuration.
- **Temporal message**: with max 7-day expiration, custom time or all read msg check.
- **Token ownership verification**: for sending and authenticated gateway reads.
- **Integrated TCP server**: for remote queries.
- **Dedicated RPC gateway**: port 19002 has a restricted DePIN RPC allowlist
  and a challenge/response protocol for authenticated operations.


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
- Gateway reads require a challenge signed by the authenticated address.
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
`depinreceivemsg` and the gateway commands accepts a section name. Sending to
a section encrypts for the active holders of the section **and of every
ancestor up to the pool root**; reading with a section token returns only that
section's subtree (its "tab"). `depinlistsections` lists the sections for UI
tabs — over the unauthenticated DePIN port it serves **names only**; the
address mode (per-address access and message counters) requires node RPC.
`depinclearmsg` accepts an optional scope so a section owner can purge their
subtree (never parents or siblings). Old clients that only ever use the root
token are unaffected — the root's subtree is the whole pool.

**Remote sends** query the serving pool's `INFO` first and scope the recipient
set to that pool's root and `maxRecipients`. This is deliberate: the pool's
port exposes raw payloads, so every extra `recipientKeys` entry is an extra
reader — encrypting up to the absolute root would include holders of ancestors
the pool does not even serve. If `INFO` cannot be queried, the send fails
rather than guess the scope.

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
- The token filter in `depinreceivemsg` is a convenience scope, **not access
  control** — that RPC requires no proof of ownership (unlike gateway
  `AUTH`+`GETMESSAGES`). What an address can actually read is fixed
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


### Dedicated RPC Gateway on Port 19002

The listener embeds a JSON-RPC 2.0 micro-endpoint with a restricted DePIN
allowlist. It is not the general node RPC interface. The allowlist includes
the DePIN send/retrieve/status operations and is intentionally narrower than
node RPC; consult the RPC help of the running node for its exact version.
- Legacy plaintext commands:
  - `PING`: reachability test
  - `INFO`: token/queue summary
  - `AUTH`: request a signed challenge (30s expiry)
  - `GETMESSAGES`: requires `AUTH` challenge + signature

Example calls using `nc` (or any TCP client):

```bash
# Send a message via the remote node. `fromaddress` is required.
printf '{"jsonrpc":"2.0","id":1,"method":"depinsendmsg","params":["&MYTOKEN","203.0.113.5","Hello team!","NXfromAddress..."]}'   | nc 203.0.113.10 19002

# Retrieve and decrypt messages using the node wallet
printf '{"jsonrpc":"2.0","id":2,"method":"depingetmsg","params":["&MYTOKEN"]}'   | nc 203.0.113.10 19002
```

Server replies follow JSON-RPC as well:

```json
{"jsonrpc":"2.0","result":{"result":"success","hash":"..."},"error":null,"id":1}
```

Methods outside the DePIN allowlist are rejected, so exposing port 19002 does
not give attackers access to the general wallet RPC surface. `depinlistsections`
is available there only in its names-only form: address-specific access and
message counters require node RPC.

### Challenge / Response flow (plaintext protocol)

1. Client requests a challenge for one of its token-holding addresses:
   ```bash
   printf 'AUTH|&MYTOKEN|NXholder...' | nc node.example.com 19002
   # → CHALLENGE|abcd1234...|30
   ```
2. Client signs the message `DEPIN-GET|<token>|<address>|<challenge>` (standard message-signature with `strMessageMagic`). The challenge is bound to the requested token or section.
3. Client sends the signed fetch request (challenge valid for 30s). The address
   field must contain **exactly the authenticated address** — the challenge only
   proves control of that one:
   ```bash
   printf 'GETMESSAGES|&MYTOKEN|NXholder...|NXholder...|<base64sig>|abcd1234...' | nc node.example.com 19002
   ```
4. Server verifies active, inherited access for the requested token + signature before returning encrypted payload. If the client fails to answer within 30 seconds, the challenge expires and the connection is closed.

> **One address per request.** Listing several addresses (`NXa,NXb`) is rejected
> with `ERROR|Only the authenticated address may be queried`: otherwise any
> authenticated holder could pull the encrypted payloads addressed to another
> holder. A wallet holding the token at several addresses repeats the
> AUTH → sign → GETMESSAGES cycle once per address and merges the results,
> discarding duplicates by message hash (a group message can be addressed to
> more than one of its addresses). `neurai-cli depingetmsg` does this
> automatically.

### Remote message sending handshake

To keep the send endpoint lightweight, port 19002 now uses the same challenge/response flow for `depinsendmsg` RPC calls:

1. Request a SEND challenge:
   ```bash
   printf 'AUTH|&MYTOKEN|NXfromAddress...|SEND\n' | nc node.example.com 19002
   # → CHALLENGE|ef01ab..|30
   ```
2. Sign `DEPIN-SEND|&MYTOKEN|NXfromAddress...|ef01ab..` (compact/base64 signature, identical to `signmessage`).
3. Call `depinsendmsg` and append `fromaddress`, `challenge`, and `signature` as the last parameters:
   ```bash
   printf '{"jsonrpc":"2.0","id":10,"method":"depinsendmsg","params":["&MYTOKEN","192.168.1.50","Hello team","NXfromAddress...","ef01ab..","<base64sig>"]}\n' \
     | nc node.example.com 19002
   ```
4. The server validates the challenge/signature within 30 seconds and only then performs the expensive holder-lookup/encryption. If the signature fails or the nonce expires, restart at step 1.

> Tip: when you run `neurai-cli depinsendmsg` from another machine (with the same wallet but without `depinmsg` enabled), the CLI now handles steps 1-4 automatically. Just pass the remote node as `ip[:port]` and include your `fromaddress`; the tool will request the challenge, sign it with the local private key, and forward the request through the gateway.

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
1. Client calls depinsendmsg "TOKEN_OR_SECTION" "HOST[:PORT]" "MESSAGE" "FROM_ADDRESS"
                                    ↓
2. For a remote pool, client queries INFO before taking wallet locks
                                    ↓
3. Client verifies that FROM_ADDRESS holds the selected section or an ancestor
                                    ↓
4. Resolve active holders with public keys, stopping at the serving pool root
                                    ↓
5. Refuse the send if the complete recipient set exceeds that pool's limit
                                    ↓
6. Encrypt the content once; ECIES-wrap the content key for each recipient
                                    ↓
7. Sign the serialized message with FROM_ADDRESS and submit it
                                    ↓
8. Receiving pool verifies scope, sender access, signature and size limits
                                    ↓
9. Store in its temporary pool; messages expire according to pool policy
```

For remote sends, `INFO` supplies both the pool root and its recipient limit.
The client fails closed if it cannot obtain this information. This avoids
encrypting a raw payload for holders of an ancestor that the remote pool does
not serve.

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

# Server port (optional, default: 19002)
depinmsgport=19002

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

#### 1. Send Message

```bash
neurai-cli depinsendmsg "TOKEN_OR_SECTION" "DEST_IP[:PORT]" "MESSAGE" "FROM_ADDRESS" (PORT)
```

**Parameters**:
- `TOKEN_OR_SECTION`: A pool root or section, for example `&MYTOKEN/GENERAL`.
- `DEST_IP[:PORT]`: Remote DePIN gateway. An explicit final `PORT` is accepted
  for compatibility, but `host:port` is clearer.
- `MESSAGE`: Text to send (maximum 1KB)
- `FROM_ADDRESS`: Address in the local wallet used for signing. It is required
  and must actively hold the target token or one of its ancestors.

**Example**:
```bash
# The client performs INFO and the send challenge automatically.
neurai-cli depinsendmsg "&MYTOKEN/GENERAL" "192.168.1.100:19005" "Hello team!" "NXspecificAddress..."
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

**Local Reading**:
```bash
neurai-cli depingetmsg "TOKEN"
```

**Remote Reading** (query another node):
```bash
neurai-cli depingetmsg "TOKEN_OR_SECTION" "REMOTE_IP[:PORT]" ("FROM_ADDRESS")
```

**Parameters**:
- `TOKEN_OR_SECTION`: A root or section scope. A section includes its descendants.
- `REMOTE_IP[:PORT]`: Optional remote gateway; omitting it reads locally.
- `FROM_ADDRESS`: Optional specific local wallet address to use. When omitted,
  the wallet queries all of its relevant branch addresses and de-duplicates by
  message hash.

**Local Example**:
```bash
neurai-cli depingetmsg "&MYTOKEN"
```

**Remote Example**:
```bash
# Query the GENERAL subtree at a remote gateway
neurai-cli depingetmsg "&MYTOKEN/GENERAL" "192.168.1.78:19003" "NXyouraddress..."
```

**Output**:
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

**Output**:
```json
{
  "enabled": true,
  "token": "&MYTOKEN",
  "port": 19002,
  "maxrecipients": 20,
  "messages": 42,
  "memoryusage": 52428,
  "oldestmessage": "2024-11-02 10:15:30",
  "newestmessage": "2024-11-09 15:20:00"
}
```

#### 4. Clear Expired Messages

```bash
neurai-cli depinclearmsg ("all"|HOURS) ("SCOPE")
```

`SCOPE` is optional and may be a served section. It clears that section and
its descendants only; it never clears a parent or sibling. Automatic cleanup
also removes expired messages.

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

For remote sending, do not manually guess this configuration: `depinsendmsg`
queries the remote gateway's `INFO` and uses its served root and recipient
limit automatically.

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
