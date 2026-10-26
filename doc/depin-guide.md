Neurai — DePIN Messaging (Experimental)
==============

## WARNING
This is an experimental, off-chain messaging system for holders of a DePIN
asset. It is currently intended for testnet and regtest. See
[`depin-messaging-protocol.md`](depin-messaging-protocol.md) for the full
protocol specification (wire formats, cryptography, authentication, test
vectors) aimed at client and library implementers, and
[`depinreceivemsg.md`](depinreceivemsg.md) for the RPC-by-RPC client guide.


## DePIN Messaging

Is a private and temporary messaging system for Neurai that enables encrypted communication between holders of a specific token. This system:

- **Does not write to blockchain**: no fees, no permanence.
- **Encrypted messages**: readable only by public keys selected by the sender.
- **One port**: everything is served by the node's standard JSON-RPC
  interface, typically behind an RPC proxy such as `neurai-rpc-proxy`. There
  is no separate listener.
- **Temporal messages**: they expire after 7 days by default (`-depinmsgexpire`,
  up to 30 days); owners can purge earlier with `depinclearmsg`.
- **Token ownership verification**: for sending, and challenge/signature
  authentication for every read or purge bound to an address.
- **Signed, encrypted replies**: every response of the remote protocol 5
  methods is signed with the node's pool key; replies bound to an address are
  encrypted for that address's revealed public key. Local wallet RPCs
  (`depinsendmsg`, `depingetmsg`, `depindecrypt`, `depinsignrpc`,
  `depinpoolpkey`) are not signed.
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

Strict ECIES bounds, the additive `depinreceiveseq` API, durable moderation
and state v2 migration are specified in
[depin-pool-state.md](depin-pool-state.md). Message plaintext size and the
4 MiB receive-response budget are independent. External library updates
remain a later integration step.

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
- Messages expire after 7 days by default (`-depinmsgexpire`, in hours, max 720)
- Automatic mempool cleanup
- Prevents data accumulation

### 5. Token-based access control

- Sending is authorized by an active holding in the target section's ancestor
  chain.
- Reads (`depinreceiveseq`, `depinreceivemsg`, `depinlistsections` with an address) require a
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
tabs — names, labels and depths with a public request (empty
address/challenge/signature, root token); a personal request (per-address
access and message counters) takes a receive challenge issued for its `token`
and reports that scope's subtree. `depinclearmsg` takes a scope so a section owner can purge
their subtree (never parents or siblings); its `admin` challenge is bound to
exactly that scope. The root's subtree is the whole pool.

**Recipient scope**: a client publishing through a service node resolves
recipients with the pool's root as `stop_at` (`depingetmsginfo` publishes it).
This is deliberate: every extra `recipientKeys` entry is an extra reader, and
encrypting up to the absolute root would include holders of ancestors the
pool does not even serve.

**Recipient limit**: a send **fails** (never silently truncates) when the
union of eligible holders across the ancestor chain exceeds
the pool's `-depinmsgmaxusers` limit (default 20, maximum 50). A leaf section can hit the limit before the root
does, because it aggregates the holders of all its ancestors.

**Privacy limits** (read before relying on sections):

- Section names, the hierarchy (`&TEST/GENERAL` → `&TEST`) and token holdings
  are **public on chain**. Sections protect message *content* (ECIES), not
  membership. Opaque labels (`&TEST/K7M2Q`) hide meaning from casual
  observers, but not existence, hierarchy or holdings.
- "The root sees everything" only holds for holders with a **revealed public
  key**; holders that never spent from their address are skipped (reported as
  `skipped_no_pubkey` in `depinsendmsg`).
- `recipientKeys` is a snapshot chosen by the sender. New publications reject
  any declared recipient without current branch permission; private subsets
  are allowed. Independent client verification still matters with a malicious
  service or directory. See [authorization and restoration](depin-authorization.md).
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


### Authenticated RPC flow (protocol 5)

Remote DePIN methods take one JSON request object with protocol 5, network,
pool identity/root/instance, fresh request ID, timestamp, scope/address/nonce,
typed args and operation signature. Legacy formats and signatures are rejected.
Bootstrap is a reduced depingetmsginfo request. Verify the pinned pool signature
and locally computed request hash before trusting any response. Private
responses, including correlatable operation errors, are encrypted for the
address. The node rechecks current on-chain permission when using a challenge.

See [the RPC 5 contract](depin-request-signatures.md) for canonical bytes,
limits, errors and examples, and [the client guide](depinreceivemsg.md) for
complete flows. The local signing helper is `depinsignrpc method request`;
it signs for the explicit destination and must not be exposed by a proxy.
Purge mode/age, read cursor/filter and the submission privacy envelope are all
covered by the signature. Content cryptography and storage framing remain unchanged; RPC 5 adds
[typed ECIES 2 destinations](depin-ecdsa.md) alongside Legacy ECIES.

The pool does not decrypt user content. Its signature does not prove that a
malicious directory lists eligible recipients: clients need independent
verification and their own recipient policy. A freeze denies current access,
but cannot revoke ciphertext already held by a recipient.

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
thoroughly tested, so DePIN messaging cannot be used on mainnet for now.


### Message Sending Flow

```
1. Client reads depingetmsginfo: pool root, recipient limit, depinpoolpkey
                                    ↓
2. Client verifies that FROM_ADDRESS holds the selected section or an ancestor
                                    ↓
3. Resolve active holders with public keys, stopping at the pool root
   (protocol 5 request with token and args.max_results/stop_at)
                                    ↓
4. Refuse the send if the complete recipient set exceeds the pool's limit
                                    ↓
5. Encrypt the content once; ECIES-wrap the content key for each recipient
                                    ↓
6. Sign the serialized message with FROM_ADDRESS
                                    ↓
7. Wrap the serialized hex for depinpoolpkey, put it in args.encrypted,
   and sign the complete depinsubmitmsg request as FROM_ADDRESS (token="")
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
    uint8_t messageType;             // 0x01 = private, 0x02 = group (default)
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

    unsigned int nMaxRecipients;           // Recipient limit (-depinmsgmaxusers)
    unsigned int nMaxMessageSize;          // -depinmsgsize
    unsigned int nMessageExpiryHours;      // -depinmsgexpire
    unsigned int nMaxPoolSizeMB;           // -depinpoolsize
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

# Optional limits:
# depinmsgsize=1024        # max content plaintext in bytes, excluding ECIES/key overhead (default 1024, max 10240)
# depinmsgexpire=168       # expiry in hours (default 168 = 7 days, max 720)
# depinpoolsize=100        # pool size in MB (default 100, max 1000)
# depinpoolpersist=0       # retain messages across restarts, written synchronously (default 0)
# depintombstonelimit=100000 # retained moderation hashes, always durable; a full store refuses further deletions (default 100000, max 1000000)
# depinmaxtipage=3600      # max active-tip age in seconds for DePIN authorization (default 3600)
# depinmaxheaderlag=2      # max known-header lead in blocks for DePIN authorization (default 2)
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

### Verify DePIN messaging status

```bash
neurai-cli depingetmsginfo '{"protocol":5,"request_id":"<fresh 32-byte hex>","timestamp_ms":<now_ms>}'
```

Verify the v5 signed wrapper before reading active root, counters and limits.


## Usage

### Available Commands

#### 1. Send Message (local wallet + local pool)

```bash
neurai-cli depinsendmsg "TOKEN_OR_SECTION" "MESSAGE" "FROM_ADDRESS"
```

**Parameters**:
- `TOKEN_OR_SECTION`: A pool root or section, for example `&MYTOKEN/GENERAL`.
- `MESSAGE`: Text to send (default maximum 1 KB, see `-depinmsgsize`)
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

**Any pool, any client**: follow [the protocol 5 guide](depinreceivemsg.md).
Obtain verified bootstrap, sign the complete challenge request, decrypt its
nonce, sign the complete read request with `depinsignrpc`, then verify/decrypt
the response. Prefer admission-sequence reads. Every remote method receives
one request object; previous positional calls and signing helpers are gone.

`contrib/depin/regtest_walkthrough.sh` runs the disposable HTTP/CLI protocol 5
regressions and leaves existing node data untouched.

**`depingetmsg` output**:
```json
[
  {
    "recipient": "NXmyaddress...",
    "sender": "NXa1b2c3d4e5f6...",
    "token": "&MYTOKEN/GENERAL",
    "message": "Hello team!",
    "message_type": "group",
    "timestamp": 1699564800,
    "date": "2024-11-09 14:20:00",
    "expires": "2024-11-16 14:20:00"
  },
  {
    "recipient": "NXmyaddress...",
    "sender": "NXz9y8x7w6v5...",
    "token": "&MYTOKEN",
    "message": "Meeting at 3pm",
    "message_type": "group",
    "timestamp": 1699568400,
    "date": "2024-11-09 15:20:00",
    "expires": "2024-11-16 15:20:00"
  }
]
```

#### 3. DePIN Messaging Information

Call `depingetmsginfo request` with the reduced protocol 5 bootstrap object
from [the contract](depin-request-signatures.md). Its signed wrapper binds
the exact request hash and includes the served network/key/root/instance.
The verified body includes protocol 5, accepted_protocols, server_time_ms,
limits, counters and persistence/sequence capabilities. A first self-signed
response does not replace an independent pin.

#### 4. Clear Expired Messages

Call `depinclearmsg request` with an admin nonce and complete operation
signature. args.mode is expired (default), all or hours; only hours accepts
and requires args.hours. Empty token normalizes to the root. Scope covers
that section and descendants; owner access is rechecked. A signed error body
is a failed operation. Automatic expiry does not need an administrative call.

#### 5. List sections for a client UI

Call `depinlistsections request`: public root-scoped objects have empty
address/challenge/signature and return names, labels and depths. Personal
objects require a receive nonce/signature and return current scoped access
and counters. Both use the protocol 5 signed response wrapper. There is no
separate unauthenticated messaging port.

#### 6. Resolve recipient public keys

```bash
# Full common v5 object: token="&MYTOKEN/GENERAL",
# args={"max_results":100,"stop_at":"&MYTOKEN"}, public authentication fields empty.
neurai-cli depingetancestorrecipients '<complete v5 request object>'
```

This informational RPC returns active recipient addresses and their revealed
public keys, plus `truncated` and skipped-holder metadata. It is useful to
external encrypting clients, but a truncated response is not a valid complete
recipient list. See [`depin-request-signatures.md`](depin-request-signatures.md)
for its full contract and [`depinreceivemsg.md`](depinreceivemsg.md) for the
security rules.

#### 7. Pool information

```bash
neurai-cli depingetmsginfo '{"protocol":5,"request_id":"<fresh 32-byte hex>","timestamp_ms":<now_ms>}'
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

## Related documents

- [DePIN messaging protocol](depin-messaging-protocol.md)
- [RPC 5 request and response signatures](depin-request-signatures.md)
- [Client integration guide](depinreceivemsg.md)
- [Authorization](depin-authorization.md)
- [Membership epochs](depin-membership.md)
- [Legacy and strict ECDSA messaging / ECIES 2](depin-ecdsa.md)
- [Pool state](depin-pool-state.md)
