Neurai - DePIN Messenge: EXPERIMENTAL VERSION
==============

## WARNING
This is an experimental version for testing the DePIN MSG mode of the Neurai network. It allows messages to be exchanged between holders of a specific token, creating a mini-network of encrypted information between everyone in the network.


## DePIN Messaging

Is a private and temporary messaging system for Neurai that enables encrypted communication between holders of a specific token. This system:

- **Does not write to blockchain**:no fees, no permanence.
- **Encrypted messages**: only readable by token holders.
- **Direct communication**: between nodes via TCP or relay Nodes with same configuration.
- **Temporal message**: with max 7-day expiration, custom time or all read msg check.
- **Token ownership verification**: to send/receive.
- **Integrated TCP server**: for remote queries.


## Key Features

### 1. Privacy (In Development)
- **Current status**: Encryption implemented as placeholder (plaintext messages)
- **Future**: Messages encrypted with ECIES (Elliptic Curve Integrated Encryption Scheme)
- Each recipient will receive a copy encrypted with their public key
- Only token holders will be able to decrypt messages

### 2. No Transaction Costs
- No network fees required
- Does not consume blockchain space
- Completely off-chain operation

### 3. Auto-Discovery of Participants
- Node automatically queries who owns the token
- No need to manually know addresses
- Uses Neurai's asset index (`-assetindex`)

### 4. Automatic Expiration
- Messages expire after 7 days
- Automatic mempool cleanup
- Prevents data accumulation

### 5. Token-Based Access Control
- Only holders of the configured token can:
  - Send messages
  - Receive and decrypt messages
- Automatic ownership verification

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

#### 2. Existing Token
You must specify a valid token that exists on the Neurai blockchain:
- Can be a **ROOT** token (e.g., `MYTOKEN`)
- Can be a **QUALIFIER** token (e.g., `#MEMBERS`)
- Can be a **RESTRICTED** token (e.g., `$SECURITY`)

**Recommendation**: Use QUALIFIER tokens (`#TOKEN`) for exclusive groups.


### Message Sending Flow

```
1. User executes: depinsendmsg "TOKEN" "192.168.1.100" "Message"
                                    ↓
2. Node validates that user owns the token
                                    ↓
3. Queries token holders using -assetindex
   (Example: finds 15 holder addresses)
                                    ↓
4. Encrypts message with ECIES for each address
   (Creates 15 encrypted copies, one per holder)
                                    ↓
5. Signs the complete package with sender's private key
                                    ↓
6. Sends directly to IP:19002
                                    ↓
7. Receiving node verifies:
   - Chat mempool active with that token ✓
   - Valid signature ✓
   - Sender owns the token ✓
                                    ↓
8. Stores in local mempool (NOT propagated to other nodes)
                                    ↓
9. Message expires automatically after 7 days
```

### Data Structure

#### CDepinMessage
```cpp
struct CDepinMessage {
    string token;                    // "MYTOKEN"
    string senderAddress;            // "NXa1b2c3d4e5f6..."
    int64_t timestamp;               // 1699564800 (UNIX time)
    vector<unsigned char> signature; // Sender's ECDSA signature

    // Encrypted messages per recipient
    vector<CDepinEncryptedMessage> encryptedMessages; // [
    //   {recipient: "NXaaa...", encryptedData: [bytes...]},
    //   {recipient: "NXbbb...", encryptedData: [bytes...]},
    //   ...
    // ]
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

# Enable DePIN messaging
depinmsg=1

# Required token for chat
depinmsgtoken=MYTOKEN

# Server port (optional, default: 19002)
depinmsgport=19002

# Maximum recipients (optional, default: 20, max: 50)
depinmsgmaxusers=20
```

### First-Time Configuration (Reindex Required)

If this is your first time activating `-assetindex`:

```bash
# 1. Stop the node
neurai-cli stop

# 2. Edit neurai.conf and add assetindex=1

# 3. Restart with reindex
neuraid -reindex

# 4. Wait for reindex to complete (may take hours)
#    You can monitor progress with:
neurai-cli getblockchaininfo
```

### Configuration for Different Use Cases

#### Small Group (< 10 members)
```ini
assetindex=1
depinmsg=1
depinmsgtoken=#TEAM       # Use QUALIFIER
depinmsgmaxusers=10
```

#### Medium Community (10-20 members)
```ini
assetindex=1
depinmsg=1
depinmsgtoken=COMMUNITY
depinmsgmaxusers=20
```

#### Large Group (20-50 members)
```ini
assetindex=1
depinmsg=1
depinmsgtoken=#MEMBERS
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
neurai-cli depinsendmsg "TOKEN" "DEST_IP" "MESSAGE"
```

**Parameters**:
- `TOKEN`: Token name (must match configuration)
- `DEST_IP`: Receiving node IP address (e.g., "192.168.1.100")
- `MESSAGE`: Text to send (maximum 1KB)

**Example**:
```bash
neurai-cli depinsendmsg "MYTOKEN" "192.168.1.100" "Hello team!"
```

**Output**:
```json
{
  "result": "success",
  "txid": "a1b2c3d4e5f6...",
  "recipients": 15,
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
neurai-cli depingetmsg "TOKEN" "REMOTE_IP" [PORT]
```

**Parameters**:
- `TOKEN`: Token name
- `REMOTE_IP` (optional): IP address of node to query
- `PORT` (optional): Remote server port (default: 19002)

**Local Example**:
```bash
neurai-cli depingetmsg "MYTOKEN"
```

**Remote Example**:
```bash
# Query node at 192.168.1.78
neurai-cli depingetmsg "MYTOKEN" "192.168.1.78"

# Query node on different port
neurai-cli depingetmsg "MYTOKEN" "192.168.1.78" 19003
```

**Output**:
```json
[
  {
    "sender": "NXa1b2c3d4e5f6...",
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
  "token": "MYTOKEN",
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
neurai-cli depinclearmsg
```

**Note**: Automatic cleanup occurs hourly, this command forces immediate cleanup.

#### 5. List Token Holders

```bash
neurai-cli listaddressesbyasset "MYTOKEN"
```

**Output**:
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
