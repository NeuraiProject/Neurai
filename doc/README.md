Neurai
=============

Setup
---------------------
Neurai downloads and, by default, stores the entire history of Neurai
transactions. To download compiled binaries of the node and wallet, visit the
[GitHub release page](https://github.com/NeuraiProject/Neurai/releases).

Running
---------------------

### Linux

1) Download and extract the binaries to the desired folder.

2) Run the GUI wallet (`./neurai-qt`) or only the daemon (`./neuraid -daemon`).

Release binaries are built with the [depends system](../depends/README.md);
to build from source, see the build notes below for the required libraries.

### macOS

1) Download `neurai-<version>-macos-arm64-unsigned.zip` (Apple Silicon) or
   `neurai-<version>-macos-x86_64-unsigned.zip` (Intel). macOS 12 or later is
   required.

2) Unzip it and move `Neurai-Qt.app` to the Applications folder.

3) The application is not signed with an Apple Developer certificate or
   notarized, so macOS blocks the first launch: Control-click it and choose
   Open. The client will begin synchronizing with the network.

### Windows

1) Download the Windows `.zip` and unpack the executables to the desired folder.

2) Double click `neurai-qt.exe` to launch it.

### Need Help?

- See the documentation at the [Neurai Wiki](https://neurai.wiki/wiki/Neurai_Wiki)
for help and more information.
- Ask for help on [Discord](https://discord.gg/j2WgJjgj8t), [Telegram](https://t.me/NeuraiDev) or [Reddit](https://www.reddit.com/r/Neurai/).

Building from source
---------------------
The following are developer notes on how to build the Neurai software on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [Dependencies](dependencies.md)
- [macOS Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Ubuntu Build Notes](build-ubuntu.md)
- [Windows Build Notes](build-windows.md)
- [Raspberry Pi Build Notes](build-raspberrypi.md)
- [Docker Build Notes](build-docker.md)

Development
---------------------
Neurai repo's [root README](../README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Release Notes](release-notes.md)
- [Release Process](release-process.md)
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [JSON-RPC Interface](JSON-RPC-interface.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [Shared Libraries](shared-libraries.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)
- [Covenants](covenants.md)
- [New opcodes](new-opcodes-depin-branch.md)

DePIN messaging (testnet and regtest)
---------------------
- [Service node guide](depin-guide.md)
- [Messaging protocol](depin-messaging-protocol.md)
- [RPC 5 request and response signatures](depin-request-signatures.md)
- [Client integration guide](depinreceivemsg.md)
- [Authorization](depin-authorization.md)
- [Membership epochs](depin-membership.md)
- [Legacy and strict ECDSA messaging / ECIES 2](depin-ecdsa.md)
- [Pool state](depin-pool-state.md)

Node behaviour
---------------------
- [Header synchronisation](header-sync-validation.md)
- [Block import and reindex](reindex-validation.md)
- [Mining behaviour](mining-behavior.md)
- [Peer time and mining](mining-time.md)
- [SPH hash compatibility](sph-hash-compatibility.md)

### Resources
- Discuss on chat [Discord](https://discord.gg/j2WgJjgj8t), [Telegram](https://t.me/NeuraiDev) or [Reddit](https://www.reddit.com/r/Neurai/).
- Find out more on the [Neurai Wiki](https://neurai.wiki/wiki/Neurai_Wiki)
- Visit the project home [Neurai.org](https://neurai.org)

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [Files](files.md)
- [Fuzz-testing](fuzzing.md)
- [Reduce Memory](reduce-memory.md)
- [Reduce Traffic](reduce-traffic.md)
- [Tor Support](tor.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)
- [ZMQ](zmq.md)

License
---------------------
Distributed under the [MIT software license](../COPYING).
This product includes software developed by the OpenSSL Project for use in the [OpenSSL Toolkit](https://www.openssl.org/). This product includes
cryptographic software written by Eric Young ([eay@cryptsoft.com](mailto:eay@cryptsoft.com)), and UPnP software written by Thomas Bernard.
