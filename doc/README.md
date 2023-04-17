Neurai Core
==============

Setup
---------------------
Neurai Core is the original Neurai client and it builds the backbone of the network. It downloads and, by default, stores the entire history of Neurai transactions; depending on the speed of your computer and network connection, the synchronization process is typically complete in under an hour.

To download compiled binaries of the Neurai Core and wallet, visit the [GitHub release page](https://github.com/NeuraiProject/Neurai/releases).

Running
---------------------
The following are some helpful notes on how to run Neurai on your native platform.

### Linux

1) Download and extract binaries to desired folder.

2) Install distribution-specific dependencies listed below.

3) Run the GUI wallet or only the Neurai core deamon

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

3) Drag Neurai Core icon to the Applications Folder

![alt tag](https://i.imgur.com/GLhBFUV.png)

4) Open the Applications folder and Launch Neurai Core. The client will begin synchronizing with the network.

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
The following are developer notes on how to build the Neurai core software on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

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
