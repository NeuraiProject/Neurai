**Steps to be performed before any Pull Request is accepted into the main branch**

  1. Check PROTOCOL_VERSION in the following location: src/version.h

  2. Check the client version in configure.ac (`_CLIENT_VERSION_*`, `_CLIENT_VERSION_IS_RELEASE`)
     and that `CLIENT_VERSION_SUFFIX` in `src/clientversion.cpp` is empty for a release

  3. All unit and functional tests pass

  4. Check dependent projects for protocol, serialization or RPC changes:
     [electrs-neurai](https://github.com/NeuraiProject/electrs-neurai),
     [neurai-rpc-proxy](https://github.com/NeuraiProject/neurai-rpc-proxy),
     [DePIN-Messaging](https://github.com/NeuraiProject/DePIN-Messaging) and the official wallets:
     [NeuraiWallet](https://github.com/NeuraiProject/NeuraiWallet) (Android),
     [neurai-webwallet](https://github.com/NeuraiProject/neurai-webwallet) (web) and
     [neurai-addon-sign](https://github.com/NeuraiProject/neurai-addon-sign) (Chrome and Firefox extension)
  
  5. Build release notes for all new features and bug fixes

**If hard fork:**

  1. Notify all exchanges, pools, and wallets of release of critical update

**Post Release :**

  1. Update neurai.org with correct popup version
  
  2. Update neurai.org with correct release download urls for each platform (Windows, Linux, Mac)

**Build Process**

  1. Verify that the release build doesn't say ***dirty*** in the commit message

