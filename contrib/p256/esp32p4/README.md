# Neurai P-256 signer firmware (ESP-IDF v6.1)

Reference firmware for NIP-060 `OP_CHECKSIG_P256`. It signs 32-byte digests
with a P-256 key and answers on the console (UART or USB Serial/JTAG):

- `info`: chip, revision, ESP-IDF version and key source;
- `pub`: `PUB <33-byte compressed public key>`;
- `sign <digest>`: `SIG <r || s>`, deterministic (RFC 6979), low S;
- `genkey <index> BURN`: only with the eFuse source and
  `CONFIG_NEURAI_P256_ALLOW_EFUSE_BURN`; generates the key with the TRNG and
  burns it (irreversible);
- `genkey`: software source; creates the key in NVS and refuses to replace an
  existing one.

The firmware never creates or replaces a key on its own and never erases NVS,
even when NVS reports an error: the key may already control funds. Erasing is
a deliberate maintenance step (`idf.py erase-flash`).

The host side is `contrib/p256/device_sign.py` (`check` runs the plan checks,
`spend` signs a NIP-060 §5 spend).

## Key source

| Source | Boards | Protection |
| --- | --- | --- |
| eFuse + ECDSA peripheral (default) | ESP32-P4 rev >= v3.0, ESP32-C5, ESP32-H2 | The key never leaves the hardware |
| Software key in NVS (`sdkconfig.software`) | ESP32-P4 rev < v3.0, ESP32-S3 | None: tests the flow only |

ESP-IDF supports the ECDSA peripheral of the ESP32-P4 only from revision v3.0
(ECO5); revisions 0.x and 1.x also need `sdkconfig.p4rev1`.

## Build and flash

```
. $IDF_PATH/export.sh
# ESP32-P4 rev >= v3.0, key in eFuse:
idf.py set-target esp32p4 build
# ESP32-P4 rev 1.x, software key:
idf.py -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.software;sdkconfig.p4rev1" set-target esp32p4 build
idf.py -p /dev/ttyACM0 flash
python3 ../device_sign.py check --port /dev/ttyACM0
```

Before burning a key, check the free key blocks with `idf.py efuse-summary`:
burning an eFuse cannot be undone, and the six key blocks are shared with
Secure Boot and flash encryption.
