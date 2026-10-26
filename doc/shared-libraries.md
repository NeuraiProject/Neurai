Shared Libraries
================

## neuraiconsensus

The purpose of this library is to make the verification functionality that is critical to Neurai's consensus available to other applications, e.g. to language bindings.

### API

The interface is defined in the C header `neuraiconsensus.h` located in  `src/script/neuraiconsensus.h`.

#### Version

`neuraiconsensus_version` returns an `unsigned int` with the API version *(currently `1`, `NEURAICONSENSUS_API_VER`)*.

#### Script Validation

`neuraiconsensus_verify_script` and `neuraiconsensus_verify_script_with_amount` (which adds `int64_t amount`, the value of the spent output, required with `WITNESS`) return an `int` with the status of the verification. It will be `1` if the input script correctly spends the previous output `scriptPubKey`.

##### Parameters
- `const unsigned char *scriptPubKey` - The previous output script that encumbers spending.
- `unsigned int scriptPubKeyLen` - The number of bytes for the `scriptPubKey`.
- `const unsigned char *txTo` - The transaction with the input that is spending the previous output.
- `unsigned int txToLen` - The number of bytes for the `txTo`.
- `unsigned int nIn` - The index of the input in `txTo` that spends the `scriptPubKey`.
- `unsigned int flags` - The script validation flags *(see below)*.
- `neuraiconsensus_error* err` - Will have the error/success code for the operation *(see below)*.

##### Script Flags
- `neuraiconsensus_SCRIPT_FLAGS_VERIFY_NONE`
- `neuraiconsensus_SCRIPT_FLAGS_VERIFY_P2SH` - Evaluate P2SH ([BIP16](https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki)) subscripts
- `neuraiconsensus_SCRIPT_FLAGS_VERIFY_DERSIG` - Enforce strict DER ([BIP66](https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki)) compliance
- `neuraiconsensus_SCRIPT_FLAGS_VERIFY_NULLDUMMY` - Enforce NULLDUMMY ([BIP147](https://github.com/bitcoin/bips/blob/master/bip-0147.mediawiki))
- `neuraiconsensus_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY` - Enable CHECKLOCKTIMEVERIFY ([BIP65](https://github.com/bitcoin/bips/blob/master/bip-0065.mediawiki))
- `neuraiconsensus_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY` - Enable CHECKSEQUENCEVERIFY ([BIP112](https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki))
- `neuraiconsensus_SCRIPT_FLAGS_VERIFY_WITNESS` - Enable WITNESS ([BIP141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki))
- `neuraiconsensus_SCRIPT_FLAGS_VERIFY_CAT`, `_CHECKTEMPLATEVERIFY`, `_CHECKSIGFROMSTACK`, `_TXHASH`, `_OUTPUTVALUE`, `_TXLOCKTIME`, `_OUTPUTSCRIPT`, `_OUTPUTASSETFIELD`, `_64BIT_INTEGERS`, `_INPUTASSETFIELD`, `_INPUTOUTPUTCOUNT` - Enable the corresponding covenant opcodes (see [covenants.md](covenants.md))

The `flags` argument is 32 bits wide, so the library cannot express the newer
flags (bit 32 and above: AuthScript strict families, NIP-041/043/044/046,
`OP_ZKVERIFY`, hashes, Ed25519, CHECKSIGADD, ...); scripts that need them
cannot be verified with this API. Some opcodes also need data the library does
not receive (all prevouts, reference inputs, chain context) and fail closed.

##### Errors
- `neuraiconsensus_ERR_OK` - No errors with input parameters *(see the return value of `neuraiconsensus_verify_script` for the verification status)*
- `neuraiconsensus_ERR_TX_INDEX` - An invalid index for `txTo`
- `neuraiconsensus_ERR_TX_SIZE_MISMATCH` - `txToLen` did not match with the size of `txTo`
- `neuraiconsensus_ERR_TX_DESERIALIZE` - An error deserializing `txTo`
- `neuraiconsensus_ERR_AMOUNT_REQUIRED` - Input amount is required if WITNESS is used
- `neuraiconsensus_ERR_INVALID_FLAGS` - `flags` contains bits outside `neuraiconsensus_SCRIPT_FLAGS_VERIFY_ALL`
