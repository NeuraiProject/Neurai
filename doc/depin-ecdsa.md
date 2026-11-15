# Legacy and strict ECDSA DePIN messaging

DePIN messaging supports Legacy P2PKH and strict ECDSA witness-v3 addresses
(`nq1r…` on mainnet, `tnq1r…` on testnet/regtest). The service uses the
network's existing activation and asset rules; it introduces no consensus
change. P2SH, generic AuthScript v1 and strict PQ are not messaging identities.

Bootstrap advertises `address_types: ["legacy", "ecdsa"]`,
`ecies_formats: [3]` and `accepted_protocols: [6]`. RPC 5 and earlier
requests are rejected. RPC fields and membership context retain their RPC 4
layout; the U16 version and request/response signature domains are 6/v6.
External SDKs and applications must migrate separately.

## Exact identities and public keys

A Legacy identity is its 20-byte P2PKH payload. A strict ECDSA identity is its
32-byte witness-v3 commitment, computed by the existing
`GetStrictAuthScriptDestinationForPubKey` helper. For ECDSA it commits to the
compressed secp256k1 key, authentication type and the strict `OP_TRUE` template
in the witness-v3 domain. It is not a padded hash160 or a public-key hash.

Addresses must use the canonical encoding returned by `EncodeDestination`;
uppercase Bech32 aliases are rejected. The public-key index must contain a
fully valid secp256k1 key that reproduces the exact destination. Strict ECDSA
requires a compressed key. A confirmed spend reveals the key. Funding an
address or holding an asset alone does not make it reachable for encryption.

The same key can derive a Legacy address and a strict ECDSA address. Their
balances, freezes, self-revocations, challenges, cursor binding and directory
entries remain independent. One holding an asset never grants the other
permission. The wallet type or key derivation path does not restrict signing:
a wallet created as ECDSA may authenticate a Legacy address if it holds the
matching private key and that exact Legacy address has the asset. The request
and content sender then name the Legacy identity. This is an authorization distinction: anyone possessing that
shared private key can still decrypt captured wrapped keys for either identity.

RPC compact signatures use the wallet's existing `signmessage`/`verifymessage`
contract. Strict ECDSA additionally binds the message-magic hash through
`StrictAuthScriptMessageHash` (domain, witness version, commitment and hash).
Legacy signatures never verify for a strict identity, even for the same key;
there is no fallback to an unbound strict signature.
Internal DER message signatures and historical saved sender keys use the same
exact key-to-destination check; the DER signature itself covers the unbound
content digest, which already contains the sender address. Wallet helpers resolve strict keys through versioned AuthScript
spend data, verify the public key against the destination, and use the selected
wallet. This supports an ECDSA client wallet alongside the separate service
wallet; it does not require sharing client private keys with a remote relay.

## Destination ids in the envelope

Both families use the one envelope format, format 3
([the protocol](depin-messaging-protocol.md#4-envelope-format-3-ceciesencryptedmessage)).
A recipient is identified by its typed destination id:

```
00 || hash160_raw20          Legacy
03 || commitment_raw32       strict ECDSA
```

The entries sort by the serialized id, byte by byte (so first by type). The
commitment's raw bytes are the reverse of `validateaddress.commitment`'s usual
uint256 display hex. The id enters the derivation of the recipient's wrap key
as serialized, type byte included: a wrapped key does not open under another
id, even of the same public key. Unknown types, duplicate or unsorted ids,
nonminimal CompactSize, truncated fields, wrong package lengths, invalid
ephemeral points and trailing bytes are rejected. Formats 1 and 2, which used
untyped Legacy ids or a separate framing for strict ids, are not read.

All existing plaintext, recipient-count and reply limits remain. The conservative
wire bound for plaintext budget P and recipient budget R is `114 + P + 94*R`.
The outer submission shell has exactly one recipient, the pool's Legacy
service identity. An addressed reply uses its request's exact destination.
Inner content can target any nonempty authorized subset mixing both families.
Admission checks every decoded destination without rewriting the sender's
signed bytes.

## Membership, history and clients

The membership observer records first valid key revelations for both families. Relevant confirmed
membership changes renew the pool revision and invalidate all RECEIVE/ADMIN
challenges. Current permissions are still checked on every operation, and recipient
authorization rejects an entire publication containing a disabled destination with `-26`.

Messages persist their verified sender key and restore without requiring the
sender to remain enabled, while future downloads still require the reader's
current permissions. Previously downloaded copies remain readable after
revocation.

Tests include independent Python encoding, mixed sends in every direction,
separate wallets, typed malformed input, exact destination isolation, first
strict key revelation, freezes/reorgs, self-revocation, strict owner moderation,
sequence cursors, restart and durable tombstones. See
`test/functional/feature_depin_ecdsa.py` and the DePIN C++ suites.

## Validation limits

Node tests do not certify external SDKs or all wallet configurations.
