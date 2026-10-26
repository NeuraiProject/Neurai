# Legacy and strict ECDSA DePIN messaging

RPC 5 supports Legacy P2PKH and strict ECDSA witness-v3 addresses
(`nq1r…` on mainnet, `tnq1r…` on testnet/regtest). The service uses the
network's existing activation and asset rules; it introduces no consensus
change. P2SH, generic AuthScript v1 and strict PQ are not messaging identities.

Bootstrap advertises `address_types: ["legacy", "ecdsa"]`,
`ecies_formats: [1, 2]` and `accepted_protocols: [5]`. RPC 4 and earlier
requests are rejected. RPC fields and membership context retain their RPC 4
layout, but U16 version and request/response signature domains are now 5/v5.
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

## ECIES formats

The AES-256-GCM content cipher, ECDH, KDF and 60-byte wrapped key packages are
unchanged. Only recipient identity framing is extended. A single ephemeral
compressed key and encrypted payload are shared by all recipients.

ECIES 1 is the existing canonical Legacy-only encoding:

```
CompactSize(33) || ephemeral_pubkey33
CompactSize(payload_length) || nonce12 || ciphertext || tag16
CompactSize(recipient_count)
  repeated: hash160_raw20 || CompactSize(60) || wrapped_package60
```

ECIES 2 is used whenever at least one recipient is strict ECDSA:

```
00 02
CompactSize(33) || ephemeral_pubkey33
CompactSize(payload_length) || nonce12 || ciphertext || tag16
CompactSize(recipient_count)
  repeated:
    (00 || hash160_raw20) OR (03 || commitment_raw32)
    CompactSize(60) || wrapped_package60
```

The map sorts first by type, then lexicographically by raw payload bytes.
The commitment's raw bytes are the reverse of `validateaddress.commitment`'s
usual uint256 display hex. ECIES 1 remains byte-for-byte unchanged. ECIES 2
with only Legacy recipients is rejected as noncanonical. Unknown versions or
types, duplicate/unsorted identities, nonminimal CompactSize, truncated fields,
wrong package lengths, invalid ephemeral points and trailing bytes are rejected.

All existing plaintext, recipient-count and reply limits remain. The conservative
wire bound for plaintext budget P and recipient budget R is `82 + P + 94*R`.
The outer submission shell still has exactly one recipient, the pool's Legacy
service identity, and therefore normally remains ECIES 1. An addressed reply
uses its request's exact destination, so ECDSA replies use ECIES 2. Inner content
can target any nonempty authorized subset mixing both families. Admission checks
every decoded destination without rewriting the sender's signed bytes.

## Membership, history and clients

The membership observer records first valid key revelations for both families. Relevant confirmed
membership changes renew the pool revision and invalidate all RECEIVE/ADMIN
challenges. Current permissions are still checked on every operation, and recipient
authorization rejects an entire publication containing a disabled destination with `-26`.

Message framing, hashes, storage version 2 and cursor version 1 are unchanged.
Historical Legacy ECIES decodes as before. Mixed/strict messages persist their
verified sender key and restore without requiring the sender to remain enabled,
while future downloads still require the reader's current permissions.
Previously downloaded copies remain decryptable after revocation.

Tests include independent Python encoding, mixed sends in every direction,
separate wallets, typed malformed input, exact destination isolation, first
strict key revelation, freezes/reorgs, self-revocation, strict owner moderation,
sequence cursors, restart and durable tombstones. See
`test/functional/feature_depin_ecdsa.py` and the DePIN C++ suites.

## Validation limits

Node tests do not certify external SDKs or all wallet configurations.
