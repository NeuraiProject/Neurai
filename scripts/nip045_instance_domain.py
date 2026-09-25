#!/usr/bin/env python3
"""Derive the public NIP-045 pool domain from a UNIQUE issuance outpoint.

Inputs displayed by RPC are reversed to wire order before hashing. The
issuance must precede the pool birth transaction, so this value can be fixed
before compiling the circuit verification keys and the MAST commitment.
"""

import argparse
import hashlib


PREFIX = b"NIP045/pool/instance/v1"


def compact_size(value: int) -> bytes:
    if not 0 <= value < 253:
        raise ValueError("UNIQUE name must be 1..252 UTF-8 bytes")
    return bytes([value])


def instance_domain(
    genesis_hash_rpc: str, issuance_txid_rpc: str, issuance_vout: int, unique_name: str
) -> bytes:
    """Return SHA256(prefix || genesis || issuance outpoint || UNIQUE name).

    Hashes are supplied as 64-character RPC hex strings and serialized in
    internal byte order. The vout is unsigned little-endian; the name is UTF-8
    preceded by its one-byte CompactSize length.
    """
    try:
        genesis = bytes.fromhex(genesis_hash_rpc)
        txid = bytes.fromhex(issuance_txid_rpc)
    except ValueError as exc:
        raise ValueError("genesis and issuance txid must be RPC hex") from exc
    if len(genesis) != 32 or len(txid) != 32:
        raise ValueError("genesis and issuance txid must be 32 bytes")
    if not 0 <= issuance_vout < 2**32:
        raise ValueError("issuance vout must be a uint32")
    name = unique_name.encode("utf-8")
    if not name or len(name) >= 253:
        raise ValueError("UNIQUE name must be 1..252 UTF-8 bytes")
    preimage = (
        PREFIX
        + genesis[::-1]
        + txid[::-1]
        + issuance_vout.to_bytes(4, "little")
        + compact_size(len(name))
        + name
    )
    return hashlib.sha256(preimage).digest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("genesis_hash_rpc")
    parser.add_argument("issuance_txid_rpc")
    parser.add_argument("issuance_vout", type=int)
    parser.add_argument("unique_name")
    args = parser.parse_args()
    print(instance_domain(**vars(args)).hex())


if __name__ == "__main__":
    main()
