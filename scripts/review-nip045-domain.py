#!/usr/bin/env python3
"""Fixed NIP-045 pool-domain vector and separation checks (no node needed)."""

from nip045_instance_domain import instance_domain


GENESIS = bytes(range(32)).hex()
ISSUANCE = bytes(range(32, 64)).hex()
EXPECTED = "a94b75826190d046d6aea7c9032826b8cbd571385551cdbf17531db7ef36d96b"


def reject(label, *args):
    try:
        instance_domain(*args)
    except ValueError:
        print("PASS", label)
    else:
        raise AssertionError(label)


base = instance_domain(GENESIS, ISSUANCE, 2, "RWAX#POOL")
assert base.hex() == EXPECTED
print("PASS independent SHA256 vector")
assert instance_domain(
    "5241e503402b81548ea32dbfd7b670829b30fb83220a92ad9804ad893ecdce71",
    "44d3cab1d9baf36c2777181d065332e78771f202cadde0d177771fe55b594d67",
    3,
    "RWAX#POOL",
).hex() == "a01b71b92ce399bfcc27513a906d800da541063dda6d065c759c42762fb5c61d"
print("PASS fixed regtest issuance vector")
for label, args in (
    ("network", ((bytes([1]) + bytes(range(1, 32))).hex(), ISSUANCE, 2, "RWAX#POOL")),
    ("issuance", (GENESIS, (bytes([33]) + bytes(range(33, 64))).hex(), 2, "RWAX#POOL")),
    ("vout", (GENESIS, ISSUANCE, 3, "RWAX#POOL")),
    ("UNIQUE", (GENESIS, ISSUANCE, 2, "RWAX#OTHER")),
):
    assert instance_domain(*args) != base, label
    print("PASS separated", label)
reject("short genesis", "00", ISSUANCE, 2, "RWAX#POOL")
reject("negative vout", GENESIS, ISSUANCE, -1, "RWAX#POOL")
reject("empty UNIQUE", GENESIS, ISSUANCE, 2, "")
reject("long UNIQUE", GENESIS, ISSUANCE, 2, "A" * 253)
