#!/usr/bin/env python3
"""Reproduce the literal phase-10 vectors in reversebytes_tests.cpp with hashlib.
No node libraries, RPC or display-byte-order conversions are used.
"""
import hashlib

for size in (0, 32, 33, 1313, 2420):
    payload = bytes(i % 256 for i in range(size))
    sha = hashlib.sha256(payload).digest()
    digests = {
        'RIPEMD160': hashlib.new('ripemd160', payload).hexdigest(),
        'SHA1': hashlib.sha1(payload).hexdigest(),
        'SHA256': sha.hex(),
        'HASH160': hashlib.new('ripemd160', sha).hexdigest(),
        'HASH256': hashlib.sha256(sha).hexdigest(),
    }
    for opcode, digest in digests.items():
        print(f'        {{{size}, OP_{opcode}, "{digest}"}},')
