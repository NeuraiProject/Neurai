#!/usr/bin/env python3
"""Stack/control and classical hashes under the same authenticated contract matrix."""
import hashlib
import importlib.util
from pathlib import Path
import sys

spec = importlib.util.spec_from_file_location('enveloped_hash_driver', Path(__file__).with_name('review-hash-merkle-regtest.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


def cases(_):
    push = driver.h.push
    result = []
    value = bytes(range(33))
    for name, opcode, digest in [
        ('RIPEMD160', 0xa6, hashlib.new('ripemd160', value).digest()),
        ('SHA1', 0xa7, hashlib.sha1(value).digest()),
        ('SHA256', 0xa8, hashlib.sha256(value).digest()),
        ('HASH160', 0xa9, hashlib.new('ripemd160', hashlib.sha256(value).digest()).digest()),
        ('HASH256', 0xaa, hashlib.sha256(hashlib.sha256(value).digest()).digest()),
    ]:
        result.append((name, bytes([opcode]) + push(digest) + b'\x88', [value]))
    A, B, C, D, E, F = [bytes([n]) for n in range(65, 71)]
    for name, op, initial, expected in [
        ('2DROP', 0x6d, [A,B,C], [A]),
        ('2DUP', 0x6e, [A,B], [A,B,A,B]),
        ('3DUP', 0x6f, [A,B,C], [A,B,C,A,B,C]),
        ('2OVER', 0x70, [A,B,C,D], [A,B,C,D,A,B]),
        ('2ROT', 0x71, [A,B,C,D,E,F], [C,D,E,F,A,B]),
        ('2SWAP', 0x72, [A,B,C,D], [C,D,A,B]),
        ('IFDUP', 0x73, [A,B], [A,B,B]),
        ('DEPTH', 0x74, [A,B,C], [A,B,C,b'\x03']),
        ('DROP', 0x75, [A,B,C], [A,B]),
        ('DUP', 0x76, [A,B,C], [A,B,C,C]),
        ('NIP', 0x77, [A,B,C], [A,C]),
        ('OVER', 0x78, [A,B,C], [A,B,C,B]),
        ('PICK', 0x79, [A,B,C,D,b'\x03'], [A,B,C,D,A]),
        ('ROLL', 0x7a, [A,B,C,D,b'\x03'], [B,C,D,A]),
        ('ROT', 0x7b, [A,B,C], [B,C,A]),
        ('SWAP', 0x7c, [A,B], [B,A]),
        ('TUCK', 0x7d, [A,B], [B,A,B]),
        ('SIZE', 0x82, [A,B,C], [A,B,C,b'\x01']),
    ]:
        # Preserve a copy so malformed witness also fails when the opcode drops
        # that operand. Check every output, and leave both stacks empty.
        script = b'\x76\x6b' + bytes([op])
        script += b''.join(push(v) + b'\x88' for v in reversed(expected))
        script += b'\x6c' + push(initial[-1]) + b'\x88'
        result.append((name, script, initial))
    for name, branch in [('IF', b'\x63\x61\x67' + push(B) + b'\x68'),
                         ('NOTIF', b'\x64' + push(B) + b'\x67\x61\x68')]:
        script = b'\x76' + push(A) + b'\x87' + branch + push(A) + b'\x88'
        result.append((name, script, [A]))
    return result


if __name__ == '__main__':
    driver.cases = cases
    # Make the shared driver record the exact case table as its vectors input.
    sys.argv.extend(['--vectors', str(Path(__file__).resolve())])
    raise SystemExit(driver.main())
