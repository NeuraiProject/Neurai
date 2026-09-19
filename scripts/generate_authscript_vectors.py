#!/usr/bin/env python3
"""Independent AuthScript vectors; no imports or calls into the node.

Uses hashlib primitives, independent serialization and Bech32m encoding.
Prints JSON including exact preimages; --check compares with the saved fixture.
Synthetic public keys exercise encoding/hashing, not signing or seed derivation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct


def sha256(data):
    return hashlib.sha256(data).digest()


def sha256d(data):
    return sha256(sha256(data))


def u32(value):
    return struct.pack('<I', value)


def u64(value):
    return struct.pack('<Q', value)


def bech32m(hrp, version, program):
    charset = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    bits = ''.join(f'{byte:08b}' for byte in program)
    bits += '0' * ((-len(bits)) % 5)
    data = [version] + [int(bits[i:i + 5], 2) for i in range(0, len(bits), 5)]
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    check = 1
    for value in expanded + data + [0] * 6:
        top = check >> 25
        check = ((check & 0x1ffffff) << 5) ^ value
        for i, generator in enumerate((0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)):
            if (top >> i) & 1:
                check ^= generator
    check ^= 0x2bc830a3
    checksum = [(check >> (5 * (5 - i))) & 31 for i in range(6)]
    return hrp + '1' + ''.join(charset[v] for v in data + checksum)


def generate():
    keys = {'pq': b'\x05' + bytes(i % 256 for i in range(1312)),
            'ecdsa': b'\x02' + bytes(range(32))}
    tag = sha256(b'NeuraiAuthScript')
    commitments = []
    for version, auth_type, key_name in ((1, 1, 'pq'), (1, 2, 'ecdsa'),
                                        (1, 0, None), (2, 1, 'pq'), (3, 2, 'ecdsa')):
        descriptor = bytes([auth_type])
        if key_name:
            descriptor += hashlib.new('ripemd160', sha256(keys[key_name])).digest()
        preimage = bytes([version]) + descriptor + sha256(b'\x51')
        sha_input = tag + tag + preimage
        commitment = sha256(sha_input)
        hrp = {1: 'nc', 2: 'pq', 3: 'nq'}[version]
        commitments.append({
            'version': version, 'auth_type': auth_type, 'key': key_name,
            'auth_descriptor_hex': descriptor.hex(), 'preimage_hex': preimage.hex(),
            'tagged_sha256_input_hex': sha_input.hex(), 'commitment_hex': commitment.hex(),
            'mainnet': bech32m(hrp, version, commitment),
            'testnet_regtest': bech32m('t' + hrp, version, commitment),
        })
    prevout = bytes(range(32)) + u32(7)
    sequence = u32(0xfffffffd)
    output_script = bytes.fromhex('76a914') + b'\xab' * 20 + bytes.fromhex('88ac')
    # All scripts/counts here are <253, so CompactSize is a single byte.
    output = u64(123456789) + bytes([len(output_script)]) + output_script
    base = (u32(2) + sha256d(prevout) + sha256d(sequence) + prevout + b'\x01\x51'
            + u64(987654321) + sequence + sha256d(output) + u32(1700000000))
    sighashes = []
    for domain, suffix in (('v1_pq', b'\x01'), ('v2_pq', b'\x02\x01'), ('v3_ecdsa', b'\x03\x02')):
        preimage = base + suffix + u32(1)
        sighashes.append({'domain': domain, 'preimage_hex': preimage.hex(),
                          'preimage_bytes': len(preimage), 'sighash_hex': sha256d(preimage).hex()})
    unsigned_tx = u32(2) + b'\x01' + prevout + b'\x00' + sequence + b'\x01' + output + u32(1700000000)
    return {'byte_order': 'raw digest bytes, not reversed uint256 display',
            'pubkeys_hex': {name: key.hex() for name, key in keys.items()},
            'witness_script_hex': '51', 'commitments': commitments,
            'unsigned_transaction_hex': unsigned_tx.hex(), 'spent_amount': 987654321,
            'hash_prevouts_hex': sha256d(prevout).hex(),
            'hash_sequence_hex': sha256d(sequence).hex(),
            'hash_outputs_hex': sha256d(output).hex(), 'sighashes': sighashes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='compare with scripts/data/authscript-vectors.json')
    args = parser.parse_args()
    result = generate()
    if args.check:
        saved = Path(__file__).resolve().parent / 'data' / 'authscript-vectors.json'
        if result != json.loads(saved.read_text()):
            raise SystemExit('FAIL: generated vectors differ from ' + str(saved))
        print('PASS: 5 commitments, 10 addresses, 3 sighashes and all preimages match')
    else:
        print(json.dumps(result, indent=2) + '\n', end='')


if __name__ == '__main__':
    main()
