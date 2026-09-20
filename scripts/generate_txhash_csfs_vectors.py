#!/usr/bin/env python3
"""Generate public NIP-042 CSFS vectors with the standalone test signer.
The saved PQ signature is verified, never compared to a freshly randomized one.
Keys are disposable; secret keys are neither printed nor saved.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess

spec = importlib.util.spec_from_file_location('txhash', Path(__file__).with_name('review-txhash-regtest.py'))
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--signer', default='/tmp/authscript-review-signer')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    refs = [bytes(range(64, 96)) + struct.pack('<I', 0x12345678),
            bytes(range(96, 128)) + struct.pack('<I', 0x87654321)]
    digest = t.field_hash(0x110, 3, 0, [bytes(36)], [0xffffffff], [(100000, b'\x51')], 0, refs)
    signed = hashlib.sha256(digest).digest()
    rows = []
    for algorithm in ('ecdsa', 'pq'):
        pub, secret = subprocess.check_output([args.signer, 'keygen', algorithm], text=True).split()
        signature = subprocess.check_output([args.signer, 'sign', algorithm], input=secret + '\n' + signed.hex() + '\n', text=True).strip()
        rows.append(dict(algorithm=algorithm, pubkey=pub, signature=signature, digest=digest.hex(), signed_hash=signed.hex()))
    args.output.write_text(json.dumps(rows, indent=2) + '\n')


if __name__ == '__main__':
    main()
