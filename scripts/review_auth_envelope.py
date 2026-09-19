"""Disposable v1 authentication and P2SH envelope for local contract tests."""
import hashlib
from pathlib import Path
import struct
import subprocess
from generate_authscript_vectors import bech32m, sha256


def compact(n):
    if n < 253:
        return bytes([n])
    return b'\xfd' + struct.pack('<H', n) if n <= 65535 else b'\xfe' + struct.pack('<I', n)


def hash160(data):
    return hashlib.new('ripemd160', sha256(data)).digest()


class Envelope:
    def __init__(self, auth=0, wrapped=False, signer=Path('/tmp/authscript-review-signer')):
        self.auth, self.wrapped, self.signer = auth, wrapped, signer
        self.pub, self.secret = b'', ''
        if auth:
            pub, self.secret = subprocess.check_output([str(signer), 'keygen', self.family], text=True).splitlines()
            self.pub = bytes.fromhex(pub)

    @property
    def family(self):
        return 'pq' if self.auth == 1 else 'ecdsa'

    def program(self, script):
        tag = sha256(b'NeuraiAuthScript')
        descriptor = bytes([self.auth]) + (hash160(self.pub) if self.auth else b'')
        return sha256(tag + tag + b'\x01' + descriptor + sha256(script))

    def output(self, program):
        native = b'\x51\x20' + program
        return b'\xa9\x14' + hash160(native) + b'\x87' if self.wrapped else native

    def address(self, node, program):
        return node.rpc('decodescript', (b'\x51\x20' + program).hex())['p2sh'] if self.wrapped else bech32m('tnq', 1, program)

    def transaction(self, utxo, script, arguments, output, amount=90_000_000, locktime=0, sequence=0xffffffff):
        prev = bytes.fromhex(utxo[0])[::-1] + struct.pack('<I', utxo[1])
        seq, lock, version = struct.pack('<I', sequence), struct.pack('<I', locktime), struct.pack('<I', 2)
        out = struct.pack('<Q', amount) + compact(len(output)) + output
        stack = [bytes([self.auth])]
        if self.auth:
            double = lambda x: sha256(sha256(x))
            preimage = (version + double(prev) + double(seq) + prev + compact(len(script)) + script +
                        struct.pack('<Q', 100_000_000) + seq + double(out) + lock + bytes([self.auth]) + struct.pack('<I', 1))
            sig = bytes.fromhex(subprocess.check_output([str(self.signer), 'sign', self.family],
                input=self.secret + '\n' + double(preimage).hex() + '\n', text=True).strip())
            stack += [sig, self.pub]
        stack += list(arguments) + [script]
        redeem = b'\x51\x20' + self.program(script)
        scriptsig = bytes([len(redeem)]) + redeem if self.wrapped else b''
        vin = b'\x01' + prev + compact(len(scriptsig)) + scriptsig + seq
        witness = compact(len(stack)) + b''.join(compact(len(x)) + x for x in stack)
        return version + vin + b'\x01' + out + lock, version + b'\x00\x01' + vin + b'\x01' + out + witness + lock


def options(parser):
    parser.add_argument('--auth', type=int, choices=[0, 1, 2], default=0)
    parser.add_argument('--wrapped', action='store_true')
    parser.add_argument('--signer', type=Path, default=Path('/tmp/authscript-review-signer'))
