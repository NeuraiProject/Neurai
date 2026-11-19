#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Talk to the ESP32 P-256 signer firmware (contrib/p256/esp32p4) over serial.

Commands:
  info   --port /dev/ttyACM0            chip revision, ESP-IDF version, key block
  pub    --port ...                     compressed public key exported by the chip
  sign   --port ... --digest HEX        sign a 32-byte digest
  check  --port ...                     the NIP-060 plan F1b checks:
           - the public key exported by the chip (1b.4);
           - the shared spend vector: the chip signs its digest and the signature
             must verify over the message, not over the digest (1b.5, double SHA-256);
           - deterministic: the same digest twice gives the same signature (1b.6);
           - the key recovered from two signatures over different digests is unique,
             equals the exported key, and verifies a third signature (1b.4);
           - every signature has low S.
  spend  --port ... --tx HEX --index N --amount SATS --spent-script HEX
                                        sign a NIP-060 §5 spend with the chip and print the
                                        signed transaction

Only the Python standard library is used (termios), so it also runs outside
the ESP-IDF environment. The firmware is a REPL: it echoes the command and
prints one line starting with INFO, PUB, SIG, OK or ERR.
"""

import argparse
import hashlib
import json
import os
import select
import sys
import termios
import time

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'test', 'functional'))
import p256_sign  # noqa: E402
from test_framework import key_p256 as k  # noqa: E402
from test_framework.messages import CTransaction, from_hex  # noqa: E402

VECTOR = os.path.join(os.path.dirname(__file__), '..', '..', 'src', 'test', 'data', 'p256_spend_vector.json')


class Device:
    def __init__(self, port, baud=115200):
        self.fd = os.open(port, os.O_RDWR | os.O_NOCTTY)
        attrs = termios.tcgetattr(self.fd)
        speed = getattr(termios, 'B%d' % baud)
        attrs[0] = 0                                   # iflag
        attrs[1] = 0                                   # oflag
        attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
        attrs[3] = 0                                   # lflag: raw
        attrs[4] = attrs[5] = speed
        termios.tcsetattr(self.fd, termios.TCSANOW, attrs)
        self.buffer = b''
        self.command('')  # wake the prompt

    def readline(self, timeout):
        end = time.time() + timeout
        while b'\n' not in self.buffer:
            left = end - time.time()
            if left <= 0:
                return None
            ready, _, _ = select.select([self.fd], [], [], left)
            if ready:
                self.buffer += os.read(self.fd, 4096)
        line, _, self.buffer = self.buffer.partition(b'\n')
        return line.decode(errors='replace').strip()

    def command(self, text, prefixes=('INFO', 'PUB', 'SIG', 'OK', 'ERR'), timeout=10):
        os.write(self.fd, text.encode() + b'\r\n')
        if not text:
            time.sleep(0.3)
            self.buffer = b''
            return None
        while True:
            line = self.readline(timeout)
            if line is None:
                raise SystemExit('no answer to %r' % text)
            # Skip the echo, the prompt and log lines.
            line = line.split('p256>')[-1].strip()
            for prefix in prefixes:
                if line.startswith(prefix + ' '):
                    if prefix == 'ERR':
                        raise SystemExit(line)
                    return line[len(prefix) + 1:]

    def info(self):
        return self.command('info')

    def pub(self):
        return bytes.fromhex(self.command('pub'))

    def sign(self, digest):
        sig = bytes.fromhex(self.command('sign ' + digest.hex()))
        assert len(sig) == 64
        return sig


def low_s(sig):
    return int.from_bytes(sig[32:], 'big') <= k.HALF_N


def check(device):
    results = []

    def report(name, passed, detail=''):
        results.append(passed)
        print('%s %s %s' % ('PASS' if passed else 'FAIL', name, detail))

    info = device.info()
    print('INFO', info)
    pub = device.pub()
    report('pub/compressed', len(pub) == 33 and k.decompress(pub) is not None, pub.hex())

    vector = json.load(open(VECTOR))
    message = bytes.fromhex(vector['message'])
    digest = bytes.fromhex(vector['digest'])
    assert hashlib.sha256(message).digest() == digest
    sig = device.sign(digest)
    report('vector/low_s', low_s(sig))
    on_message = k.verify(pub, message, sig)
    on_digest = k.verify(pub, digest, sig)
    report('vector/verifies_over_message', on_message,
           '' if on_message else ('the firmware hashes the digest again' if on_digest else 'does not verify'))

    again = device.sign(digest)
    report('deterministic/same_digest_same_signature', again == sig)

    d1 = hashlib.sha256(b'NIP-060 device check 1').digest()
    d2 = hashlib.sha256(b'NIP-060 device check 2').digest()
    d3 = hashlib.sha256(b'NIP-060 device check 3').digest()
    s1, s2, s3 = device.sign(d1), device.sign(d2), device.sign(d3)
    report('low_s/all', all(low_s(s) for s in (s1, s2, s3)))
    c1, c2 = k.recover_candidates(d1, s1), k.recover_candidates(d2, s2)
    common = set(c1) & set(c2)
    report('recover/unique_common_key', len(common) == 1, '%d and %d candidates' % (len(c1), len(c2)))
    recovered = common.pop() if len(common) == 1 else b''
    report('recover/equals_exported', recovered == pub)
    # s3 signs d3 as a digest (verify() would hash it again): check the equation directly.
    point = k.decompress(recovered) if recovered else None
    confirmed = False
    if point is not None:
        e = int.from_bytes(d3, 'big') % k.N
        r = int.from_bytes(s3[:32], 'big')
        w = pow(int.from_bytes(s3[32:], 'big'), -1, k.N)
        R = k._add(k.point_mul(e * w % k.N), k.point_mul(r * w % k.N, point))
        confirmed = R is not None and R[0] % k.N == r
    report('recover/confirmed_by_third_signature', confirmed)
    print('RESULT', 'PASS' if all(results) else 'FAIL')
    return all(results)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=('info', 'pub', 'sign', 'check', 'spend'))
    parser.add_argument('--port', required=True)
    parser.add_argument('--baud', type=int, default=115200)
    parser.add_argument('--digest')
    parser.add_argument('--tx')
    parser.add_argument('--index', type=int, default=0)
    parser.add_argument('--amount', type=int)
    parser.add_argument('--spent-script')
    args = parser.parse_args()
    device = Device(args.port, args.baud)
    if args.command == 'info':
        print(device.info())
    elif args.command == 'pub':
        pub = device.pub()
        print('pubkey', pub.hex())
        script = p256_sign.witness_script(pub)
        print('witness_script', script.hex())
        print('scriptPubKey', (b'\x51\x20' + p256_sign.authscript_program(script)).hex())
    elif args.command == 'sign':
        print(device.sign(bytes.fromhex(args.digest)).hex())
    elif args.command == 'check':
        sys.exit(0 if check(device) else 1)
    else:
        tx = from_hex(CTransaction(), args.tx)
        msg = p256_sign.message(tx, args.index, args.amount, bytes.fromhex(args.spent_script))
        pub = device.pub()
        sig = device.sign(hashlib.sha256(msg).digest())
        if not k.verify(pub, msg, sig):
            raise SystemExit('the device signature does not verify for this spend')
        script = p256_sign.witness_script(pub)
        print(p256_sign.with_witness(tx, args.index, sig, script).serialize_with_witness().hex())


if __name__ == '__main__':
    main()
