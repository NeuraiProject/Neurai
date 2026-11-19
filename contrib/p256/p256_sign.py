#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Reference signer for the NIP-060 §5 pattern (P-256 key, no envelope key).

The witness script of the spent AuthScript v1 output (authType 0x00) is

  <ff01> OP_TXHASH 3 OP_TXFIELD OP_CAT 1 OP_TXFIELD OP_CAT <pubkey33> OP_CHECKSIG_P256

so the key signs SHA-256(TXHASH || spent scriptPubKey || amount), where
TXHASH is OP_TXHASH with the selector 0x01ff for the input being signed. The
transaction alone does not carry the spent scriptPubKey or the amount: they
are given explicitly, as witness_utxo in PSBT.

Commands:
  script   --pubkey HEX                       print the witness script and the AuthScript program
  message  --tx HEX --index N --amount SATS --spent-script HEX
                                              print the message and the 32-byte digest to sign
  sign     ... --privkey HEX --witness-script HEX
                                              sign with a local key (tests only) and print the signed tx
  insert   ... --signature HEX --witness-script HEX [--pubkey HEX]
                                              insert a signature made elsewhere (a device): 64-byte
                                              r || s or DER; S is normalized to low S; with --pubkey
                                              the signature is checked first

The witness of the input becomes [0x00, signature64, witness script].
"""

import argparse
import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'test', 'functional'))
from test_framework import key_p256 as k  # noqa: E402
from test_framework.messages import CTransaction, CTxInWitness, from_hex  # noqa: E402

OP_TXHASH = 0xb5
OP_TXFIELD = 0xb6
OP_CAT = 0x7e
OP_3 = 0x53
OP_1 = 0x51
OP_CHECKSIG_P256 = 0xe0
TXHASH_ALL = 0x01ff


def sha256(data):
    return hashlib.sha256(data).digest()


def double_sha(data):
    return sha256(sha256(data))


def witness_script(pubkey):
    """NIP-060 §5 witness script for a 33-byte compressed P-256 key."""
    assert len(pubkey) == 33
    return (bytes([0x02, 0xff, 0x01, OP_TXHASH, OP_3, OP_TXFIELD, OP_CAT, OP_1, OP_TXFIELD, OP_CAT, 0x21]) +
            pubkey + bytes([OP_CHECKSIG_P256]))


def authscript_program(script):
    """AuthScript v1 commitment without an envelope key (authType 0x00)."""
    tag = sha256(b'NeuraiAuthScript')
    return sha256(tag + tag + b'\x01\x00' + sha256(script))


def txhash(tx, index, mask=TXHASH_ALL):
    """OP_TXHASH (NIP-042), as TransactionSignatureChecker::GetTxFieldHash."""
    prevouts = [txin.prevout.serialize() for txin in tx.vin]
    sequences = [txin.nSequence for txin in tx.vin]
    # Reference inputs (NIP-014): the outpoints of vrefin, only in version 3
    # transactions; any other version hashes the empty string, as the node does.
    refs = b''.join(ref.serialize() for ref in tx.vrefin) if tx.nVersion == 3 else b''
    fields = [struct.pack('<I', tx.nVersion & 0xffffffff), struct.pack('<I', tx.nLockTime),
              double_sha(b''.join(prevouts)),
              double_sha(b''.join(struct.pack('<I', s) for s in sequences)),
              double_sha(b''.join(out.serialize() for out in tx.vout)),
              prevouts[index], struct.pack('<I', sequences[index]), struct.pack('<I', index),
              double_sha(refs)]
    tag = sha256(b'NeuraiTxHash')
    return sha256(tag + tag + struct.pack('<H', mask) +
                  b''.join(field for bit, field in enumerate(fields) if mask & (1 << bit)))


def message(tx, index, amount, spent_script):
    """TXHASH || spent scriptPubKey || amount (8 bytes, little endian)."""
    return txhash(tx, index) + spent_script + struct.pack('<q', amount)


def der_to_raw(sig):
    """Convert a DER ECDSA signature to 64-byte r || s."""
    if len(sig) == 64:
        return sig
    if sig[0] != 0x30 or sig[2] != 0x02:
        raise SystemExit('signature is neither 64-byte r || s nor DER')
    rlen = sig[3]
    r = int.from_bytes(sig[4:4 + rlen], 'big')
    if sig[4 + rlen] != 0x02:
        raise SystemExit('bad DER signature')
    slen = sig[5 + rlen]
    s = int.from_bytes(sig[6 + rlen:6 + rlen + slen], 'big')
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


def low_s(sig):
    s = int.from_bytes(sig[32:], 'big')
    if s > k.HALF_N:
        s = k.N - s
    return sig[:32] + s.to_bytes(32, 'big')


def with_witness(tx, index, sig, script):
    while len(tx.wit.vtxinwit) < len(tx.vin):
        tx.wit.vtxinwit.append(CTxInWitness())
    tx.wit.vtxinwit[index].scriptWitness.stack = [b'\x00', sig, script]
    return tx


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=('script', 'message', 'sign', 'insert'))
    parser.add_argument('--tx')
    parser.add_argument('--index', type=int, default=0)
    parser.add_argument('--amount', type=int, help='amount of the spent output, in satoshis')
    parser.add_argument('--spent-script', help='scriptPubKey of the spent output, hex')
    parser.add_argument('--privkey')
    parser.add_argument('--pubkey')
    parser.add_argument('--signature')
    parser.add_argument('--witness-script')
    args = parser.parse_args()

    if args.command == 'script':
        script = witness_script(bytes.fromhex(args.pubkey))
        print('witness_script', script.hex())
        print('program', authscript_program(script).hex())
        print('scriptPubKey', (b'\x51\x20' + authscript_program(script)).hex())
        return

    tx = from_hex(CTransaction(), args.tx)
    msg = message(tx, args.index, args.amount, bytes.fromhex(args.spent_script))
    if args.command == 'message':
        print('message', msg.hex())
        print('digest', sha256(msg).hex())
        return
    script = bytes.fromhex(args.witness_script)
    if args.command == 'sign':
        sig = k.sign(int(args.privkey, 16), msg)
    else:
        sig = low_s(der_to_raw(bytes.fromhex(args.signature)))
        if args.pubkey and not k.verify(bytes.fromhex(args.pubkey), msg, sig):
            raise SystemExit('the signature does not verify for this transaction, amount and spent script')
    print(with_witness(tx, args.index, sig, script).serialize_with_witness().hex())


if __name__ == '__main__':
    main()
