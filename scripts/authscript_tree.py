#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license; see COPYING.
"""Independent byte construction for NIP-044 integration tests.

No node bindings, key management or signature verifier. Hash bytes use wire order.
"""
import hashlib

H = lambda b: hashlib.sha256(b).digest()
D = lambda b: H(H(b))

def tagged(tag, data):
    return H(H(tag.encode('ascii')) * 2 + data)

def compact(n):
    if not 0 <= n < 2**64:
        raise ValueError('CompactSize range')
    if n < 253:
        return bytes([n])
    for limit, marker, size in [(2**16, 253, 2), (2**32, 254, 4), (2**64, 255, 8)]:
        if n < limit:
            return bytes([marker]) + n.to_bytes(size, 'little')

def leaf(script, version=1):
    if version != 1 or len(script) > 10000:
        raise ValueError('leaf')
    return tagged('NeuraiAuthLeaf', bytes([version]) + compact(len(script)) + script)

def branch(a, b):
    if len(a) != 32 or len(b) != 32:
        raise ValueError('branch')
    return tagged('NeuraiAuthBranch', min(a, b) + max(a, b))

def commitment(root, descriptor=b'\x00'):
    if len(root) != 32 or not (descriptor == b'\x00' or
            (len(descriptor) == 21 and descriptor[0] in (1, 2))):
        raise ValueError('descriptor/root')
    return tagged('NeuraiAuthScript', b'\x04' + descriptor + root)

def tree(scripts):
    if not scripts or any(not n or not n.isascii() for n in scripts):
        raise ValueError('unique nonempty ASCII labels required')
    def build(names):
        if len(names) == 1:
            return leaf(scripts[names[0]]), {names[0]: []}
        cut = 1 << ((len(names)-1).bit_length()-1)
        a, pa = build(names[:cut]); b, pb = build(names[cut:])
        return branch(a, b), {**{n: p+[b] for n, p in pa.items()},
                              **{n: p+[a] for n, p in pb.items()}}
    root, paths = build(sorted(scripts))
    if any(len(p) > 32 for p in paths.values()):
        raise ValueError('depth')
    return root, {n: b'\x01'+b''.join(p) for n, p in paths.items()}

def recover(script, control):
    if not control or (len(control)-1) % 32 or len(control) > 1025:
        raise ValueError('control')
    h = leaf(script, control[0])
    for i in range(1, len(control), 32):
        h = branch(h, control[i:i+32])
    return h

def signature_hash(base_hash, role, auth_type, program, leaf_hash):
    if role not in (0, 1) or auth_type not in (0x10, 0x11, 0x12):
        raise ValueError('signing context')
    if role == 0 and auth_type == 0x10:
        raise ValueError('NoAuth has no global signature')
    if any(len(x) != 32 for x in (base_hash, program, leaf_hash)):
        raise ValueError('hash length')
    return tagged('NeuraiAuthTreeSig', b'\x01'+bytes([role, auth_type])+
                  program+leaf_hash+base_hash)

