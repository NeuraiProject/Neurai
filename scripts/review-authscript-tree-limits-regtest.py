#!/usr/bin/env python3
"""NIP-044 exact tx/block sigop limits; reuses the audited block/PoW harness.
Runs --auth 0/1/2, optionally --wrapped. Global signatures use the independent
NeuraiAuthTreeSig formula. Hidden signature opcodes still count as sigops.
"""
import importlib.util
from pathlib import Path
import struct
import authscript_tree as tree
from review_auth_envelope import Envelope, hash160

spec = importlib.util.spec_from_file_location('limits', Path(__file__).with_name('review-csfs-block-limit-regtest.py'))
limits = importlib.util.module_from_spec(spec)
spec.loader.exec_module(limits)

class TreeEnvelope(Envelope):
    def program(self, script):
        descriptor = bytes([self.auth]) + (hash160(self.pub) if self.auth else b'')
        return tree.commitment(tree.leaf(script), descriptor)

def spend(funding, indices, scripts, natives, chosen, env):
    h = limits.h
    sequence = b'\xff' * 4
    prevouts = b''.join(h.outpoint(funding, indices[i]) for i in chosen)
    outputs = b'\x01' + limits.output((len(chosen)-1)*limits.COIN, b'\x53\x20'+bytes(range(32)))
    inputs, witness = h.compact(len(chosen)), b''
    marker = 0x10 + env.auth
    for i in chosen:
        ss = h.push(natives[i]) if env.wrapped else b''
        prev = h.outpoint(funding, indices[i])
        inputs += prev + h.compact(len(ss)) + ss + sequence
        stack = [bytes([marker])]
        if env.auth:
            pre = (struct.pack('<I',2)+tree.D(prevouts)+tree.D(sequence*len(chosen))+prev+
                   h.compact(len(scripts[i]))+scripts[i]+struct.pack('<Q',limits.COIN)+sequence+
                   tree.D(outputs[1:])+bytes(4)+bytes([marker])+struct.pack('<I',1))
            digest = tree.signature_hash(tree.D(pre),0,marker,env.program(scripts[i]),tree.leaf(scripts[i]))
            stack += [env.sign(digest),env.pub]
        stack += [scripts[i],b'\x01']
        witness += h.compact(len(stack))+b''.join(h.compact(len(x))+x for x in stack)
    version,lock = struct.pack('<I',2),bytes(4)
    return version+inputs+outputs+lock, version+b'\x00\x01'+inputs+outputs+witness+lock

if __name__ == '__main__':
    limits.Envelope = TreeEnvelope
    limits.spend = spend
    raise SystemExit(limits.main())
