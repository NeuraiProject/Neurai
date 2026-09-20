#!/usr/bin/env python3
"""Independent integer arithmetic for NIP-043 Merkle vectors.
Shares the pinned round constants, not the node's field/permutation code.
No write mode: compare the JSON output and fixed C++ expected roots.
"""
import json
from pathlib import Path
import re

P = 21888242871839275222246405745257275088548364400416034343698204186575808495617
text = (Path(__file__).resolve().parents[1] / 'src/crypto/poseidon_bn254_constants.h').read_text()

def constants(name):
    body = text.split(name, 1)[1].split('};', 1)[0]
    limbs = [int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]+)ULL', body)]
    return [sum(limbs[i+j] << (64*j) for j in range(4)) for i in range(0, len(limbs), 4)]

C = constants('POSEIDON_BN254_RC[195][4]')
M = constants('POSEIDON_BN254_MDS[3][3][4]')
assert len(C) == 195 and len(M) == 9

def node(left, right):
    state = [0, left, right]
    for rnd in range(65):
        state = [(x+C[3*rnd+i]) % P for i,x in enumerate(state)]
        for i in (range(3) if rnd < 4 or rnd >= 61 else (0,)):
            state[i] = pow(state[i], 5, P)
        state = [sum(M[3*i+j]*state[j] for j in range(3)) % P for i in range(3)]
    return state[0]

assert node(1,2) == int('115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a',16)
rows=[]
for depth in (1,2,32):
    root=1
    for i in range(depth):
        root=node(2,root) if i%2 else node(root,2)
    bitmap=sum((i%2)<<i for i in range(depth)).to_bytes((depth+7)//8,'little')
    proof=bytes([depth])+(2).to_bytes(32,'big')*depth+bitmap
    rows.append(dict(depth=depth,leaf=(1).to_bytes(32,'big').hex(),proof=proof.hex(),root=root.to_bytes(32,'big').hex()))
if __name__=='__main__':print(json.dumps(rows,indent=2))
