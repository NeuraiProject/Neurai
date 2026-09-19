#!/usr/bin/env python3
"""Python big-int oracle for NIP-036 byte sponge (no C++ Montgomery arithmetic).
Shares the pinned RC/MDS table; does NOT independently certify those constants.
Prints C++ input/output literals for the phase-12 tests.
"""
from pathlib import Path
import re

R = 21888242871839275222246405745257275088548364400416034343698204186575808495617
header = (Path(__file__).resolve().parents[1] / 'src/crypto/poseidon_bn254_constants.h').read_text()
def constants(name):
    body = header.split(name, 1)[1].split('};', 1)[0]
    limbs = [int(v, 16) for v in re.findall(r'0x([0-9a-fA-F]+)ULL', body)]
    return [sum(limbs[i+j] << (64*j) for j in range(4)) for i in range(0,len(limbs),4)]
RC, M = constants('POSEIDON_BN254_RC[195][4]'), constants('POSEIDON_BN254_MDS[3][3][4]')
assert len(RC)==195 and len(M)==9

def permute(state):
    for round_no in range(65):
        state = [(x+RC[round_no*3+i])%R for i,x in enumerate(state)]
        state = [pow(x,5,R) if i==0 or round_no<4 or round_no>=61 else x for i,x in enumerate(state)]
        state = [sum(M[i*3+j]*state[j] for j in range(3))%R for i in range(3)]
    return state

assert permute([0,1,2])[0] == int('115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a',16)
def sponge(data):
    padded = data+b'\x01'
    padded += b'\0' * (-len(padded)%31)
    elements = [int.from_bytes(padded[i:i+31],'big') for i in range(0,len(padded),31)]
    state=[0,0,0]
    for i in range(0,len(elements),2):
        for j,x in enumerate(elements[i:i+2]): state[j]=(state[j]+x)%R
        state=permute(state)
    return state[0].to_bytes(32,'big').hex()
assert sponge(b'') == '067761295e881eec953a764e4d72bbccedf07472b57b9a3f754dcb5012441956'
# Short literals; large-pattern vectors already exist in poseidon_sponge_tests.
inputs=[bytes(i%256 for i in range(n)) for n in (0,1,30,31,32,33,61,62,63,92,93)]
inputs += [bytes([v])+bytes(range(32)) for v in (1,2,3)]
inputs += [b'\xff'*31,b'\xff'*32,R.to_bytes(32,'big'),(R+1).to_bytes(32,'big')]
for data in inputs: print(f'        {{"{data.hex()}", "{sponge(data)}"}},')
