#!/usr/bin/env python3
"""Deterministic public SPH/X16 inputs; no wallet, node or network required."""
import hashlib
import json
from pathlib import Path
import random
import struct
import sys

out = Path(sys.argv[1]); out.mkdir(parents=True, exist_ok=True)
rng = random.Random(0x53504820261022)
rows = []
lengths = [0,1,2,3,4,7,8,15,16,31,32,47,48,55,56,63,64,65,71,72,79,80,81,95,96,111,112,119,120,127,128,129,255,256,257,511,512,513,1023,1024,1025,4095,4096,4097]
for algorithm in range(16):
    for length in lengths:
        for pattern in range(3):
            data = bytes([0 if pattern == 0 else 255])*length if pattern < 2 else bytes((i*37+11)&255 for i in range(length))
            rows.append((algorithm, data, 'boundary'))
    for n in range(128):
        length = rng.randrange(2049)
        rows.append((algorithm, bytes(rng.randrange(256) for _ in range(length)), 'random'))
for algorithm in [9,12]:
    rows.append((algorithm, bytes(rng.randrange(256) for _ in range(65536)), 'long'))
for algorithm in [16,17]:
    for selector in range(16):
        for pattern in range(3):
            header = bytearray(rng.randrange(256) for _ in range(80))
            header[4:12] = bytes([selector*17])*8
            rows.append((algorithm, bytes(header), 'selector-%d'%selector))
    for n in range(128):
        rows.append((algorithm, bytes(rng.randrange(256) for _ in range(80)), 'mixed'))
# Fixed Neurai mainnet genesis, independently pinned in chainparams.cpp.
genesis = (struct.pack('<I',4) + bytes(32) +
           bytes.fromhex('4b28bf93d960cd83d1889757381d5a587208464e9075bdc0739151fbe15f5951')[::-1] +
           struct.pack('<III',1681720840,0x1e00ffff,7131026))
for algorithm in [16,17]: rows.append((algorithm,genesis,'mainnet-genesis'))
corpus = ''.join('%d %s\n'%(algorithm,data.hex() or '-') for algorithm,data,kind in rows).encode()
(out/'corpus.txt').write_bytes(corpus)
(out/'corpus.json').write_text(json.dumps({'seed':'0x53504820261022','cases':len(rows),'sha256':hashlib.sha256(corpus).hexdigest(),'entries':[{'algorithm':a,'bytes':len(d),'kind':kind} for a,d,kind in rows]},indent=2)+'\n')
print('Generated',len(rows),'cases',len(corpus),'bytes')
