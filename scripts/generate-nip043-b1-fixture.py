#!/usr/bin/env python3
"""Freeze actual NIP-043 constructor bytes, not its VM or mocked crypto.
Default: check committed fixture. --write: regenerate explicitly after review.
Only B1_q0 executes; other MAST leaves contain unexecuted DEMO VKs.
"""
import argparse, contextlib, hashlib, importlib.util, io, json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s)
 with contextlib.redirect_stdout(io.StringIO()):s.loader.exec_module(m)
 return m
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');args=p.parse_args()
c=load('constructor',ROOT/'NIP/bench/nip043_v3_scripts.py')
pose=load('poseidon',ROOT/'scripts/generate-poseidon-review-vectors.py')
leaves=c.all_leaves();commitment,paths=c.mast(leaves)
old=bytes(108)+b'\x00';new=bytes(108)+b'\x01'
data={'scope':'B1_q0 only; other leaves/VKs are DEMO, not verified',
 'constructor_sha256':hashlib.sha256((ROOT/'NIP/bench/nip043_v3_scripts.py').read_bytes()).hexdigest(),
 'name':c.NAME.decode(),'unique':c.ID.decode(),'program':commitment.hex(),
 'leaf':leaves['B1_q0'].bytes().hex(),'control':(b'\x01'+b''.join(paths['B1_q0'])).hex(),
 'opcodes':leaves['B1_q0'].nops(),'delay':c.T,'old':old.hex(),'new':new.hex(),
 'old_hash':pose.sponge(old),'new_hash':pose.sponge(new)}
f=ROOT/'src/test/data/nip043_b1_fixture.json'
if args.write:f.write_text(json.dumps(data,indent=2)+'\n')
else:assert json.loads(f.read_text())==data,'fixture differs: review before explicit regeneration'
print(json.dumps({'fixture':'match','opcodes':data['opcodes'],'leaf_bytes':len(bytes.fromhex(data['leaf'])),'delay':data['delay']}))
