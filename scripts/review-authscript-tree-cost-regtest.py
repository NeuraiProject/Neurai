#!/usr/bin/env python3
"""Validate near-full blocks of maximal MAST leaves and paths, including failure.
300 inputs, 10000-byte leaves, depth 32. Local isolated regtest only. Timings
are observations, not a throughput claim or a consensus performance bound.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import time
import authscript_tree as tree

spec=importlib.util.spec_from_file_location('limits',Path(__file__).with_name('review-csfs-block-limit-regtest.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
h=m.h

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bindir',type=Path,default=Path('/root/Neurai/src'))
    args=parser.parse_args();directory=Path(tempfile.mkdtemp(prefix='nip044-cost-'))
    nodes=[];report={'binary_sha256':h.digest_file(args.bindir/'neuraid'),'results':[],'inputs':300,'leaf_bytes':10000,'depth':32}
    def check(label,ok,observed=None):
        report['results'].append({'case':label,'passed':bool(ok),'observed':observed})
        print(('PASS ' if ok else 'FAIL ')+label,flush=True)
        if not ok:raise RuntimeError(label+': '+str(observed))
    try:
        source=h.Node(args.bindir,directory/'source',['-bypassdownload=1']);nodes.append(source);source.ready()
        miner=source.rpc('getnewaddress');source.rpc('generatetoaddress',110,miner)
        scripts=[];controls=[];spks=[];payments={}
        for index in range(300):
            data=struct.pack('<I',index)+bytes(2996)
            script=(h.push(data)+b'\x75')*3+h.push(bytes(983))+b'\x75\x51'
            assert len(script)==10000
            root=tree.leaf(script);control=b'\x01'
            for depth in range(32):
                sibling=tree.H(struct.pack('<II',index,depth));control+=sibling;root=tree.branch(root,sibling)
            program=tree.commitment(root);scripts.append(script);controls.append(control);spks.append(b'\x51\x20'+program)
            payments[m.bech32m('tnc',1,program)]=1
        funded=source.rpc('sendmany','',payments);source.rpc('generatetoaddress',1,miner)
        tx=source.rpc('getrawtransaction',funded,True);lookup={x['scriptPubKey']['hex']:x['n'] for x in tx['vout']}
        inputs=h.compact(300)+b''.join(h.outpoint(funded,lookup[s.hex()])+b'\x00'+b'\xff'*4 for s in spks)
        outputs=b'\x01'+m.output(299*h.COIN,b'\x53\x20'+bytes(range(32)))
        version=struct.pack('<I',2);stripped=version+inputs+outputs+bytes(4)
        template=source.rpc('getblocktemplate',{'rules':['segwit']})
        candidates={}
        for invalid in (False,True):
            witness=b''
            for index,(script,control) in enumerate(zip(scripts,controls)):
                if invalid and index==299:control=control[:-1]+bytes([control[-1]^1])
                stack=[b'\x10',script,control]
                witness+=h.compact(len(stack))+b''.join(h.compact(len(x))+x for x in stack)
            wire=version+b'\x00\x01'+inputs+outputs+witness+bytes(4)
            raw,blockhash,weight=m.block(template,(stripped,wire))
            check(f'weight/invalid{int(invalid)}',weight<template['weightlimit'],weight)
            candidates[invalid]=(raw,blockhash)
        history=[source.rpc('getblock',source.rpc('getblockhash',i),False) for i in range(1,112)]
        for par in (1,2):
            n=h.Node(args.bindir,directory/f'validator{par}',['-disablewallet=1',f'-par={par}']);nodes.append(n);n.ready()
            for wire in history:
                result=n.rpc('submitblock',wire)
                if result is not None:raise RuntimeError(result)
            for invalid in (True,False):
                raw,blockhash=candidates[invalid]
                begin=time.monotonic();result=n.rpc('submitblock',raw.hex());elapsed=time.monotonic()-begin
                check(f'par{par}/invalid{int(invalid)}',
                      (isinstance(result,str) and ('script' in result or (par==2 and result=='block-validation-failed'))) if invalid else result is None,
                      {'result':result,'seconds':elapsed,'bytes':len(raw)})
                if invalid and par==2:
                    check('par2/checkqueue_failure', 'ConnectBlock: CheckQueue failed' in (n.directory/'regtest/debug.log').read_text())
                check(f'par{par}/tip_invalid{int(invalid)}',n.rpc('getblockcount')==(111 if invalid else 112))
        report['success']=True
    finally:
        for n in nodes:n.close()
        (directory/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print('REPORT '+str(directory/'report.json'),flush=True)

if __name__=='__main__':main()
