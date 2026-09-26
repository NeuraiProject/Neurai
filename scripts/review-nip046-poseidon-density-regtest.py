#!/usr/bin/env python3
"""Exploratory full-block Poseidon density probe, isolated regtest only.
One uncached first submission, NOT the 30-sample resource acceptance protocol.
The long RPC deadline lets the node finish; latency is evidence, not a crash.
"""
import argparse
import base64
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import time
import urllib.request
import urllib.error

spec=importlib.util.spec_from_file_location('load',Path(__file__).with_name('review-nip046-load-regtest.py'))
l=importlib.util.module_from_spec(spec);spec.loader.exec_module(l)
r=l.r
D=r.b.hash256

def merkle(leaves):
    while len(leaves)>1:
        if len(leaves)%2:leaves=leaves+[leaves[-1]]
        leaves=[D(leaves[i]+leaves[i+1]) for i in range(0,len(leaves),2)]
    return leaves[0]

def build(template, transactions):
    witness_root=merkle([bytes(32)]+[D(w) for _,w in transactions])
    commitment=D(witness_root+bytes(32))
    height=template['height']; hb=height.to_bytes((height.bit_length()+7)//8,'little')
    if hb[-1]&128:hb+=b'\x00'
    ss=r.h.push(hb)+b'\x00'
    ins=b'\x01'+bytes(32)+b'\xff'*4+r.h.compact(len(ss))+ss+b'\xff'*4
    outs=b'\x02'+r.b.output(template['coinbasevalue'],b'\x51')+r.b.output(0,b'\x6a\x24\xaa\x21\xa9\xed'+commitment)
    cb=struct.pack('<I',2)+ins+outs+bytes(4)
    cbw=struct.pack('<I',2)+b'\x00\x01'+ins+outs+b'\x01\x20'+bytes(32)+bytes(4)
    root=merkle([D(cb)]+[D(t) for t,_ in transactions])
    bits=int(template['bits'],16);target=(bits&0x7fffff)<<(8*((bits>>24)-3))
    prefix=struct.pack('<I',template['version'])+bytes.fromhex(template['previousblockhash'])[::-1]+root+struct.pack('<II',template['curtime'],bits)
    count=r.h.compact(len(transactions)+1)
    for nonce in range(1000000):
        header=prefix+struct.pack('<I',nonce)
        if int.from_bytes(D(header),'little')<=target:
            wire=header+count+cbw+b''.join(w for _,w in transactions)
            base=80+len(count)+len(cb)+sum(len(t) for t,_ in transactions)
            return wire,D(header)[::-1].hex(),3*base+len(wire)
    raise RuntimeError('regtest PoW search exhausted')

def submit_slow(node, raw):
    data=json.dumps({'jsonrpc':'1.0','id':'density','method':'submitblock','params':[raw.hex()]}).encode()
    auth=base64.b64encode(b'review:disposable-regtest').decode()
    request=urllib.request.Request(f'http://127.0.0.1:{node.port}',data,{'Authorization':'Basic '+auth})
    try:reply=urllib.request.urlopen(request,timeout=600)
    except urllib.error.HTTPError as error:reply=error
    with reply:decoded=json.load(reply)
    if decoded.get('error'):raise RuntimeError(decoded['error'])
    return decoded['result']

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bindir',type=Path,default=Path('/root/Neurai/src'))
    p.add_argument('--par',type=int,choices=[1,2],default=1)
    p.add_argument('--poseidon-work-height',type=int,choices=[-1,0],default=0,help='-1 preserves the pre-budget baseline')
    p.add_argument('--weight-target',type=int,default=7900000)
    args=p.parse_args(); directory=Path(tempfile.mkdtemp(prefix='nip046-density-'));nodes=[]
    report=dict(results=[],par=args.par,binary_sha256=r.h.digest_file(args.bindir/'neuraid'),driver_sha256=r.h.digest_file(Path(__file__)),
                scope='single cold script-validation submission; no production acceptance threshold')
    def check(name,ok,observed=None):
        report['results'].append(dict(case=name,passed=bool(ok),observed=observed));print(('PASS ' if ok else 'FAIL ')+name,flush=True)
        if not ok:raise RuntimeError(f'{name}: {observed}')
    def start(name):
        n=r.h.Node(args.bindir,directory/name,['-bypassdownload=1','-authscriptbudgetheight=0',f'-poseidonworkheight={args.poseidon_work_height}','-acceptnonstdtxn=0','-minrelaytxfee=0.00001','-maxsigcachesize=0',f'-par={args.par}'])
        nodes.append(n);n.ready();return n
    try:
        source=start('source');miner=source.rpc('getnewaddress','','legacy');source.rpc('generatetoaddress',610,miner)
        pay=bytes.fromhex(source.rpc('validateaddress',miner)['scriptPubKey'])
        script=b'\xc9'*511+b'\x75\x51';_,spk=r.address(script);witness=[b'\x00',b'',script]
        example=bytes.fromhex(r.a.raw_transaction([('00'*32,0)],[(190000000,pay)],[],[witness]))
        weight=len(example)+3*len(r.strip_witness(example))
        limit=source.rpc('getblocktemplate',{'rules':['segwit']})['weightlimit']
        count=max(1,(min(args.weight_target,limit-4000)-4000)//weight)
        funding=[]
        while len(funding)<count:
            batch=min(500,count-len(funding))
            raw=struct.pack('<I',2)+b'\x00'+r.h.compact(batch)+r.b.output(200000000,spk)*batch+bytes(4)
            funded=source.rpc('fundrawtransaction',raw.hex(),{'feeRate':0.001})
            signed=source.rpc('signrawtransaction',funded['hex'])
            if not signed['complete']:raise RuntimeError('funding signature incomplete')
            txid=source.rpc('sendrawtransaction',signed['hex']);source.rpc('generatetoaddress',1,miner)
            coins=source.rpc('getrawtransaction',txid,True)['vout']
            funding.extend((txid,o['n']) for o in coins if o['scriptPubKey']['hex']==spk.hex())
        check('funding_count',len(funding)==count,len(funding))
        transactions=[]
        for outpoint in funding:
            wire=bytes.fromhex(r.a.raw_transaction([outpoint],[(190000000,pay)],[],[witness]))
            transactions.append((r.strip_witness(wire),wire))
        raw,expected,blockweight=build(source.rpc('getblocktemplate',{'rules':['segwit']}),transactions)
        check('block_weight',blockweight<=limit,blockweight)
        report['workload']=dict(transactions=count,block_weight=blockweight,hash_calls=count*511,
                               poseidon_bytes_per_input=510*32,opcodes_per_input=512,input_sigop_cost=0,output_sigop_cost_per_transaction=4)
        # Keep the exact bytes for forensic reproduction in this disposable directory.
        (directory/'candidate.block').write_bytes(raw)
        report['candidate_sha256']=r.h.digest_file(directory/'candidate.block')
        v=start('validator')
        for height in range(1,source.rpc('getblockcount')+1):
            result=v.rpc('submitblock',source.rpc('getblock',source.rpc('getblockhash',height),False))
            if result is not None:raise RuntimeError(result)
        check('empty_mempool',not v.rpc('getrawmempool'))
        print(f'SUBMIT {count} transactions, {count*511} Poseidon calls, par={args.par}',flush=True)
        c0,_=l.counters(v.proc.pid);start_wall=time.perf_counter()
        result=submit_slow(v,raw)
        wall=time.perf_counter()-start_wall;c1,rss=l.counters(v.proc.pid)
        report['measurement']=dict(wall_s=wall,daemon_cpu_s=c1-c0,daemon_hwm_kib=rss)
        active=args.poseidon_work_height>=0 and v.rpc('getblockcount')+1>=args.poseidon_work_height
        if active and count*511>200000:
            check('work_budget_rejected',result=='bad-blk-poseidon-work' and v.rpc('getbestblockhash')!=expected,result)
        else:
            check('accepted',result is None and v.rpc('getbestblockhash')==expected,result)
        report['success']=True
    except Exception as error:
        report['error']=str(error);print('ERROR '+str(error),flush=True)
    finally:
        for node in reversed(nodes):node.close()
        (directory/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('REPORT '+str(directory/'report.json'),flush=True)
    return int(not report.get('success',False))
if __name__=='__main__':raise SystemExit(main())
