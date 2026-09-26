#!/usr/bin/env python3
"""Large, heterogeneous script fields at their element boundary; real isolated UTXOs.
Nonstandard bare scripts are funded/mined in handcrafted consensus-valid blocks.
No production settings, wallet keys or existing datadirs are modified.
"""
import argparse, importlib.util, json, struct, tempfile, time, traceback
from pathlib import Path
spec=importlib.util.spec_from_file_location('wide',Path(__file__).with_name('review-wide-introspection-regtest.py'))
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
r,h,d,m=w.r,w.h,w.d,w.m

def padded(tag,size):
    data=(tag.encode()+b'|' + b'A'*size)[:size-5]
    return b'\x4d'+struct.pack('<H',len(data))+data+b'\x75\x51'

def stripped(raw):
    return r.strip_witness(raw) if raw[4:6]==b'\x00\x01' else raw

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--size',type=int,choices=(3071,3072),default=3072);p.add_argument('--fill',action='store_true');p.add_argument('--par',type=int,choices=(1,2),default=1);p.add_argument('--bindir',type=Path,default=Path('/root/Neurai/src'));args=p.parse_args()
    base=Path(tempfile.mkdtemp(prefix='large-introspection-'));nodes=[]
    report=dict(size=args.size,fill=args.fill,par=args.par,binary_sha256=h.digest_file(args.bindir/'neuraid'),driver_sha256=h.digest_file(Path(__file__)),results=[],measurements=[])
    def check(label,ok,value=None):
        report['results'].append(dict(case=label,passed=bool(ok),observed=value));print(('PASS ' if ok else 'FAIL ')+label,flush=True)
        if not ok:raise RuntimeError(f'{label}: {value}')
    def start(name):
        n=m.w.WorkTestNode(args.bindir,base/name,['-bypassdownload=1','-acceptnonstdtxn=0','-minrelaytxfee=0.00001','-poseidonworkheight=0','-authscriptbudgetheight=0','-maxsigcachesize=0',f'-par={args.par}']);nodes.append(n);n.ready();return n
    def measure(n,label,method,*params):
        cpu,_=d.l.counters(n.proc.pid);t=time.perf_counter();v=n.rpc(method,*params);elapsed=time.perf_counter()-t;after,mem=d.l.counters(n.proc.pid);report['measurements'].append(dict(case=label,wall_s=elapsed,daemon_cpu_s=after-cpu,daemon_hwm_kib=mem));return v
    try:
        source=start('source');miner=source.rpc('getnewaddress','','legacy');pay=bytes.fromhex(source.rpc('validateaddress',miner)['scriptPubKey']);source.rpc('generatetoaddress',610,miner)
        # Stack guard,I,R,O. Exact byte comparisons distinguish all three destinations.
        unit=b'\x51\x53\xc4\x53\x79\x88'+b'\x00\x53\xd2\x52\x79\x88'+b'\x00\xcd\x51\x79\x88'
        script=unit*56+b'\x6d\x75\x69\x51';_,spk=r.address(script)
        input_script=padded('INPUT',args.size);ref_script=padded('REFERENCE',args.size);out_script=padded('OUTPUT',args.size)
        over=padded('OVERSIZE',3073);other_ref=padded('OTHERREF',args.size)
        witness=[b'\x00',b'\x01',input_script,ref_script,out_script,script]
        example=bytes.fromhex(r.a.raw_transaction([('00'*32,0),('11'*32,0)],[(380000000,out_script),(10000000,pay)],[('22'*32,0),('33'*32,0)],[witness,[]]))
        txweight=len(example)+3*len(stripped(example));count=(7900000-2000)//txweight if args.fill else 1
        check('model/distinct_and_lengths',len({input_script,ref_script,out_script})==3 and all(len(s)==args.size for s in (input_script,ref_script,out_script)) and len(over)==3073)
        report['workload']=dict(transactions=count,inputs_per_tx=2,script_bytes=len(script),opcodes=507,queries_per_tx=168,queried_bytes=args.size,tx_weight=txweight)
        # Batch funding stays below the wallet's 400000-WU construction limit.
        items=[(200000000,spk)]*count+[(200000000,input_script)]*count+[(200000000,s) for s in (ref_script,other_ref,over)]
        found={spk:[],input_script:[],ref_script:[],other_ref:[],over:[]}
        for offset in range(0,len(items),20):
            group=items[offset:offset+20];raw=struct.pack('<I',2)+b'\x00'+h.compact(len(group))+b''.join(r.b.output(v,s) for v,s in group)+bytes(4)
            f=source.rpc('fundrawtransaction',raw.hex(),{'feeRate':0.001});sg=source.rpc('signrawtransaction',f['hex']);check(f'funding/{offset}',sg['complete'])
            wire=bytes.fromhex(sg['hex']);txid=r.b.hash256(stripped(wire))[::-1].hex();t=source.rpc('getblocktemplate',{'rules':['segwit']});t['coinbasevalue']=0;block,_,_=d.build(t,[(stripped(wire),wire)]);result=source.rpc('submitblock',block.hex());check(f'funding_block/{offset}',result is None,result)
            for out in source.rpc('getrawtransaction',txid,True)['vout']:
                key=bytes.fromhex(out['scriptPubKey']['hex'])
                if key in found:found[key].append((txid,out['n']))
        check('funding/counts',len(found[spk])==count and len(found[input_script])==count and all(len(found[x])==1 for x in (ref_script,other_ref,over)))
        refs=[found[ref_script][0],found[other_ref][0]]
        outputs=[(380000000,out_script),(10000000,pay)]
        def wire(i,guard=True,mutation=None):
            ins=[found[spk][i],found[input_script][i]];ws=[list(witness),[]];outs=list(outputs);rr=list(refs)
            if not guard:ws[0][1]=b''
            if mutation=='input_order':ins.reverse();ws.reverse()
            if mutation=='ref_order':rr.reverse()
            if mutation=='output_order':outs.reverse()
            if mutation=='input_size':ins[1]=found[over][0]
            if mutation=='ref_size':rr[0]=found[over][0]
            if mutation=='output_size':outs[0]=(380000000,over)
            return bytes.fromhex(r.a.raw_transaction(ins,outs,rr,ws))
        good=[wire(i) for i in range(count)];bad=wire(count-1,guard=False)
        result=source.rpc('testmempoolaccept',[good[-1].hex()])[0];check('policy/nonstandard',not result.get('allowed') and 'scriptpubkey' in result.get('reject-reason',''),result)
        history=[source.rpc('getblock',source.rpc('getblockhash',i),False) for i in range(1,source.rpc('getblockcount')+1)]
        v=start('validator')
        for raw in history:
            result=v.rpc('submitblock',raw)
            if result is not None:raise RuntimeError('history: '+str(result))
        tip=v.rpc('getbestblockhash');template=v.rpc('getblocktemplate',{'rules':['segwit']});template['coinbasevalue']=0
        def make(last,delta):
            t=dict(template);t['curtime']+=delta
            return d.build(t,[(stripped(x),x) for x in good[:-1]+[last]])
        def reject(label,last,delta,diagnostic):
            raw,_,_=make(last,delta);log=v.directory/'regtest'/'debug.log';offset=log.stat().st_size;result=measure(v,label,'submitblock',raw.hex())
            ok=isinstance(result,str) and (result=='block-validation-failed' or diagnostic in result)
            check(label,ok and (args.par==2 or diagnostic.encode() in log.read_bytes()[offset:]) and v.rpc('getbestblockhash')==tip,result)
        reject('negative/late_guard',bad,0,'Script failed an OP_VERIFY operation')
        for i,kind in enumerate(('input_order','ref_order','output_order','input_size','ref_size','output_size'),1):
            diagnostic={'input_size':'OP_INPUTFIELD failed','ref_size':'OP_REFINPUTFIELD failed','output_size':'OP_OUTPUTSCRIPT failed'}.get(kind,'Script failed an OP_EQUALVERIFY operation')
            reject('negative/'+kind,wire(count-1,mutation=kind),i,diagnostic)
        raw,bhash,weight=make(good[-1],10);report['workload']['block_weight']=weight
        check('model/block_weight',weight<7900000 and (not args.fill or weight>7800000),weight)
        result=measure(v,'first_valid','submitblock',raw.hex());check('block/valid',result is None and v.rpc('getbestblockhash')==bhash,result)
        for i in range(6):check(f'verifychain/{i}',measure(v,f'verifychain/{i}','verifychain',4,1))
        measure(v,'reorg','invalidateblock',bhash);check('reorg/policy',v.rpc('getbestblockhash')==tip and not v.rpc('getrawmempool'))
        reject('negative/warm_guard',bad,11,'Script failed an OP_VERIFY operation')
        v.rpc('reconsiderblock',bhash);check('reorg/restored',v.rpc('getbestblockhash')==bhash)
        report['success']=True
    except Exception as e:report['error']=str(e);report['traceback']=traceback.format_exc();print(report['traceback'],flush=True)
    finally:
        for n in reversed(nodes):n.close()
        (base/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('REPORT '+str(base/'report.json'),flush=True)
    return int(not report.get('success'))
if __name__=='__main__':raise SystemExit(main())
