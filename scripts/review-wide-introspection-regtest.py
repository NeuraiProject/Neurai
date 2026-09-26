#!/usr/bin/env python3
"""Real wide transactions: independent TXHASH digests and spent/reference/output queries.
Runs isolated regtests. Results are resource screening, not mainnet approval.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import statistics
import struct
import tempfile
import time
import traceback

spec=importlib.util.spec_from_file_location('mixed',Path(__file__).with_name('review-mixed-resources-regtest.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
r,h,d=m.r,m.h,m.d

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--profile',choices=['txhash','fields'],required=True)
    p.add_argument('--inputs',type=int,choices=[100,1000],default=100)
    p.add_argument('--par',type=int,choices=[1,2],default=1)
    p.add_argument('--transactions',type=int,choices=range(1,6),default=1)
    p.add_argument('--bindir',type=Path,default=Path('/root/Neurai/src'))
    args=p.parse_args();ref_count=64 if args.inputs==100 else 128;total_inputs=args.inputs*args.transactions;directory=Path(tempfile.mkdtemp(prefix='wide-introspection-'));nodes=[]
    report=dict(profile=args.profile,inputs=args.inputs,par=args.par,binary_sha256=h.digest_file(args.bindir/'neuraid'),driver_sha256=h.digest_file(Path(__file__)),results=[],measurements=[])
    def check(name,ok,value=None):
        report['results'].append(dict(case=name,passed=bool(ok),observed=value));print(('PASS ' if ok else 'FAIL ')+name,flush=True)
        if not ok:raise RuntimeError(f'{name}: {value}')
    def start(name):
        n=m.w.WorkTestNode(args.bindir,directory/name,['-bypassdownload=1','-acceptnonstdtxn=0','-minrelaytxfee=0.00001','-authscriptbudgetheight=0','-poseidonworkheight=0','-maxsigcachesize=0',f'-par={args.par}'])
        nodes.append(n);n.ready();return n
    def measure(n,label,method,*params):
        cpu,_=d.l.counters(n.proc.pid);t=time.perf_counter();v=n.rpc(method,*params);elapsed=time.perf_counter()-t;after,mem=d.l.counters(n.proc.pid)
        report['measurements'].append(dict(case=label,wall_s=elapsed,daemon_cpu_s=after-cpu,daemon_hwm_kib=mem));return v
    try:
        n=start('source');miner=n.rpc('getnewaddress','','legacy');pay=bytes.fromhex(n.rpc('validateaddress',miner)['scriptPubKey']);n.rpc('generatetoaddress',610,miner)
        # The exact expected digest is a witness argument, avoiding a commitment cycle.
        # [guard, expected] -> 170*(selector TXHASH OVER EQUALVERIFY) -> DROP VERIFY TRUE.
        if args.profile=='txhash':
            script=(h.push(b'\xff\x01')+b'\xb5\x78\x88')*170+b'\x75\x69\x51'
            ops=512
        else:
            # Compare the last spent input's script to this input's script; then
            # query the last reference and last output. All indices are real.
            num=lambda i:h.push(i.to_bytes((i.bit_length()+8)//8,'little'))
            unit=(num(args.inputs-1)+b'\x53\xc4\x53\xb6\x88'+num(ref_count-1)+b'\x53\xd2\x78\x88'+num(999)+b'\xcd\x78\x88')
            # Nine counted opcodes per round, plus DROP and VERIFY; pushes do not count.
            script=unit*56+b'\x75\x69\x51';ops=506
        # Count serialized opcodes independently of the construction formula.
        pos=counted=0
        while pos<len(script):
            op=script[pos];pos+=1
            if op<=75:pos+=op
            elif op in (76,77,78):
                width={76:1,77:2,78:4}[op];length=int.from_bytes(script[pos:pos+width],'little');pos+=width+length
            elif op>96:counted+=1
        check('model/serialized_opcount',pos==len(script) and counted==ops,counted)
        _,spk=r.address(script)
        # Fund in batches so funding itself stays within standard transaction size.
        coins=[];refs=[]
        for number in range(0,total_inputs+128,400):
            items=[(200000000,spk) if i<total_inputs else (100000000,pay) for i in range(number,min(number+400,total_inputs+128))]
            raw=struct.pack('<I',2)+b'\x00'+h.compact(len(items))+b''.join(r.b.output(v,s) for v,s in items)+bytes(4)
            f=n.rpc('fundrawtransaction',raw.hex(),{'feeRate':0.001});sg=n.rpc('signrawtransaction',f['hex']);check(f'funding/{number}',sg['complete'])
            txid=n.rpc('sendrawtransaction',sg['hex']);n.rpc('generatetoaddress',1,miner)
            # Change can be inserted at any index. Match scripts and amounts.
            out=n.rpc('getrawtransaction',txid,True)['vout']
            coins += [(txid,o['n']) for o in out if o['scriptPubKey']['hex']==spk.hex()]
            refs += [(txid,o['n']) for o in out if o['scriptPubKey']['hex']==pay.hex() and o['value']==1]
        check('funding/counts',len(coins)==total_inputs and len(refs)==128,(len(coins),len(refs)))
        allrefs=refs
        refs=allrefs[:ref_count]
        outputs=[((args.inputs*200000000-10000000)//1000, pay)]*1000  # 0.1 XNA total fee.
        groups=[coins[i:i+args.inputs] for i in range(0,len(coins),args.inputs)]
        coins=groups[-1]
        prevouts=[h.outpoint(*x) for x in coins];reference_bytes=[h.outpoint(*x) for x in refs]
        witnesses=[]
        for i in range(args.inputs):
            stack=[b'\x00',b'\x01']
            if args.profile=='txhash':stack.append(r.t.field_hash(511,3,0,prevouts,[0xffffffff]*args.inputs,outputs,i,reference_bytes))
            else:stack.append(pay)
            witnesses.append(stack+[script])
        def wire(ws,outs=outputs,rr=refs):return bytes.fromhex(r.a.raw_transaction(coins,outs,rr,ws))
        prefix=[]
        for group in groups[:-1]:
            stacks=[list(x) for x in witnesses]
            if args.profile=='txhash':
                for i,stack in enumerate(stacks):
                    stack[2]=r.t.field_hash(511,3,0,[h.outpoint(*x) for x in group],[0xffffffff]*args.inputs,outputs,i,reference_bytes)
            prefix.append(bytes.fromhex(r.a.raw_transaction(group,outputs,refs,stacks)))
        good=wire(witnesses);badw=[list(x) for x in witnesses];badw[-1][1]=b'';bad=wire(badw)
        report['workload']=dict(transactions=args.transactions,inputs=args.inputs,outputs=1000,references=ref_count,opcodes=ops,script_bytes=len(script),tx_weight=len(good)+3*len(r.strip_witness(good)),txhash_calls=170*args.inputs if args.profile=='txhash' else 0,field_queries=224*args.inputs if args.profile=='fields' else 0)
        check('model/ops',ops<=512)
        check('negative/witness_only',r.strip_witness(good)==r.strip_witness(bad))
        admit=measure(n,'mempool_valid','testmempoolaccept',[good.hex()])[0]
        if args.inputs==100:
            check('policy/standard',bool(admit.get('allowed')),admit)
            extra=n.rpc('testmempoolaccept',[wire(witnesses,rr=allrefs[:65]).hex()])[0]
            check('policy/reference_limit',not extra.get('allowed') and 'too-many-refinputs' in extra.get('reject-reason',''),extra)
            result=n.rpc('testmempoolaccept',[bad.hex()])[0]
            check('policy/late_guard',not result.get('allowed') and 'Script failed an OP_VERIFY operation' in result.get('reject-reason',''),result)
            ids=[n.rpc('sendrawtransaction',x.hex()) for x in prefix+[good]];template=measure(n,'template','getblocktemplate',{'rules':['segwit']})
            check('miner/included',set(ids)=={x['txid'] for x in template['transactions']})
        else:
            check('policy/reference_limit',not admit.get('allowed') and 'too-many-refinputs' in admit.get('reject-reason',''),admit)
            smallrefs=n.rpc('testmempoolaccept',[wire(witnesses,rr=allrefs[:64]).hex()])[0]
            check('policy/oversize',not smallrefs.get('allowed') and 'tx-size' in smallrefs.get('reject-reason',''),smallrefs)
        history=[n.rpc('getblock',n.rpc('getblockhash',i),False) for i in range(1,n.rpc('getblockcount')+1)]
        template=n.rpc('getblocktemplate',{'rules':['segwit']});template['coinbasevalue']=0
        v=start('validator')
        for block in history:
            result=v.rpc('submitblock',block)
            if result is not None:raise RuntimeError('history: '+str(result))
        tip=v.rpc('getbestblockhash')
        def blockwire(tx,delta):
            t=dict(template);t['curtime']+=delta
            return d.build(t,[(r.strip_witness(x),x) for x in prefix+[tx]])
        def reject(name,tx,delta):
            raw,_,_=blockwire(tx,delta)
            log=v.directory/'regtest'/'debug.log';offset=log.stat().st_size
            result=measure(v,name,'submitblock',raw.hex())
            diagnostic=('Script failed an OP_VERIFY operation' if 'guard' in name else
                        'OP_REFINPUTFIELD failed' if name.endswith('reference_index') else
                        'Script failed an OP_EQUALVERIFY operation')
            # Workers expose a generic queue error; synchronous validation must
            # also identify the intended failed opcode in its new log segment.
            expected=isinstance(result,str) and (result=='block-validation-failed' or diagnostic in result)
            check(name,expected and (args.par==2 or diagnostic.encode() in log.read_bytes()[offset:]) and
                  v.rpc('getbestblockhash')==tip,result)
        reject('negative/late_guard',bad,0)
        if args.profile=='txhash':
            reject('negative/reference_order',wire(witnesses,rr=refs[::-1]),1)
            changed=list(outputs);changed[-1]=(changed[-1][0]-1,pay)
            reject('negative/output_amount',wire(witnesses,outs=changed),2)
            wrong=[list(x) for x in witnesses];wrong[-1][2]=wrong[0][2]
            reject('negative/input_index',wire(wrong),3)
        else:
            changed=list(outputs);changed[-1]=(changed[-1][0],b'\x51')
            reject('negative/output_script',wire(witnesses,outs=changed),1)
            reject('negative/reference_index',wire(witnesses,rr=refs[:-1]),2)
        raw,bhash,weight=blockwire(good,4);report['workload']['block_weight']=weight
        check('model/block_weight',weight<7900000,weight)
        result=measure(v,'first_valid','submitblock',raw.hex());check('block/valid',result is None and v.rpc('getbestblockhash')==bhash,result)
        for i in range(6):check(f'verifychain/{i}',measure(v,f'verifychain/{i}','verifychain',4,1))
        measure(v,'reorg','invalidateblock',bhash);check('reorg/tip',v.rpc('getbestblockhash')==tip)
        expected={r.b.hash256(r.strip_witness(x))[::-1].hex() for x in prefix+[good]} if args.inputs==100 else set()
        check('reorg/policy',set(v.rpc('getrawmempool'))==expected)
        reject('negative/warm_guard',bad,5)
        v.rpc('reconsiderblock',bhash);check('reorg/restored',v.rpc('getbestblockhash')==bhash)
        report['success']=True
    except Exception as e:
        report['error']=str(e);report['traceback']=traceback.format_exc();print(report['traceback'],flush=True)
    finally:
        for n in reversed(nodes):n.close()
        (directory/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('REPORT '+str(directory/'report.json'),flush=True)
    return int(not report.get('success'))
if __name__=='__main__':raise SystemExit(main())
