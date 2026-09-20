#!/usr/bin/env python3
"""Local NIP-046 resource samples, not a mainnet capacity certification.
Large blocks of independent NoAuth spends, standard admission, then level-4
verification with a minimal script cache (not an OS cold-cache claim).
"""
import argparse
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import statistics
import tempfile
import time

spec = importlib.util.spec_from_file_location('thread', Path(__file__).with_name('review-contract-thread-regtest.py'))
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)

def counters(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    cpu = (int(fields[11]) + int(fields[12])) / os.sysconf('SC_CLK_TCK')
    status = Path(f'/proc/{pid}/status').read_text().splitlines()
    rss = int(next(line for line in status if line.startswith('VmHWM:')).split()[1])
    return cpu, rss

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bindir', type=Path, default=Path('/root/Neurai/src'))
    p.add_argument('--profile', choices=['sha256', 'sha1', 'ripemd160', 'hash160', 'hash256', 'keccak256', 'blake2b', 'blake3', 'sha3_256', 'sha512', 'stack', 'copy', 'poseidon', 'poseidon-chain', 'merkle1', 'merkle2', 'merkle3', 'merkle4', 'merkle5'], required=True)
    p.add_argument('--par', type=int, choices=[1, 2], default=1)
    p.add_argument('--poseidon-work-height', type=int, choices=[-1,0], default=0, help='-1 for historical byte-budget-only measurements')
    p.add_argument('--samples', type=int, default=30)
    p.add_argument('--inputs-per-tx', type=int, choices=[1,2], default=1)
    p.add_argument('--weight-target', type=int, default=3800000)
    args = p.parse_args()
    if args.samples < 30: p.error('at least 30 measured samples required')
    directory = Path(tempfile.mkdtemp(prefix='nip046-load-')); nodes = []
    report = dict(profile=args.profile, par=args.par, results=[], samples=[],
                  binary_sha256=r.h.digest_file(args.bindir/'neuraid'),
                  driver_sha256=r.h.digest_file(Path(__file__)),
                  environment=dict(platform=platform.platform(), cpuinfo=Path('/proc/cpuinfo').read_text(),
                                   clock_ticks=os.sysconf('SC_CLK_TCK'), cpu_count=os.cpu_count()),
                  cache='maxsigcachesize=0 (minimum two entries); page cache uncontrolled',
                  acceptance='experimental measurements only; no approved mainnet thresholds')
    def check(name, ok, observed=None):
        report['results'].append(dict(case=name, passed=bool(ok), observed=observed))
        print(('PASS ' if ok else 'FAIL ')+name, flush=True)
        if not ok: raise RuntimeError(f'{name}: {observed}')
    def start(label):
        n = r.h.Node(args.bindir, directory/label, ['-bypassdownload=1', '-acceptnonstdtxn=0',
                    '-minrelaytxfee=0.00001', '-authscriptbudgetheight=0', f'-poseidonworkheight={args.poseidon_work_height}', '-maxsigcachesize=0', f'-par={args.par}'])
        nodes.append(n); n.ready(); return n
    try:
        hashes={'sha256':0xa8,'sha1':0xa7,'ripemd160':0xa6,'hash160':0xa9,'hash256':0xaa,
                'keccak256':0xba,'blake2b':0xbb,'blake3':0xc8,'sha3_256':0xca,'sha512':0xcb}
        if args.profile in hashes:
            double=args.profile in ('hash160','hash256')
            script=bytes([hashes[args.profile],0x75])*21+b'\x51'
            wa=[b'\x42'*3072]*20+[b'\x42'*(736 if double else 2752)]
            ops, classic, poseidon = 42, 65536, 0
        elif args.profile.startswith('merkle'):
            scheme=int(args.profile[-1]); leaf=bytes(32) if scheme in (1,5) else b''
            charge=1984 if scheme==5 else 7168 if scheme==1 else 4160
            repetitions=(30720 if scheme==5 else 65536)//charge
            wa=[leaf,bytes([scheme]),b'\x20'+bytes(32*32+4),bytes(32)]*repetitions
            script=b'\xc1\x75'*repetitions+b'\x51'
            ops,classic,poseidon=2*repetitions,0 if scheme==5 else repetitions*charge,repetitions*charge if scheme==5 else 0
        elif args.profile == 'copy':
            script=b'\x76\x75'*213+b'\x75'*85+b'\x61\x51'
            wa=[b'\x42'*1024]+[b'\x42'*3072]*84
            ops,classic,poseidon=512,0,0
        elif args.profile == 'poseidon-chain':
            # Small-input path: first input empty, then 510 outputs of 32 B.
            # This is within the byte budget but has many more sponge calls.
            script=b'\xc9'*511+b'\x75\x51';wa=[b'']
            ops,classic,poseidon=512,0,510*32
        elif args.profile == 'stack':
            script=b'\x7c'*426+b'\x75'*86+b'\x51'; wa=[b'\x42'*3072]*85+[b'\x42'*1024]
            ops, classic, poseidon = 512, 0, 0
        else:
            script=b'\xc9\x75'*10+b'\x51'; wa=[b'\x42'*3072]*10
            ops, classic, poseidon = 20, 0, 30720
        source=start('source'); miner=source.rpc('getnewaddress', '', 'legacy')
        source.rpc('generatetoaddress',610,miner)
        pay=bytes.fromhex(source.rpc('validateaddress',miner)['scriptPubKey'])
        address,spk=r.address(script); witness=[b'\x00',*wa,script]
        payout=200000000*args.inputs_per_tx-10000000
        dummy=bytes.fromhex(r.a.raw_transaction([('00'*32,i) for i in range(args.inputs_per_tx)],[(payout,pay)],[],[witness]*args.inputs_per_tx))
        txweight=len(dummy)+3*len(r.strip_witness(dummy))
        limit=source.rpc('getblocktemplate',{'rules':['segwit']})['weightlimit']
        count=max(1,(min(args.weight_target,limit-4000)-4000)//txweight)
        work = 511 if args.profile == 'poseidon-chain' else 500 if args.profile == 'poseidon' else 480 if args.profile == 'merkle5' else 0
        work_active = args.poseidon_work_height >= 0 and source.rpc('getblockcount')+1 >= args.poseidon_work_height
        if work_active and work:
            count = min(count, 200000 // (work * args.inputs_per_tx))
        report['workload']=dict(poseidon_permutations_per_input=work, poseidon_work_active=work_active, transactions=count, tx_weight=txweight, weight_limit=limit,
            weight_target=args.weight_target, inputs_per_transaction=args.inputs_per_tx, opcodes_per_input=ops, classic_units_per_input=classic,
            poseidon_bytes_per_input=poseidon, initial_argument_bytes=sum(map(len,wa)), input_sigop_cost=0, output_sigop_cost_per_transaction=4,
            static_script_bytes=len(script))
        funding=[]
        for i in range(count*args.inputs_per_tx):
            txid=source.rpc('sendtoaddress',address,2)
            tx=source.rpc('getrawtransaction',txid,True)
            idx=next(o['n'] for o in tx['vout'] if o['scriptPubKey']['hex']==spk.hex())
            funding.append((txid,idx))
            if i%15==14:source.rpc('generatetoaddress',1,miner)
        source.rpc('generatetoaddress',1,miner)
        height=source.rpc('getblockcount')
        history=[source.rpc('getblock',source.rpc('getblockhash',i),False) for i in range(1,height+1)]
        cpu0,_=counters(source.proc.pid); start_wall=time.perf_counter()
        ids=[]
        for offset in range(0,len(funding),args.inputs_per_tx):
            wire=r.a.raw_transaction(funding[offset:offset+args.inputs_per_tx],[(payout,pay)],[],[witness]*args.inputs_per_tx)
            ids.append(source.rpc('sendrawtransaction',wire))
        cpu1,rss=counters(source.proc.pid)
        report['admission']=dict(daemon_cpu_s=cpu1-cpu0,wall_s=time.perf_counter()-start_wall,daemon_hwm_kib=rss)
        check('mempool_all_spends',set(ids).issubset(set(source.rpc('getrawmempool'))))
        tip=source.rpc('generatetoaddress',1,miner)[0]
        block=source.rpc('getblock',tip)
        check('block_all_spends',set(ids).issubset(set(block['tx'])))
        report['workload']['actual_block_weight']=block['weight']
        raw=source.rpc('getblock',tip,False)
        v=start('validator')
        for previous in history:
            result=v.rpc('submitblock',previous)
            if result is not None:raise RuntimeError(result)
        check('validator_mempool_empty',not v.rpc('getrawmempool'))
        c0,_=counters(v.proc.pid); t0=time.perf_counter()
        result=v.rpc('submitblock',raw)
        c1,rss=counters(v.proc.pid)
        report['first_submit']=dict(wall_s=time.perf_counter()-t0,daemon_cpu_s=c1-c0,daemon_hwm_kib=rss)
        check('full_block_accepted',result is None and v.rpc('getbestblockhash')==tip,result)
        for i in range(5+args.samples):
            c0,_=counters(v.proc.pid); t0=time.perf_counter()
            ok=v.rpc('verifychain',4,1)
            wall=time.perf_counter()-t0; c1,rss=counters(v.proc.pid)
            if not ok:raise RuntimeError(f'verifychain failed sample {i}')
            if i>=5:report['samples'].append(dict(wall_s=wall,daemon_cpu_s=c1-c0,daemon_hwm_kib=rss))
            if i>=5 and (i-4)%10==0:print(f'MEASURED {i-4}/{args.samples}',flush=True)
        check('verifychain_samples',len(report['samples'])==args.samples)
        for field in ('wall_s','daemon_cpu_s','daemon_hwm_kib'):
            values=sorted(x[field] for x in report['samples'])
            report.setdefault('summary',{})[field]=dict(median=statistics.median(values),p95=values[math.ceil(len(values)*0.95)-1],maximum=max(values))
        report['success']=True
    except Exception as error:
        report['error']=str(error); print('ERROR '+str(error),flush=True)
    finally:
        for n in reversed(nodes):n.close()
        (directory/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print('REPORT '+str(directory/'report.json'),flush=True)
    return int(not report.get('success',False))
if __name__=='__main__':raise SystemExit(main())
