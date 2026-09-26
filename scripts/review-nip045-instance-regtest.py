#!/usr/bin/env python3
"""Verify a public NIP-045 TEST instance domain against a regtest chain.

The supplied node datadir is cloned on the test machine, including any
wallet files it contains. Only public chain metadata enters the report;
no wallet keys or proving witnesses are exported.
"""
import argparse
import base64
import hashlib
import json
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from nip045_instance_domain import instance_domain

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--source-datadir', type=Path, required=True)
p.add_argument('--bindir', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--issuance-txid', required=True)
p.add_argument('--issuance-vout', type=int, required=True)
p.add_argument('--unique-name', required=True)
p.add_argument('--deposit-txid', required=True)
p.add_argument('--expected-domain', required=True)
a = p.parse_args()
a.output.mkdir(parents=True, exist_ok=False)
report = dict(scope=__doc__, checks=[], success=False,
              runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              binary_sha256=hashlib.sha256((a.bindir/'neuraid').read_bytes()).hexdigest())

def save():
    (a.output/'report.json').write_text(json.dumps(report, indent=2)+'\n')

def check(label, okay, detail=None):
    report['checks'].append(dict(case=label, passed=bool(okay), detail=detail))
    print(('PASS ' if okay else 'FAIL ') + label, flush=True)
    save()
    if not okay: raise AssertionError((label, detail))

shutil.copytree(a.source_datadir, a.output/'node')
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
log = (a.output/'node.log').open('w')
cmd = [str(a.bindir/'neuraid'), '-regtest', '-server', '-listen=0', '-connect=0',
       '-dnsseed=0', '-discover=0', '-txindex=1', '-keypool=3',
       '-fallbackfee=0.01', '-strictauthscriptheight=0', '-rpcuser=review',
       '-rpcpassword=disposable-regtest', '-rpcport='+str(port),
       '-datadir='+str(a.output/'node'), '-bypassdownload=1',
       '-acceptnonstdtxn=0', '-par=1']
proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)

def rpc(method, *params):
    body = json.dumps(dict(jsonrpc='1.0', id='review', method=method,
                           params=params)).encode()
    auth = base64.b64encode(b'review:disposable-regtest').decode()
    request = urllib.request.Request('http://127.0.0.1:'+str(port), body,
                {'Authorization':'Basic '+auth, 'Content-Type':'application/json'})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.load(response)
    if data['error']: raise RuntimeError(data['error'])
    return data['result']

try:
    for attempt in range(100):
        try:
            rpc('getblockcount'); break
        except Exception:
            if proc.poll() is not None: raise RuntimeError('node exited before RPC')
            time.sleep(.2)
    else: raise TimeoutError('node RPC startup')
    genesis = rpc('getblockhash', 0)
    issuance = rpc('getrawtransaction', a.issuance_txid, True)
    check('issuance confirmed', issuance.get('confirmations', 0) > 0)
    check('issuance output exists', 0 <= a.issuance_vout < len(issuance['vout']))
    script = issuance['vout'][a.issuance_vout]['scriptPubKey']
    check('output is UNIQUE issuance',
          script.get('type') == 'new_asset' and
          script.get('asset',{}).get('name') == a.unique_name and
          script.get('asset',{}).get('amount') == 1.0 and
          script.get('asset',{}).get('reissuable') == 0,
          {k:script.get(k) for k in ('type','asset')})
    deposit = rpc('getrawtransaction', a.deposit_txid, True)
    check('deposit confirmed', deposit.get('confirmations', 0) > 0)
    birth = rpc('getrawtransaction', deposit['vin'][0]['txid'], True)
    check('birth confirmed', birth.get('confirmations', 0) > 0)
    heights = [rpc('getblockheader', tx['blockhash'])['height']
               for tx in (issuance, birth, deposit)]
    check('issuance precedes pool birth and deposit', heights[0] < heights[1] < heights[2], heights)
    domain = instance_domain(genesis, a.issuance_txid, a.issuance_vout,
                             a.unique_name).hex()
    check('domain matches independent fixture', domain == a.expected_domain, domain)
    report.update(success=True, genesis_rpc=genesis,
                  issuance=dict(txid=a.issuance_txid, vout=a.issuance_vout,
                                name=a.unique_name, height=heights[0]),
                  birth_height=heights[1], deposit_height=heights[2], domain=domain)
finally:
    try: rpc('stop')
    except Exception: pass
    proc.wait(timeout=30)
    log.close()
    save()
