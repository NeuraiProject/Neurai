"""Loopback-only BIP152 v2 transport checks for the NIP-044 regtest driver.
Uses real cmpctblock/getblocktxn/blocktxn messages, never submitblock for the
candidate. Historical blocks are loaded separately by the caller.
"""
import importlib.util
from pathlib import Path
import socket
import struct
import time
from authscript_tree import H, D, compact

_spec = importlib.util.spec_from_file_location('tree_siphash', Path(__file__).resolve().parents[1]/'test/functional/test_framework/siphash.py')
_sip = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_sip)

class Peer:
    def __init__(self, port):
        self.sock = socket.create_connection(('127.0.0.1',port),timeout=10)
        self.sock.settimeout(10)
        addr = struct.pack('<Q',9)+bytes(10)+b'\xff\xff\x7f\x00\x00\x01'+struct.pack('>H',port)
        agent=b'/nip044-local-test/'
        self.send('version',struct.pack('<iQq',70026,9,int(time.time()))+addr+addr+
                  struct.pack('<Q',0x4400440044)+compact(len(agent))+agent+struct.pack('<i',120)+b'\x01')
        self.until('version');self.send('verack');self.until('verack')
        self.send('sendcmpct',b'\x01'+struct.pack('<Q',2))
        self.send('ping',struct.pack('<Q',440044));self.until('pong')

    def send(self, command, payload=b''):
        self.sock.sendall(b'RUEN'+command.encode().ljust(12,b'\0')+struct.pack('<I',len(payload))+D(payload)[:4]+payload)

    def read_exact(self, size):
        result=b''
        while len(result)<size:
            part=self.sock.recv(size-len(result))
            if not part:raise RuntimeError('P2P peer disconnected')
            result+=part
        return result

    def receive(self):
        header=self.read_exact(24)
        if header[:4]!=b'RUEN':raise RuntimeError('wrong network magic')
        size=struct.unpack('<I',header[16:20])[0]
        if size>8_000_000:raise RuntimeError('oversized local test message')
        payload=self.read_exact(size)
        if D(payload)[:4]!=header[20:24]:raise RuntimeError('bad P2P checksum')
        return header[4:16].rstrip(b'\0').decode(),payload

    def until(self, wanted):
        deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            command,payload=self.receive()
            if command=='ping':self.send('pong',payload)
            if command==wanted:return payload
            if command=='reject':raise RuntimeError('P2P reject '+payload.hex())
        raise RuntimeError('P2P timeout waiting for '+wanted)


def relay(source, validator, port, blockhash, known, check, label):
    info=source.rpc('getblock',blockhash)
    header=bytes.fromhex(source.rpc('getblockheader',blockhash,False))
    txs=[bytes.fromhex(source.rpc('getrawtransaction',txid)) for txid in info['tx']]
    if known:
        for tx in txs[1:]:validator.rpc('sendrawtransaction',tx.hex())
    nonce=struct.pack('<Q',44)
    key=H(header+nonce)
    k0,k1=struct.unpack('<QQ',key[:16])
    shortids=b''.join(struct.pack('<Q',_sip.siphash256(k0,k1,int.from_bytes(D(tx),'little')))[:6] for tx in txs[1:])
    payload=header+nonce+compact(len(txs)-1)+shortids+b'\x01\x00'+txs[0]
    peer=Peer(port)
    try:
        peer.send('cmpctblock',payload)
        if not known:
            request=peer.until('getblocktxn')
            # Four non-prefilled transactions, consecutive indices 1,2,3,4.
            expected=D(header)+compact(len(txs)-1)+b'\x01'+b'\x00'*(len(txs)-2)
            check(label+'/missing_transactions_requested',request==expected,request.hex())
            peer.send('blocktxn',D(header)+compact(len(txs)-1)+b''.join(txs[1:]))
        deadline=time.monotonic()+15
        while validator.rpc('getbestblockhash')!=blockhash and time.monotonic()<deadline:
            time.sleep(0.05)
        check(label+'/tip',validator.rpc('getbestblockhash')==blockhash)
        for txid,tx in zip(info['tx'][1:],txs[1:]):
            check(label+'/witness/'+txid,validator.rpc('getrawtransaction',txid)==tx.hex())
        check(label+'/verifychain',validator.rpc('verifychain',4,0))
    finally:
        peer.sock.close()
