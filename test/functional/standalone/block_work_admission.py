#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see COPYING.
"""Difficulty admission, orphan retry and disk import on isolated real nodes.

Run separately for main, test and regtest, on either maintained branch.
No third-party Python modules or external peers are required.
"""
import argparse
import base64
import hashlib
import http.client
import json
from pathlib import Path
import socket
import struct
import subprocess
import time


def dhash(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def wait_for(predicate, timeout=120):
    end = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > end: raise AssertionError('Timed out')
        time.sleep(.05)


def address(test):
    raw = bytes([127 if test else 53]) + b'\x11' * 20
    number = int.from_bytes(raw + dhash(raw)[:4], 'big')
    result = ''
    while number:
        number, digit = divmod(number, 58)
        result = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'[digit] + result
    return result


class Node:
    def __init__(self, args, directory, extra=()):
        self.args = args
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)
        self.log = (directory / 'console.log').open('a')
        command = [str(args.neuraid), '-datadir=' + str(directory), '-server', '-disablewallet',
                   '-connect=0', '-dnsseed=0', '-discover=0', '-listen=1', '-bind=127.0.0.1',
                   '-port=29800', '-rpcport=29801', '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1',
                   '-rpcuser=work-test', '-rpcpassword=isolated-test', '-bypassdownload',
                   '-disablesafemode', '-minimumchainwork=0', '-par=2', '-dbcache=32', '-debug=net', '-checkblockindex']
        if args.network == 'test': command.append('-testnet')
        if args.network == 'regtest': command.append('-regtest')
        self.process = subprocess.Popen(command + list(extra), stdout=self.log, stderr=subprocess.STDOUT)
        def started():
            assert self.process.poll() is None, 'Node exited during startup'
            try: self.rpc('getblockcount'); return True
            except (OSError, RuntimeError): return False
        try: wait_for(started)
        except Exception:
            self.close()
            raise

    def rpc(self, method, *params):
        connection = http.client.HTTPConnection('127.0.0.1', 29801, timeout=90)
        auth = base64.b64encode(b'work-test:isolated-test').decode()
        try:
            connection.request('POST', '/', json.dumps(dict(id=1, method=method, params=params)),
                               {'Authorization': 'Basic ' + auth})
            result = json.loads(connection.getresponse().read())
        finally: connection.close()
        if result.get('error'): raise RuntimeError(result['error'])
        return result['result']

    def stats(self):
        stats = self.rpc('gettxoutsetinfo')
        return {k: stats[k] for k in ('height', 'bestblock', 'total_amount', 'hash_serialized_2')}

    def close(self):
        try:
            if self.process.poll() is None:
                try: self.rpc('stop')
                except (OSError, RuntimeError): self.process.terminate()
            try: code = self.process.wait(timeout=90)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait(); raise
            assert code == 0, ('node exit', code)
        finally: self.log.close()


class Peer:
    def __init__(self, magic):
        self.magic = magic
        self.sock = socket.create_connection(('127.0.0.1', 29800), timeout=5)
        self.sock.settimeout(5)
        addr = struct.pack('<Q', 9) + b'\0' * 10 + b'\xff\xff\x7f\0\0\1' + struct.pack('>H', 29800)
        ua = b'/work-admission-test/'
        self.send('version', struct.pack('<iQq', 70030, 9, int(time.time())) + addr + addr +
                  struct.pack('<Q', 734928) + bytes([len(ua)]) + ua + struct.pack('<i?', 0, False))
        while True:
            command, _ = self.receive()
            if command == 'version': self.send('verack', b'')
            if command == 'verack': break

    def send(self, command, body):
        self.sock.sendall(self.magic + command.encode().ljust(12, b'\0') +
                          struct.pack('<I', len(body)) + dhash(body)[:4] + body)

    def receive(self):
        def read(size):
            result = b''
            while len(result) < size:
                data = self.sock.recv(size - len(result))
                if not data: raise EOFError()
                result += data
            return result
        header = read(24)
        return header[4:16].rstrip(b'\0').decode(), read(struct.unpack('<I', header[16:20])[0])

    def ping(self):
        nonce = struct.pack('<Q', 879332)
        self.send('ping', nonce)
        end = time.monotonic() + 10
        while time.monotonic() < end:
            command, body = self.receive()
            if command == 'ping': self.send('pong', body)
            if command == 'pong' and body == nonce: return
        raise AssertionError('No pong after temporary admission')

    def expect_disconnect(self):
        end = time.monotonic() + 10
        while time.monotonic() < end:
            try:
                command, body = self.receive()
                if command == 'ping': self.send('pong', body)
            except (EOFError, ConnectionResetError): return
            except socket.timeout: pass
        raise AssertionError('Invalid difficulty did not disconnect peer')

    def close(self): self.sock.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--neuraid', type=Path, required=True)
    parser.add_argument('--network', choices=['main', 'test', 'regtest'], required=True)
    parser.add_argument('--tmpdir', type=Path, required=True)
    args = parser.parse_args()
    args.neuraid = args.neuraid.resolve(); args.tmpdir = args.tmpdir.resolve()
    args.tmpdir.mkdir(parents=True)
    results = []
    magic = {'main': b'NEUR', 'test': b'RUEN', 'regtest': b'RUEN'}[args.network]
    node = Node(args, args.tmpdir / 'miner')
    try:
        hashes = node.rpc('generatetoaddress', 3, address(args.network != 'main'))
        blocks = [bytes.fromhex(node.rpc('getblock', h, 0)) for h in hashes]
        genesis = bytes.fromhex(node.rpc('getblock', node.rpc('getblockhash', 0), 0))
        expected = node.stats()
        # Derive the header size from the actual network/branch, not its name.
        header_size = 120 if len(bytes.fromhex(node.rpc('getblockheader', hashes[0], False))) == 120 else 80
    finally: node.close()

    recipient = args.tmpdir / 'recipient'
    node = Node(args, recipient)
    try:
        for command in ('block', 'headers', 'cmpctblock'):
            header = bytearray(blocks[0][:header_size])
            bits = struct.unpack('<I', header[72:76])[0]
            header[72:76] = struct.pack('<I', bits ^ 1)
            payload = bytes(header) + b'\0'
            if command == 'headers': payload = b'\1' + payload
            if command == 'cmpctblock': payload = bytes(header) + struct.pack('<Q', 0) + b'\0\0'
            peer = Peer(magic)
            try:
                peer.send(command, payload)
                peer.expect_disconnect()
            finally: peer.close()
            assert node.rpc('getblockcount') == 0
            results.append(dict(message=command, bad_difficulty_disconnected=True))
        peer = Peer(magic)
        try:
            peer.send('block', blocks[2])
            peer.ping()
            assert node.rpc('getblockcount') == 0
            assert node.rpc('submitblock', blocks[0].hex()) is None
            assert node.rpc('submitblock', blocks[1].hex()) is None
            # Reuse the exact same child and peer after providing its ancestry.
            peer.send('block', blocks[2])
            peer.ping()
            wait_for(lambda: node.rpc('getblockcount') == 3)
        finally: peer.close()
        assert node.stats() == expected
        assert node.rpc('verifychain', 4, 0)
        log = next(recipient.rglob('debug.log')).read_text()
        assert 'bad-diffbits' in log and 'block-parent-unavailable' in log
        results.append(dict(orphan_retry=True, peer_preserved=True, **expected))
    finally: node.close()

    for extra in ([], ['-reindex'], ['-reindex-chainstate']):
        node = Node(args, recipient, extra)
        try:
            wait_for(lambda: node.rpc('getblockcount') == 3)
            assert node.stats() == expected
            assert node.rpc('verifychain', 4, 0)
            results.append(dict(restart=extra, **expected))
        finally: node.close()

    imported = args.tmpdir / 'ordered.dat'
    with imported.open('wb') as stream:
        for block in [genesis] + blocks: stream.write(magic + struct.pack('<I', len(block)) + block)
    node = Node(args, args.tmpdir / 'import', ['-loadblock=' + str(imported)])
    try:
        wait_for(lambda: node.rpc('getblockcount') == 3)
        assert node.stats() == expected
        assert node.rpc('verifychain', 4, 0)
        results.append(dict(ordered_import=True, **expected))
    finally: node.close()
    # Only reindex has disk positions for queueing out-of-order children.
    # A bootstrap/-loadblock file uses normal parent-first order above.
    network_dir = next(recipient.rglob('blk00000.dat')).parent.parent.relative_to(recipient)
    reversed_data = args.tmpdir / 'reverse-reindex'
    block_dir = reversed_data / network_dir / 'blocks'
    block_dir.mkdir(parents=True)
    with (block_dir / 'blk00000.dat').open('wb') as stream:
        for block in [genesis] + list(reversed(blocks)):
            stream.write(magic + struct.pack('<I', len(block)) + block)
    node = Node(args, reversed_data, ['-reindex'])
    try:
        wait_for(lambda: node.rpc('getblockcount') == 3)
        assert node.stats() == expected
        assert node.rpc('verifychain', 4, 0)
        results.append(dict(reverse_reindex=True, **expected))
    finally: node.close()
    (args.tmpdir / 'results.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == '__main__': main()
