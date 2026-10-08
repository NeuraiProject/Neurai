#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see COPYING.
"""Standalone clock-policy regression test, using only Python's standard library.

Run against an isolated binary with --neuraid PATH --network main|test --tmpdir DIR.
The node has no external peers. All simulated peers use distinct loopback IPs.
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
import threading
import time

NOW = 2000000000
RPC_PORT, P2P_PORT = 29603, 29604


def wait_for(predicate, timeout=30):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError('Timed out waiting for test condition')


def digest(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def mining_address(test):
    raw = bytes([127 if test else 53]) + b'\x11' * 20
    raw += digest(raw)[:4]
    value, result = int.from_bytes(raw, 'big'), ''
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    while value:
        value, digit = divmod(value, 58)
        result = alphabet[digit] + result
    return result


class Peer:
    def __init__(self, sock, timestamp, magic):
        self.sock, self.magic = sock, magic
        self.lock = threading.Lock()
        self.ready, self.pong, self.closed = threading.Event(), threading.Event(), threading.Event()
        self.error = None
        self.sock.settimeout(1)
        self.thread = threading.Thread(target=self.run, daemon=True)
        address = struct.pack('<Q', 9) + b'\0' * 10 + b'\xff\xff\x7f\0\0\1' + struct.pack('>H', P2P_PORT)
        agent = b'/clock-policy-test:0.1/'
        version = struct.pack('<iQq', 70030, 9, timestamp) + address * 2
        version += struct.pack('<Q', id(self)) + bytes([len(agent)]) + agent + struct.pack('<i?', 0, True)
        # Send our version before the reader can reply with verack.
        self.send(b'version', version)
        self.thread.start()

    def send(self, command, payload=b''):
        message = self.magic + command.ljust(12, b'\0') + struct.pack('<I', len(payload)) + digest(payload)[:4] + payload
        with self.lock:
            self.sock.sendall(message)

    def receive(self, size):
        result = b''
        while len(result) < size and not self.closed.is_set():
            try:
                part = self.sock.recv(size - len(result))
            except socket.timeout:
                continue
            if not part:
                raise EOFError()
            result += part
        if len(result) != size:
            raise EOFError()
        return result

    def run(self):
        try:
            while not self.closed.is_set():
                header = self.receive(24)
                assert header[:4] == self.magic
                size = struct.unpack('<I', header[16:20])[0]
                assert size < 4000000
                payload = self.receive(size)
                assert digest(payload)[:4] == header[20:24]
                command = header[4:16].rstrip(b'\0')
                if command == b'version':
                    self.send(b'verack')
                elif command == b'verack':
                    self.ready.set()
                elif command == b'ping':
                    self.send(b'pong', payload)
                elif command == b'pong':
                    self.pong.set()
                elif command == b'getheaders':
                    self.send(b'headers', b'\0')
        except (EOFError, OSError):
            pass
        except Exception as error:
            self.error = error

    def sync(self):
        assert self.ready.wait(20), 'Peer handshake failed'
        self.pong.clear()
        self.send(b'ping', struct.pack('<Q', 12345))
        assert self.pong.wait(20), 'Peer ping failed'
        assert self.error is None, self.error

    def close(self):
        self.closed.set()
        self.sock.close()
        self.thread.join(3)


class Node:
    def __init__(self, args, scenario, limit):
        self.args, self.peers, self.listeners = args, [], []
        self.magic = b'RUEN' if args.network == 'test' else b'NEUR'
        self.data = args.tmpdir / scenario
        self.data.mkdir(parents=True)
        self.log = (args.tmpdir / (scenario + '.log')).open('w')
        command = [str(args.neuraid), '-datadir=' + str(self.data), '-server', '-disablewallet',
                   '-connect=0', '-dnsseed=0', '-discover=0', '-listen=1', '-bind=127.0.0.1',
                   '-port=' + str(P2P_PORT), '-rpcport=' + str(RPC_PORT), '-rpcbind=127.0.0.1',
                   '-rpcallowip=127.0.0.1', '-rpcuser=clock-test', '-rpcpassword=isolated-test',
                   '-mocktime=' + str(NOW), '-bypassdownload', '-disablesafemode', '-par=1', '-dbcache=32',
                   '-miningaddress=' + mining_address(args.network == 'test')]
        if args.network == 'test':
            command.append('-testnet')
        if limit is not None:
            command.append('-maxtimeadjustment=' + str(limit))
        self.process = subprocess.Popen(command, stdout=self.log, stderr=subprocess.STDOUT)
        def started():
            assert self.process.poll() is None, 'Node exited during startup'
            try:
                self.rpc('getnetworkinfo')
                return True
            except (OSError, RuntimeError):
                return False
        try:
            wait_for(started, 90)
        except Exception:
            self.close()
            raise

    def rpc(self, method, *params):
        connection = http.client.HTTPConnection('127.0.0.1', RPC_PORT, timeout=30)
        auth = base64.b64encode(b'clock-test:isolated-test').decode()
        connection.request('POST', '/', json.dumps(dict(id=1, method=method, params=params)),
                           {'Authorization': 'Basic ' + auth})
        result = json.loads(connection.getresponse().read())
        connection.close()
        if result.get('error'):
            raise RuntimeError(result['error'])
        return result['result']

    def peer(self, inbound, identity, timestamp):
        if inbound:
            sock = socket.socket()
            sock.bind(('127.0.2.' + str(identity), 0))
            sock.connect(('127.0.0.1', P2P_PORT))
        else:
            server = socket.socket()
            server.bind(('127.0.1.' + str(identity), 0))
            server.listen(1)
            server.settimeout(20)
            self.listeners.append(server)
            address, port = server.getsockname()
            self.rpc('addnode', address + ':' + str(port), 'onetry')
            sock, _ = server.accept()
        peer = Peer(sock, timestamp, self.magic)
        self.peers.append(peer)
        peer.sync()
        return peer

    def offset(self):
        return self.rpc('getnetworkinfo')['timeoffset']

    def close(self):
        if self.process.poll() is None:
            try:
                self.rpc('stop')
            except Exception:
                self.process.terminate()
        result = self.process.wait(timeout=60)
        for peer in self.peers:
            peer.close()
        for listener in self.listeners:
            listener.close()
        self.log.close()
        assert result == 0, 'Node exited with status ' + str(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--neuraid', type=Path, required=True)
    parser.add_argument('--network', choices=['main', 'test'], required=True)
    parser.add_argument('--tmpdir', type=Path, required=True)
    parser.add_argument('--case', help='Run only one scenario (used for mutation checks)')
    args = parser.parse_args()
    args.neuraid = args.neuraid.resolve()
    args.tmpdir.mkdir(parents=True, exist_ok=True)
    scenarios = [
        ('inbound', None, 250, 0), ('outbound', None, 250, 250),
        ('negative-boundary', None, -300, -300), ('positive-boundary', None, 300, 300),
        ('too-far-forward', None, 301, 0), ('too-far-back', None, -301, 0),
        ('disabled', 0, 250, 0), ('negative-setting', -1, -250, 0),
        ('custom-boundary', 120, 120, 120), ('custom-exceeded', 120, 121, 0),
        ('extreme-past', None, -(1 << 63) - NOW, 0),
        ('extreme-future', None, (1 << 63) - 1 - NOW, 0),
    ]
    if args.case:
        scenarios = [scenario for scenario in scenarios if scenario[0] == args.case]
        assert scenarios, 'Unknown scenario'
    results = []
    for name, limit, sample, expected in scenarios:
        node = Node(args, name, limit)
        try:
            for identity in range(1, 5):
                node.peer(name == 'inbound', identity, NOW + sample)
            assert node.offset() == expected, (name, node.offset(), expected)
            peers = node.rpc('getpeerinfo')
            reported = max(-(1 << 63), min((1 << 63) - 1, sample))
            assert len(peers) == 4
            assert all(peer['inbound'] == (name == 'inbound') for peer in peers)
            assert all(peer['timeoffset'] == reported for peer in peers), peers
            if name == 'outbound':
                for identity in range(10, 18):
                    node.peer(True, identity, NOW - 250)
                # New connections from an already sampled IP cannot replace its sample.
                for _ in range(4):
                    node.peer(False, 1, NOW - 250)
                assert node.offset() == 250
            if expected:
                assert node.rpc('getblocktemplate', {})['curtime'] == NOW + expected
            results.append(dict(scenario=name,offset=expected,connections=len(node.rpc('getpeerinfo'))))
        finally:
            node.close()
        (args.tmpdir / 'results.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
