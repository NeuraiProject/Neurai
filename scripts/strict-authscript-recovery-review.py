#!/usr/bin/env python3
"""Regtest regressions for strict-address import and mnemonic recovery.

Run inside the build Docker:
  python3 /src/scripts/strict-authscript-recovery-review.py --bindir /root/Neurai/src
Uses fresh temporary wallets, public test words and loopback-only nodes. Returns
nonzero if any expectation fails; never prints private keys or RPC credentials.
"""
import argparse
import base64
import json
import pathlib
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


WORDS = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for(predicate, description):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except (OSError, RuntimeError, urllib.error.URLError):
            pass
        time.sleep(0.2)
    raise RuntimeError("Timeout: " + description)


class Node:
    def __init__(self, bindir, base, name, restore=False):
        self.path = base / name
        self.path.mkdir()
        self.rpcport, self.p2pport = free_port(), free_port()
        self.log = (self.path / "process.log").open("w")
        args = [str(bindir / "neuraid"), "-regtest", "-server", "-listen=1",
                "-bind=127.0.0.1", "-connect=0", "-dnsseed=0", "-discover=0",
                "-upnp=0", "-keypool=5", "-fallbackfee=0.01", "-txindex=1",
                "-rpcuser=review", "-rpcpassword=local-test-only",
                "-datadir=" + str(self.path), "-rpcport=" + str(self.rpcport),
                "-port=" + str(self.p2pport)]
        if restore:
            args += ["-addresstype=pq", "-mnemonic=" + WORDS]
        self.proc = subprocess.Popen(args, stdout=self.log, stderr=subprocess.STDOUT)

    def rpc(self, method, *params):
        data = json.dumps({"jsonrpc": "1.0", "id": "review", "method": method,
                           "params": params}).encode()
        auth = base64.b64encode(b"review:local-test-only").decode()
        request = urllib.request.Request("http://127.0.0.1:%d" % self.rpcport,
                                        data, {"Authorization": "Basic " + auth})
        try:
            response = urllib.request.urlopen(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            result = json.load(response)
        if result.get("error"):
            # Avoid echoing any RPC arguments (private keys in import calls).
            raise RuntimeError("RPC %s failed (code %s)" % (method, result["error"]["code"]))
        return result["result"]

    def ready(self):
        wait_for(lambda: self.rpc("getblockcount") >= 0, "node startup")

    def close(self):
        if self.proc.poll() is None:
            try:
                self.rpc("stop")
            except Exception:
                self.proc.terminate()
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        self.log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bindir", type=pathlib.Path, default=pathlib.Path("/root/Neurai/src"))
    args = parser.parse_args()
    base = pathlib.Path(tempfile.mkdtemp(prefix="strict-recovery-review-"))
    print("Artifacts:", base, flush=True)
    nodes, results = [], []

    def start(name, restore=False):
        node = Node(args.bindir, base, name, restore)
        nodes.append(node)
        node.ready()
        return node

    def check(name, condition):
        results.append({"test": name, "passed": bool(condition)})
        print(("PASS: " if condition else "FAIL: ") + name, flush=True)

    try:
        source = start("source", True)
        pq = source.rpc("getnewaddress", "", "pq")
        ec = source.rpc("getnewaddress", "", "ecdsa")
        miner = source.rpc("getnewaddress")
        importer = start("importer")
        for name, address in [("PQ", pq), ("ECDSA", ec)]:
            secret = source.rpc("dumpprivkey", address)
            importer.rpc("importprivkey", secret, "", False)
            del secret
            check(name + " strict destination recognized after WIF import",
                  importer.rpc("validateaddress", address).get("ismine", False))

        # Fund both families, then restore the same seed without issuing any
        # addresses on the restored wallet. Its scan must find these payments.
        source.rpc("generatetoaddress", 102, miner)
        source.rpc("sendtoaddress", pq, 5)
        source.rpc("sendtoaddress", ec, 5)
        source.rpc("generatetoaddress", 1, miner)
        restored = start("restored", True)
        restored.rpc("addnode", "127.0.0.1:%d" % source.p2pport, "onetry")
        wait_for(lambda: restored.rpc("getbestblockhash") == source.rpc("getbestblockhash"),
                 "restored node synchronization")
        for name, address in [("PQ", pq), ("ECDSA", ec)]:
            check(name + " strict destination recognized after mnemonic restore",
                  restored.rpc("validateaddress", address).get("ismine", False))
            coins = restored.rpc("listunspent", 1, 999999, [address])
            check(name + " funded strict output recovered from mnemonic",
                  any(coin.get("spendable") and coin["amount"] >= 5 for coin in coins))
        # Scanning may advance the shared v1/PQ keypool, so getnewaddress is
        # not an index-stable control. Check the actual recovered private key
        # instead, without logging it. All words here are public test data.
        dump = base / "restored-test-wallet.txt"
        restored.rpc("dumpwallet", str(dump))
        secret = source.rpc("dumpprivkey", pq)
        recovered_keys = {line.split()[0] for line in dump.read_text().splitlines()
                          if line and not line.startswith("#")}
        check("Mnemonic restored the PQ key even if its strict destination is missing",
              secret in recovered_keys)
        del secret, recovered_keys
        dump.unlink()
    finally:
        for node in reversed(nodes):
            node.close()
        (base / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    failed = sum(not result["passed"] for result in results)
    print("RESULT: %d passed, %d failed" % (len(results) - failed, failed), flush=True)
    return bool(failed)


if __name__ == "__main__":
    raise SystemExit(main())
