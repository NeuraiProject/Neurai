#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Birth of one C7 XNA TEST pool instance on testnet or regtest.

Verifiable birth (README.md, "Instance"):
  1. issue the root NAME, non-reissuable, and the UNIQUE NAME#POOL;
  2. birth transaction: inputs NAME#POOL, NAME! and a funding coin; output 0 is
     the empty state, output 1 sends NAME! to the global burn address, output 2
     is the change;
  3. domain, asset id and context from c7_ref.py; contract from c7_contract.py.

The C7 instance reuses the C6 circuits, verifying keys and proving files, taken
from the C6 pool config. It writes c7-<network>.json for neurai-qt and a
report with every transaction. On testnet it never mines and waits for public
miners; on regtest it mines the confirmations itself.

    deploy_c7.py --rpc-config rpc.json --name C7TEST1022A --out <dir>

Without the C6 constructors, --leaf-template takes the contract from a pinned
C7 config instead. A leaf depends on its instance only through the context,
pushed once, and the pool name, pushed four times; the name length also sets
a few offsets. The template's leaves are rewritten with the new context and a
name of the same length, after its own leaves rebuild its pinned commitment.

    deploy_c7.py --rpc-config rpc.json --name C7TEST1106A --out <dir> \\
        --leaf-template c7-testnet.json
"""
import argparse
import base64
import hashlib
import json
import struct
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import c7_contract  # noqa: E402
import c7_ref  # noqa: E402

COIN = 100_000_000
PROFILE = "C7-XNA-TEST-v1"
OPERATIONS = ("D", "T1", "T2", "T3", "W", "J2")
BURN = {"test": "tBURNXXXXXXXXXXXXXXXXXXXXXXXVZLroy", "regtest": "tBURNXXXXXXXXXXXXXXXXXXXXXXXVZLroy"}
NETWORK_NAME = {"test": "testnet", "regtest": "regtest"}


class RPC:
    def __init__(self, path):
        self.s = json.loads(path.read_text())

    def call(self, method, *params):
        s = self.s
        body = json.dumps({"id": "c7-birth", "method": method, "params": params}).encode()
        auth = base64.b64encode((s["user"] + ":" + s["password"]).encode()).decode()
        url = s["url"] if "url" in s else "http://127.0.0.1:" + str(s["port"])
        req = urllib.request.Request(url, body,
                                     {"Authorization": "Basic " + auth, "Content-Type": "application/json"})
        try:
            response = urllib.request.urlopen(req, timeout=300)
        except urllib.error.HTTPError as e:
            response = e
        with response:
            reply = json.load(response)
        if reply.get("error"):
            raise RuntimeError(method + ": " + str(reply["error"]))
        return reply["result"]


def compact(n):
    return bytes([n]) if n < 253 else b"\xfd" + struct.pack("<H", n)


def tagged(tag, data):
    t = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(t + t + data).digest()


def commitment(leaves):
    """AuthScript program of the leaves: the MAST sorted by form name, as
    BuildMast() in src/privacy/c6_config.cpp and c7-transaction.js build it."""
    def tree(items):
        if len(items) == 1:
            script = items[0]["script"]
            return tagged("NeuraiAuthLeaf", b"\x01" + compact(len(script)) + script)
        cut = 1
        while cut * 2 < len(items):
            cut *= 2
        a, b = tree(items[:cut]), tree(items[cut:])
        return tagged("NeuraiAuthBranch", min(a, b) + max(a, b))
    return tagged("NeuraiAuthScript", b"\x04\x00" + tree(sorted(leaves, key=lambda l: l["form"])))


def template_contract(path, vks, identity, ctx):
    """Contract of a new instance from a pinned C7 config (see --leaf-template).
    Returns (commitment, leaves, opening, state script)."""
    t = json.loads(path.read_text())
    t = t.get("config", t)
    manifest, deployment = t["manifest"], t["deployment"]
    if manifest.get("profile") != PROFILE or deployment.get("kind") != "xna":
        raise ValueError("leaf template: a C7 XNA config is required")
    if any(bytes.fromhex(manifest["vks"][op]) != vks[op] for op in OPERATIONS):
        raise ValueError("leaf template: its verifying keys are not the C6 ones")
    old, new = manifest["identity"].encode(), identity.encode()
    if len(old) != len(new):
        raise ValueError("leaf template: the pool name must have the template's length, " + str(len(old)) + " bytes")
    old_push, new_push = compact(len(old)) + old, compact(len(new)) + new
    old_ctx = bytes.fromhex(manifest["context"])
    rows = [{"form": l["form"], "script": bytes.fromhex(l["script"]), "args": l["args"]} for l in deployment["leaves"]]
    if commitment(rows) != bytes.fromhex(deployment["commitment"]):
        raise ValueError("leaf template: its leaves do not rebuild its commitment")
    leaves = []
    for row in rows:
        s = row["script"]
        if s.count(old_ctx) != 1 or s.count(old_push) != 4 or s.count(old) != 4:
            raise ValueError("leaf template: unexpected instance bytes in leaf " + row["form"])
        leaves.append(dict(row, script=s.replace(old_ctx, ctx).replace(old_push, new_push)))
    C = commitment(leaves)
    opening = bytes.fromhex(deployment["anchor"]["opening"])
    state = bytes.fromhex(deployment["anchor"]["script"])
    if (state[:34] != b"\x51\x20" + bytes.fromhex(deployment["commitment"]) or state[34:].count(old_push) != 1 or
            state[-33:] != c7_ref.poseidon_bytes(opening) + b"\x75"):
        raise ValueError("leaf template: unexpected birth state")
    return C, leaves, opening, b"\x51\x20" + C + state[34:].replace(old_push, new_push)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--rpc-config", type=Path, required=True, help='{"port": n, "user": "...", "password": "..."}')
    p.add_argument("--name", required=True, help="fresh root asset name, e.g. C7TEST1022A")
    p.add_argument("--out", type=Path, required=True, help="new directory for the config and the report")
    p.add_argument("--c6-config", type=Path, default=HERE.parent / "privacy-c6/c6-testnet.json",
                   help="C6 pool config: source of the verifying keys and proving file pins")
    p.add_argument("--repo-root", type=Path, default=HERE.parents[2], help="checkout with scripts/ and NIP/bench/")
    p.add_argument("--leaf-template", type=Path,
                   help="pinned C7 config whose leaves are rewritten for this instance, instead of the C6 constructors")
    a = p.parse_args()
    if not a.name.isalnum() or not a.name.isupper() or not 3 <= len(a.name) <= 20:
        raise ValueError("root name: 3 to 20 upper-case letters and digits")
    a.out.mkdir(parents=True, exist_ok=False)
    Contract, j = (None, None) if a.leaf_template else c7_contract.load(a.repo_root)

    report = {"success": False, "scope": __doc__.split("\n")[0], "checks": [], "transactions": [], "phase": "preflight",
              "keys": "C6 PUBLIC TEST keys reused; not production keys"}

    def save():
        (a.out / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    def check(label, yes):
        report["checks"].append({"case": label, "passed": bool(yes)})
        save()
        print(("PASS " if yes else "FAIL ") + label, flush=True)
        if not yes:
            raise RuntimeError(label)

    node = RPC(a.rpc_config)
    info = node.call("getblockchaininfo")
    chain = info["chain"]
    check("testnet or regtest node", chain in BURN)
    if chain == "test":
        check("testnet name starts with C7TEST", a.name.startswith("C7TEST"))
    regtest = chain == "regtest"
    genesis = node.call("getblockhash", 0)

    def mine():
        if regtest:
            node.call("generatetoaddress", 1, node.call("getnewaddress"))

    def confirm(txid):
        print("Waiting for confirmation: " + txid, flush=True)
        deadline = time.monotonic() + 1800
        while time.monotonic() < deadline:
            mine()
            tx = node.call("getrawtransaction", txid, True)
            if tx.get("confirmations", 0) >= 1:
                return tx
            time.sleep(1 if regtest else 5)
        raise RuntimeError("Confirmation timeout; do not repeat this send: " + txid)

    def sent(phase, method, *params):
        report["phase"] = phase
        save()
        txid = node.call(method, *params)
        if isinstance(txid, list):
            if len(txid) != 1:
                raise ValueError("Expected one transaction")
            txid = txid[0]
        report["transactions"].append({"phase": phase, "txid": txid})
        save()
        return confirm(txid)

    try:
        check("privacy profile 3 active for the next block", info.get("zk_portable_tree", {}).get("active_for_next_block") is True)
        check("node synchronised", info["blocks"] == info["headers"] and (regtest or info["verificationprogress"] > 0.999))
        report["nodeVersion"] = node.call("getnetworkinfo")["subversion"]
        c6 = json.loads(a.c6_config.read_text())
        c6 = c6.get("config", c6)
        vks = {op: bytes.fromhex(c6["manifest"]["vks"][op]) for op in OPERATIONS}
        check("C6 verifying keys match their pins",
              all(hashlib.sha256(vks[op]).hexdigest() == c6["manifest"]["vk_sha256"][op] for op in OPERATIONS))
        if a.leaf_template:
            # Everything but the context is checked before any coin is spent.
            template_contract(a.leaf_template, vks, a.name + "#POOL", bytes(32))
            check("leaf template rebuilds its pinned commitment", True)
            report["leafTemplate"] = str(a.leaf_template)
        try:
            existing = bool(node.call("getassetdata", a.name))
        except RuntimeError as e:
            if "not found" not in str(e).lower() and "exist" not in str(e).lower():
                raise
            existing = False
        check("fresh root asset name", not existing)
        address = node.call("getnewaddress", "", "legacy")
        pay = bytes.fromhex(node.call("validateaddress", address)["scriptPubKey"])

        # 1. Root (non-reissuable) and UNIQUE.
        sent("root-issuance", "issue", a.name, 1, address, "", 0, False)
        issuance = sent("unique-issuance", "issueunique", a.name, ["POOL"], None, address)
        identity = a.name + "#POOL"
        owner = a.name + "!"
        emission = [v for v in issuance["vout"] if v["scriptPubKey"].get("asset", {}).get("name") == identity]
        owners = [v for v in issuance["vout"] if v["scriptPubKey"].get("asset", {}).get("name") == owner]
        check("one UNIQUE emission output and one owner token output", len(emission) == 1 and len(owners) == 1)
        emission_vout, owner_vout = emission[0]["n"], owners[0]["n"]

        # 2. Instance and contract.
        domain = c7_ref.pool_domain(genesis, issuance["txid"], emission_vout, identity)
        asset = c7_ref.xna_asset_id()
        ctx = c7_ref.pool_context(domain, asset)
        if a.leaf_template:
            C, rows, opening, state = template_contract(a.leaf_template, vks, identity, ctx)
            # A rewrite changes no opcode, so the template's operation counts hold.
            check("nine leaves within the script size limit",
                  len(rows) == 9 and all(len(r["script"]) <= 10000 for r in rows))
        else:
            check("context agrees with the C6 constructor", ctx == j.tr.P(b"NeuraiPoolCtx\x01" + domain + asset +
                                                                        struct.pack("<Q", 1) + bytes(32)))
            pool = Contract(vks, ctx, j.tr.EMPTY_W_DATA, identity.encode())
            C, leaves, controls, guard = pool.construct()
            check("nine leaves within the script limits",
                  len(leaves) == 9 and all(len(s.bytes()) <= 10000 and s.nops() <= 512 for s in leaves.values()))
            rows = [{"form": f, "script": s.bytes(), "args": pool.leaf(f)[1]} for f, s in leaves.items()]
            opening = j.packets.World().state()
            state = j.c.asset_script(C, identity.encode(), COIN, j.tr.P(opening))
        check("leaves rebuild the commitment", commitment(rows) == C)

        # 3. Birth: state, burn of NAME!, change.
        funding = sent("birth-funding", "sendtoaddress", address, 2)
        coins = [v for v in funding["vout"] if round(v["value"] * COIN) == 2 * COIN and v["scriptPubKey"]["hex"] == pay.hex()]
        check("one exact birth funding coin", len(coins) == 1)
        burn = BURN[chain]
        check("global burn address is valid here", node.call("validateaddress", burn)["isvalid"])
        template = node.call("decoderawtransaction", node.call("createrawtransaction", [], {burn: {"transfer": {owner: 1}}}))
        burn_script = bytes.fromhex(template["vout"][0]["scriptPubKey"]["hex"])
        points = [(issuance["txid"], emission_vout), (issuance["txid"], owner_vout), (funding["txid"], coins[0]["n"])]
        raw = struct.pack("<I", 3) + compact(len(points))
        raw += b"".join(bytes.fromhex(t)[::-1] + struct.pack("<I", n) + b"\x00" + b"\xff" * 4 for t, n in points)
        outputs = [(0, state), (0, burn_script), (190_000_000, pay)]
        raw += compact(len(outputs)) + b"".join(struct.pack("<Q", v) + compact(len(s)) + s for v, s in outputs)
        # Version 3 without reference inputs: no vrefin field (NIP-014 flag 2 is
        # unset), so the lock time follows the outputs.
        raw += bytes(4)
        signed = node.call("signrawtransaction", raw.hex())
        check("birth signatures complete", signed["complete"])
        (a.out / "birth.hex").write_text(signed["hex"] + "\n")
        accept = node.call("testmempoolaccept", [signed["hex"]])[0]
        report["birthAdmission"] = accept
        check("birth accepted by the node", accept.get("allowed") in (True, 1))
        birth = sent("birth", "sendrawtransaction", signed["hex"])
        block = node.call("getblockheader", birth["blockhash"])
        check("empty state at output 0", birth["vout"][0]["scriptPubKey"]["hex"] == state.hex() and
              node.call("gettxout", birth["txid"], 0, False) is not None)
        burned = birth["vout"][1]["scriptPubKey"]
        check("owner token burned at output 1", burned.get("asset", {}).get("name") == owner and
              burned.get("addresses") == [burn])

        manifest = {"profile": PROFILE, "network": bytes.fromhex(genesis)[::-1].hex(), "identity": identity,
                    "context": ctx.hex(), "commitment": C.hex(), "vks": {op: v.hex() for op, v in vks.items()},
                    "vk_sha256": {op: hashlib.sha256(v).hexdigest() for op, v in vks.items()},
                    "fees": {op: ["10000000", "20000000", "50000000"] for op in vks}}
        deployment = {"kind": "xna", "genesis": genesis, "commitment": C.hex(),
                      "emission": issuance["txid"] + ":" + str(emission_vout),
                      "ownerBurn": birth["txid"] + ":1",
                      "anchor": {"height": block["height"], "hash": block["hash"], "outpoint": birth["txid"] + ":0",
                                 "opening": opening.hex(), "script": state.hex()},
                      "leaves": [{"form": r["form"], "script": r["script"].hex(), "args": r["args"]} for r in rows]}
        config = {"manifest": manifest, "deployment": deployment, "domain": domain.hex(), "assetId": asset.hex(),
                  "network": NETWORK_NAME[chain], "expectedGenesis": manifest["network"], "expectedCommitment": C.hex(),
                  "artifacts": c6["artifacts"], "artifactBaseUrl": "/privacy-c7/", "reservations": []}
        name = "c7-" + NETWORK_NAME[chain] + ".json"
        (a.out / name).write_text(json.dumps({"enabled": True, "testOnly": True, "config": config}, indent=2) + "\n")
        report.update(identity=identity, emission=deployment["emission"], birth=birth["txid"], height=block["height"],
                      domain=domain.hex(), context=ctx.hex(), commitment=C.hex(), config=name,
                      pin={"identity": identity, "emission": deployment["emission"], "commitment": C.hex()})
        report["phase"] = "confirmed-birth"
        report["success"] = True
        save()
        print(json.dumps(report["pin"], indent=2))
    except BaseException as e:
        report["error"] = str(e)
        save()
        raise


if __name__ == "__main__":
    main()
