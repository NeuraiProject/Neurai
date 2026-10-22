#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see COPYING.

"""DePIN authorization on real blocks, reorgs and persisted-pool restarts.

Use a private regtest chain and disposable Legacy keys. No external crypto
packages are needed: the wallet RPCs implement the same signing and decryption
operations as a client. Database/cache races are covered by the C++ suites.
"""

import json
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal

from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, get_rpc_proxy

TOKEN = "&MESSAGING"


class DepinMessagingPermissionsTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.depin_args = ["-assetindex", "-pubkeyindex", "-addresstype=legacy",
                     "-depinmsg=1", "-depinmsgtoken=" + TOKEN,
                     "-depinpoolpersist=1", "-depinratelimit=0"]
        self.extra_args = [self.depin_args]
        self.sequence = 0

    @staticmethod
    def plain(response):
        return json.loads(bytes.fromhex(response["body"]).decode())

    def reveal(self, address):
        node = self.nodes[0]
        txid = node.sendtoaddress(address, 10)
        node.generate(1)
        decoded = node.decoderawtransaction(node.gettransaction(txid)["hex"])
        vout = next(v["n"] for v in decoded["vout"]
                    if address in v["scriptPubKey"].get("addresses", []))
        raw = node.createrawtransaction([{"txid": txid, "vout": vout}],
                                       {node.getnewaddress(): Decimal("9.99")})
        signed = node.signrawtransaction(raw)
        assert signed["complete"]
        node.sendrawtransaction(signed["hex"])
        node.generate(1)

    def request(self, address, kind="receive"):
        node = self.nodes[0]
        # Native helper supplies the node's clock. Distinct milliseconds also
        # make the test reliable under mock time and exercise signmessage interop.
        clock = node.depinsignrequest(address, TOKEN, kind)["timestamp"]
        self.sequence += 1
        timestamp = clock + self.sequence
        preimage = "DEPIN-REQ|{}|{}|{}|{}".format(kind, TOKEN, address, timestamp)
        signature = node.signmessage(address, preimage)
        return [TOKEN, address, timestamp, signature, kind]

    def challenge(self, address, kind="receive"):
        node = self.nodes[0]
        response = node.depinchallenge(*self.request(address, kind))
        return node.depindecrypt(address, response["encrypted"])["challenge"]

    def receive(self, address, nonce=None):
        node = self.nodes[0]
        nonce = nonce or self.challenge(address)
        signature = node.depinsignchallenge(address, TOKEN, nonce)["signature"]
        result = node.depinreceivemsg(TOKEN, address, nonce, signature)
        return node.depindecrypt(address, result["encrypted"])["messages"]

    def run_test(self):
        node = self.nodes[0]
        self.log.info("Issue a group, reveal Legacy keys and send encrypted history")
        node.generate(432)
        assert self.plain(node.depingetmsginfo())["ready"]
        sender, revoked, remaining, admin, successor = [node.getnewaddress() for _ in range(5)]
        for address in (sender, revoked, remaining, admin, successor):
            self.reveal(address)
        node.issue(TOKEN, 100, sender)
        node.generate(1)
        for address in (revoked, remaining):
            node.transferfromaddress(TOKEN, sender, 10, address, "", 0, "", sender)
            node.generate(1)
        first = node.depinsendmsg(TOKEN, "historical message", sender)["hash"]
        original = self.receive(revoked)
        assert_equal(len(original), 1)
        assert_equal(original[0]["hash"], first)
        pending = self.challenge(revoked)

        self.log.info("A confirmed freeze invalidates access through an existing nonce")
        node.freezedepin(TOKEN, revoked, admin)
        freeze_block = node.generate(1)[0]
        signature = node.depinsignchallenge(revoked, TOKEN, pending)["signature"]
        assert_raises_rpc_error(-32600, "no active balance", node.depinreceivemsg,
                                TOKEN, revoked, pending, signature)
        assert_equal(node.depingetmsg(TOKEN, revoked), [])
        assert_equal(len(self.receive(remaining)), 1)
        second = node.depinsendmsg(TOKEN, "after recipient freeze", sender)["hash"]
        messages = self.receive(remaining)
        fresh = next(m for m in messages if m["hash"] == second)
        assert_raises_rpc_error(-22, "required recipient missing", node.depindecrypt,
                                revoked, fresh["encrypted_payload_hex"])
        # Copies delivered before revocation remain decryptable with that key.
        assert_equal(node.depindecrypt(revoked, original[0]["encrypted_payload_hex"]),
                     "historical message")

        self.log.info("Restart preserves history after both sender and recipient lose access")
        node.freezedepin(TOKEN, sender, admin)
        sender_freeze_block = node.generate(1)[0]
        self.restart_node(0, self.depin_args)
        node = self.nodes[0]
        assert_equal({m["hash"] for m in self.receive(remaining)}, {first, second})
        assert_raises_rpc_error(-32600, "no active balance", node.depinchallenge,
                                *self.request(revoked))
        assert_raises_rpc_error(None, "", node.depinsendmsg,
                                TOKEN, "forbidden sender", sender)

        self.log.info("Reorganizations restore and revoke permissions on the active branch")
        node.invalidateblock(freeze_block)
        # An orphaned freeze in the mempool must not revoke confirmed ownership.
        assert_equal(len(self.receive(revoked)), 1)
        node.reconsiderblock(sender_freeze_block)
        assert_raises_rpc_error(-32600, "no active balance", node.depinchallenge,
                                *self.request(revoked))
        node.unfreezedepin(TOKEN, revoked, admin)
        node.generate(1)
        assert_equal(len(self.receive(revoked)), 1)
        assert_equal(len(self.receive(remaining)), 2)

        self.log.info("A confirmed owner move revokes old administrative challenges")
        admin_nonce = self.challenge(admin, "admin")
        node.transfer(TOKEN + "!", 1, successor)
        owner_block = node.generate(1)[0]
        admin_sig = node.depinsignchallenge(admin, TOKEN, admin_nonce, "admin")["signature"]
        assert_raises_rpc_error(-32600, "does not hold the owner token", node.depinclearmsg,
                                TOKEN, admin, admin_nonce, admin_sig)
        self.challenge(successor, "admin")
        node.invalidateblock(owner_block)
        node.depinclearmsg(TOKEN, admin, admin_nonce, admin_sig)  # Deletes expired only.
        assert_equal(len(self.receive(remaining)), 2)
        node.reconsiderblock(owner_block)

        self.log.info("A node stalled after IBD denies service but keeps diagnostics available")
        tip_time = node.getblockheader(node.getbestblockhash())["time"]
        node.setmocktime(tip_time + 3601)
        assert not self.plain(node.depingetmsginfo())["ready"]
        assert_equal(self.plain(node.depinpoolstats())["total_messages"], 2)
        assert_raises_rpc_error(-10, "DePIN service not ready", node.depinchallenge,
                                *self.request(remaining))
        node.setmocktime(0)
        assert self.plain(node.depingetmsginfo())["ready"]

        self.log.info("Concurrent signed requests and block validation obey lock order")
        def request_during_mining(address, eligible):
            # A separate HTTP connection is required for this thread.
            rpc = get_rpc_proxy(node.url, 0, timeout=60)
            for _ in range(40):
                timestamp = rpc.depinsignrequest(address, TOKEN)["timestamp"]
                self.sequence += 1
                timestamp += self.sequence
                preimage = "DEPIN-REQ|receive|{}|{}|{}".format(TOKEN, address, timestamp)
                params = [TOKEN, address, timestamp, rpc.signmessage(address, preimage)]
                if eligible:
                    response = rpc.depinchallenge(*params)
                    assert rpc.depindecrypt(address, response["encrypted"])["challenge"]
                    self.plain(rpc.depingetancestorrecipients(TOKEN))
                else:
                    assert_raises_rpc_error(-32600, "no active balance", rpc.depinchallenge, *params)
            return 40

        with ThreadPoolExecutor(max_workers=2) as executor:
            requests = executor.submit(request_during_mining, remaining, True)
            rejected = executor.submit(request_during_mining, admin, False)
            for _ in range(8):
                node.generate(1)
            assert_equal(requests.result(timeout=120), 40)
            assert_equal(rejected.result(timeout=120), 40)

        self.log.info("Confirmed self-revocation and its reorg affect existing challenges")
        node.unfreezedepin(TOKEN, sender, successor)
        node.generate(1)
        nonces = {address: self.challenge(address) for address in (sender, revoked, remaining)}
        revoke_tx = node.selfrevokedepin(TOKEN)[0]
        decoded = node.decoderawtransaction(node.gettransaction(revoke_tx)["hex"])
        self_revoked = next(v["scriptPubKey"]["addresses"][0] for v in decoded["vout"]
                            if v["scriptPubKey"].get("asset", {}).get("name") == TOKEN)
        # A mempool-only revocation does not alter confirmed authorization.
        self.receive(self_revoked)
        revoke_block = node.generate(1)[0]
        old_nonce = nonces[self_revoked]
        signature = node.depinsignchallenge(self_revoked, TOKEN, old_nonce)["signature"]
        assert_raises_rpc_error(-32600, "no active balance", node.depinreceivemsg,
                                TOKEN, self_revoked, old_nonce, signature)
        node.invalidateblock(revoke_block)
        assert self.receive(self_revoked, old_nonce)
        node.reconsiderblock(revoke_block)
        assert_raises_rpc_error(-32600, "no active balance", node.depinchallenge,
                                *self.request(self_revoked))
        node.unfreezedepin(TOKEN, self_revoked, successor)
        node.generate(1)
        assert self.receive(self_revoked)

        self.log.info("Disabled persistence neither restores nor promises to retain history")
        without_persistence = [arg for arg in self.depin_args if not arg.startswith("-depinpoolpersist=")]
        without_persistence.append("-depinpoolpersist=0")
        self.restart_node(0, without_persistence)
        node = self.nodes[0]
        assert_equal(self.plain(node.depingetmsginfo())["messages"], 0)
        node.depinsendmsg(TOKEN, "volatile message", remaining)
        assert_equal(self.plain(node.depingetmsginfo())["messages"], 1)
        self.restart_node(0, without_persistence)
        assert_equal(self.plain(self.nodes[0].depingetmsginfo())["messages"], 0)


if __name__ == "__main__":
    DepinMessagingPermissionsTest().main()
