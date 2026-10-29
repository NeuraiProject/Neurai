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

from test_framework.depin import DepinClient
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

    def info_response(self, node=None):
        return DepinClient(node or self.nodes[0]).bootstrap()[0]

    def request(self, address, kind="receive", rpc=None):
        return [DepinClient(rpc or self.nodes[0]).prepare("depinchallenge", TOKEN, address, args={"type": kind})]

    def call_request(self, node, method, request):
        return DepinClient(node).call_request(method, request)

    def challenge(self, address, kind="receive"):
        return self.call_request(self.nodes[0], "depinchallenge", self.request(address, kind)[0])["challenge"]

    def read_request(self, address, nonce, node=None, args=None):
        return DepinClient(node or self.nodes[0]).prepare("depinreceivemsg", TOKEN, address, nonce, args)

    def receive(self, address, nonce=None):
        nonce = nonce or self.challenge(address)
        return self.call_request(self.nodes[0], "depinreceivemsg", self.read_request(address, nonce))["messages"]


    def run_test(self):
        node = self.nodes[0]
        self.log.info("Issue a group, reveal Legacy keys and send encrypted history")
        node.generate(432)
        assert self.plain(self.info_response(node))["ready"]
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
        pending = self.read_request(revoked, self.challenge(revoked))

        self.log.info("A confirmed freeze invalidates access through an existing nonce")
        node.freezedepin(TOKEN, revoked, admin)
        freeze_block = node.generate(1)[0]
        request = pending
        assert_raises_rpc_error(-32600, "membership changed", self.call_request, node, "depinreceivemsg", request)
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
        assert_raises_rpc_error(-32600, "no active balance", self.call_request, node, "depinchallenge",
                                *self.request(revoked))
        assert_raises_rpc_error(None, "", node.depinsendmsg,
                                TOKEN, "forbidden sender", sender)

        self.log.info("Reorganizations restore and revoke permissions on the active branch")
        node.invalidateblock(freeze_block)
        # An orphaned freeze in the mempool must not revoke confirmed ownership.
        assert_equal(len(self.receive(revoked)), 1)
        node.reconsiderblock(sender_freeze_block)
        assert_raises_rpc_error(-32600, "no active balance", self.call_request, node, "depinchallenge",
                                *self.request(revoked))
        node.unfreezedepin(TOKEN, revoked, admin)
        node.generate(1)
        assert_equal(len(self.receive(revoked)), 1)
        assert_equal(len(self.receive(remaining)), 2)

        self.log.info("A confirmed owner move revokes old administrative challenges")
        admin_nonce = self.challenge(admin, "admin")
        admin_request = DepinClient(node).prepare("depinclearmsg", TOKEN, admin, admin_nonce)
        node.transfer(TOKEN + "!", 1, successor)
        owner_block = node.generate(1)[0]
        assert_raises_rpc_error(-32600, "membership changed", self.call_request, node, "depinclearmsg", admin_request)
        self.challenge(successor, "admin")
        node.invalidateblock(owner_block)
        assert_raises_rpc_error(-32600, "membership changed", self.call_request, node, "depinclearmsg", admin_request)
        fresh_admin = DepinClient(node).prepare("depinclearmsg", TOKEN, admin, self.challenge(admin, "admin"))
        self.call_request(node, "depinclearmsg", fresh_admin)  # Deletes expired only.
        assert_equal(len(self.receive(remaining)), 2)
        node.reconsiderblock(owner_block)

        self.log.info("A node stalled after IBD denies service but keeps diagnostics available")
        tip_time = node.getblockheader(node.getbestblockhash())["time"]
        node.setmocktime(tip_time + 3601)
        assert not self.plain(self.info_response(node))["ready"]
        assert_equal(DepinClient(node).call("depinpoolstats", TOKEN)["total_messages"], 2)
        assert_raises_rpc_error(-10, "DePIN service not ready", self.call_request, node, "depinchallenge",
                                *self.request(remaining))
        node.setmocktime(0)
        assert self.plain(self.info_response(node))["ready"]

        self.log.info("Concurrent signed requests and block validation obey lock order")
        def request_during_mining(address, eligible):
            rpc = get_rpc_proxy(node.url, 500 + int(eligible))
            client = DepinClient(rpc)
            for _ in range(40):
                request = self.request(address, rpc=rpc)[0]
                if eligible:
                    assert client.call_request("depinchallenge", request)["challenge"]
                    client.call("depingetancestorrecipients", TOKEN)
                else:
                    assert_raises_rpc_error(-32600, "no active balance", client.call_request, "depinchallenge", request)
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
        old_nonce = nonces[self_revoked]
        request = self.read_request(self_revoked, old_nonce)
        revoke_block = node.generate(1)[0]
        assert_raises_rpc_error(-32600, "membership changed", self.call_request, node, "depinreceivemsg", request)
        node.invalidateblock(revoke_block)
        assert_raises_rpc_error(-32600, "membership changed", self.call_request, node, "depinreceivemsg", request)
        assert self.receive(self_revoked)
        node.reconsiderblock(revoke_block)
        assert_raises_rpc_error(-32600, "no active balance", self.call_request, node, "depinchallenge",
                                *self.request(self_revoked))
        node.unfreezedepin(TOKEN, self_revoked, successor)
        node.generate(1)
        assert self.receive(self_revoked)

        self.log.info("Disabled persistence neither restores nor promises to retain history")
        without_persistence = [arg for arg in self.depin_args if not arg.startswith("-depinpoolpersist=")]
        without_persistence.append("-depinpoolpersist=0")
        self.restart_node(0, without_persistence)
        node = self.nodes[0]
        assert_equal(self.plain(self.info_response(node))["messages"], 0)
        node.depinsendmsg(TOKEN, "volatile message", remaining)
        assert_equal(self.plain(self.info_response(node))["messages"], 1)
        self.restart_node(0, without_persistence)
        assert_equal(self.plain(self.info_response(self.nodes[0]))["messages"], 0)


if __name__ == "__main__":
    DepinMessagingPermissionsTest().main()
