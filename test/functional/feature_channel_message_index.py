#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Test the chain-wide channel message index (-channelmessageindex, NIP-048 C).

- A node without the index creates no store and refuses queries.
- Every message an owner or message channel token carries back to its own
  address is indexed, with its authority, payload, expiry and the data of an
  OP_RETURN output of the same transaction; legacy messaging can stay off.
- Expiry is decided at query time against a reference time.
- Proofs and raw transactions can be attached; REST answers like the RPC.
- A limit splits the answer into pages that end between blocks.
- A message whose block leaves the active chain disappears, and comes back
  when it is mined again.
- A message sent to another address is not a channel message.
- A node that enables the index later catches up and answers alike, and a
  restart keeps the index.
"""

from decimal import Decimal
import hashlib
import http.client
import json
import os
from urllib.parse import urlparse

from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, connect_nodes_bi

IPFS = "QmZPGfJojdTzaqCWJu2m3krark38X1rqEHBo4SjeqHKB26"


class ChannelMessageIndexTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [['-channelmessageindex', '-txindex'], []]

    @staticmethod
    def messages(node, channel, **options):
        return node.getchannelmessages(channel, options)["messages"]

    def txids(self, node, channel, **options):
        return [m["txid"] for m in self.messages(node, channel, **options)]

    def run_test(self):
        n0, n1 = self.nodes
        n0.generate(150)
        self.sync_all()

        self.log.info("A node without the index creates nothing and refuses queries")
        assert not os.path.exists(os.path.join(n1.datadir, "regtest", "indexes", "channelmessages"))
        assert_raises_rpc_error(-1, "start the node with -channelmessageindex", n1.getchannelmessages, "NEWS!")
        assert_raises_rpc_error(-8, "owner token", n0.getchannelmessages, "NEWS")

        self.log.info("Owner and channel messages are indexed")
        n0.issue("NEWS", 1000)
        n0.generate(1)
        n0.issue("NEWS~ALERTS")
        n0.generate(1)
        token = n0.listmyassets("NEWS!", True)["NEWS!"]["outpoints"][0]
        owner_address = n0.gettxout(token["txid"], token["vout"])["scriptPubKey"]["addresses"][0]
        txid1 = n0.sendmessage("NEWS!", IPFS)[0]
        expire = n0.getblockchaininfo()["mediantime"] + 1000
        txid2 = n0.sendmessage("NEWS~ALERTS", "aa" * 32, expire)[0]
        n0.generate(1)

        # An owner message whose OP_RETURN carries the content it hashes (NIP-048 D1)
        outpoint = n0.listmyassets("NEWS!", True)["NEWS!"]["outpoints"][0]
        payload = b"manifest v1".hex()
        digest = hashlib.sha256(bytes.fromhex(payload)).hexdigest()
        raw = n0.createrawtransaction(
            [{"txid": outpoint["txid"], "vout": outpoint["vout"]}],
            {owner_address: {"transferwithmessage": {"NEWS!": 1, "message": digest, "expire_time": 0}},
             "data": payload})
        txid3 = n0.sendrawtransaction(n0.signrawtransaction(n0.fundrawtransaction(raw)["hex"])["hex"])
        n0.generate(1)
        self.sync_all()

        owner = self.messages(n0, "NEWS!")
        assert_equal([m["txid"] for m in owner], [txid1, txid3])
        assert_equal((owner[0]["authority"], owner[0]["message"], owner[0]["address"]), ("owner", IPFS, owner_address))
        assert "op_return" not in owner[0]
        assert_equal((owner[1]["message"], owner[1]["op_return"], owner[1]["op_return_matches"]), (digest, payload, True))
        assert_equal(self.txids(n0, "NEWS!", message=digest), [txid3])
        assert_equal(self.txids(n0, "NEWS!", from_height=owner[1]["height"]), [txid3])
        assert_equal(self.txids(n0, "NEWS!", to_height=owner[0]["height"]), [txid1])
        assert n0.viewallmessages().startswith("Messaging is disabled")

        self.log.info("Expiry is decided at query time")
        alerts = self.messages(n0, "NEWS~ALERTS")
        assert_equal([(m["txid"], m["authority"], m["expire_time"], m["expired"]) for m in alerts],
                     [(txid2, "channel", expire, False)])
        assert_equal(self.messages(n0, "NEWS~ALERTS", reference_time=expire), [])
        assert_equal(self.messages(n0, "NEWS~ALERTS", reference_time=expire, include_expired=True)[0]["expired"], True)

        self.log.info("Proofs and raw transactions")
        for message in self.messages(n0, "NEWS!", include_tx=True, include_proof=True):
            assert_equal(n0.verifytxoutproof(message["proof"]), [message["txid"]])
            assert_equal(n0.decoderawtransaction(message["tx"])["txid"], message["txid"])

        self.log.info("REST answers like the RPC")
        url = urlparse(n0.url)
        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.request('GET', '/rest/channelmessages/0/NEWS!.json')
        response = conn.getresponse()
        assert_equal(response.status, 200)
        assert_equal(json.loads(response.read().decode('utf-8'), parse_float=Decimal), n0.getchannelmessages("NEWS!"))

        self.log.info("A message whose block leaves the active chain disappears, and returns when mined again")
        txid4 = n0.sendmessage("NEWS!", "cc" * 32)[0]
        block = n0.generate(1)[0]
        self.sync_all()
        assert txid4 in self.txids(n0, "NEWS!")
        n0.invalidateblock(block)
        assert txid4 not in self.txids(n0, "NEWS!")
        n0.generate(2)
        self.sync_all()
        again = [m for m in self.messages(n0, "NEWS!") if m["txid"] == txid4]
        assert_equal(len(again), 1)
        assert again[0]["block_hash"] != block

        self.log.info("A message sent to another address is not a channel message")
        n0.transfer(asset_name="NEWS~ALERTS", qty=1, to_address=n0.getnewaddress(), message="dd" * 32)
        n0.generate(1)
        self.sync_all()
        assert_equal(self.txids(n0, "NEWS~ALERTS", include_expired=True), [txid2])

        self.log.info("Pages end between blocks and next_from_height resumes them")
        txid5 = n0.sendmessage("NEWS!", "ee" * 32)[0]
        txid6 = n0.sendmessage("NEWS!", "ff" * 32)[0]
        n0.generate(1)
        self.sync_all()
        everything = n0.getchannelmessages("NEWS!")
        assert_equal(everything["next_from_height"], None)
        pages, options = [], {"limit": 1}
        while True:
            page = n0.getchannelmessages("NEWS!", options)
            pages.append([m["txid"] for m in page["messages"]])
            if page["next_from_height"] is None:
                break
            options["from_height"] = page["next_from_height"]
        assert_equal([txid for page in pages for txid in page], [m["txid"] for m in everything["messages"]])
        # The two messages of the last block stay together, past the limit
        assert_equal(sorted(pages[-1]), sorted([txid5, txid6]))
        assert all(len(page) == 1 for page in pages[:-1])
        assert_raises_rpc_error(-8, "limit must be between", n0.getchannelmessages, "NEWS!", {"limit": 0})

        self.log.info("A node that enables the index later catches up and answers alike")
        self.restart_node(1, ['-channelmessageindex'])
        connect_nodes_bi(self.nodes, 0, 1)
        self.sync_all()
        for channel in ("NEWS!", "NEWS~ALERTS"):
            options = {"include_expired": True, "reference_time": expire}
            assert_equal(n1.getchannelmessages(channel, options), n0.getchannelmessages(channel, options))

        self.log.info("A restart keeps the index")
        before = n0.getchannelmessages("NEWS!")
        self.restart_node(0, ['-channelmessageindex', '-txindex'])
        assert_equal(self.nodes[0].getchannelmessages("NEWS!"), before)


if __name__ == '__main__':
    ChannelMessageIndexTest().main()
