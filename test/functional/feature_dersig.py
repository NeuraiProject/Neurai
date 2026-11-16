#!/usr/bin/env python3
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Copyright (c) 2017-2020 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Test BIP66 (DER SIG).

On this chain BIP66 is enforced from genesis: blocks must be version 3 or
later, and a block with a non-DER signature is invalid at any height.
"""

from io import BytesIO
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import p2p_port, assert_equal, hex_str_to_bytes
from test_framework.mininode import to_hex, CTransaction, NodeConnCB, NodeConn, NetworkThread, MsgBlock, wait_until, mininode_lock, MsgTx
from test_framework.blocktools import create_coinbase, create_block
from test_framework.script import CScript

DERSIG_HEIGHT = 1251

# Reject codes that we might receive in this test
REJECT_INVALID = 16
REJECT_OBSOLETE = 17
REJECT_NONSTANDARD = 64

# A canonical signature consists of:
# <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
def un_der_ify(tx):
    """
    Make the signature in vin 0 of a tx non-DER-compliant,
    by adding padding after the S-value.
    """
    script_sig = CScript(tx.vin[0].scriptSig)
    newscript = []
    for i in script_sig:
        if len(newscript) == 0:
            newscript.append(i[0:-1] + b'\0' + i[-1:])
        else:
            newscript.append(i)
    tx.vin[0].scriptSig = CScript(newscript)

def create_transaction(node, coinbase, to_address, amount):
    from_txid = node.getblock(coinbase)['tx'][0]
    inputs = [{ "txid" : from_txid, "vout" : 0}]
    outputs = { to_address : amount }
    rawtx = node.createrawtransaction(inputs, outputs)
    signresult = node.signrawtransaction(rawtx)
    tx = CTransaction()
    tx.deserialize(BytesIO(hex_str_to_bytes(signresult['hex'])))
    return tx

class BIP66Test(NeuraiTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [['-whitelist=127.0.0.1']]
        self.setup_clean_chain = True

    def run_test(self):
        node0 = NodeConnCB()
        connections = [NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], node0)]
        node0.add_connection(connections[0])
        NetworkThread().start() # Start up network handling in another thread

        # wait_for_verack ensures that the P2P connection is fully up.
        node0.wait_for_verack()

        self.log.info("Mining %d blocks", DERSIG_HEIGHT - 2)
        self.coinbase_blocks = self.nodes[0].generate(DERSIG_HEIGHT - 2)
        self.nodeaddress = self.nodes[0].getnewaddress()

        self.log.info("Test that blocks must be at least version 3")
        tip = self.nodes[0].getbestblockhash()
        tip_header = self.nodes[0].getblock(tip)
        block_time = tip_header['time'] + 1
        block = create_block(int(tip, 16), create_coinbase(DERSIG_HEIGHT - 1), block_time)
        block.nVersion = 2
        block.nBits = int(tip_header['bits'], 16)
        block.rehash()
        block.solve()
        node0.send_and_ping(MsgBlock(block))
        assert_equal(self.nodes[0].getbestblockhash(), tip)
        tip = int(tip, 16)

        wait_until(lambda: "reject" in node0.last_message.keys(), lock=mininode_lock, err_msg="last_message")
        with mininode_lock:
            assert_equal(node0.last_message["reject"].code, REJECT_OBSOLETE)
            assert_equal(node0.last_message["reject"].reason, b'bad-version(0x00000002)')
            assert_equal(node0.last_message["reject"].data, block.sha256)
            del node0.last_message["reject"]

        self.log.info("Test that transactions with non-DER signatures cannot appear in a block")
        block.nVersion = tip_header['version']

        spendtx = create_transaction(self.nodes[0], self.coinbase_blocks[1], self.nodeaddress, 1.0)
        un_der_ify(spendtx)
        spendtx.rehash()

        # The mempool applies BIP66 as a consensus rule: it refuses the
        # transaction for its script.
        result = self.nodes[0].testmempoolaccept([to_hex(spendtx)], True)[0]  # the coinbase pays a high fee
        assert not result['allowed']
        assert 'Non-canonical DER signature' in result['reject-reason'], result

        # Now we verify that a block with this transaction is invalid.
        block.vtx.append(spendtx)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.rehash()
        block.solve()

        node0.send_and_ping(MsgBlock(block))
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), tip)

        wait_until(lambda: "reject" in node0.last_message.keys(), lock=mininode_lock, err_msg="last_message")
        with mininode_lock:
            # We can receive different reject messages depending on whether
            # neuraid is running with multiple script check threads. If script
            # check threads are not in use, then transaction script validation
            # happens sequentially, and neuraid produces more specific reject
            # reasons.
            assert node0.last_message["reject"].code in [REJECT_INVALID, REJECT_NONSTANDARD]
            assert_equal(node0.last_message["reject"].data, block.sha256)
            if node0.last_message["reject"].code == REJECT_INVALID:
                # Generic rejection when a block is invalid
                assert_equal(node0.last_message["reject"].reason, b'block-validation-failed')
            else:
                assert b'Non-canonical DER signature' in node0.last_message["reject"].reason

        self.log.info("Test that a block with a DERSIG-compliant transaction is accepted")
        block.vtx[1] = create_transaction(self.nodes[0],
                self.coinbase_blocks[1], self.nodeaddress, 1.0)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.rehash()
        block.solve()

        node0.send_and_ping(MsgBlock(block))
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block.sha256)

if __name__ == '__main__':
    BIP66Test().main()
