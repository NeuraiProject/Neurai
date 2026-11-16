#!/usr/bin/env python3
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Copyright (c) 2017-2020 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Test BIP65 (CHECKLOCKTIMEVERIFY).

On this chain BIP65 is enforced from genesis: blocks must be version 4 or
later, and a block with a transaction that fails CHECKLOCKTIMEVERIFY is
invalid at any height.
"""

from io import BytesIO
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import p2p_port, assert_equal
from test_framework.mininode import to_hex, CTransaction, hex_str_to_bytes, NodeConn, NodeConnCB, NetworkThread, MsgBlock, wait_until, mininode_lock, MsgTx
from test_framework.blocktools import create_coinbase, create_block
from test_framework.script import CScript, OP_1NEGATE, OP_CHECKLOCKTIMEVERIFY, OP_DROP, CScriptNum

CLTV_HEIGHT = 1351

# Reject codes that we might receive in this test
REJECT_INVALID = 16
REJECT_OBSOLETE = 17
REJECT_NONSTANDARD = 64

def cltv_invalidate(tx):
    """Modify the signature in vin 0 of the tx to fail CLTV

    Prepends -1 CLTV DROP in the scriptSig itself.

    TODO: test more ways that transactions using CLTV could be invalid (eg
    locktime requirements fail, sequence time requirements fail, etc).
    """
    tx.vin[0].scriptSig = CScript([OP_1NEGATE, OP_CHECKLOCKTIMEVERIFY, OP_DROP] +
                                  list(CScript(tx.vin[0].scriptSig)))

def cltv_validate(node, tx, height):
    """Modify the signature in vin 0 of the tx to pass CLTV
    Prepends <height> CLTV DROP in the scriptSig, and sets
    the locktime to height"""
    tx.vin[0].nSequence = 0
    tx.nLockTime = height

    # Need to re-sign, since nSequence and nLockTime changed
    signed_result = node.signrawtransaction(to_hex(tx))
    new_tx = CTransaction()
    new_tx.deserialize(BytesIO(hex_str_to_bytes(signed_result['hex'])))

    new_tx.vin[0].scriptSig = CScript([CScriptNum(height), OP_CHECKLOCKTIMEVERIFY, OP_DROP] +
                                  list(CScript(new_tx.vin[0].scriptSig)))
    return new_tx

def create_transaction(node, coinbase, to_address, amount):
    from_txid = node.getblock(coinbase)['tx'][0]
    inputs = [{ "txid" : from_txid, "vout" : 0}]
    outputs = { to_address : amount }
    rawtx = node.createrawtransaction(inputs, outputs)
    signresult = node.signrawtransaction(rawtx)
    tx = CTransaction()
    tx.deserialize(BytesIO(hex_str_to_bytes(signresult['hex'])))
    return tx

class BIP65Test(NeuraiTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [['-acceptnonstdtxn=1', '-whitelist=127.0.0.1']]
        self.setup_clean_chain = True

    def run_test(self):
        node0 = NodeConnCB()
        connections = [NodeConn('127.0.0.1', p2p_port(0), self.nodes[0], node0)]
        node0.add_connection(connections[0])

        NetworkThread().start() # Start up network handling in another thread

        # wait_for_verack ensures that the P2P connection is fully up.
        node0.wait_for_verack()

        self.log.info("Mining %d blocks", CLTV_HEIGHT - 2)
        self.coinbase_blocks = self.nodes[0].generate(CLTV_HEIGHT - 2)
        self.nodeaddress = self.nodes[0].getnewaddress()

        self.log.info("Test that blocks must be at least version 4")
        tip = self.nodes[0].getbestblockhash()
        tip_header = self.nodes[0].getblock(tip)
        block_time = tip_header['time'] + 1
        block = create_block(int(tip, 16), create_coinbase(CLTV_HEIGHT - 1), block_time)
        block.nVersion = 3
        block.nBits = int(tip_header['bits'], 16)
        block.solve()
        node0.send_and_ping(MsgBlock(block))
        assert_equal(self.nodes[0].getbestblockhash(), tip)
        tip = int(tip, 16)

        wait_until(lambda: "reject" in node0.last_message.keys(), lock=mininode_lock, err_msg="last_message")
        with mininode_lock:
            assert_equal(node0.last_message["reject"].code, REJECT_OBSOLETE)
            assert_equal(node0.last_message["reject"].reason, b'bad-version(0x00000003)')
            assert_equal(node0.last_message["reject"].data, block.sha256)
            del node0.last_message["reject"]

        self.log.info("Test that invalid-according-to-cltv transactions cannot appear in a block")
        block.nVersion = tip_header['version']

        spendtx = create_transaction(self.nodes[0], self.coinbase_blocks[1],
                self.nodeaddress, 1.0)
        cltv_invalidate(spendtx)
        spendtx.rehash()

        # The mempool applies BIP65 as a consensus rule: it refuses the
        # transaction for its script (-acceptnonstdtxn lets its non-push-only scriptSig reach the script check).
        result = self.nodes[0].testmempoolaccept([to_hex(spendtx)], True)[0]  # the coinbase pays a high fee
        assert not result['allowed']
        assert 'Negative locktime' in result['reject-reason'], result

        # Now we verify that a block with this transaction is invalid.
        block.vtx.append(spendtx)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()

        node0.send_and_ping(MsgBlock(block))
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), tip)

        wait_until(lambda: "reject" in node0.last_message.keys(), lock=mininode_lock, err_msg="last_message")
        with mininode_lock:
            assert node0.last_message["reject"].code in [REJECT_INVALID, REJECT_NONSTANDARD]
            assert_equal(node0.last_message["reject"].data, block.sha256)
            if node0.last_message["reject"].code == REJECT_INVALID:
                # Generic rejection when a block is invalid
                assert_equal(node0.last_message["reject"].reason, b'block-validation-failed')
            else:
                assert b'Negative locktime' in node0.last_message["reject"].reason

        self.log.info("Test that a block with a valid-according-to-CLTV transaction is accepted")
        # The block is at height CLTV_HEIGHT - 1: a lock time of the tip's height
        # is final there and satisfies the CHECKLOCKTIMEVERIFY.
        spendtx = cltv_validate(self.nodes[0], spendtx, CLTV_HEIGHT - 2)
        spendtx.rehash()

        block.vtx.pop(1)
        block.vtx.append(spendtx)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.solve()

        node0.send_and_ping(MsgBlock(block))
        assert_equal(int(self.nodes[0].getbestblockhash(), 16), block.sha256)


if __name__ == '__main__':
    BIP65Test().main()
