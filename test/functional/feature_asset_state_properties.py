#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

"""
Properties of the asset state under random operations.

Random asset operations of every kind (issues, reissues, transfers, tags,
restrictions, verifier strings, DEPIN freezes, self-revocations and transfer
states) are confirmed in random blocks, on one chain or on two competing
branches. Whatever the path a node followed to a block, its asset state must
be the state of that block:

- every node at the same tip reports the same state, with or without the
  asset index, with a different mempool, and after a reorganisation;
- disconnecting blocks brings back the state the node had before them, and
  connecting them again the state it had after them;
- a node stopped in the middle of a flush, or killed, recovers that state;
- a node that only ever connected the final chain reports it too;
- every block template is valid: `generate` never fails, and the nodes run
  the mempool consistency checks that regtest enables by default.

The sequence is drawn from a seed. ASSET_PROPERTY_SEED and
ASSET_PROPERTY_ROUNDS change it, ASSET_PROPERTY_HOLDER the address type of the
holder wallet (legacy, ecdsa or pq). Wallets choose their own coins, so a seed
gives the same kind of sequence and not the same transactions.
"""

import itertools
import os
import random
import shutil
import time
from collections import Counter

from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import NeuraiTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, connect_nodes_bi, disconnect_nodes

SEED = int(os.environ.get('ASSET_PROPERTY_SEED', '20261114'))
ROUNDS = int(os.environ.get('ASSET_PROPERTY_ROUNDS', '10'))
HOLDER_TYPE = os.environ.get('ASSET_PROPERTY_HOLDER', 'legacy')
# Fields left out of the comparisons, to look past a known difference
IGNORED = set(filter(None, os.environ.get('ASSET_PROPERTY_IGNORE', '').split(',')))

# Nodes
OWNER = 0    # wallet with the owner tokens; asset and public key indexes
TWIN = 1     # a copy of the owner's wallet: it signs conflicting operations on another branch
HOLDER = 2   # wallet that holds units
CHECKED = 3  # no wallet activity: its blocks are disconnected, and it is stopped in the middle of flushes
BARE = 4     # no wallet activity and no index
FRESH = 5    # started at the end: it only ever connects the final chain
INDEXED = (OWNER, TWIN, HOLDER, CHECKED, FRESH)

PLAIN = ["ALPHA", "BETA"]
TAGS = ["#KYC", "#GOLD"]
RESTRICTED = ["$ALPHA", "$BETA"]
DEPIN = ["&GRID", "&MESH", "&SEAL"]
VERIFIERS = ["true", "#KYC", "#GOLD", "#KYC&#GOLD", "#KYC|#GOLD"]
IPFS = ["QmcvyefkqQX3PpjpY5L8B2yMd47XrVwAipr6cxUt2zvYU8", "QmacSRmrkVmvJfbCpmU6pK72furJ8E8fbKHindrLxmYMQo"]
RECOVERING = "bringing it to the chain state"


def normalised(value):
    """The same answer with every list in a fixed order."""
    if isinstance(value, dict):
        return {key: normalised(item) for key, item in value.items()}
    if isinstance(value, list):
        return sorted((normalised(item) for item in value), key=repr)
    return value


def differences(a, b, path=""):
    """The places where two states differ, as readable lines."""
    if isinstance(a, dict) and isinstance(b, dict):
        for key in sorted(set(a) | set(b), key=str):
            if key in IGNORED:
                continue
            if key not in a:
                yield "%s[%s]: missing / %r" % (path, key, b[key])
            elif key not in b:
                yield "%s[%s]: %r / missing" % (path, key, a[key])
            else:
                yield from differences(a[key], b[key], "%s[%s]" % (path, key))
    elif a != b:
        yield "%s: %r / %r" % (path, a, b)


class AssetStatePropertiesTest(NeuraiTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 6
        index = ['-assetindex']
        self.extra_args = [index + ['-pubkeyindex'], index + ['-pubkeyindex'],
                           index + ['-addresstype=' + HOLDER_TYPE], index, [], index]

    def setup_network(self):
        self.add_nodes(self.num_nodes, self.extra_args)
        # The twin runs on a copy of the owner's wallet, made before the
        # wallet has seen anything: same keys, same coins, same assets
        self.start_node(OWNER)
        self.stop_node(OWNER)
        twin_dir = os.path.join(self.nodes[TWIN].datadir, "regtest")
        os.makedirs(twin_dir, exist_ok=True)
        shutil.copy(os.path.join(self.nodes[OWNER].datadir, "regtest", "wallet.dat"), twin_dir)
        self.running = [OWNER, TWIN, HOLDER, CHECKED, BARE]
        for n in self.running:
            self.start_node(n)
        self.links = set()
        self.arrange([self.running])

    # ------------------------------------------------------------ connections
    def forget_links(self, n):
        self.links = {link for link in self.links if n not in link}

    def disconnect(self, a, b):
        try:
            disconnect_nodes(self.nodes[a], b)
        except JSONRPCException as e:
            # the other side closed the connection first
            if "Node not found in connected nodes" not in e.error['message']:
                raise

    def arrange(self, groups):
        """Connect the nodes of each group with each other, and with nobody else."""
        group_of = {n: i for i, group in enumerate(groups) for n in group}
        for link in list(self.links):
            a, b = tuple(link)
            if a not in group_of or group_of[a] != group_of.get(b):
                self.disconnect(a, b)
                self.disconnect(b, a)
                self.links.discard(link)
        for group in groups:
            for a, b in itertools.combinations(sorted(group), 2):
                if frozenset((a, b)) not in self.links:
                    connect_nodes_bi(self.nodes, a, b)
                    self.links.add(frozenset((a, b)))

    def same_tip(self, group, timeout=180):
        """Wait until the nodes of the group are at the same block."""
        deadline = time.time() + timeout
        while True:
            tips = {n: self.nodes[n].getbestblockhash() for n in group}
            if len(set(tips.values())) == 1:
                return tips[group[0]]
            if time.time() > deadline:
                for n in group:
                    self.log.error("node %d: height %d, tip %s, chain tips %s", n, self.nodes[n].getblockcount(), tips[n],
                                   [(tip['height'], tip['status']) for tip in self.nodes[n].getchaintips()])
                raise AssertionError("the nodes do not agree on the tip")
            time.sleep(0.05)

    def relayed(self, group, miner, timeout=5):
        """Give the transactions of the group a moment to reach the miner."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            pool = set(self.nodes[miner].getrawmempool())
            if all(set(self.nodes[n].getrawmempool()) <= pool for n in group):
                return
            time.sleep(0.05)

    def mine(self, miner, group):
        """A block from the miner's mempool, which its group follows. The template must be valid."""
        self.relayed(group, miner)
        self.nodes[miner].generate(1)
        self.blocks += 1
        return self.same_tip(group)

    # ------------------------------------------------------------------ state
    def ask(self, method, *args):
        try:
            return method(*args)
        except JSONRPCException as e:
            return "error: " + e.error['message']

    def state(self, n, flush, known=None):
        """The asset state a node reports.

        Without `flush`, only what the node answers from its cache. With it,
        also the listings, which the node reads from its databases after
        writing them: asking for them is a full flush. `known` limits the
        questions to the asset names of an earlier moment."""
        node = self.nodes[n]
        names, depin = known or (sorted(self.names), list(self.depin))
        restrictable = RESTRICTED + depin
        state = {
            'tip': node.getbestblockhash(),
            'asset': {name: self.ask(node.getassetdata, name) for name in names},
            'tag': {"%s %s" % (address, tag): self.ask(node.checkaddresstag, address, tag)
                    for address in self.addresses for tag in TAGS},
            'restriction': {"%s %s" % (address, asset): self.ask(node.checkaddressrestriction, address, asset)
                            for address in self.addresses for asset in restrictable},
            'global': {asset: self.ask(node.checkglobalrestriction, asset) for asset in RESTRICTED},
        }
        if n in INDEXED:
            state['depin (index)'] = {"%s %s" % (asset, address): self.ask(node.checkdepinvalidity, asset, address)
                                      for asset in depin for address in self.addresses}
        if flush:
            state['listed'] = {
                'assets': self.ask(node.listassets, "*", True),
                'global': self.ask(node.listglobalrestrictions),
                'restrictions': {address: self.ask(node.listaddressrestrictions, address) for address in self.addresses},
                'tags': {address: self.ask(node.listtagsforaddress, address) for address in self.addresses},
            }
            if n in INDEXED:
                tokens = names + [name + "!" for name in names]
                state['listed (index)'] = {
                    'holders': {name: self.ask(node.listaddressesbyasset, name) for name in tokens},
                    'balances': {address: self.ask(node.listassetbalancesbyaddress, address) for address in self.addresses},
                    'depin holders': {asset: self.ask(node.listdepinholders, asset) for asset in depin},
                    # the addresses of a tag are only recorded with the asset index
                    'tagged': {tag: self.ask(node.listaddressesfortag, tag) for tag in TAGS},
                }
        return normalised(state)

    def assert_same_state(self, what, a, b):
        """Two states are equal in every part that both hold."""
        found = []
        for part in sorted(set(a) & set(b)):
            found += list(differences(a[part], b[part], part))
        if found:
            self.log.error("%s: %d differences (seed %d, round %d)", what, len(found), SEED, self.round)
            for line in found[:40]:
                self.log.error("  %s", line)
            raise AssertionError("%s: the asset states differ" % what)

    def assert_nodes_agree(self, flushed):
        """Every running node reports the state of the first one; `flushed` also compare their listings."""
        tip = self.same_tip(self.running)
        states = {n: self.state(n, n in flushed) for n in self.running}
        for n in self.running:
            assert_equal(states[n]['tip'], tip)
        # each part of the state, among the nodes that hold it: the listings
        # need a flush and some answers need the asset index
        for part in sorted({part for state in states.values() for part in state}):
            holders = [n for n in self.running if part in states[n]]
            for n in holders[1:]:
                self.assert_same_state("node %d against node %d" % (n, holders[0]),
                                       {part: states[n][part]}, {part: states[holders[0]][part]})
                self.comparisons += 1

    # -------------------------------------------------------------- operations
    def attempt(self, n, kind, method, *args):
        """An operation that the node accepts or refuses. Either is fine: the properties are about the state."""
        try:
            result = getattr(self.nodes[n], method)(*args)
        except JSONRPCException as e:
            self.refused[kind] += 1
            self.log.debug("round %d node %d %s%r refused: %s", self.round, n, method, args, e.error['message'])
            return None
        self.accepted[kind] += 1
        txid = result[0] if isinstance(result, list) else result
        self.sent[n].append(txid)
        self.log.debug("round %d node %d %s%r -> %s", self.round, n, method, args, txid)
        return txid

    def toggled(self, n, check, *args):
        """Whether the node sees a flag set; a node that cannot say counts as not set."""
        return self.ask(getattr(self.nodes[n], check), *args) is True

    def numbered(self, prefix, kind):
        """A name with a small number: often a new one, sometimes one that exists, also on the other branch."""
        number = self.rng.randint(0, self.counters[kind])
        if number == self.counters[kind]:
            self.counters[kind] += 1
        return "%s%d" % (prefix, number)

    def owner_operation(self, n):
        rng = self.rng
        kind = rng.choices(
            ['reissue', 'transfer', 'issue sub-asset', 'issue unique', 'tag', 'freeze address', 'freeze asset',
             'reissue restricted', 'transfer restricted', 'distribute depin', 'freeze depin', 'transfer state',
             'move owner token', 'issue depin section', 'send coins'],
            [10, 10, 4, 3, 10, 8, 3, 8, 6, 10, 12, 8, 4, 3, 3])[0]
        owner, holder, everyone = self.owner_addresses, self.holder_addresses, self.addresses
        if kind == 'reissue':
            asset = rng.choice(PLAIN + self.sub_assets)
            data = self.ask(self.nodes[n].getassetdata, asset)
            units = -1
            if isinstance(data, dict) and data['units'] < 8 and rng.random() < 0.3:
                units = data['units'] + 1
            arguments = [asset, rng.randint(1, 50), rng.choice(owner), "", True, units]
            if rng.random() < 0.3:
                arguments.append(rng.choice(IPFS))
            self.attempt(n, kind, 'reissue', *arguments)
        elif kind == 'transfer':
            self.attempt(n, kind, 'transfer', rng.choice(PLAIN + self.sub_assets), rng.randint(1, 5), rng.choice(everyone))
        elif kind == 'issue sub-asset':
            name = self.numbered(rng.choice(PLAIN) + "/S", kind)
            self.names.add(name)
            if name not in self.sub_assets:
                self.sub_assets.append(name)
            self.attempt(n, kind, 'issue', name, rng.randint(10, 100), rng.choice(owner))
        elif kind == 'issue unique':
            root, tag = rng.choice(PLAIN), self.numbered("U", kind)
            self.names.add("%s#%s" % (root, tag))
            self.attempt(n, kind, 'issueunique', root, [tag])
        elif kind == 'tag':
            # the first owner address keeps its tags: restricted assets are reissued to it
            address, tag = rng.choice(everyone[1:]), rng.choice(TAGS)
            method = 'removetagfromaddress' if self.toggled(n, 'checkaddresstag', address, tag) else 'addtagtoaddress'
            self.attempt(n, kind, method, tag, address)
        elif kind == 'freeze address':
            asset, address = rng.choice(RESTRICTED), rng.choice(everyone[1:])
            method = 'unfreezeaddress' if self.toggled(n, 'checkaddressrestriction', address, asset) else 'freezeaddress'
            self.attempt(n, kind, method, asset, address)
        elif kind == 'freeze asset':
            asset = rng.choice(RESTRICTED)
            method = 'unfreezerestrictedasset' if self.toggled(n, 'checkglobalrestriction', asset) else 'freezerestrictedasset'
            self.attempt(n, kind, method, asset)
        elif kind == 'reissue restricted':
            arguments = [rng.choice(RESTRICTED), rng.randint(1, 20), owner[0]]
            if rng.random() < 0.6:
                arguments += [True, rng.choice(VERIFIERS)]
            self.attempt(n, kind, 'reissuerestrictedasset', *arguments)
        elif kind == 'transfer restricted':
            self.attempt(n, kind, 'transfer', rng.choice(RESTRICTED), rng.randint(1, 3), rng.choice(everyone))
        elif kind == 'distribute depin':
            self.attempt(n, kind, 'transfer', rng.choice(self.depin), rng.randint(1, 3), rng.choice(everyone))
        elif kind == 'freeze depin':
            method = rng.choice(['freezedepin', 'unfreezedepin'])
            self.attempt(n, kind, method, rng.choice(self.depin), rng.choice(holder + owner[1:]))
        elif kind == 'transfer state':
            asset = rng.choice(DEPIN)
            data = self.ask(self.nodes[n].getassetdata, asset)
            is_open = isinstance(data, dict) and data.get('transfer_state') == 'open'
            # mostly the operation the state allows, sometimes one it does not
            method = rng.choices(['closedepin', 'opendepin'] if is_open else ['opendepin', 'closedepin'], [5, 1])[0]
            if asset == "&SEAL" and not is_open and rng.random() < 0.15:
                method = 'sealdepin'
            self.attempt(n, kind, method, asset)
        elif kind == 'move owner token':
            self.attempt(n, kind, 'transfer', rng.choice(PLAIN + DEPIN) + "!", 1, rng.choice(owner))
        elif kind == 'issue depin section':
            name = self.numbered(rng.choice(DEPIN[:2]) + "/SEC", kind)
            self.names.add(name)
            if name not in self.depin:
                self.depin.append(name)
            self.attempt(n, kind, 'issue', name, rng.randint(5, 20), rng.choice(owner))
        else:
            self.attempt(n, kind, 'sendtoaddress', rng.choice(holder), rng.randint(1, 5))

    def holder_operation(self):
        rng = self.rng
        kind = rng.choices(['holder transfer', 'holder depin transfer', 'self-revoke', 'holder restricted transfer'],
                           [10, 10, 5, 6])[0]
        if kind == 'holder transfer':
            self.attempt(HOLDER, kind, 'transfer', rng.choice(PLAIN + self.sub_assets), 1, rng.choice(self.addresses))
        elif kind == 'holder depin transfer':
            # the change goes back to a holder address, never to the keypool
            self.attempt(HOLDER, kind, 'transfer', rng.choice(self.depin), 1, rng.choice(self.addresses),
                         "", 0, "", rng.choice(self.holder_addresses))
        elif kind == 'self-revoke':
            self.attempt(HOLDER, kind, 'selfrevokedepin', rng.choice(self.depin))
        else:
            self.attempt(HOLDER, kind, 'transfer', rng.choice(RESTRICTED), 1, rng.choice(self.addresses),
                         "", 0, "", rng.choice(self.holder_addresses))

    def operations(self, group, owner_node):
        """A few operations from the wallets of a connected group."""
        for _ in range(self.rng.randint(2, 7)):
            if HOLDER in group and (owner_node is None or self.rng.random() < 0.3):
                self.holder_operation()
            elif owner_node is not None:
                self.owner_operation(owner_node)

    def blocks_of(self, group, count):
        """`count` blocks of random operations on the chain of a connected group."""
        owners = [n for n in (OWNER, TWIN) if n in group]
        for _ in range(count):
            # one of the two wallets with the owner keys acts in each block
            self.operations(group, self.rng.choice(owners) if owners else None)
            self.mine(self.rng.choice(owners), group)

    def release_stuck_transactions(self):
        """Let the wallets forget the transactions that no mempool holds after a reorganisation."""
        for n in (OWNER, TWIN, HOLDER):
            pool = set(self.nodes[n].getrawmempool())
            pending = []
            for txid in self.sent[n]:
                details = self.ask(self.nodes[n].gettransaction, txid)
                if not isinstance(details, dict) or details['confirmations'] != 0:
                    continue  # confirmed, or in conflict with the chain
                if txid in pool:
                    pending.append(txid)
                else:
                    self.ask(self.nodes[n].abandontransaction, txid)
            self.sent[n] = pending

    # ----------------------------------------------------------- checked node
    def log_size(self):
        return os.path.getsize(os.path.join(self.nodes[CHECKED].datadir, "regtest", "debug.log"))

    def log_since(self, offset):
        with open(os.path.join(self.nodes[CHECKED].datadir, "regtest", "debug.log"), errors="replace") as log:
            log.seek(offset)
            return log.read()

    def restart_checked(self, extra_args):
        self.stop_node(CHECKED)
        self.forget_links(CHECKED)
        self.start_node(CHECKED, self.extra_args[CHECKED] + extra_args)

    def stop_checked_abruptly(self, how):
        """Stop the checked node at the armed point of a flush, or kill it."""
        node = self.nodes[CHECKED]
        self.forget_links(CHECKED)
        if how == 'kill':
            node.process.kill()
            node.process.wait(timeout=60)
            node.running = False
            node.process = None
            node.rpc_connected = False
            return
        try:
            node.gettxoutsetinfo()  # a full flush, which the armed point interrupts
        except Exception:  # pylint: disable=broad-except
            pass
        node.wait_until_stopped()

    def recover_checked(self, how, interrupted):
        """Start the checked node again after an abrupt stop."""
        node = self.nodes[CHECKED]
        offset = self.log_size()
        if interrupted:
            # ...stopping it once more, while it brings its asset state forward
            node.start(self.extra_args[CHECKED] + ['-assetflushcrashpoint=3'])
            node.wait_until_stopped()
            self.recoveries['interrupted'] += 1
        self.start_node(CHECKED, self.extra_args[CHECKED])
        log = self.log_since(offset)
        assert "cannot be brought to it" not in log, "the checked node could not recover its asset state"
        if how in ('flush point 1', 'flush point 2'):
            # in one start or the other: an interrupted recovery may have had one block to apply
            assert RECOVERING in log, "the checked node did not recover its asset state"
        self.recoveries[how] += 1

    def undo_and_redo(self, before, known, flush_first):
        """Disconnect the blocks of the round from the checked node, and connect them again.

        `before` is its state before the round and `known` the asset names of that moment."""
        node = self.nodes[CHECKED]
        self.arrange([[n for n in self.running if n != CHECKED]])
        after = self.state(CHECKED, flush_first)
        height = node.getblockheader(before['tip'])['height']
        count = node.getblockcount() - height
        invalidated = []
        while node.getblockcount() > height:
            # also the branches the node saw and left: without them it would move to one
            invalidated.append(node.getblockhash(height + 1))
            node.invalidateblock(invalidated[-1])
        self.assert_same_state("checked node after disconnecting %d blocks" % count,
                               self.state(CHECKED, 'listed' in before, known), before)
        for name in sorted(self.names - set(known[0])):
            # issued in the round, if at all
            assert_equal(node.getassetdata(name), None)
        for block in reversed(invalidated):
            node.reconsiderblock(block)
        deadline = time.time() + 120
        while node.getbestblockhash() != after['tip']:
            assert time.time() < deadline, "the checked node did not connect its blocks again"
            time.sleep(0.05)
        self.assert_same_state("checked node after connecting the blocks again", self.state(CHECKED, flush_first), after)
        self.undone += 1

    # ------------------------------------------------------------------ steps
    def setup_assets(self):
        self.log.info("Issuing plain, restricted, qualifier and DEPIN assets and handing them out (seed %d)...", SEED)
        owner, holder = self.nodes[OWNER], self.nodes[HOLDER]
        everyone = self.running
        self.rng = random.Random(SEED)
        self.round = 0
        self.blocks = self.comparisons = self.undone = 0
        self.accepted, self.refused, self.recoveries, self.counters = Counter(), Counter(), Counter(), Counter()
        self.sent = {OWNER: [], TWIN: [], HOLDER: []}
        self.sub_assets = []
        self.depin = list(DEPIN)
        self.names = set(PLAIN + TAGS + RESTRICTED + DEPIN)

        owner.generate(432)
        self.same_tip(everyone)
        self.owner_addresses = [owner.getnewaddress() for _ in range(4)]
        self.holder_addresses = [holder.getnewaddress() for _ in range(5)]
        self.addresses = self.owner_addresses + self.holder_addresses
        for address in self.holder_addresses:
            owner.sendtoaddress(address, 200)
        for asset in PLAIN:
            owner.issue(asset, 1000, self.owner_addresses[0])
        for tag in TAGS:
            owner.issuequalifierasset(tag, 10)
        for asset in DEPIN:
            owner.issue(asset, 100, self.owner_addresses[0])
        self.mine(OWNER, everyone)
        for tag in TAGS:
            owner.addtagtoaddress(tag, self.owner_addresses[0])
        self.mine(OWNER, everyone)
        for asset in RESTRICTED:
            owner.issuerestrictedasset(asset, 100, "true", self.owner_addresses[0])
        self.mine(OWNER, everyone)
        for address in self.holder_addresses:
            owner.transfer(self.rng.choice(PLAIN), 20, address)
            owner.transfer(self.rng.choice(DEPIN), 5, address)
            owner.transfer(self.rng.choice(RESTRICTED), 5, address)
            self.mine(OWNER, everyone)
        self.assert_nodes_agree(set(everyone))
        # The one listing that needs the asset index says so on a node without it
        assert_raises_rpc_error(-1, "requires -assetindex", self.nodes[BARE].listaddressesfortag, TAGS[0])
        assert_equal(self.nodes[OWNER].listaddressesfortag(TAGS[0]), [self.owner_addresses[0]])

    def one_round(self):
        rng = self.rng
        everyone = self.running
        start = self.nodes[OWNER].getblockcount()
        fork = rng.random() < 0.5
        on_checked = rng.choices(['nothing', 'undo', 'flush point 1', 'flush point 2', 'coins flush', 'kill'],
                                 [2, 5, 3, 3, 2, 1])[0]

        # Two branches from here, or one chain
        if fork:
            others = [HOLDER, CHECKED, BARE]
            rng.shuffle(others)
            cut = rng.randint(0, len(others))
            sides = [[OWNER] + others[:cut], [TWIN] + others[cut:]]
            lengths = rng.sample(range(1, 5), 2)
        else:
            sides = [list(everyone)]
            lengths = [rng.randint(1, 4)]
        end = start + max(lengths)
        own_side = next(side for side in sides if CHECKED in side)
        own_length = lengths[sides.index(own_side)]
        self.log.info("Round %d from height %d: %s; checked node: %s", self.round, start,
                      " against ".join("%d blocks on %s" % (length, side) for length, side in zip(lengths, sides)), on_checked)

        # The checked node: its state before the round, or the point at which it will stop
        before = known = None
        flush_first = rng.random() < 0.5
        if on_checked == 'undo':
            known = (sorted(self.names), list(self.depin))
            before = self.state(CHECKED, rng.random() < 0.5, known)
        elif on_checked in ('flush point 1', 'flush point 2'):
            self.restart_checked(['-assetflushcrashpoint=' + on_checked[-1], '-assetflushcrashheight=%d' % end])
        elif on_checked == 'coins flush':
            self.restart_checked(['-dbcrashratio=1', '-dbbatchsize=1'])

        self.arrange(sides)
        for side, length in zip(sides, lengths):
            self.blocks_of(side, length)
        if fork and on_checked.startswith('flush point') and own_length < max(lengths) and flush_first:
            # every database of the checked node is written on the branch that is about to lose
            self.nodes[CHECKED].gettxoutsetinfo()

        # One chain again: the shorter branch is disconnected, and its
        # operations go back to the mempools that still accept them
        self.arrange([everyone])
        tip = self.same_tip(everyone)
        assert_equal(self.nodes[OWNER].getblockcount(), end)
        if fork:
            self.reorganisations += 1

        if on_checked == 'undo':
            self.undo_and_redo(before, known, flush_first)
        elif on_checked != 'nothing':
            self.stop_checked_abruptly(on_checked)
            self.recover_checked(on_checked, interrupted=on_checked == 'flush point 1' and rng.random() < 0.4)
        self.arrange([everyone])
        assert_equal(self.same_tip(everyone), tip)

        # The next blocks carry what came back from the losing branch, from either miner
        self.release_stuck_transactions()
        for _ in range(rng.randint(1, 2)):
            self.mine(rng.choice([OWNER, TWIN]), everyone)
        flushed = {n for n in everyone if rng.random() < 0.5}
        if on_checked not in ('nothing', 'undo'):
            flushed |= {CHECKED, OWNER}
        self.assert_nodes_agree(flushed)

    def final_chain_only(self):
        self.log.info("A node that only ever connects the final chain reports the same state...")
        everyone = self.running
        for _ in range(2):
            self.mine(OWNER, everyone)
        self.start_node(FRESH)
        self.running = everyone + [FRESH]
        self.arrange([self.running])
        self.same_tip(self.running, timeout=600)
        self.assert_nodes_agree(set(self.running))
        # Level 3 undoes the last blocks in memory. Level 4, which connects them
        # again, is left out: it undoes every block into one cache, where the
        # undo of an older change does not replace the undo of a newer change
        # of the same state, and it can refuse a valid block (doc/depin-assets.md).
        for n in (FRESH, CHECKED):
            assert self.nodes[n].verifychain(3, 50)
        self.assert_nodes_agree(set(self.running))

    def run_test(self):
        self.reorganisations = 0
        self.setup_assets()
        for self.round in range(1, ROUNDS + 1):
            self.one_round()
        self.final_chain_only()

        kinds = sorted(set(self.accepted) | set(self.refused))
        self.log.info("RESULT seed=%d rounds=%d blocks=%d reorganisations=%d undone=%d recoveries=%s comparisons=%d",
                      SEED, ROUNDS, self.blocks, self.reorganisations, self.undone, dict(self.recoveries), self.comparisons)
        self.log.info("RESULT operations accepted/refused: %s",
                      ", ".join("%s %d/%d" % (kind, self.accepted[kind], self.refused[kind]) for kind in kinds))
        # A run that changes little proves little
        assert sum(self.accepted.values()) >= 4 * ROUNDS, "too few operations were accepted"
        assert len([kind for kind in kinds if self.accepted[kind]]) >= 10, "too few kinds of operation were accepted"


if __name__ == '__main__':
    AssetStatePropertiesTest().main()
