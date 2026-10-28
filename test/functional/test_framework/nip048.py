#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Independent reference of NIP-048 distribution plans.

The node only computes plans (getdistributionplan); a wallet pays them. These
helpers recompute everything a plan commits to from public data, so a test
proves that the format can be verified outside the node:

- snapshot hash: tag 0x03 || asset || height (int32) || block hash (internal
  byte order) || count || (script, held int64) sorted by script bytes
- leaf: tag 0x00 || script || amount (int64); inner node: tag 0x01 || left || right
- Merkle root: RFC 6962 split, SHA-256 of the empty string for no leaves
- plan hash: tag 0x02 || version (uint8) || network || asset || height ||
  block hash || snapshot hash || [announcement txid, version 2 only] ||
  distribution asset || amount || policy (uint8) || exclusions || distributed
  || remainder || leaf count (uint32) || root
- announcement: tag 0x05 || network || asset || height, carried as the
  message of an owner token transfer before the snapshot height
- snapshot with holder state (format 2, D3): tag 0x06 || asset || height ||
  block hash || global freeze (uint8) || count || (script, held, flags (uint8:
  1 frozen, 2 self-revoked), sorted tags) sorted by script
- report: tag 0x07 || count || (address, weight int64) sorted by address
- plan version 3 (qualifier or report): after the snapshot hash, the
  announcement txid (zero if none), the qualifier and the report hash (zero if
  none)
- plan version 4 (equal allocation or minimum holding): after the version 3
  fields, the allocation (uint8: 0 holdings, 1 equal) and the minimum holding
  (int64, 0 if none)

Strings and scripts carry a compact-size length; integers are little endian.
"""

from decimal import Decimal
import hashlib
import struct

from .util import assert_equal

COIN = 100000000
POLICIES = {"payer": 0, "largest": 1}
ALLOCATIONS = {"holdings": 0, "equal": 1}


def _compact_size(n):
    if n < 253:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    if n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)


def _ser(data):
    return _compact_size(len(data)) + data


def _tagged(tag, data):
    return hashlib.sha256(bytes([tag]) + data).digest()


def leaf_hash(script, amount):
    return _tagged(0x00, _ser(script) + struct.pack('<q', amount))


def merkle_root(hashes):
    if not hashes:
        return hashlib.sha256(b'').digest()
    if len(hashes) == 1:
        return hashes[0]
    split = 1
    while split * 2 < len(hashes):
        split *= 2
    return _tagged(0x01, merkle_root(hashes[:split]) + merkle_root(hashes[split:]))


def merkle_path(hashes, index):
    """RFC 6962 audit path of the leaf at index, deepest sibling first."""
    if len(hashes) <= 1:
        return []
    split = 1
    while split * 2 < len(hashes):
        split *= 2
    if index < split:
        return merkle_path(hashes[:split], index) + [merkle_root(hashes[split:])]
    return merkle_path(hashes[split:], index - split) + [merkle_root(hashes[:split])]


def batch_id(plan_hash_bytes, max_outputs, index):
    return _tagged(0x04, plan_hash_bytes + struct.pack('<I', max_outputs) + struct.pack('<I', index))


def allocate(holdings, amount, unit, policy):
    """holdings: (script, weight) sorted by script. Returns (amounts, remainder)
    in satoshis: floor(A * w / W) in whole units, the remainder by policy."""
    total = sum(weight for _, weight in holdings)
    units = amount // unit
    shares = [units * weight // total for _, weight in holdings]
    left = units - sum(shares)
    if policy == POLICIES['largest'] and left:
        fractions = [units * weight % total for _, weight in holdings]
        for i in sorted(range(len(holdings)), key=lambda i: (-fractions[i], holdings[i][0]))[:left]:
            shares[i] += 1
        left = 0
    return [share * unit for share in shares], left * unit


def verify_inclusion(leaf, index, count, path, root):
    """RFC 9162 section 2.1.3.2 inclusion check."""
    if index >= count:
        return False
    fn, sn, r = index, count - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = _tagged(0x01, p + r)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = _tagged(0x01, r + p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_proof(proof, plan):
    """Check a getdistributionproof result against a plan, from its fields alone."""
    assert_equal(proof['plan_hash'], plan['plan_hash'])
    assert_equal(proof['merkle_root'], plan['merkle_root'])
    leaf = leaf_hash(bytes.fromhex(proof['script']), _sat(proof['amount']))
    assert_equal(proof['leaf_hash'], leaf.hex())
    path = [bytes.fromhex(p) for p in proof['path']]
    assert verify_inclusion(leaf, proof['index'], proof['leaf_count'], path, bytes.fromhex(plan['merkle_root']))


def snapshot_hash(asset, height, block_hash, holdings):
    data = _ser(asset.encode()) + struct.pack('<i', height) + block_hash + _compact_size(len(holdings))
    for script, held in holdings:
        data += _ser(script) + struct.pack('<q', held)
    return _tagged(0x03, data)


def announcement_hash(network, asset, height):
    return _tagged(0x05, _ser(network.encode()) + _ser(asset.encode()) + struct.pack('<i', height))


def snapshot_hash_v2(asset, height, block_hash, global_frozen, holdings):
    """holdings: (script, held, flags, tags), sorted by script."""
    data = _ser(asset.encode()) + struct.pack('<i', height) + block_hash + bytes([1 if global_frozen else 0])
    data += _compact_size(len(holdings))
    for script, held, flags, tags in holdings:
        data += _ser(script) + struct.pack('<q', held) + bytes([flags]) + _compact_size(len(tags))
        for tag in sorted(tags):
            data += _ser(tag.encode())
    return _tagged(0x06, data)


def report_hash(weights):
    data = _compact_size(len(weights))
    for address in sorted(weights, key=lambda a: a.encode()):
        data += _ser(address.encode()) + struct.pack('<q', weights[address])
    return _tagged(0x07, data)


def plan_hash(version, network, asset, height, block_hash, snap_hash, dist_asset, amount, policy,
              exclusions, distributed, remainder, leaf_count, root, announcement=None, qualifier=None,
              report=None, allocation=0, min_held=0):
    data = bytes([version]) + _ser(network.encode()) + _ser(asset.encode()) + struct.pack('<i', height)
    data += block_hash + snap_hash
    if version >= 2:
        data += announcement or bytes(32)
    if version >= 3:
        data += _ser((qualifier or "").encode()) + (report or bytes(32))
    if version >= 4:
        data += bytes([allocation]) + struct.pack('<q', min_held)
    data += _ser(dist_asset.encode()) + struct.pack('<q', amount) + bytes([policy])
    data += _compact_size(len(exclusions))
    for address in exclusions:
        data += _ser(address.encode())
    data += struct.pack('<q', distributed) + struct.pack('<q', remainder) + struct.pack('<I', leaf_count) + root
    return _tagged(0x02, data)


def _sat(value):
    return int(Decimal(value) * COIN)


def _script(node, address):
    return bytes.fromhex(node.validateaddress(address)['scriptPubKey'])


def _unit(node, asset):
    if asset == "XNA":
        return 1
    return 10 ** (8 - node.getassetdata(asset)['units'])


def verify_plan(node, plan, weights=None):
    """Recompute a getdistributionplan result from the snapshot and check every
    commitment; `weights` are the report weights the plan was given, if any."""
    snap = plan['snapshot']
    block_hash = bytes.fromhex(snap['block_hash'])[::-1] if snap['block_hash'] else bytes(32)

    # Snapshot hash over every holder in the snapshot, with holder state in format 2
    stored = node.getsnapshot(snap['asset_name'], snap['height'])
    owners = {o['address']: o for o in stored['owners']}
    if stored['format'] == 2:
        holdings = sorted((_script(node, o['address']), _sat(o['amount_owned']),
                           (1 if o['frozen'] else 0) | (2 if o['self_revoked'] else 0), o['tags'])
                          for o in owners.values())
        snap_hash = snapshot_hash_v2(snap['asset_name'], snap['height'], block_hash, stored['global_frozen'], holdings)
    else:
        holdings = sorted((_script(node, o['address']), _sat(o['amount_owned'])) for o in owners.values())
        snap_hash = snapshot_hash(snap['asset_name'], snap['height'], block_hash, holdings)
    assert_equal(snap['snapshot_hash'], snap_hash.hex())

    # Eligibility: every holder is a recipient, has a zero share or is excluded
    # for a reason the snapshot or the parameters confirm
    placed = [r['address'] for r in plan['recipients']] + [z['address'] for z in plan['zero_amount']]
    excluded = {e['address']: e['reason'] for e in plan['excluded']}
    assert_equal(sorted(placed + list(excluded)), sorted(owners))
    min_held = _sat(plan['min_held'])
    for address in placed:
        owner = owners[address]
        if stored['format'] == 2:
            assert not stored['global_frozen'] and not owner['frozen'] and not owner['self_revoked']
            if plan['qualifier']:
                assert plan['qualifier'] in owner['tags']
        assert address not in plan['exception_addresses']
        assert _sat(owner['amount_owned']) >= min_held
    for address, reason in excluded.items():
        owner = owners[address]
        if reason == 'exception':
            assert address in plan['exception_addresses']
        elif reason == 'globally_frozen':
            assert stored['global_frozen']
        elif reason in ('frozen', 'self_revoked'):
            assert owner[reason]
        elif reason == 'missing_qualifier':
            assert plan['qualifier'] not in owner['tags']
        elif reason == 'below_minimum':
            assert _sat(owner['amount_owned']) < min_held
        else:
            assert reason in ('burn', 'no_weight'), reason

    # Allocation: floor(A * w / W) in whole units, remainder by policy; w is the
    # holding, the report weight, or 1 for equal shares
    allocation = ALLOCATIONS[plan['allocation']]
    policy = POLICIES[plan['remainder_policy']]
    unit = _unit(node, plan['distribution_asset_name'])
    if allocation == ALLOCATIONS['equal']:
        assert plan['report'] is None

    def weight_of(entry):
        if allocation == ALLOCATIONS['equal']:
            return 1
        return entry['weight'] if plan['report'] is not None else _sat(entry['held'])
    eligible = sorted([(_script(node, r['address']), weight_of(r)) for r in plan['recipients']] +
                      [(_script(node, z['address']), weight_of(z)) for z in plan['zero_amount']])
    amounts, remainder = allocate(eligible, _sat(plan['amount']), unit, policy)
    expected = [(script, amount) for (script, _), amount in zip(eligible, amounts) if amount]
    leaves = [(bytes.fromhex(r['script']), _sat(r['amount'])) for r in plan['recipients']]
    assert_equal(leaves, expected)
    assert_equal(_sat(plan['remainder']), remainder)
    assert_equal(_sat(plan['distributed']), sum(amount for _, amount in leaves))

    # Merkle root and plan hash
    root = merkle_root([leaf_hash(script, amount) for script, amount in leaves])
    assert_equal(plan['merkle_root'], root.hex())
    announcement = None
    if plan['announcement'] is not None:
        announcement = bytes.fromhex(plan['announcement']['txid'])[::-1]
    report = bytes.fromhex(plan['report']['hash']) if plan['report'] is not None else None
    if allocation or min_held:
        assert_equal(plan['version'], 4)
    elif plan['qualifier'] or report:
        assert_equal(plan['version'], 3)
    else:
        assert_equal(plan['version'], 2 if announcement else 1)
    if report and weights is not None:
        assert_equal(report, report_hash(weights))
    expected_hash = plan_hash(plan['version'], plan['network'], snap['asset_name'], snap['height'], block_hash,
                              snap_hash, plan['distribution_asset_name'], _sat(plan['amount']), policy,
                              plan['exception_addresses'], _sat(plan['distributed']), _sat(plan['remainder']),
                              len(leaves), root, announcement, plan['qualifier'], report, allocation, min_held)
    assert_equal(plan['plan_hash'], expected_hash.hex())


def plan_amounts(plan):
    return {r['address']: r['amount'] for r in plan['recipients']}


def pay_plan(node, plan):
    """Pay a plan from the node's wallet in one transaction, as an operator would.

    There is no wallet call that sends an asset to several recipients, and
    fundrawtransaction does not select asset inputs (NIP-048 2.8), so the asset
    inputs and change are chosen here. Paying recipient by recipient is wrong
    when a recipient belongs to the paying wallet: the next transfer can spend
    what the previous one just paid."""
    asset = plan['distribution_asset_name']
    amounts = plan_amounts(plan)
    if asset == "XNA":
        return node.sendmany("", amounts)

    needed = sum(amounts.values())
    inputs, have = [], Decimal(0)
    for outpoint in node.listmyassets(asset, True)[asset]['outpoints']:
        if have >= needed:
            break
        inputs.append({'txid': outpoint['txid'], 'vout': outpoint['vout']})
        have += outpoint['amount']
    assert have >= needed, "the wallet holds %s of the %s %s the plan needs" % (have, needed, asset)

    outputs = {address: {'transfer': {asset: amount}} for address, amount in amounts.items()}
    if have > needed:
        outputs[node.getnewaddress()] = {'transfer': {asset: have - needed}}
    funded = node.fundrawtransaction(node.createrawtransaction(inputs, outputs))['hex']
    return node.sendrawtransaction(node.signrawtransaction(funded)['hex'])
