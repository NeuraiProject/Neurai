#!/usr/bin/env python3
# Copyright (c) 2026 The Neurai developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""C7 pool contract: the C6 leaves with the C7 publication framing.

Built on the C6 constructors of a Neurai-DePIN checkout (scripts/pool_c6_*.py
and NIP/bench/nip043_v3_scripts.py). Only the publication framing changes:
note records are 230 bytes and their first byte is fixed to 0x02 (byte 1, the
view tag, is free). Circuits, verifying keys, the state, the reserve and every
other rule are the C6 ones, so the profile 3 consensus predicate is unchanged.
"""
import sys
from pathlib import Path

RECORD_BYTES = 230
RECORD_PREFIX = b"\x02"
J2_RECORD = 98                      # J2: 03 01 || nf0 || nf1 || cm || record || zero padding
J2_END = J2_RECORD + RECORD_BYTES   # 328


def load(repo_root):
    """Returns (Contract class, pool_c6_j2 module) with the C7 framing installed."""
    root = Path(repo_root)
    sys.path.insert(0, str(root / "scripts"))
    import pool_c4_publication as publication
    import pool_c6_j2 as j2

    def layout(form):
        if form in ("D0", "D1"):
            count, deposit = 1, True
        elif form in ("T1", "T2", "T3", "T4"):
            count, deposit = int(form[1]), False
        else:
            raise ValueError("Unsupported C7 publication form")
        end = 34 + 32 * count + RECORD_BYTES * count
        fixed = [(0, bytes([publication.VERSION, count])), (end, bytes(publication.BLOB_BYTES - end))]
        if deposit:
            fixed.append((2, bytes(32)))
        records = [34 + 32 * count + RECORD_BYTES * i for i in range(count)]
        fixed.extend((at, RECORD_PREFIX) for at in records)
        return dict(cms=[34 + 32 * i for i in range(count)], records=records, nf=None if deposit else 2,
                    fixed=fixed, end=end)

    # check_framing() and every C6 leaf read the layout through the module.
    publication.layout = layout
    publication.RECORD_BYTES = RECORD_BYTES
    c, old = j2.c, j2.old

    class Contract(j2.Contract):
        def leaf(self, form):
            if form != "J2":
                return super().leaf(form)
            # The C6 J2 leaf with the C7 record window [98, 328).
            args = ["tree" + str(i) for i in range(5)] + ["proof", "vk", "chunk1", "chunk2", "R", "prevouts"]
            s = j2.J2Script(args, form, self.vks["J2"])
            own = self.state(s)
            s.same(c.op("INPUTCOUNT"), 2)
            s.same(c.op("OUTPUTCOUNT"), 2)
            self.context(s, 2, True)
            s.same(c.op("TXHASH", b"\x0b\x00"), old.fixed_fields_hash(2))
            cv = s.let("C_reserve", self.reserve_commitment(own))
            self.reserve(s, cv)
            self.reserve(s, cv, out=True)
            self.money(s, self.reserve_value(out=True), positive=True)
            fee = s.let("fee", c.op("SUB", self.reserve_value(), self.reserve_value(out=True)))
            self.money(s, fee)
            s.length(c.Ref("R"), 32)
            s.length(c.Ref("chunk1"), 2048)
            s.length(c.Ref("chunk2"), 2048)
            s.same(old.publication.slice_expr(0, 2), b"\x03\x01")
            s.same(old.publication.slice_expr(J2_RECORD, 1), RECORD_PREFIX)
            for start, size in ((J2_END, 2048 - J2_END), (2048, 2048)):
                s.same(old.publication.slice_expr(start, size), bytes(size))
            data = c.pose(c.cat(c.pose(c.cat(c.pose(j2.DATA_TAG), c.Ref("chunk1"))), c.Ref("chunk2")))
            s.zk([self.context_value, c.Ref("R"), old.publication.slice_expr(2, 32),
                  old.publication.slice_expr(34, 32), data, self.field_amount(fee), old.publication.slice_expr(66, 32)])
            s.finish()
            return s, args, 7

    return Contract, j2
