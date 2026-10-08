#!/usr/bin/env python3
"""Offline checks for deterministic, append-only header anchor generation."""

import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("anchors", Path(__file__).with_name("gen-header-anchors.py"))
anchors = importlib.util.module_from_spec(spec)
spec.loader.exec_module(anchors)


class Source:
    def __init__(self):
        self.chain = "main"
        self.height = 6500
        self.tip = "a" * 64
        self.checkpoint = "b" * 64
        self.checkpoint_reads = 0
        self.reorg = False

    def __call__(self, method, *params):
        if method == "getblockchaininfo":
            return {"chain": self.chain, "blocks": self.height, "bestblockhash": self.tip}
        if method == "getnetworkinfo":
            return {"version": 1000600, "subversion": "/Neurai:1.0.6/"}
        if method == "getblockhash":
            height = params[0]
            if height == 0:
                return anchors.MAINNET_GENESIS
            if height == 6250:
                self.checkpoint_reads += 1
                return "c" * 64 if self.reorg and self.checkpoint_reads > 1 else self.checkpoint
            if height == self.height:
                return self.tip
            return f"{height:064x}"
        raise AssertionError(method)


class AnchorGenerationTests(unittest.TestCase):
    def collect(self, source):
        return anchors.collect(source, 6250, "b" * 64)

    def test_output_is_identical_across_sources(self):
        first, metadata = self.collect(Source())
        other = Source()
        other.height = 6501
        other.tip = "d" * 64
        second, _ = self.collect(other)
        self.assertEqual(anchors.render(first, 6250), anchors.render(second, 6250))
        self.assertEqual(metadata["anchor_count"], 3)
        self.assertEqual(first, [f"{height:064x}" for height in (2000, 4000, 6000)])

    def test_wrong_network_or_unfinished_chain_is_rejected(self):
        source = Source()
        source.chain = "test"
        with self.assertRaisesRegex(ValueError, "mainnet"):
            self.collect(source)
        source.chain = "main"
        source.height = 6000
        with self.assertRaisesRegex(ValueError, "not validated"):
            self.collect(source)

    def test_checkpoint_mismatch_is_rejected(self):
        source = Source()
        source.checkpoint = "e" * 64
        with self.assertRaisesRegex(ValueError, "checkpoint does not match"):
            self.collect(source)

    def test_reorganization_during_collection_is_rejected(self):
        source = Source()
        source.reorg = True
        with self.assertRaisesRegex(ValueError, "chain changed"):
            self.collect(source)

    def test_existing_prefix_cannot_be_changed_or_shortened(self):
        values, _ = self.collect(Source())
        old = anchors.render(values[:2], 4000)
        self.assertEqual(anchors.render(values, 6250, old), anchors.render(values, 6250))
        changed = ["f" * 64] + values[1:]
        with self.assertRaisesRegex(ValueError, "only append"):
            anchors.render(changed, 6250, old)
        with self.assertRaisesRegex(ValueError, "only append"):
            anchors.render(values[:1], 2000, old)

    def test_invalid_hashes_counts_and_previous_format_are_rejected(self):
        with self.assertRaises(ValueError):
            anchors.render(["not a hash"], 2000)
        with self.assertRaises(ValueError):
            anchors.render(["a" * 64], 4000)
        with self.assertRaises(ValueError):
            anchors.render(["a" * 64], 2000, "not a generated header")
        broken = anchors.render(["a" * 64], 2000).replace("// 2000", "// 4000")
        with self.assertRaises(ValueError):
            anchors.previous_anchors(broken)
        malformed_last = anchors.render(["a" * 64, "b" * 64], 4000).replace("b" * 64, "invalid")
        with self.assertRaises(ValueError):
            anchors.previous_anchors(malformed_last)


if __name__ == "__main__":
    unittest.main()
