#!/usr/bin/env python3
"""Deterministic NIP-046 fixtures; cost oracle, NOT a Script interpreter.
Default checks the frozen file. --write explicitly replaces it for review.
"""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'src/test/data/nip046_budget_vectors.json'


def vectors():
    cases = []
    for n in (201, 202, 512, 513):
        cases.append(dict(name=f'ops_{n}', script_hex=(b'\x61'*n+b'\x51').hex(),
                          witness_sizes=[], op_count=n, classic_units=0,
                          before=n <= 201, after=n <= 512))
    # SHA256 DROP consumes the top element each time; all outputs are discarded.
    for last in (2751, 2752, 2753):
        sizes = [3072]*20+[last]
        units = sum(size+64 for size in sizes)
        cases.append(dict(name=f'sha256_{units}', script_hex=(b'\xa8\x75'*21+b'\x51').hex(),
                          witness_sizes=sizes, op_count=42, classic_units=units,
                          before=True, after=units <= 65536))
    # 86 elements fit exactly at 256 KiB; one extra byte is forbidden initially.
    # The first DROP hides that excess under the historical post-op check.
    for last in (1024, 1025):
        sizes = [3072]*85+[last]
        cases.append(dict(name=f'initial_memory_{sum(sizes)}',
                          script_hex=(b'\x75'*86+b'\x51').hex(), witness_sizes=sizes,
                          op_count=86, classic_units=0, before=True,
                          after=sum(sizes) <= 262144))
    for c in cases:
        c['script_sha256'] = hashlib.sha256(bytes.fromhex(c['script_hex'])).hexdigest()
    assert [c['classic_units'] for c in cases[4:7]] == [65535, 65536, 65537]
    assert [sum(c['witness_sizes']) for c in cases[7:]] == [262144, 262145]
    return dict(schema=1, scope='native v1 NoAuth; widened elements enabled; proposed parameters',
                witness_fill='repeat byte 0x42 for each size, in listed stack order', cases=cases)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--write', action='store_true')
    args = p.parse_args()
    expected = vectors()
    if args.write:
        FIXTURE.write_text(json.dumps(expected, indent=2)+'\n')
    actual = json.loads(FIXTURE.read_text())
    if actual != expected:
        raise SystemExit('Frozen fixture differs: review before explicit --write')
    print(f'{len(expected["cases"])} frozen vectors checked; not node validation')


if __name__ == '__main__':
    main()
