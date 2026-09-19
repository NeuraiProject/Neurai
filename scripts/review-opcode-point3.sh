#!/usr/bin/env bash
# Run inside the test container. Each invocation keeps its own evidence.
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
OUT=$(mktemp -d "${TMPDIR:-/tmp}/opcode-point3-XXXXXX")
echo "Evidence: $OUT"

# name  script  expected_checks  extra arguments...
RUNS=(
    "weight-limits-0-native review-weight-limits-regtest.py 43 --auth 0"
    "weight-limits-0-wrapped review-weight-limits-regtest.py 43 --auth 0 --wrapped"
    "weight-limits-1-native review-weight-limits-regtest.py 43 --auth 1"
    "weight-limits-1-wrapped review-weight-limits-regtest.py 43 --auth 1 --wrapped"
    "weight-limits-2-native review-weight-limits-regtest.py 43 --auth 2"
    "weight-limits-2-wrapped review-weight-limits-regtest.py 43 --auth 2 --wrapped"
    "witness-limits-0-native      review-witness-limits-regtest.py          253 --auth 0"
    "witness-limits-0-wrapped     review-witness-limits-regtest.py          128 --auth 0 --wrapped"
    "witness-limits-1-native      review-witness-limits-regtest.py          128 --auth 1"
    "witness-limits-1-wrapped     review-witness-limits-regtest.py          128 --auth 1 --wrapped"
    "witness-limits-2-native      review-witness-limits-regtest.py          128 --auth 2"
    "witness-limits-2-wrapped     review-witness-limits-regtest.py          128 --auth 2 --wrapped"
    "block-limit-csfs-0-native    review-csfs-block-limit-regtest.py         26 --opcode csfs --auth 0"
    "block-limit-csfs-0-wrapped   review-csfs-block-limit-regtest.py         26 --opcode csfs --auth 0 --wrapped"
    "block-limit-csfs-1-native    review-csfs-block-limit-regtest.py         26 --opcode csfs --auth 1"
    "block-limit-csfs-1-wrapped   review-csfs-block-limit-regtest.py         26 --opcode csfs --auth 1 --wrapped"
    "block-limit-csfs-2-native    review-csfs-block-limit-regtest.py         26 --opcode csfs --auth 2"
    "block-limit-csfs-2-wrapped   review-csfs-block-limit-regtest.py         26 --opcode csfs --auth 2 --wrapped"
    "block-limit-checksigadd-1-native  review-csfs-block-limit-regtest.py    26 --opcode checksigadd --auth 1"
    "block-limit-checksigadd-2-wrapped review-csfs-block-limit-regtest.py    26 --opcode checksigadd --auth 2 --wrapped"
    "block-limit-ed25519-1-wrapped review-csfs-block-limit-regtest.py        26 --opcode ed25519 --auth 1 --wrapped"
    "block-limit-ed25519-2-native  review-csfs-block-limit-regtest.py        26 --opcode ed25519 --auth 2"
    "signatures-assets-refs       review-signatures-assets-refs-regtest.py 7712"
    "signatures-activation        review-signatures-activation-regtest.py  401"
)

# Sequential execution is intentional: do not start another case after failure.
for entry in "${RUNS[@]}"; do
    read -r name script expected extra <<< "$entry"
    # shellcheck disable=SC2086
    code=0
    python3 "$SCRIPT_DIR/$script" $extra > "$OUT/$name.log" 2>&1 || code=$?
    echo "$name exit=$code" | tee -a "$OUT/summary.txt"
    if (( code != 0 )); then
        echo "Stopped: see $OUT/$name.log" >&2
        exit "$code"
    fi
    # A zero exit status alone is insufficient: require a complete, successful
    # report with the expected number of checks and preserve it beside the log.
    python3 - "$OUT" "$name" "$expected" $extra <<'PY'
import json
import pathlib
import sys

out, name, expected = pathlib.Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
extra = sys.argv[4:]
auth = int(extra[extra.index('--auth') + 1]) if '--auth' in extra else None
wrapped = '--wrapped' in extra
paths = [line.removeprefix('Report: ') for line in (out / (name + '.log')).read_text().splitlines()
         if line.startswith('Report: ')]
if len(paths) != 1:
    raise SystemExit('Expected exactly one report: ' + name)
data = pathlib.Path(paths[0]).read_bytes()
report = json.loads(data)
if (report.get('error') is not None or report.get('failed') != 0
        or report.get('passed') != expected
        or len(report.get('results', [])) != expected
        or not all(row.get('passed') is True for row in report['results'])
        or (auth is not None and report.get('auth') != auth)
        or (auth is not None and report.get('wrapped') is not wrapped)):
    raise SystemExit('Incomplete or unsuccessful report: ' + name)
(out / (name + '.json')).write_bytes(data)
PY
done
echo "PASS: ${#RUNS[@]} runs" | tee -a "$OUT/summary.txt"
