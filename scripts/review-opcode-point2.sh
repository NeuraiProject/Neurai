#!/usr/bin/env bash
# Run inside the test container. Each invocation keeps its own evidence.
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
OUT=$(mktemp -d "${TMPDIR:-/tmp}/opcode-point2-XXXXXX")
echo "Evidence: $OUT"

# Sequential execution is intentional: do not start another case after failure.
for family in stack-envelope hash-merkle arithmetic timelock; do
    for auth in 0 1 2; do
        for wrapped in native wrapped; do
            name="$family-$auth-$wrapped"
            flags=(--auth "$auth")
            if [[ $wrapped == wrapped ]]; then flags+=(--wrapped); fi
            code=0
            python3 "$SCRIPT_DIR/review-$family-regtest.py" "${flags[@]}" > "$OUT/$name.log" 2>&1 || code=$?
            echo "$name exit=$code" | tee -a "$OUT/summary.txt"
            if (( code != 0 )); then
                echo "Stopped: see $OUT/$name.log" >&2
                exit "$code"
            fi
            # A zero exit status alone is insufficient: require a complete,
            # successful report and preserve it beside the log.
            python3 - "$OUT" "$name" "$auth" "$wrapped" <<'PY'
import json
import pathlib
import sys

out, name, auth, wrapped = sys.argv[1:]
out = pathlib.Path(out)
paths = [line.removeprefix('Report: ') for line in
         (out / (name + '.log')).read_text().splitlines()
         if line.startswith('Report: ')]
if len(paths) != 1:
    raise SystemExit('Expected exactly one report: ' + name)
data = pathlib.Path(paths[0]).read_bytes()
report = json.loads(data)
expected = {'stack-envelope': 1404, 'hash-merkle': 564,
            'arithmetic': 404, 'timelock': 480}[name.rsplit('-', 2)[0]]
if (report.get('error') is not None or report.get('failed') != 0
        or report.get('passed') != expected
        or len(report.get('results', [])) != expected
        or not all(row.get('passed') is True for row in report['results'])
        or report.get('auth') != int(auth)
        or report.get('wrapped') is not (wrapped == 'wrapped')):
    raise SystemExit('Incomplete or unsuccessful report: ' + name)
(out / (name + '.json')).write_bytes(data)
PY
        done
    done
done
echo 'PASS: 24 runs, 17112 checks' | tee -a "$OUT/summary.txt"
