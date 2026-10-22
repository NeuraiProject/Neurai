#!/usr/bin/env bash
# Disposable protocol 4 RPC walkthrough and attack regressions.
# Run after building neuraid/neurai-cli and configuring the functional framework.
# Arguments are passed to the framework, e.g. --tmpdir=/tmp/depin-rpc4 --nocleanup.
# The framework chooses fresh wallets, ports and data directories; no existing
# node or DATADIR is reused. The independent client verifies signatures first.
set -euo pipefail
cd "$(dirname "$0")/../.."
exec python3 test/functional/feature_depin_request_signatures.py "$@"
