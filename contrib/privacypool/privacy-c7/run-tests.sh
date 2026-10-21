#!/bin/sh
# Run the C7 reference checks in containers: vectors file, unit tests, libsodium and OpenSSL,
# and the Zcash fpe crate. Needs Docker; writes nothing in the repository.
set -eu
cd "$(dirname "$0")/../../.."
IMAGE=neurai-c7-ref:1
docker build -q -t "$IMAGE" contrib/privacypool/privacy-c7 >/dev/null
RUN="docker run --rm -u $(id -u):$(id -g) -e PYTHONDONTWRITEBYTECODE=1 -v $PWD:/repo:ro -w /repo/contrib/privacypool/privacy-c7"
$RUN "$IMAGE" python3 gen_c7_vectors.py
$RUN "$IMAGE" python3 -m unittest test_c7_ref
$RUN "$IMAGE" python3 xcheck_libsodium.py
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
$RUN "$IMAGE" python3 xcheck_fpe.py input > "$TMP/input.txt"
docker run --rm -i -v "$PWD/contrib/privacypool/privacy-c7/xcheck_fpe:/src:ro" -e CARGO_TARGET_DIR=/tmp/target -w /src \
  rust:1.90-slim sh -c 'cargo build -q --release --locked && /tmp/target/release/c7-xcheck-fpe' \
  < "$TMP/input.txt" > "$TMP/output.txt"
docker run --rm -u "$(id -u):$(id -g)" -e PYTHONDONTWRITEBYTECODE=1 -v "$PWD:/repo:ro" -v "$TMP:/tmp/fpe:ro" \
  -w /repo/contrib/privacypool/privacy-c7 "$IMAGE" python3 xcheck_fpe.py compare /tmp/fpe/input.txt /tmp/fpe/output.txt
