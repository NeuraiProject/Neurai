#!/usr/bin/env bash

set -euo pipefail

IMAGE_NAME="${1:-neurai-linux64-bin}"
OUTPUT_DIR="${2:-./artifacts/linux64}"

CONTAINER_NAME="neurai-extract-$$"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

mkdir -p "${OUTPUT_DIR}"

cleanup() {
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}

trap cleanup EXIT

docker create --name "${CONTAINER_NAME}" "${IMAGE_NAME}" >/dev/null

copy_if_exists() {
  local src="$1"
  local dest_name="$2"

  if docker cp "${CONTAINER_NAME}:${src}" "${OUTPUT_DIR}/${dest_name}" 2>/dev/null; then
    printf 'copied %s\n' "${dest_name}"
  else
    printf 'missing %s\n' "${src}"
  fi
}

copy_if_exists "/root/Neurai/src/neuraid" "neuraid"
copy_if_exists "/root/Neurai/src/neurai-cli" "neurai-cli"
copy_if_exists "/root/Neurai/src/neurai-tx" "neurai-tx"
copy_if_exists "/root/Neurai/src/qt/neurai-qt" "neurai-qt"

printf 'output: %s\n' "$(cd "${OUTPUT_DIR}" && pwd)"
printf 'repo: %s\n' "${REPO_ROOT}"
