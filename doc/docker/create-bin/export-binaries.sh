#!/bin/sh
set -eu

if [ "$#" -gt 1 ]; then
    echo 'Usage: export-binaries [output-directory]' >&2
    exit 2
fi
destination=${1:-/output}
if [ "$destination" = /binaries ]; then
    echo 'Choose an output directory other than /binaries' >&2
    exit 2
fi
mkdir -p "$destination"
cp -R /binaries/. "$destination/"
printf 'Binaries extracted to %s\n' "$destination"
