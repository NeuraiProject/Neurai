#!/usr/bin/env bash
# Run inside the test Docker. Requires Qt6 development tools, protobuf and the
# existing Neurai depends/BDB installations. No changes to /root/Neurai binaries.
set -euo pipefail
source_root=${SOURCE_ROOT:-/src}
review_dir=$(mktemp -d /tmp/qt-point6-XXXXXX)
printf 'Artifacts: %s\n' "$review_dir"
mkdir "$review_dir/source" "$review_dir/run"
git -c safe.directory="$source_root" -C "$source_root" rev-parse HEAD > "$review_dir/revision.txt"
git -c safe.directory="$source_root" -C "$source_root" archive HEAD | tar -x -C "$review_dir/source"
git -c safe.directory="$source_root" -C "$source_root" diff --binary HEAD > "$review_dir/working-tree.patch"
if [ -s "$review_dir/working-tree.patch" ]; then
    git -C "$review_dir/source" apply "$review_dir/working-tree.patch"
fi
cp "$source_root/scripts/review-qt-wallet-flows.cpp" "$review_dir/source/src/qt/test/test_main.cpp"
sha256sum "$source_root/scripts/review-qt-wallet-flows.cpp" > "$review_dir/harness.sha256"
cd "$review_dir/source"
./autogen.sh > "$review_dir/autogen.log" 2>&1
./configure --prefix=/root/Neurai/depends/x86_64-pc-linux-gnu --with-gui=qt6 \
    --enable-gui-tests --enable-tests --disable-bench --disable-maintainer-mode \
    BDB_CFLAGS=-I/root/db4/include BDB_LIBS='-L/root/db4/lib -ldb_cxx-4.8' \
    LIBS='-lm -ldl -lpthread' > "$review_dir/configure.log" 2>&1
make -j4 -C src qt/neurai-qt > "$review_dir/build.log" 2>&1
make -j2 -C src qt/test/test_neurai-qt > "$review_dir/test-build.log" 2>&1
sha256sum src/qt/neurai-qt src/qt/test/test_neurai-qt > "$review_dir/binaries.sha256"
cd "$review_dir/run"
set +e
timeout 120 "$review_dir/source/src/qt/test/test_neurai-qt" > flows.log 2>&1
result=$?
set -e
cat flows.log
printf '%s\n' "$result" > exit-code.txt
if [ "$result" -ne 0 ]; then exit "$result"; fi
python3 "$source_root/scripts/review-qt-app-smoke.py" "$review_dir/source/src/qt/neurai-qt"
