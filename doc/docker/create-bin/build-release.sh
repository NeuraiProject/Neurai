#!/usr/bin/env bash
# Runs inside the builder stage; never executes cross-compiled programs.
set -euo pipefail

target=${1:?Missing target: linux, windows or macos}
: "${REPOSITORY:=https://github.com/NeuraiProject/Neurai.git}"
: "${BRANCH:=DePIN-Test}"
: "${BUILD_TYPE:=user}"
: "${JOBS:=2}"
case "$target" in linux|windows|macos) ;; *) echo "Invalid target: $target" >&2; exit 2 ;; esac
case "$BUILD_TYPE" in
    user) no_qt=; gui=qt6 ;;
    server) no_qt=1; gui=no ;;
    *) echo 'BUILD_TYPE must be user or server' >&2; exit 2 ;;
esac
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || { echo 'JOBS must be a positive integer' >&2; exit 2; }
git check-ref-format "refs/heads/$BRANCH"
if [[ -n "${SOURCE_COMMIT:-}" && ! "$SOURCE_COMMIT" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
    echo 'SOURCE_COMMIT must be a full Git commit hash' >&2
    exit 2
fi

source_root=/src/neurai
git clone --depth 1 --single-branch --branch "$BRANCH" -- "$REPOSITORY" "$source_root"
if [[ -n "${SOURCE_COMMIT:-}" ]]; then
    if [[ $(git -C "$source_root" rev-parse HEAD) != "$SOURCE_COMMIT" ]]; then
        git -C "$source_root" fetch --depth 1 origin "$SOURCE_COMMIT"
    fi
    git -C "$source_root" checkout --detach "$SOURCE_COMMIT"
fi
cd "$source_root"

configure_options=(
    --prefix=/ --disable-debug --disable-tests --disable-gui-tests
    --disable-bench --disable-man --disable-maintainer-mode
    --disable-dependency-tracking --disable-ccache --disable-shared --enable-static
    --enable-hardening --enable-reduce-exports --enable-wallet
    --without-libs --with-daemon --with-cli "--with-gui=$gui"
)
if [[ "$BUILD_TYPE" == user ]]; then
    configure_options+=(--with-qrencode)
else
    configure_options+=(--without-qrencode)
fi
suffix=
case "$target" in
    linux)
        host=x86_64-pc-linux-gnu
        strip_tool='strip'
        link_flags='-static-libstdc++ -static-libgcc -Wl,--gc-sections'
        configure_options+=(--with-tx)
        ;;
    windows)
        host=x86_64-w64-mingw32
        strip_tool=$host-strip
        suffix=.exe
        link_flags='-static -static-libstdc++ -static-libgcc -Wl,--gc-sections'
        # Matches the current Windows CI: neurai-tx does not link there yet.
        configure_options+=(--without-tx)
        ;;
    macos)
        if [[ ! -f contrib/mac-cross/env.sh ]]; then
            echo "Branch $BRANCH has no contrib/mac-cross support; use a compatible branch" >&2
            exit 1
        fi
        export MAC_WORKDIR=/opt/mac
        export MAC_ARCH=${MAC_ARCH:-x86_64} OSX_MIN_VERSION=${OSX_MIN_VERSION:-12.0}
        export JOBS NO_QT=$no_qt
        # shellcheck disable=SC1091
        source contrib/mac-cross/env.sh
        mac_paths "$source_root"
        contrib/mac-cross/setup.sh
        mac_environment "$source_root"
        host=$MAC_HOST
        # Strip at link time, before ld64.lld signs ARM64 code pages.
        link_flags='-Wl,-dead_strip,-S,-x'
        configure_options+=(--with-tx)
        ;;
esac
depends_prefix=${MAC_DEPENDS_PREFIX:-"$source_root/depends/$host"}
depends_options=()
if [[ "$target" == linux && "$BUILD_TYPE" == user ]]; then
    # These recipes normally build shared libraries. Keep the overrides here,
    # and salt their cache: depends does not hash command-line config options.
    depends_options+=(
        'HOST_ID_SALT=neurai-release-static-linux-v1'
        'freetype_download_path=https://download-mirror.savannah.gnu.org/releases/freetype'
        'freetype_config_opts_linux=-DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON'
        'expat_config_opts_linux=--enable-static --disable-shared --with-pic'
        'dbus_config_opts_linux=--enable-static --disable-shared --with-pic'
        'fontconfig_config_opts_linux=--enable-static --disable-shared --with-pic --sysconfdir=/etc --localstatedir=/var --with-default-fonts=/usr/share/fonts --with-add-fonts=/usr/local/share/fonts --with-cache-dir=/var/cache/fontconfig'
    )
fi
make -C depends -j"$JOBS" HOST="$host" PREFIX="$depends_prefix" \
    JOBS="$JOBS" DEBUG= NO_QT="$no_qt" \
    SOURCES_PATH=/cache/sources BASE_CACHE=/cache/built "${depends_options[@]}"

./autogen.sh
CONFIG_SITE="$depends_prefix/share/config.site" ./configure \
    "${configure_options[@]}" \
    CFLAGS='-Os -g0 -ffunction-sections -fdata-sections' \
    CXXFLAGS='-Os -g0 -ffunction-sections -fdata-sections' \
    LDFLAGS="$link_flags"
make -j"$JOBS"

mkdir -p /binaries
binaries=("src/neuraid$suffix" "src/neurai-cli$suffix")
if [[ "$target" != windows ]]; then binaries+=(src/neurai-tx); fi
if [[ "$BUILD_TYPE" == user ]]; then binaries+=("src/qt/neurai-qt$suffix"); fi
for binary in "${binaries[@]}"; do
    destination=/binaries/$(basename "$binary")
    install -m 755 "$binary" "$destination"
    if [[ "$target" != macos ]]; then "$strip_tool" --strip-all "$destination"; fi
done

# Fail rather than silently ship binaries that need build-machine libraries.
case "$target" in
    linux)
        for binary in /binaries/*; do
            readelf -d "$binary" > /tmp/neurai-dynamic.txt
            while read -r library; do
                case "$library" in
                    libc.so.*|libm.so.*|libpthread.so.*|libdl.so.*|librt.so.*|libresolv.so.*|ld-linux*) ;;
                    *) echo "Unexpected shared dependency in $binary: $library" >&2; exit 1 ;;
                esac
            done < <(sed -n 's/.*Shared library: \[\(.*\)\]/\1/p' /tmp/neurai-dynamic.txt)
        done
        ;;
    windows)
        for binary in /binaries/*.exe; do
            "$host-objdump" -p "$binary" > /tmp/neurai-imports.txt
            while read -r library; do
                case "${library,,}" in
                    api-ms-win-*.dll|ext-ms-win-*.dll|advapi32.dll|authz.dll|bcrypt.dll|\
                    comctl32.dll|comdlg32.dll|crypt32.dll|d2d1.dll|d3d9.dll|d3d11.dll|\
                    d3d12.dll|dnsapi.dll|dwmapi.dll|dwrite.dll|dxgi.dll|gdi32.dll|\
                    imm32.dll|iphlpapi.dll|kernel32.dll|kernelbase.dll|mpr.dll|msvcrt.dll|\
                    netapi32.dll|ntdll.dll|ole32.dll|oleaut32.dll|powrprof.dll|propsys.dll|\
                    rpcrt4.dll|runtimeobject.dll|secur32.dll|setupapi.dll|shell32.dll|\
                    shlwapi.dll|shcore.dll|user32.dll|userenv.dll|ucrtbase.dll|uxtheme.dll|\
                    version.dll|winhttp.dll|winmm.dll|winspool.drv|ws2_32.dll|wtsapi32.dll) ;;
                    *) echo "Unexpected runtime DLL dependency in $binary: $library" >&2; exit 1 ;;
                esac
            done < <(sed -n 's/.*DLL Name: //p' /tmp/neurai-imports.txt)
        done
        ;;
    macos)
        exported=()
        for binary in "${binaries[@]}"; do exported+=("/binaries/$(basename "$binary")"); done
        python3 contrib/mac-cross/verify.py --minimum "$OSX_MIN_VERSION" \
            --sdk "$OSX_SDK_VERSION" --architecture "$MAC_ARCH" \
            --output /binaries/macos-verification.json "${exported[@]}"
        ;;
esac

cp COPYING /binaries/COPYING
if [[ -d "$depends_prefix/share/licenses" ]]; then
    cp -R "$depends_prefix/share/licenses" /binaries/licenses
fi
{
    printf 'repository=%s\nbranch=%s\ncommit=%s\n' "$REPOSITORY" "$BRANCH" "$(git rev-parse HEAD)"
    printf 'target=%s\nhost=%s\nprofile=%s\ndebug=disabled\n' "$target" "$host" "$BUILD_TYPE"
    printf 'cflags=-Os -g0 -ffunction-sections -fdata-sections\n'
    if [[ "$target" == macos ]]; then printf 'minimum_macos=%s\n' "$OSX_MIN_VERSION"; fi
} > /binaries/BUILD-INFO.txt
cd /binaries
find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > /tmp/neurai-SHA256SUMS
mv /tmp/neurai-SHA256SUMS SHA256SUMS
