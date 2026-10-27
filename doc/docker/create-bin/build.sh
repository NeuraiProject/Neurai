#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: build.sh [--no-cache] <linux|windows|macos> [branch] [user|server] [x86_64|arm64]

Defaults: branch=DePIN-Test, profile=user, architecture=x86_64.
Architecture selection is only available for macOS.
Binaries are always extracted into tests/output next to this script.

Options (accepted before or after positional arguments):
  --no-cache              Rebuild Docker layers; keep depends cache mounts.
  -h, --help              Show this help message.

Optional variables:
  JOBS=2                  Parallel build jobs.
  REPOSITORY=https://github.com/NeuraiProject/Neurai.git
  SOURCE_COMMIT=<sha>      Pin a full commit hash from the selected branch.
  IMAGE=<name:tag>         Final image name.
  OSX_MIN_VERSION=12.0     Minimum macOS version.
EOF
}
# Parse the complete workflow before starting long-running commands.
main() {
    docker_build_options=()
    positional_arguments=()
    while (( $# )); do
        case "$1" in
            --no-cache) docker_build_options=(--no-cache) ;;
            -h|--help) usage; exit 0 ;;
            --) shift; positional_arguments+=("$@"); break ;;
            -*) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
            *) positional_arguments+=("$1") ;;
        esac
        shift
    done
    set -- "${positional_arguments[@]}"
    if (( $# < 1 || $# > 4 )); then usage >&2; exit 2; fi
    target=$1
    branch=${2:-DePIN-Test}
    profile=${3:-user}
    architecture=${4:-x86_64}
    case "$target" in
        linux) dockerfile=Dockerfile-Linux64 ;;
        windows) dockerfile=Dockerfile-Win64 ;;
        macos) dockerfile=Dockerfile-MacOS ;;
        *) usage >&2; exit 2 ;;
    esac
    case "$profile" in user|server) ;; *) echo 'Profile must be user or server' >&2; exit 2 ;; esac
    case "$architecture" in x86_64|arm64) ;; *) echo 'Architecture must be x86_64 or arm64' >&2; exit 2 ;; esac
    if [[ "$target" != macos && "$architecture" != x86_64 ]]; then
        echo 'These Dockerfiles only support x86_64 for Linux and Windows' >&2
        exit 2
    fi
    jobs=${JOBS:-2}
    [[ "$jobs" =~ ^[1-9][0-9]*$ ]] || { echo 'JOBS must be a positive integer' >&2; exit 2; }
    command -v docker >/dev/null
    command -v git >/dev/null
    git check-ref-format "refs/heads/$branch"

    script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    repository=${REPOSITORY:-https://github.com/NeuraiProject/Neurai.git}
    commit=${SOURCE_COMMIT:-}
    if [[ -z "$commit" ]]; then
        # Resolve on every invocation: a cached git clone cannot hide new commits.
        remote_ref=$(git ls-remote --exit-code -- "$repository" "refs/heads/$branch")
        read -r commit _ <<< "$remote_ref"
    fi
    if [[ ! "$commit" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]]; then
        echo 'SOURCE_COMMIT must be a full Git commit hash' >&2
        exit 2
    fi
    image=${IMAGE:-"neurai-release-$target-$architecture-$profile:${commit:0:12}"}
    output_dir="$script_dir/tests/output"
    mkdir -p "$output_dir"
    output_dir=$(cd "$output_dir" && pwd)
    printf 'Building %s (%s, %s), branch %s, commit %s\n' "$target" "$architecture" "$profile" "$branch" "$commit"

    docker build "${docker_build_options[@]}" --platform linux/amd64 \
        --file "$script_dir/$dockerfile" --tag "$image" \
        --build-arg "REPOSITORY=$repository" --build-arg "BRANCH=$branch" \
        --build-arg "SOURCE_COMMIT=$commit" --build-arg "BUILD_TYPE=$profile" \
        --build-arg "JOBS=$jobs" --build-arg "MAC_ARCH=$architecture" \
        --build-arg "OSX_MIN_VERSION=${OSX_MIN_VERSION:-12.0}" "$script_dir"
    docker run --rm --user "$(id -u):$(id -g)" \
        --volume "$output_dir:/output" "$image"
    printf 'Output: %s\nReusable image: %s\n' "$output_dir" "$image"
}

# Exit from this parsed block so script updates cannot affect a running build.
{
    main "$@"
    exit
}
