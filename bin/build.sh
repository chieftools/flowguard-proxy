#!/bin/bash
# Build static flowguard binaries with the same flags as the packages.
#
#   bin/build.sh [VERSION] [all|native|linux-amd64|linux-arm64]
#
# Linux builds are fully static (CGO_ENABLED=0 with the pure-Go resolver and
# user lookup), so one binary runs on every supported distribution
# regardless of its glibc.

set -euo pipefail

VERSION="${1:-dev}"
TARGET="${2:-all}"
case "${TARGET}" in
    all|native|linux-amd64|linux-arm64)
        ;;
    *)
        echo "Unsupported build target: ${TARGET}" >&2
        exit 1
        ;;
esac

cd "$(dirname "${BASH_SOURCE[0]}")/.."

export CGO_ENABLED=0

BUILD_FLAGS=(-mod=readonly -trimpath -buildvcs=false -tags=netgo,osusergo)
LDFLAGS="-s -w -X main.Version=${VERSION}"

build() {
    local goos="$1" goarch="$2" output="$3"
    echo "Building FlowGuard ${VERSION} for ${goos}/${goarch}..."
    GOOS="${goos}" GOARCH="${goarch}" go build "${BUILD_FLAGS[@]}" -ldflags="${LDFLAGS}" -o "${output}" .
}

if [ "${TARGET}" = all ] || [ "${TARGET}" = native ]; then
    build "$(go env GOOS)" "$(go env GOARCH)" flowguard
fi

if [ "${TARGET}" = all ] || [ "${TARGET}" = linux-amd64 ]; then
    build linux amd64 flowguard-linux-amd64
fi

if [ "${TARGET}" = all ] || [ "${TARGET}" = linux-arm64 ]; then
    build linux arm64 flowguard-linux-arm64
fi
