#!/bin/bash

set -euo pipefail

if ! command -v unshare >/dev/null 2>&1; then
    echo "unshare is required" >&2
    exit 1
fi
if ! command -v ip >/dev/null 2>&1; then
    echo "iproute2 is required" >&2
    exit 1
fi
if ! command -v iptables >/dev/null 2>&1; then
    echo "iptables is required" >&2
    exit 1
fi

RUNNER=(unshare)
if [ "$(id -u)" -ne 0 ]; then
    RUNNER=(sudo unshare)
fi

TEST_BINARY="$(mktemp /tmp/flowguard-transparent-test.XXXXXX)"
trap 'rm -f "${TEST_BINARY}"' EXIT
go test -c -o "${TEST_BINARY}" ./proxy

"${RUNNER[@]}" --net --mount --mount-proc bash -c '
set -euo pipefail
ip link set lo up
ip address add 192.0.2.10/32 dev lo
ip link add flowguard-test type dummy
ip link set flowguard-test up
ip route add default dev flowguard-test
export FLOWGUARD_TRANSPARENT_INTEGRATION=1
"$1" -test.run "^TestTransparentNetworkSourceRoundTripIntegration$" -test.count=1 -test.v
' _ "${TEST_BINARY}"
