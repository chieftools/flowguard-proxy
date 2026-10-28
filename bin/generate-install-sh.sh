#!/bin/bash
# Write the repository's install.sh for PACKAGE_BASE_URL to stdout:
#
#   bin/generate-install-sh.sh https://pkg.flowguard.network > install.sh

set -euo pipefail

PACKAGE_BASE_URL="${1:-}"

if [[ ! "${PACKAGE_BASE_URL}" =~ ^https://[a-zA-Z0-9.-]+$ ]]; then
    echo "PACKAGE_BASE_URL must be an HTTPS hostname without a trailing slash." >&2
    exit 1
fi

sed "s|__PACKAGE_BASE_URL__|${PACKAGE_BASE_URL}|g" "$(dirname "${BASH_SOURCE[0]}")/../packaging/install.sh"
