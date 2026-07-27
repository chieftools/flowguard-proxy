#!/bin/bash

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <version>" >&2
    exit 2
fi

VERSION="${1#v}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHANGELOG_PATH="${SCRIPT_DIR}/../CHANGELOG.md"

awk -v heading="## [${VERSION}]" '
    $0 == heading {
        matches++
        capturing = 1
        next
    }

    capturing && /^## / {
        capturing = 0
    }

    capturing {
        body = body $0 ORS
    }

    END {
        if (matches != 1) {
            printf "Expected exactly one changelog section for %s, found %d\n", heading, matches > "/dev/stderr"
            exit 1
        }

        if (body !~ /[^[:space:]]/) {
            printf "Changelog section for %s is empty\n", heading > "/dev/stderr"
            exit 1
        }

        sub(/^[[:space:]]+/, "", body)
        sub(/[[:space:]]+$/, "", body)
        print body
    }
' "${CHANGELOG_PATH}"
