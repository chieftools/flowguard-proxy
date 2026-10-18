#!/bin/bash

# Prepares a release: moves the Unreleased changelog entries under the new
# version, points the Caddy plugin module at the new root version, commits,
# and creates the signed vX.Y.Z and caddy/vX.Y.Z tags on that commit.
#
# Steps that were already done, such as a changelog section written by hand,
# are skipped. Pass --push to push main and both tags atomically.

set -euo pipefail

usage() {
    echo "Usage: $0 <version> [--push]" >&2
    exit 2
}

VERSION=""
PUSH=false
for arg in "$@"; do
    case "${arg}" in
        --push) PUSH=true ;;
        -*) usage ;;
        *)
            [ -z "${VERSION}" ] || usage
            VERSION="${arg#v}"
            ;;
    esac
done
[ -n "${VERSION}" ] || usage

if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Release version must use numeric X.Y.Z format." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

CHANGELOG_PATH="CHANGELOG.md"
CADDY_DIR="caddy"
ROOT_MODULE="go.chief.tools/flowguard-proxy"
REPO_URL="https://github.com/chieftools/flowguard-proxy"
TAG="v${VERSION}"
CADDY_TAG="caddy/v${VERSION}"

# Preconditions

BRANCH="$(git symbolic-ref --short HEAD)"
if [ "${BRANCH}" != "main" ]; then
    echo "Releases are made from main, not ${BRANCH}." >&2
    exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
    echo "The working tree has uncommitted changes; commit or stash them first." >&2
    exit 1
fi

for tag in "${TAG}" "${CADDY_TAG}"; do
    if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
        echo "Tag ${tag} already exists." >&2
        exit 1
    fi
done

LATEST_TAG="$(git tag --list 'v*' --sort=-v:refname | head -n 1)"
if [ -n "${LATEST_TAG}" ]; then
    HIGHEST="$(printf '%s\n%s\n' "${LATEST_TAG#v}" "${VERSION}" | sort -V | tail -n 1)"
    if [ "${HIGHEST}" != "${VERSION}" ] || [ "${LATEST_TAG#v}" = "${VERSION}" ]; then
        echo "Version ${VERSION} must be newer than the latest release ${LATEST_TAG}." >&2
        exit 1
    fi
fi

# Changelog

if ! grep -qxF "## [${VERSION}]" "${CHANGELOG_PATH}"; then
    if ! "${SCRIPT_DIR}/changelog-section.sh" Unreleased >/dev/null; then
        echo "Add the release's changes to the Unreleased section of ${CHANGELOG_PATH} first." >&2
        exit 1
    fi

    echo "==> Moving Unreleased changes under ${VERSION}"
    awk -v version="${VERSION}" '
        { print }
        $0 == "## [Unreleased]" {
            print ""
            print "## [" version "]"
        }
    ' "${CHANGELOG_PATH}" > "${CHANGELOG_PATH}.tmp"
    mv "${CHANGELOG_PATH}.tmp" "${CHANGELOG_PATH}"
fi

if ! grep -q "^\[${VERSION}\]: " "${CHANGELOG_PATH}"; then
    echo "==> Adding ${VERSION} to the changelog links"
    awk -v version="${VERSION}" -v repo="${REPO_URL}" '
        /^\[Unreleased\]: / {
            print "[Unreleased]: " repo "/compare/v" version "...HEAD"
            print "[" version "]: " repo "/releases/tag/v" version
            replaced = 1
            next
        }
        { print }
        END {
            if (!replaced) {
                print "No [Unreleased] link found in the changelog footer" > "/dev/stderr"
                exit 1
            }
        }
    ' "${CHANGELOG_PATH}" > "${CHANGELOG_PATH}.tmp"
    mv "${CHANGELOG_PATH}.tmp" "${CHANGELOG_PATH}"
fi

# Fails when the release section is missing or empty.
"${SCRIPT_DIR}/changelog-section.sh" "${VERSION}" >/dev/null

# Caddy module

# Builds outside this repository ignore caddy/go.mod's replace directive, so
# the plugin must require the root module at the version it is released with.
echo "==> Pointing the Caddy plugin at ${ROOT_MODULE} ${TAG}"
(cd "${CADDY_DIR}" && go mod edit -require="${ROOT_MODULE}@${TAG}" && go build ./...)

# Commit and tag

if [ -n "$(git status --porcelain)" ]; then
    git add "${CHANGELOG_PATH}" "${CADDY_DIR}/go.mod"
    git commit -q -m "Update changelog"
    echo "==> Committed $(git rev-parse --short HEAD) Update changelog"
fi

git tag -s "${TAG}" -m "${VERSION}"
git tag -s "${CADDY_TAG}" -m "${VERSION}"
echo "==> Tagged $(git rev-parse --short HEAD) as ${TAG} and ${CADDY_TAG}"

if [ "${PUSH}" = true ]; then
    git push --atomic origin main "${TAG}" "${CADDY_TAG}"
else
    echo ""
    echo "Review the release, then push it with:"
    echo "  git push --atomic origin main ${TAG} ${CADDY_TAG}"
fi
