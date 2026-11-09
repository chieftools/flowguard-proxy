#!/bin/bash

set -e

echo "==> Updating direct dependencies..."
go get -u ./...

echo ""
echo "==> Tidying go.mod and go.sum..."
go mod tidy

echo ""
echo "==> Outdated direct dependencies:"
go list -m -u -mod=mod -f '{{if and (not .Indirect) .Update}}{{.Path}}: {{.Version}} -> {{.Update.Version}}{{end}}' all 2>/dev/null | grep -v '^$' || echo "All direct dependencies are up to date."

# The Caddy plugin is a nested module that ./... does not reach. Tidying it
# raises the dependencies it shares with the root module to the versions above.
# Caddy itself is not updated here because CI builds it at a pinned version.
echo ""
echo "==> Tidying the Caddy plugin module..."
(cd caddy && go mod tidy)

# Shared dependencies can move past what the pinned Caddy release compiles
# against, which otherwise only surfaces when bin/release.sh builds the plugin.
echo ""
echo "==> Building the Caddy plugin module..."
if ! (cd caddy && go build ./...); then
    echo "" >&2
    echo "The Caddy plugin no longer builds against the updated dependencies." >&2
    echo "Pin the offending shared dependency in go.mod and caddy/go.mod until Caddy supports it." >&2
    exit 1
fi

echo ""
echo "==> Outdated direct Caddy plugin dependencies:"
(cd caddy && go list -m -u -mod=mod -f '{{if and (not .Indirect) .Update}}{{.Path}}: {{.Version}} -> {{.Update.Version}}{{end}}' all 2>/dev/null | grep -v '^$') || echo "All direct dependencies are up to date."

echo ""
echo "==> Done."
