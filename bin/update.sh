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

echo ""
echo "==> Outdated direct Caddy plugin dependencies:"
(cd caddy && go list -m -u -mod=mod -f '{{if and (not .Indirect) .Update}}{{.Path}}: {{.Version}} -> {{.Update.Version}}{{end}}' all 2>/dev/null | grep -v '^$') || echo "All direct dependencies are up to date."

echo ""
echo "==> Done."
