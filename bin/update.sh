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

echo ""
echo "==> Done."
