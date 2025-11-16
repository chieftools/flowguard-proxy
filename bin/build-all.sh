#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get version from argument or use default
VERSION="${1:-1.0.0}"
RELEASE="${2:-1}"

echo -e "${BLUE}======================================${NC}"
echo -e "${BLUE}Building FlowGuard Packages v${VERSION}${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Build DEB package
echo -e "${YELLOW}[1/2] Building Debian package...${NC}"
echo ""
"${SCRIPT_DIR}/build-deb.sh" "${VERSION}"
echo ""

# Build RPM package
echo -e "${YELLOW}[2/2] Building RPM package...${NC}"
echo ""
"${SCRIPT_DIR}/build-rpm.sh" "${VERSION}" "${RELEASE}"
echo ""

# Summary
echo -e "${BLUE}======================================${NC}"
echo -e "${GREEN}All packages built successfully!${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""
echo "Built packages:"
ls -lh flowguard_${VERSION}_amd64.deb flowguard-${VERSION}-${RELEASE}.x86_64.rpm 2>/dev/null || {
    echo -e "${RED}Warning: Some package files may not be found${NC}"
    ls -lh flowguard*.deb flowguard*.rpm 2>/dev/null || true
}
echo ""
