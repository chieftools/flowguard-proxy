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

# Build DEB packages
echo -e "${YELLOW}[1/4] Building Debian amd64 package...${NC}"
echo ""
"${SCRIPT_DIR}/build-deb.sh" "${VERSION}" "amd64"
echo ""

echo -e "${YELLOW}[2/4] Building Debian arm64 package...${NC}"
echo ""
"${SCRIPT_DIR}/build-deb.sh" "${VERSION}" "arm64"
echo ""

# Build RPM packages
echo -e "${YELLOW}[3/4] Building RPM x86_64 package...${NC}"
echo ""
"${SCRIPT_DIR}/build-rpm.sh" "${VERSION}" "${RELEASE}" "x86_64"
echo ""

echo -e "${YELLOW}[4/4] Building RPM aarch64 package...${NC}"
echo ""
"${SCRIPT_DIR}/build-rpm.sh" "${VERSION}" "${RELEASE}" "aarch64"
echo ""

# Summary
echo -e "${BLUE}======================================${NC}"
echo -e "${GREEN}All packages built successfully!${NC}"
echo -e "${BLUE}======================================${NC}"
echo ""
echo "Built packages:"
ls -lh flowguard_${VERSION}_amd64.deb flowguard_${VERSION}_arm64.deb \
       flowguard-${VERSION}-${RELEASE}.x86_64.rpm flowguard-${VERSION}-${RELEASE}.aarch64.rpm 2>/dev/null || {
    echo -e "${RED}Warning: Some package files may not be found${NC}"
    ls -lh flowguard*.deb flowguard*.rpm 2>/dev/null || true
}
echo ""
