#!/bin/bash

set -e

# Package information
PACKAGE_NAME="flowguard"
VERSION="${1:-1.0.0}"
RELEASE="${2:-1}"
ARCH="x86_64"
MAINTAINER="FlowGuard Team <hello@flowguard.network>"
DESCRIPTION="High-performance reverse proxy with dynamic rule-based security filtering."
URL="https://flowguard.network"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Building FlowGuard RPM package v${VERSION}-${RELEASE}${NC}"

# Detect if we're on macOS and need to use Docker
USE_DOCKER=false
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo -e "${YELLOW}Detected macOS - checking for Docker...${NC}"
    if command -v docker &> /dev/null; then
        USE_DOCKER=true
        echo -e "${GREEN}Using Docker to build RPM package${NC}"
    else
        echo -e "${RED}Error: Docker is required to build RPM packages on macOS${NC}"
        echo -e "${YELLOW}Please install Docker Desktop from https://www.docker.com/products/docker-desktop${NC}"
        exit 1
    fi
fi

# Create temporary build directory
BUILD_DIR="$(mktemp -d)"
RPMBUILD_DIR="${BUILD_DIR}/rpmbuild"

echo -e "${YELLOW}Creating RPM build structure...${NC}"

# Create RPM build directory structure
mkdir -p "${RPMBUILD_DIR}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
mkdir -p "${RPMBUILD_DIR}/BUILDROOT"

# Build the binary for Linux AMD64
echo -e "${YELLOW}Building FlowGuard binary...${NC}"
BINARY_DIR="${RPMBUILD_DIR}/BUILD"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -tags netgo,osusergo -buildvcs=false -o "${BINARY_DIR}/flowguard" .

# Strip the binary to reduce size
strip "${BINARY_DIR}/flowguard" 2>/dev/null || true

# Create default configuration file
echo -e "${YELLOW}Creating default configuration...${NC}"
mkdir -p "${RPMBUILD_DIR}/SOURCES"
cat > "${RPMBUILD_DIR}/SOURCES/config.json" << 'EOF'
{
  "$schema": "https://pkg.flowguard.network/config.schema.json",
  "host": {
    "cache_dir": "/var/cache/flowguard",
  },
  "rules": {},
  "actions": {},
  "logging": null,
  "ip_database": null,
  "trusted_proxies": null
}
EOF

# Create systemd service file
echo -e "${YELLOW}Creating systemd service file...${NC}"
cat > "${RPMBUILD_DIR}/SOURCES/flowguard.service" << 'EOF'
[Unit]
Description=FlowGuard Security Proxy
Documentation=https://flowguard.network
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/bin/flowguard --config /etc/flowguard/config.json
ExecReload=/bin/kill -HUP $MAINPID
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30s
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

# Create the spec file
echo -e "${YELLOW}Creating RPM spec file...${NC}"
cat > "${RPMBUILD_DIR}/SPECS/flowguard.spec" << EOF
Name:           ${PACKAGE_NAME}
Version:        ${VERSION}
Release:        ${RELEASE}%{?dist}
Summary:        ${DESCRIPTION}

License:        Proprietary
URL:            ${URL}
Source0:        config.json
Source1:        flowguard.service

# Don't strip the binary or check for build-id
%global debug_package %{nil}
%global _build_id_links none
%define _binaries_in_noarch_packages_terminate_build 0

Requires:       iptables
Recommends:     ipset

%description
FlowGuard is a high-performance Go-based reverse proxy with
dynamic rule-based security filtering designed for transparent
HTTP/HTTPS traffic interception.

%prep
# No prep needed - binary is pre-built

%build
# No build needed - binary is pre-built

%install
rm -rf %{buildroot}

# Create directory structure
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/etc/flowguard
mkdir -p %{buildroot}/var/log/flowguard
mkdir -p %{buildroot}/var/cache/flowguard
mkdir -p %{buildroot}/usr/lib/systemd/system

# Install binary
install -m 0755 %{_builddir}/flowguard %{buildroot}/usr/bin/flowguard

# Install configuration
install -m 0644 %{SOURCE0} %{buildroot}/etc/flowguard/config.json

# Install systemd service
install -m 0644 %{SOURCE1} %{buildroot}/usr/lib/systemd/system/flowguard.service

%files
%attr(0755, root, root) /usr/bin/flowguard
%config(noreplace) %attr(0644, root, root) /etc/flowguard/config.json
%attr(0755, root, root) %dir /etc/flowguard
%attr(0755, root, root) %dir /var/log/flowguard
%attr(0755, root, root) %dir /var/cache/flowguard
%attr(0644, root, root) /usr/lib/systemd/system/flowguard.service

%pre
# Pre-installation script
exit 0

%post
# Post-installation script

# Create runtime directories if they don't exist
mkdir -p /etc/flowguard
mkdir -p /var/log/flowguard
mkdir -p /var/cache/flowguard

# Set proper ownership and permissions
chown -R root:root /var/log/flowguard
chown -R root:root /var/cache/flowguard
chown -R root:root /etc/flowguard
chmod 755 /etc/flowguard
chmod 644 /etc/flowguard/config.json
chmod 755 /usr/bin/flowguard

# Reload systemd
systemctl daemon-reload

# Check if this is an upgrade
if [ "\$1" -eq 2 ]; then
    # This is an upgrade - restart the service if it was previously enabled
    if systemctl is-enabled --quiet flowguard.service 2>/dev/null; then
        echo "Restarting FlowGuard service after upgrade..."
        systemctl restart flowguard.service || true
    fi
else
    # Fresh install - show setup instructions
    echo ""
    echo "FlowGuard has been installed successfully!"
    echo ""
    echo "To configure FlowGuard:"
    echo "  1. Edit the configuration file: /etc/flowguard/config.json or follow instructions from https://flowguard.network"
    echo "  2. Start the service: systemctl start flowguard"
    echo "  3. Start the service on boot: systemctl enable flowguard"
    echo ""
    echo "Important directories:"
    echo "  Configuration: /etc/flowguard/"
    echo "  Cache:         /var/cache/flowguard/"
    echo "  Logs:          /var/log/flowguard/"
    echo ""
    echo "To check service status: systemctl status flowguard"
    echo "To view logs: journalctl -u flowguard -f"
    echo ""
fi

exit 0

%preun
# Pre-uninstallation script

# Stop the service if it's running
if systemctl is-active --quiet flowguard.service; then
    echo "Stopping FlowGuard service..."
    systemctl stop flowguard.service || true
fi

# Only disable service on actual removal, not upgrades
if [ "\$1" -eq 0 ]; then
    if systemctl is-enabled --quiet flowguard.service; then
        systemctl disable flowguard.service || true
    fi
fi

exit 0

%postun
# Post-uninstallation script

# Reload systemd after removal
systemctl daemon-reload || true

# On complete removal (not upgrade), clean up
if [ "\$1" -eq 0 ]; then
    # Remove logs and cache (but keep config in case of reinstall)
    # To fully remove, use: rpm -e --allmatches flowguard && rm -rf /etc/flowguard
    rm -rf /var/log/flowguard
    rm -rf /var/cache/flowguard
fi

exit 0

%changelog
* $(date +'%a %b %d %Y') ${MAINTAINER} - ${VERSION}-${RELEASE}
- Package release of FlowGuard v${VERSION}

EOF

# Build the RPM package
echo -e "${YELLOW}Building RPM package...${NC}"

if [ "$USE_DOCKER" = true ]; then
    # Build using Docker with Rocky Linux
    echo -e "${YELLOW}Building RPM in Docker container...${NC}"

    # Create a Dockerfile for the build
    cat > "${BUILD_DIR}/Dockerfile" << 'DOCKERFILE_EOF'
FROM rockylinux:8

RUN yum install -y rpm-build rpmdevtools

WORKDIR /build

CMD ["rpmbuild", "--define", "_topdir /build/rpmbuild", \
     "--define", "_builddir /build/rpmbuild/BUILD", \
     "-bb", "/build/rpmbuild/SPECS/flowguard.spec"]
DOCKERFILE_EOF

    # Build the Docker image
    docker build -t flowguard-rpm-builder "${BUILD_DIR}" > /dev/null 2>&1

    # Run the build in Docker (with --target x86_64 to specify architecture)
    docker run --rm -v "${BUILD_DIR}:/build" flowguard-rpm-builder \
        rpmbuild --define "_topdir /build/rpmbuild" \
                 --define "_builddir /build/rpmbuild/BUILD" \
                 --target x86_64 \
                 -bb /build/rpmbuild/SPECS/flowguard.spec

    # Clean up Docker image
    docker rmi flowguard-rpm-builder > /dev/null 2>&1 || true
else
    # Build natively on Linux
    rpmbuild --define "_topdir ${RPMBUILD_DIR}" \
             --define "_builddir ${BINARY_DIR}" \
             --target "${ARCH}" \
             -bb "${RPMBUILD_DIR}/SPECS/flowguard.spec"
fi

# Find and move the built RPM to current directory
PACKAGE_FILE="${PACKAGE_NAME}-${VERSION}-${RELEASE}.${ARCH}.rpm"
if [ -f "${RPMBUILD_DIR}/RPMS/${ARCH}/${PACKAGE_NAME}-${VERSION}-${RELEASE}"*.rpm ]; then
    mv "${RPMBUILD_DIR}/RPMS/${ARCH}/${PACKAGE_NAME}-${VERSION}-${RELEASE}"*.rpm "./${PACKAGE_FILE}"
else
    echo -e "${RED}Error: RPM package not found in expected location${NC}"
    echo "Looking in: ${RPMBUILD_DIR}/RPMS/"
    find "${RPMBUILD_DIR}/RPMS/" -name "*.rpm" 2>/dev/null || true
    exit 1
fi

# Clean up
rm -rf "${BUILD_DIR}"

# Display package info
echo -e "${GREEN}Package built successfully!${NC}"
echo -e "${GREEN}Package: ${PACKAGE_FILE}${NC}"
echo ""
echo "Package information:"
rpm -qip "${PACKAGE_FILE}"
echo ""
echo "Package contents:"
rpm -qlp "${PACKAGE_FILE}"
echo ""
echo -e "${GREEN}To install: sudo rpm -ivh ${PACKAGE_FILE}${NC}"
echo -e "${GREEN}To upgrade: sudo rpm -Uvh ${PACKAGE_FILE}${NC}"
echo -e "${GREEN}To remove:  sudo rpm -e ${PACKAGE_NAME}${NC}"
