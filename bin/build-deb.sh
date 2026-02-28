#!/bin/bash

set -e

# Package information
PACKAGE_NAME="flowguard"
VERSION="${1:-1.0.0}"
ARCH="amd64"
MAINTAINER="FlowGuard Team <hello@flowguard.network>"
DESCRIPTION="High-performance reverse proxy with dynamic rule-based security filtering."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Building FlowGuard Debian package v${VERSION}${NC}"

# Create temporary build directory
BUILD_DIR="$(mktemp -d)"
DEB_DIR="${BUILD_DIR}/${PACKAGE_NAME}_${VERSION}_${ARCH}"

echo -e "${YELLOW}Creating package structure...${NC}"

# Create Debian package structure
mkdir -p "${DEB_DIR}/DEBIAN"
mkdir -p "${DEB_DIR}/usr/bin"
mkdir -p "${DEB_DIR}/etc/flowguard"
mkdir -p "${DEB_DIR}/etc/systemd/system"
mkdir -p "${DEB_DIR}/var/log/flowguard"
mkdir -p "${DEB_DIR}/var/cache/flowguard"
mkdir -p "${DEB_DIR}/usr/share/doc/flowguard"

# Build the binary for Linux AMD64
echo -e "${YELLOW}Building FlowGuard binary...${NC}"
GOEXPERIMENT=nogreenteagc CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -tags netgo,osusergo -buildvcs=false -o "${DEB_DIR}/usr/bin/flowguard" .

# Strip the binary to reduce size
strip "${DEB_DIR}/usr/bin/flowguard" 2>/dev/null || true

# Create default configuration file
echo -e "${YELLOW}Creating default configuration...${NC}"
cat > "${DEB_DIR}/etc/flowguard/config.json" << 'EOF'
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
cat > "${DEB_DIR}/etc/systemd/system/flowguard.service" << 'EOF'
[Unit]
Description=FlowGuard Security Proxy
Documentation=https://flowguard.network
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/bin/flowguard run --config /etc/flowguard/config.json
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

# Create control file
echo -e "${YELLOW}Creating control file...${NC}"
INSTALLED_SIZE=$(du -sk "${DEB_DIR}" | cut -f1)
cat > "${DEB_DIR}/DEBIAN/control" << EOF
Package: ${PACKAGE_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Installed-Size: ${INSTALLED_SIZE}
Maintainer: ${MAINTAINER}
Description: ${DESCRIPTION}
 FlowGuard is a high-performance Go-based reverse proxy with
 dynamic rule-based security filtering designed for transparent
 HTTP/HTTPS traffic interception.
Depends: iptables
Suggests: ipset
EOF

# Create postinst script
echo -e "${YELLOW}Creating post-installation script...${NC}"
cat > "${DEB_DIR}/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

# Create runtime directories if they don't exist
mkdir -p /etc/flowguard
mkdir -p /var/log/flowguard
mkdir -p /var/cache/flowguard

# Set proper ownership and permissions
chown -R root:root /etc/flowguard
chown -R root:root /var/log/flowguard
chown -R root:root /var/cache/flowguard
chmod 755 /etc/flowguard
chmod 644 /etc/flowguard/config.json
chmod 755 /usr/bin/flowguard

# Reload systemd
systemctl daemon-reload

# Check if this is an upgrade
if [ "$1" = "configure" ] && [ -n "$2" ]; then
    # This is an upgrade - restart the service if it was running.
    # The service was left running during the upgrade (not stopped in prerm),
    # so try-restart will restart it to pick up the new binary.
    systemctl try-restart flowguard.service || true
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
EOF
chmod 755 "${DEB_DIR}/DEBIAN/postinst"

# Create prerm script
echo -e "${YELLOW}Creating pre-removal script...${NC}"
cat > "${DEB_DIR}/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e

# Only stop the service on removal, not on upgrades.
# On upgrades we leave the service running; postinst will try-restart it
# to pick up the new binary (this is the standard dh_installsystemd pattern).
if [ "$1" = "remove" ]; then
    if systemctl is-active --quiet flowguard.service 2>/dev/null; then
        echo "Stopping FlowGuard service..."
        systemctl stop flowguard.service || true
    fi
    if systemctl is-enabled --quiet flowguard.service 2>/dev/null; then
        systemctl disable flowguard.service || true
    fi
fi

exit 0
EOF
chmod 755 "${DEB_DIR}/DEBIAN/prerm"

# Create postrm script
echo -e "${YELLOW}Creating post-removal script...${NC}"
cat > "${DEB_DIR}/DEBIAN/postrm" << 'EOF'
#!/bin/bash
set -e

# Reload systemd after removal
systemctl daemon-reload || true

# On purge, remove configuration, logs and cache
if [ "$1" = "purge" ]; then
    rm -rf /etc/flowguard
    rm -rf /var/log/flowguard
    rm -rf /var/cache/flowguard
fi

exit 0
EOF
chmod 755 "${DEB_DIR}/DEBIAN/postrm"

# Create conffiles to preserve configuration during upgrades
echo -e "${YELLOW}Marking configuration files...${NC}"
cat > "${DEB_DIR}/DEBIAN/conffiles" << EOF
/etc/flowguard/config.json
EOF

# Create changelog
echo -e "${YELLOW}Creating changelog...${NC}"
cat > "${DEB_DIR}/usr/share/doc/flowguard/changelog" << EOF
flowguard (${VERSION}) stable; urgency=medium

  * Package release of FlowGuard v${VERSION}

 -- ${MAINTAINER}  $(date -R)
EOF
gzip -9 "${DEB_DIR}/usr/share/doc/flowguard/changelog"

# Build the package
echo -e "${YELLOW}Building Debian package...${NC}"
dpkg-deb --build --root-owner-group -Zgzip "${DEB_DIR}"

# Move package to current directory
PACKAGE_FILE="${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"
mv "${BUILD_DIR}/${PACKAGE_FILE}" .

# Clean up
rm -rf "${BUILD_DIR}"

# Display package info
echo -e "${GREEN}Package built successfully!${NC}"
echo -e "${GREEN}Package: ${PACKAGE_FILE}${NC}"
echo ""
echo "Package information:"
dpkg-deb --info "${PACKAGE_FILE}"
echo ""
echo "Package contents:"
dpkg-deb --contents "${PACKAGE_FILE}" | head -20
echo "..."
echo ""
echo -e "${GREEN}To install: sudo dpkg -i ${PACKAGE_FILE}${NC}"
echo -e "${GREEN}To remove: sudo dpkg -r ${PACKAGE_NAME}${NC}"
echo -e "${GREEN}To purge:  sudo dpkg -P ${PACKAGE_NAME}${NC}"
