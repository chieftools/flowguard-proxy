#!/bin/bash
# Install FlowGuard from the FlowGuard package repository:
#
#   curl -fsSL __PACKAGE_BASE_URL__/install.sh | sudo bash
#
# This configures the signed apt or yum/dnf repository under the names the
# updater looks for, then installs the flowguard package. It does not set up
# the server: run `flowguard setup <key>` from FlowGuard afterwards. Running it
# again is safe.
#
# bin/generate-install-sh.sh fills in the repository URL.

set -euo pipefail

PACKAGE_BASE_URL="__PACKAGE_BASE_URL__"

KEYRING=/etc/apt/keyrings/flowguard.gpg
LEGACY_KEYRING=/etc/apt/trusted.gpg.d/flowguard.gpg
APT_SOURCES=/etc/apt/sources.list.d/flowguard.sources
APT_LIST=/etc/apt/sources.list.d/flowguard.list
YUM_REPO=/etc/yum.repos.d/flowguard.repo

fail() {
    echo "FlowGuard install: $*" >&2
    exit 1
}

if [ "$(id -u)" -ne 0 ]; then
    fail "run this script as root, for example with sudo bash."
fi

if ! command -v curl >/dev/null 2>&1; then
    fail "curl is required."
fi

# Detect architecture
MACHINE_ARCH="$(uname -m)"
case "${MACHINE_ARCH}" in
    x86_64|amd64)  RPM_ARCH="x86_64"; DEB_ARCH="amd64" ;;
    aarch64|arm64) RPM_ARCH="aarch64"; DEB_ARCH="arm64" ;;
    *) fail "unsupported architecture ${MACHINE_ARCH}." ;;
esac

# Detect OS. Derivatives such as CloudLinux or Linux Mint name their parent
# distributions in ID_LIKE, so fall back to that when ID is unknown.
if [ ! -r /etc/os-release ]; then
    fail "cannot detect the distribution: /etc/os-release is missing."
fi
# shellcheck source=/dev/null
OS_ID="$(. /etc/os-release && printf '%s' "${ID:-}")"
# shellcheck source=/dev/null
OS_ID_LIKE="$(. /etc/os-release && printf '%s' "${ID_LIKE:-}")"

OS_FAMILY=""
for CANDIDATE in ${OS_ID} ${OS_ID_LIKE}; do
    case "${CANDIDATE}" in
        ubuntu|debian) OS_FAMILY="debian"; break ;;
        centos|rhel|rocky|almalinux|cloudlinux|fedora) OS_FAMILY="rhel"; break ;;
    esac
done

# The binary form of the ASCII-armored key, without depending on gpg (which
# minimal Debian installs lack): the armor's base64 body minus its headers
# and checksum line. No POSIX character classes: Ubuntu 16.04 and older
# ship mawk 1.3.3, which lacks them.
dearmor() {
    awk '
        /^-----BEGIN PGP PUBLIC KEY BLOCK-----/ { body = 1; headers = 1; next }
        /^-----END PGP PUBLIC KEY BLOCK-----/ { body = 0 }
        body && headers { if ($0 ~ /^[ \t\r]*$/) headers = 0; next }
        body && !/^=/ { print }
    ' | base64 -d
}

# Write the repository source for apt: deb822 with signed-by from apt 1.1,
# a one-line .list with the key in trusted.gpg.d before that.
write_apt_source() {
    local url="$1"

    if dpkg --compare-versions "${APT_VERSION:-0}" ge 1.1; then
        # Add repository using deb822 format, trusting the key for it only
        rm -f "${APT_LIST}" "${LEGACY_KEYRING}"
        printf '%s\n' \
            'Types: deb' \
            "URIs: ${url}/deb" \
            'Suites: stable' \
            'Components: main' \
            "Architectures: ${DEB_ARCH}" \
            "Signed-By: ${KEYRING}" \
            > "${APT_SOURCES}"
        SOURCES="${APT_SOURCES}"
    else
        # apt 1.0 (Ubuntu 14.04) reads neither deb822 files nor signed-by,
        # so the key goes into apt-key's trusted.gpg.d. FlowGuard cannot
        # upgrade itself with this apt (it needs 1.1 or later).
        rm -f "${APT_SOURCES}"
        install -m 0644 "${KEYRING}" "${LEGACY_KEYRING}"
        printf 'deb [arch=%s] %s/deb stable main\n' "${DEB_ARCH}" "${url}" > "${APT_LIST}"
        SOURCES="${APT_LIST}"
    fi
}

# Whether apt offers the flowguard package.
apt_has_flowguard() {
    local candidate
    candidate="$(apt-cache policy flowguard 2>/dev/null | awk '/Candidate:/ { print $2 }')"
    [ -n "${candidate}" ] && [ "${candidate}" != "(none)" ]
}

# Refresh the FlowGuard repository only, the way the updater does, so
# unrelated broken repositories cannot get in the way. Succeeds when apt then
# offers the flowguard package.
refresh_apt_source() {
    apt-get update \
        -o Dir::Etc::sourcelist="${SOURCES}" \
        -o Dir::Etc::sourceparts=- \
        -o APT::Get::List-Cleanup=0 || true

    apt_has_flowguard
}

install_apt() {
    echo "Setting up the FlowGuard repository for Debian/Ubuntu..."

    # Keep apt and its hooks from prompting, as the updater does. Piped into
    # bash, nobody can answer a dialog such as needrestart's "Pending kernel
    # upgrade", and reading stdin would eat this script.
    export DEBIAN_FRONTEND=noninteractive APT_LISTCHANGES_FRONTEND=none NEEDRESTART_SUSPEND=1

    APT_VERSION="$(dpkg-query -W -f='${Version}' apt 2>/dev/null || true)"
    REPOSITORY_URL="${PACKAGE_BASE_URL}"

    # Refresh every repository: FlowGuard depends on iptables and iproute2.
    # Unrelated third-party repositories can make "apt-get update" return
    # non-zero even when the rest fetched fine.
    if ! apt-get update; then
        echo "apt-get update reported errors; continuing because unrelated repositories may be broken."
    fi

    # apt before 1.5 needs apt-transport-https for HTTPS repositories.
    if [ "${REPOSITORY_URL#https:}" != "${REPOSITORY_URL}" ] && [ ! -e /usr/lib/apt/methods/https ]; then
        echo "Installing apt-transport-https..."
        if ! apt-get install -y apt-transport-https ca-certificates < /dev/null; then
            echo "Could not install apt-transport-https; apt will use the repository over HTTP."
            REPOSITORY_URL="http://${PACKAGE_BASE_URL#https://}"
        fi
    fi

    # Add GPG key. curl brings its own TLS, which works where apt's may not.
    install -d -m 0755 /etc/apt/keyrings
    curl -fsSL "${PACKAGE_BASE_URL}/gpg.key" | dearmor > "${KEYRING}.tmp"
    if [ ! -s "${KEYRING}.tmp" ]; then
        rm -f "${KEYRING}.tmp"
        fail "could not download the repository signing key."
    fi
    chmod 0644 "${KEYRING}.tmp"
    mv -f "${KEYRING}.tmp" "${KEYRING}"

    write_apt_source "${REPOSITORY_URL}"

    if ! refresh_apt_source; then
        if [ "${REPOSITORY_URL#https:}" = "${REPOSITORY_URL}" ]; then
            fail "apt could not read the FlowGuard repository at ${REPOSITORY_URL}."
        fi

        # apt's HTTPS can be too old for the repository host: Ubuntu 14.04's
        # GnuTLS has none of its ciphers. The repository's metadata is signed
        # and checked by apt, so HTTP only gives up privacy, not integrity.
        echo "apt could not reach the FlowGuard repository over HTTPS; using HTTP instead. Packages stay signature-checked."
        REPOSITORY_URL="http://${PACKAGE_BASE_URL#https://}"
        write_apt_source "${REPOSITORY_URL}"

        if ! refresh_apt_source; then
            fail "apt could not read the FlowGuard repository over HTTPS or HTTP."
        fi
    fi

    apt-get install -y flowguard < /dev/null
}

install_rpm() {
    echo "Setting up the FlowGuard repository for RHEL/CentOS/Rocky/Alma/Fedora/CloudLinux..."

    # Add repository
    cat > "${YUM_REPO}.tmp" << EOF
[flowguard]
name=FlowGuard Repository
baseurl=${PACKAGE_BASE_URL}/rpm/stable/${RPM_ARCH}
enabled=1
gpgcheck=1
gpgkey=${PACKAGE_BASE_URL}/gpg.key
EOF
    chmod 0644 "${YUM_REPO}.tmp"
    mv -f "${YUM_REPO}.tmp" "${YUM_REPO}"

    if command -v dnf >/dev/null 2>&1; then
        PACKAGE_MANAGER=dnf
    elif command -v yum >/dev/null 2>&1; then
        PACKAGE_MANAGER=yum
    else
        fail "neither dnf nor yum found."
    fi

    # Try the FlowGuard repository on its own first: EOL releases such as
    # CentOS 7 often have unreachable mirrors configured. That works when
    # iptables and iproute are installed already, which they usually are.
    if ! "${PACKAGE_MANAGER}" -y --disablerepo='*' --enablerepo=flowguard install flowguard; then
        echo "Installing with every repository, for the iptables and iproute dependencies..."
        "${PACKAGE_MANAGER}" -y install flowguard
    fi
}

case "${OS_FAMILY}" in
    debian) install_apt ;;
    rhel) install_rpm ;;
    *)
        echo "Unsupported OS: ${OS_ID:-unknown}" >&2
        echo "Please install manually from https://github.com/chieftools/flowguard-proxy/releases" >&2
        exit 1
        ;;
esac

echo ""
echo "FlowGuard installed: $(flowguard version)"
echo "Set up this server with the setup command shown in https://flowguard.network:"
echo "  sudo flowguard setup <key>"
if [ -d /run/systemd/system ]; then
    echo "Then start the service, also on boot:"
    echo "  sudo systemctl enable --now flowguard"
elif command -v update-rc.d >/dev/null 2>&1; then
    echo "Then start the service, also on boot:"
    echo "  sudo update-rc.d flowguard defaults && sudo /etc/init.d/flowguard start"
elif command -v chkconfig >/dev/null 2>&1; then
    echo "Then start the service, also on boot:"
    echo "  sudo chkconfig --add flowguard && sudo chkconfig flowguard on && sudo /etc/init.d/flowguard start"
else
    echo "Then start it:"
    echo "  sudo flowguard run --log-file /var/log/flowguard/flowguard.log"
fi
