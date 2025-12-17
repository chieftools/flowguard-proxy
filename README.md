# FlowGuard Proxy

A high-performance Go-based reverse proxy with advanced security features, designed to transparently intercept and filter HTTP/HTTPS traffic with dynamic rule-based filtering and minimal disruption.

It features an (optional) [control panel](https://flowguard.network/) for easy management, configuration, and monitoring. The control panel will allow for realtime and centralized management of multiple FlowGuard instances in addition to providing access to GeoIP databases and AbuseIPDB IP lists.

> [!IMPORTANT]  
> FlowGuard is intended for use by experienced system administrators and security professionals. Improper configuration may lead to service disruption. Always test configurations in a safe environment before deploying to production.

> [!CAUTION]
> FlowGuard is a new project in active development and may have undiscovered bugs or security vulnerabilities. Use at your own risk and always keep software up to date.

## Features

### Core Functionality
- **Transparent Traffic Interception**: Redirects traffic from ports 80 and 443 to proxy ports using iptables
- **HTTPS Decryption**: Dynamically loads and manages SSL certificates for transparent HTTPS inspection
- **Automatic Certificate Management**: Monitors and reloads certificates from the filesystem for seamless rotation
- **Graceful Shutdown**: Automatically removes iptables rules on shutdown to restore original traffic flow

### Security Middleware
- **Dynamic Rule-Based Filtering**: Flexible rule engine with conditions for path, domain, IP, ASN, user-agent, headers, ipset, and iplist matching
- **IP Database Integration**: ASN and geolocation lookups using configurable IP databases (MaxMind format)
- **IP List System**: Built-in high-performance in-memory IP lists with automatic URL refresh (10M+ lookups/sec)
- **IPSet Integration**: Direct integration with Linux ipset for kernel-level IP blocking
- **Trusted Proxy Support**: Properly handles X-Forwarded-For headers from configurable trusted proxies
- **Real Client IP Detection**: Extracts actual client IPs through proxy chains for accurate filtering
- **Hot Configuration Reload**: Automatic configuration file monitoring and reloading without restart

### Advanced Features
- **Structured Logging**: Sink-based logging to files, Axiom, Loki, or OpenObserve with hot-reload support
- **Efficient connection handling**: Minimal overhead with optimized middleware chain
- **Certificate caching**: Automatic refresh for seamless rotation
- **Network interface binding**: Support for multi-homed systems
- **Smart caching**: ETag-aware HTTP caching for external resources with stale-while-revalidate
- **Regex optimization**: Compiled pattern caching for rule matching

## Installation

### Prerequisites (for building from source)

- Go 1.25 or later
- Linux system with iptables support
- Root/sudo access for port redirection
- ipset installed for IP filtering (optional)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/chieftools/flowguard-proxy.git
cd flowguard-proxy

# Build for current platform
go build -o flowguard .
```

### Quick Install

```bash
curl -sS https://pkg.flowguard.network/install.sh | sudo bash
```

### Install on Debian/Ubuntu

```bash
# Add FlowGuard repository
curl -sS https://pkg.flowguard.network/gpg.key | gpg --dearmor --yes -o /etc/apt/trusted.gpg.d/flowguard.gpg
echo "deb https://pkg.flowguard.network/deb stable main" | sudo tee /etc/apt/sources.list.d/flowguard.list

# Update package list and install
sudo apt update
sudo apt install flowguard

# Setup initial configuration (optional - use FlowGuard control panel or create manually)
flowguard setup fgsvr_...

# Alternatively create the /etc/flowguard/config.json manually

# Ensure certificates are properly detected
flowguard certificates

# Start the FlowGuard service
sudo systemctl start flowguard

# Enable FlowGuard to start on boot
sudo systemctl enable flowguard
```

### Install on RHEL/CentOS/Rocky/Alma

```bash
# Add FlowGuard repository
sudo tee /etc/yum.repos.d/flowguard.repo << 'EOF'
[flowguard]
name=FlowGuard Repository
baseurl=https://pkg.flowguard.network/rpm/stable/x86_64
enabled=1
gpgcheck=1
gpgkey=https://pkg.flowguard.network/gpg.key
EOF

# Install FlowGuard
sudo yum install flowguard

# Setup initial configuration (optional - use FlowGuard control panel or create manually)
flowguard setup fgsvr_...

# Start the FlowGuard service
sudo systemctl start flowguard

# Enable FlowGuard to start on boot
sudo systemctl enable flowguard
```

### Upgrading

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install --only-upgrade flowguard

# RHEL/CentOS/Rocky/Alma
sudo yum check-update --disablerepo=* --enablerepo=flowguard
sudo yum update flowguard
```

### Configure your server

Since FlowGuard operates as a reverse proxy, backend servers must be configured correctly to see the original client IPs. This typically involves setting up the backend to trust the proxy and extract the real client IP from headers like `X-Forwarded-For`.

This is an example of how this can be done in NGINX, replacing `<public v4 address>` and `<public v6 address>` with the actual public IP addresses of your server:

Remember to add _all_ public IPs assigned to your server if you are using FlowGuard in it's default configuration where it will intercept traffic on all public IPs assigned to the server.

```nginx
real_ip_header X-Forwarded-For;
real_ip_recursive on;
set_real_ip_from <public v4 address>;
set_real_ip_from <public v6 address>;
```

A script that can generate this for you:

```bash
NGINX_CONF=/etc/nginx/conf.d/flowguard.conf

echo "real_ip_header X-Forwarded-For;" > $NGINX_CONF
echo "real_ip_recursive on;" >> $NGINX_CONF
echo "set_real_ip_from "`curl -sS ipv4.chief.tools`";" >> $NGINX_CONF
echo "set_real_ip_from "`curl -sS ipv6.chief.tools`";" >> $NGINX_CONF

cat $NGINX_CONF

service nginx configtest
# service nginx reload
```

## Certificate Management

The proxy expects combined certificate files (cert + key) in the specified certificate path. Files should be named by hostname and contain both the certificate chain and private key.

Certificate files are:
- Loaded on-demand when first requested
- Cached in memory for performance
- Automatically refreshed periodically to support rotation
- Validated on load to ensure proper format

## Logging

FlowGuard provides structured logging with multiple simultaneous destinations (sinks). Each sink can be independently configured and supports hot-reload.

### Supported Sinks

- **File**: Local file logging
- **Axiom**: Axiom analytics platform
- **Loki**: Grafana Loki with JSON flattening
- **OpenObserve**: OpenObserve with automatic field flattening

### Configuration

```json
{
  "logging": {
    "sinks": {
      "local_log": {
        "type": "file",
        "path": "/var/log/flowguard/main.log"
      },
      "axiom": {
        "type": "axiom",
        "token": "xaat-your-token",
        "dataset": "flowguard-production"
      },
      "loki": {
        "type": "loki",
        "url": "http://loki:3100/loki/api/v1/push",
        "labels": {
          "job": "flowguard",
          "environment": "production"
        }
      },
      "openobserve": {
        "type": "openobserve",
        "url": "https://observe.example.com",
        "organization": "my-org",
        "stream": "flowguard",
        "username": "admin@example.com",
        "password": "api-token"
      }
    },
    "header_whitelist": ["cf-", "sec-ch-", "user-agent"]
  }
}
```

### Log Entry Format

Each log entry includes:
- Request details (method, URL, headers, TLS info)
- Client information (IP, country, ASN)
- Rule matching results (which rule matched, action taken)
- Response details (status, timing, headers)
- Host metadata (server ID, hostname, version)

### Smart Config Updates

Sinks are only restarted when their specific configuration changes. Adding, removing, or modifying one sink doesn't affect others.

## Configuration

### Configuration File

FlowGuard uses a JSON configuration file for advanced filtering rules. The configuration supports:

- **Rules**: Define matching conditions and associated actions
- **Actions**: Specify what to do when rules match:
  - `log`: Log request and continue processing (can be overridden by later rules)
  - `allow`: Allow request and stop rule processing
  - `block`: Block request with custom status/message
  - `rate_limit`: Rate limit requests based on defined thresholds
- **IP Database**: Configure IP geolocation database source and refresh interval
- **Trusted Proxies**: Configure trusted proxy networks for proper client IP detection
- **IP Lists**: Configure in-memory IP lists for high-performance matching
- **Logging**: Configure structured logging sinks (file, Axiom, Loki, OpenObserve)

#### JSON Schema Support

The repository includes a `config.schema.json` file that provides:
- **IDE Autocomplete**: IntelliSense support in VS Code, IntelliJ, and other modern IDEs
- **Validation**: Real-time error checking as you edit
- **Documentation**: Inline descriptions for all properties

To use the schema, add this line to your config.json:
```json
{
  "$schema": "https://raw.githubusercontent.com/chieftools/flowguard-proxy/main/config.schema.json"
}
```

Example configuration structure:

```json
{
  "rules": {
    "log-suspicious-agents": {
      "action": "log-action",
      "conditions": {
        "matches": [
          {
            "type": "agent",
            "match": "contains",
            "value": "bot"
          }
        ]
      }
    },
    "block-malicious-agents": {
      "action": "block-403",
      "conditions": {
        "operator": "OR",
        "matches": [
          {
            "type": "agent",
            "match": "contains",
            "value": "scanner"
          }
        ]
      }
    }
  },
  "actions": {
    "log-action": {
      "action": "log"
    },
    "block-403": {
      "action": "block",
      "status": 403,
      "message": "Forbidden"
    }
  },
  "ip_database": {
    "url": "https://example.com/ipinfo.mmdb",
    "refresh_interval_seconds": 86400
  },
  "trusted_proxies": {
    "ipnets": [
      "https://www.cloudflare.com/ips-v4",
      "https://www.cloudflare.com/ips-v6",
      "192.168.1.0/24"
    ],
    "refresh_interval_seconds": 43200
  }
}
```

### Rule Conditions

Rules support complex conditions with logical operators:

- **Operators**: `AND`, `OR`, `NOT`
- **Match Types**:
  - `path`: URL path matching
  - `domain`: Host header matching
  - `user-agent`: User-Agent header matching
  - `header`: Arbitrary header matching
  - `ip`: Client IP matching
  - `asn`: Autonomous System Number matching
  - `as-name`: ASN organization name matching
  - `as-domain`: ASN domain matching
  - `country`: Country code matching (from GeoIP database)
  - `continent`: Continent code matching (from GeoIP database)
  - `ipset`: Linux ipset membership checking (external tool required)
  - `iplist`: In-memory IP list matching (built-in, no dependencies)
- **Match Operations**: `equals`, `not-equals`, `contains`, `not-contains`, `starts-with`, `not-starts-with`, `ends-with`, `not-ends-with`, `regex`, `not-regex`, `in`, `not-in`, `exists`, `missing`

## Security Configuration

### IP List System (Recommended)

FlowGuard includes a built-in high-performance IP list system using radix trees for 10M+ lookups/second. Lists are loaded from URLs or files and automatically refreshed.

**Configuration:**
```json
{
  "ip_lists": {
    "blocklist": {
      "url": "https://example.com/blocklist.txt",
      "refresh_interval_seconds": 3600
    },
    "local_allowlist": {
      "path": "/etc/flowguard/allowlist.txt"
    }
  }
}
```

**List Format:** One IP or CIDR per line (supports both IPv4 and IPv6):
```
192.168.1.1
10.0.0.0/24
2001:db8::/32
```

**Rule Usage:**
```json
{
  "type": "iplist",
  "match": "in",
  "value": "blocklist"
}
```

**Testing:**
```bash
# Show list stats (load time, memory usage, entry count)
flowguard iplist blocklist

# Check if IP is in list
flowguard iplist blocklist contains 192.168.1.1
```

### IPSet Integration (Legacy)

For existing IPSet infrastructure, create and populate lists before starting:

```bash
# Create IPv4 blocklist
sudo ipset create abuseipdb_v4 hash:net

# Create IPv6 blocklist
sudo ipset create abuseipdb_v6 hash:net family inet6

# Add IPs to blocklist
sudo ipset add abuseipdb_v4 192.168.1.100
sudo ipset add abuseipdb_v6 2001:db8::1
```

**Note:** IP Lists (`iplist` type) are recommended for new deployments due to easier management, automatic updates, and unified IPv4/IPv6 support. Use IPSet (`ipset` type) only if you have existing IPSet infrastructure.

### Dynamic Security Rules

The proxy uses a flexible rule engine defined in the configuration file. Rules can be updated without restarting the service by modifying the configuration file - FlowGuard automatically detects and reloads changes.

## Architecture

### Components

- **Main**: Entry point, command-line parsing, signal handling
- **Proxy Manager**: Coordinates proxy servers, iptables/TPROXY rules, and graceful shutdown
- **HTTP/HTTPS Servers**: Handle incoming requests and forward to backends
- **Certificate Manager**: Dynamic SSL certificate loading and management
- **Configuration Manager**: Hot-reload configuration with rule management
- **Cache System**: Caching layer for external data fetches with ETag support
- **IP List Manager**: High-performance radix tree-based IP list matching
- **Logger Manager**: Sink-based structured logging with hot-reload
- **Middleware Chain**:
  - Rules Engine: Dynamic rule-based filtering with complex conditions
  - IP Lookup: ASN and geolocation database integration
  - Client IP extraction from trusted proxy chains

### Traffic Flow

1. Original traffic to ports 80/443 is redirected via iptables to proxy ports
2. Proxy receives connection and extracts real client IP through trusted proxy chains
3. For HTTPS, appropriate certificate is loaded/retrieved from cache
4. Rules engine evaluates all configured rules against the request
5. Request is either logged, blocked, or allowed based on rule evaluation
6. Valid requests are forwarded to original destination
7. Response is returned to client through proxy with appropriate headers

## Development

### Running Tests

```bash
go test ./...
```

## Security Vulnerabilities

If you discover a security vulnerability within this project, please report it privately via GitHub: https://github.com/chieftools/flowguard-proxy/security/advisories/new.
All security vulnerabilities will be swiftly addressed. There is no bug bounty program at this time.

## License

FlowGuard Proxy is open-source software licensed under the Apache License 2.0. This means you are free to use, modify, and distribute the software for both commercial and non-commercial purposes. See the [LICENSE](LICENSE) file for details.
