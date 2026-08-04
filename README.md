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
- **Dynamic Rule-Based Filtering**: Flexible rule engine with conditions for path, method, domain, IP/CIDR, ASN, user-agent, headers, query parameters, cookies, and iplist matching
- **IP Database Integration**: ASN and geolocation lookups using configurable IP databases (MaxMind format)
- **IP List System**: Built-in high-performance in-memory IP lists with automatic URL refresh (10M+ lookups/sec)
- **Trusted Proxy Support**: Properly handles X-Forwarded-For headers from configurable trusted proxies
- **Real Client IP Detection**: Extracts actual client IPs through proxy chains for accurate filtering
- **Hot Configuration Reload**: Automatic configuration file monitoring and reloading without restart

### Advanced Features
- **Structured Logging**: Sink-based logging to files, Loki, or OpenObserve with hot-reload support
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
# Create a dedicated keyring directory
sudo install -d -m 0755 /etc/apt/keyrings

# Add the FlowGuard repository key
curl -fsSL https://pkg.flowguard.network/gpg.key | sudo gpg --dearmor --yes -o /etc/apt/keyrings/flowguard.gpg
sudo chmod a+r /etc/apt/keyrings/flowguard.gpg

# Detect the local Debian architecture
DEB_ARCH="$(dpkg --print-architecture)"

# Add the FlowGuard repository
cat <<EOF | sudo tee /etc/apt/sources.list.d/flowguard.sources >/dev/null
Types: deb
URIs: https://pkg.flowguard.network/deb
Suites: stable
Components: main
Architectures: ${DEB_ARCH}
Signed-By: /etc/apt/keyrings/flowguard.gpg
EOF

# Update package list and install
sudo apt update
sudo apt install flowguard

# Setup initial configuration (optional - use FlowGuard control panel or create manually)
# Alternatively create the /etc/flowguard/config.json manually
flowguard setup fgsvr_...

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
sudo yum clean expire-cache --disablerepo=* --enablerepo=flowguard
sudo yum update flowguard
```

### Configure your server

FlowGuard supports two upstream client-IP modes. The default, `headers`, works with any HTTP backend. FlowGuard removes incoming forwarding headers and writes canonical `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`, and `X-Forwarded-Proto` values from its validated client identity.

The backend must trust only connections that actually came through FlowGuard. Trusting a public server address is not inherently unsafe, but it becomes a spoofing risk if an attacker or another local workload can reach the backend directly while supplying its own forwarding headers. FlowGuard installs a direct-port guard for its interception listeners; you should still keep backend exposure and local workload access as narrow as possible.

`set_real_ip_from` matches the TCP source address of the peer sending the forwarding header; it does not trust every request sent to that public destination. When FlowGuard is disabled, a direct client's source address does not match the server's own public address, so NGINX ignores client-supplied forwarding headers. If a CDN or another trusted proxy may connect directly while FlowGuard is disabled, keep that proxy's ranges in the trusted set as well.

For NGINX, replace the example addresses with every address on which FlowGuard accepts traffic:

```nginx
real_ip_header X-Forwarded-For;
real_ip_recursive on;
set_real_ip_from <public v4 address>;
set_real_ip_from <public v6 address>;
```

You can generate this configuration from the server's public addresses:

```bash
NGINX_CONF=/etc/nginx/conf.d/flowguard.conf

echo "real_ip_header X-Forwarded-For;" > "${NGINX_CONF}"
echo "real_ip_recursive on;" >> "${NGINX_CONF}"
echo "set_real_ip_from $(curl -sS ipv4.chief.tools);" >> "${NGINX_CONF}"
echo "set_real_ip_from $(curl -sS ipv6.chief.tools);" >> "${NGINX_CONF}"
cat "${NGINX_CONF}"
nginx -t
# systemctl reload nginx
```

#### Transparent upstream client IP

On a same-host Linux deployment, the opt-in `transparent` mode makes the validated client IP the TCP source address seen by the backend. NGINX, Apache, and other HTTP servers can then use their ordinary remote address without real-IP header configuration.

> [!WARNING]
> Transparent source preservation is per address family. On an IPv4-only server, a validated IPv6 client cannot be the source of an IPv4 TCP connection, and the inverse is also true. FlowGuard therefore uses canonical `X-Forwarded-For` and `X-Real-IP` header fallback only for opposite-family clients on genuinely single-stack servers. The fallback connection is pinned to the corresponding FlowGuard bind address, which the backend must trust with `real_ip` or equivalent handling. Matching-family requests remain fully transparent. Configure complete IPv4/IPv6 address pairs when both families must be preserved as the backend TCP source.

For a quick test, override the configured mode for this process only. Transparent settings still come from the configuration, with the defaults below used when they are omitted:

```bash
sudo flowguard run --upstream-client-ip-mode transparent --bind 192.0.2.10
```

```json
{
  "server": {
    "upstream": {
      "client_ip_mode": "transparent",
      "transparent": {
        "fwmark": 17991,
        "route_table": 17991,
        "rule_priority": 17991,
        "max_client_pools": 4096,
        "pool_idle_seconds": 90
      }
    }
  }
}
```

Before restarting FlowGuard, inspect the selected addresses, pairing, commands, sysctl access, and routing identifiers:

```bash
sudo flowguard network inspect
# Or inspect the same explicit bind set used by `flowguard run --bind`:
sudo flowguard network inspect --bind 192.0.2.10,2001:db8::10
```

The report always includes both header-mode and transparent-mode readiness, regardless of the configured mode. The configured mode is marked in the report and determines the command's exit status.

Transparent mode:

- Requires Linux, root privileges, `ip`, `iptables`, and `ip6tables` when IPv6 is active.
- Supports same-host HTTP and HTTPS backends. It is not a remote-backend routing feature.
- Creates a dedicated `FLOWGUARD_UPSTREAM` mangle chain and dedicated policy rule/table, adopts exact stale FlowGuard-owned resources after a crash, and removes them on clean shutdown.
- Temporarily enables `net.ipv4.conf.all.src_valid_mark` when needed and restores the previous value on shutdown.
- Performs a real source-address round trip before opening public listeners. Startup fails if interception cannot be proven.
- Uses the validated client as the TCP source for matching or paired address families. A single-stack family mismatch uses canonical header fallback from the endpoint's bind address; it never falls back because a transparent dial or route failed.
- Bounds per-client connection pools with an LRU limit; overflow requests use non-persistent connections rather than growing the pool without limit.
- Treats all upstream mode, mark, table, pool, and address-pair settings as startup-only. Restart FlowGuard after changing them.

For dual-stack servers, FlowGuard must know which IPv4 and IPv6 addresses represent the same backend. Resolution is deliberately conservative: explicit `address_pairs` win, then one IPv4 and one IPv6 co-listed in a single NGINX `server` block, then a single unambiguous remaining pair. FlowGuard refuses to start transparent mode if multiple addresses remain ambiguous:

```json
{
  "server": {
    "upstream": {
      "client_ip_mode": "transparent",
      "transparent": {
        "address_pairs": [
          {
            "ipv4": "192.0.2.10",
            "ipv6": "2001:db8::10"
          }
        ]
      }
    }
  }
}
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
- **Loki**: Grafana Loki with JSON flattening
- **OpenObserve**: OpenObserve with automatic field flattening

Challenge activity is logged in a top-level `challenge` object. The `rule.result` field remains the final request disposition such as `proxy`, `block`, or `rate_limit`; challenge outcomes such as `issued_html`, `issued_non_html`, `passed`, `verify_success`, and `verify_failed` are recorded under `challenge.outcome`. Challenge logs include `challenge.rule.id/name` and `challenge.action.id/name`, captured from the challenge token when verification or clearance events are logged.

### Configuration

```json
{
  "logging": {
    "sinks": {
      "local_log": {
        "type": "file",
        "path": "/var/log/flowguard/main.log"
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
- Request details (method, URL, headers, TLS info, JA4 fingerprint when available)
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
  - `challenge`: Require a first-party proof-of-work browser challenge before continuing
- **IP Database**: Configure IP geolocation database source and refresh interval
- **Trusted Proxies**: Configure trusted proxy networks for proper client IP detection
- **Upstream Client IP**: Choose canonical forwarding headers or same-host Linux transparent source sockets
- **IP Lists**: Configure in-memory IP lists for high-performance matching
- **Challenges**: Configure FlowGuard-owned challenge defaults and clearance cookies
- **Logging**: Configure structured logging sinks (file, Loki, OpenObserve)

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
    "header_auth": {
      "values": ["high-entropy-shared-secret"]
    },
    "refresh_interval_seconds": 43200
  }
}
```

When using `trusted_proxies.header_auth`, FlowGuard defaults to the `FG-Trusted-Proxy-Secret` header. Configure the upstream proxy to strip any client-supplied copy of that header and set its own high-entropy value. Set `header_auth.header` only when you need a custom header name.

### Rule Conditions

Rules support complex conditions with logical operators:

- **Operators**: `AND`, `OR`, `NAND`, `NOR`
- Unsupported operator values are rejected when the configuration is loaded.
- **Match Types**:
  - `path`: URL path matching
  - `method`: HTTP method matching
  - `domain`: Host header matching
  - `user-agent`: User-Agent header matching
  - `header`: Arbitrary header matching
  - `query-param`: Query parameter matching
  - `cookie`: Request cookie matching
  - `ip`: Client IP matching, including optional inline CIDR ranges
  - `proxy-ip`: Immediate trusted proxy IP matching, including optional inline CIDR ranges
  - `asn`: Autonomous System Number matching
  - `proxy-asn`: Immediate trusted proxy Autonomous System Number matching
  - `as-name`: ASN organization name matching
  - `as-domain`: ASN domain matching
  - `country`: Country code matching (from GeoIP database)
  - `continent`: Continent code matching (from GeoIP database)
  - `iplist`: In-memory IP list matching (built-in, no dependencies)
  - `proxy-iplist`: Immediate trusted proxy IP-list matching
  - `fingerprint-ja4`: JA4 TLS client fingerprint matching (HTTPS and HTTP/3 requests)
- **Match Operations**: `equals`, `not-equals`, `contains`, `not-contains`, `starts-with`, `not-starts-with`, `ends-with`, `not-ends-with`, `regex`, `not-regex`, `in`, `not-in`, `exists`, `missing`

### Bot Challenge Interstitials

Rules can use the `challenge` action to require a browser to pass a same-origin proof-of-work check before reaching protected resources. FlowGuard serves its own challenge endpoints under the reserved `/fg-cgi/` prefix; requests to unknown `/fg-cgi/*` paths are handled by FlowGuard and are not proxied upstream.

Successful challenges set an HTTP-only `fg_clearance` cookie. By default, clearance is scoped to the matching rule, lasts 30 minutes, and is bound to the client IP and User-Agent. Non-HTML requests fail closed with a machine-readable response and `X-FlowGuard-Challenge-URL` so API clients can be pre-cleared through a browser flow.

When multiple challenge rules match the same request, the first matching challenge rule wins. Later challenge rules are skipped after the first one has either issued a challenge or accepted valid clearance, so overlapping challenge rules should be ordered intentionally. Nested or cumulative challenges are not supported.

Proof-of-work defaults to calibrated PBKDF2-SHA256. Calibrated mode signs an explicit `work_units` target into the challenge and requires a sequential hash chain, which gives more predictable solve time than probabilistic leading-zero difficulty. If `work_units` is omitted, FlowGuard derives it from `difficulty_bits` so legacy difficulty tuning still changes the deterministic effort; set `work_units` directly when you want exact control. `difficulty_bits` is also used by configs that explicitly set `effort_mode` to `probabilistic`.

Challenges also include a signed dwell-time gate. By default, the browser must remain on the challenge page for at least 1500ms before FlowGuard accepts verification, preventing instant 1ms interstitials even when the proof completes quickly.

```json
{
  "challenges": {
    "default_ttl_seconds": 1800,
    "min_page_time_ms": 1500,
    "pow": {
      "algorithm": "pbkdf2-sha256",
      "effort_mode": "calibrated",
      "difficulty_bits": 18,
      "challenge_ttl_seconds": 120,
      "pbkdf2_iterations": 100
    }
  },
  "rules": {
    "challenge-admin": {
      "action": "pow-admin",
      "conditions": {
        "matches": [
          {
            "type": "path",
            "match": "starts-with",
            "value": "/admin"
          }
        ]
      }
    }
  },
  "actions": {
    "pow-admin": {
      "action": "challenge",
      "message": "Security check required",
      "challenge": {
        "type": "pow",
        "clearance_scope": "rule",
        "ttl_seconds": 1800,
        "min_page_time_ms": 1500,
        "algorithm": "pbkdf2-sha256",
        "effort_mode": "calibrated",
        "difficulty_bits": 18,
        "pbkdf2_iterations": 100
      }
    }
  }
}
```

For local previewing, run:

```bash
./bin/dev.sh
```

This builds `./flowguard` and runs `./flowguard dev`, starting a local-only preview server at `http://127.0.0.1:18080/` with links for the challenge, block, and rate-limit scenarios. The preview command does not install firewall rules and only fronts its own in-process demo backend.

The preview command is behind the `devtools` Go build tag and is not included in normal or production builds.

### JA4 Fingerprints

FlowGuard logs JA4 TLS client fingerprints at `request.fingerprint.ja4` for HTTPS and HTTP/3 requests. Cleartext HTTP requests do not have a JA4 fingerprint.

JA4 is useful as one bot signal alongside IP, ASN, user-agent, path, and rate limits. Avoid blocking on a fingerprint alone unless you have validated it against your own traffic.

**Exact match:**
```json
{
  "type": "fingerprint-ja4",
  "match": "equals",
  "value": "t13d1516h2_8daaf6152771_02713d6af862"
}
```

**Match a JA4 prefix:**
```json
{
  "type": "fingerprint-ja4",
  "match": "starts-with",
  "value": "t13d1516h2_"
}
```

## Security Configuration

### IP List System

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

Use `proxy-iplist` to match the immediate trusted proxy against the same lists. For a fail-closed proxy allowlist, block when the proxy IP is absent or is not in the list:

```json
{
  "operator": "OR",
  "matches": [
    {
      "type": "proxy-ip",
      "match": "missing"
    },
    {
      "type": "proxy-iplist",
      "match": "not-in",
      "value": "local_allowlist"
    }
  ]
}
```

**Testing:**
```bash
# Show list stats (load time, memory usage, entry count)
flowguard iplist blocklist

# Check if IP is in list
flowguard iplist blocklist contains 192.168.1.1
```

### Dynamic Security Rules

The proxy uses a flexible rule engine defined in the configuration file. Rules can be updated without restarting the service by modifying the configuration file - FlowGuard automatically detects and reloads changes.

## Architecture

### Components

- **Main**: Entry point, command-line parsing, signal handling
- **Proxy Manager**: Coordinates proxy servers, interception rules, transparent upstream policy routing, and graceful shutdown
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
6. Valid requests are forwarded to the same-host backend using canonical headers or the validated client IP as the transparent TCP source
7. Response is returned to client through proxy with appropriate headers

## Development

### Running Tests

```bash
go test ./...
```

On Linux, run the privileged transparent-source round-trip in an isolated network namespace:

```bash
./bin/test-transparent-upstream.sh
```

## Security Vulnerabilities

If you discover a security vulnerability within this project, please report it privately via GitHub: https://github.com/chieftools/flowguard-proxy/security/advisories/new.
All security vulnerabilities will be swiftly addressed. There is no bug bounty program at this time.

## License

FlowGuard Proxy is open-source software licensed under the Apache License 2.0. This means you are free to use, modify, and distribute the software for both commercial and non-commercial purposes. See the [LICENSE](LICENSE) file for details.
