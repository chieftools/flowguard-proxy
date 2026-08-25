# FlowGuard Proxy

FlowGuard Proxy is a Go reverse proxy for Linux. It redirects inbound HTTP and
HTTPS traffic through configurable security rules before forwarding requests to
an existing backend. It can pass the validated client IP through canonical
headers or preserve it as the source address on supported same-host setups.

The optional [FlowGuard control panel](https://flowguard.network/) manages setup,
configuration, logs, GeoIP data, and managed IP reputation lists. Proxy traffic
and request filtering stay on the FlowGuard host.

> [!IMPORTANT]
> FlowGuard changes firewall and routing state. Test those changes before using
> them on a production host.

> [!CAUTION]
> FlowGuard is under active development. Keep it updated and review configuration
> changes before deployment.

## Features

### Proxy and networking

- Redirects ports 80 and 443 to FlowGuard with `iptables` or `ip6tables`.
- Serves HTTP/1.1, HTTP/2, and HTTP/3 according to the configured protocol set.
- Terminates TLS with certificates loaded from a directory, Traefik `acme.json`,
  or NGINX configuration.
- Supports canonical forwarding headers and same-host transparent client source
  addresses.
- Binds to multiple IPv4 and IPv6 addresses.
- Removes FlowGuard-owned firewall and routing state during a clean shutdown.

### Request filtering

- Evaluates ordered rules against request fields, client and proxy addresses,
  ASN and GeoIP data, JA4 fingerprints, and named IP lists.
- Supports log, allow, block, rate-limit, and browser challenge actions.
- Resolves trusted proxy chains before rules evaluate the client identity.
- Keeps URL-backed IP lists current with conditional requests and stale-cache
  fallback when a source is temporarily unavailable.
- Compiles regular expressions when configuration loads.

### Operations

- Reloads configuration and certificates after file changes.
- Writes structured request logs to files, Loki, or OpenObserve.
- Can synchronize bans from active local Fail2Ban jails.
- Monitors FlowGuard-owned firewall state and repairs missing rules by default.

## Installation

### Prerequisites for source builds

- Go 1.27 or later
- Linux with `iptables`; IPv6 and transparent mode have extra requirements
- Root access for firewall, routing, and privileged service configuration

### Build from source

```bash
# Clone the repository
git clone https://github.com/chieftools/flowguard-proxy.git
cd flowguard-proxy

# Build for current platform
go build -o flowguard .
```

### Quick install

```bash
curl -fsSL https://pkg.flowguard.network/install.sh | sudo bash
```

The installer supports Debian, Ubuntu, RHEL, CentOS, Rocky Linux, AlmaLinux, and
Fedora on amd64 or arm64 systems.

### Install on Debian or Ubuntu

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

# Configure with a host key from the FlowGuard control panel
sudo flowguard setup fgsvr_...

# Check the detected certificates
sudo flowguard certificates

# Start FlowGuard now and on boot
sudo systemctl enable --now flowguard
```

You can edit `/etc/flowguard/config.json` instead of using the control panel.

### Install on RHEL, CentOS, Rocky Linux, AlmaLinux, or Fedora

```bash
# Add FlowGuard repository
sudo tee /etc/yum.repos.d/flowguard.repo << 'EOF'
[flowguard]
name=FlowGuard Repository
baseurl=https://pkg.flowguard.network/rpm/stable/$basearch
enabled=1
gpgcheck=1
gpgkey=https://pkg.flowguard.network/gpg.key
EOF

# Install FlowGuard
sudo yum install flowguard

# Configure with a host key from the FlowGuard control panel
sudo flowguard setup fgsvr_...

# Start FlowGuard now and on boot
sudo systemctl enable --now flowguard
```

You can edit `/etc/flowguard/config.json` instead of using the control panel.

### Upgrade

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install --only-upgrade flowguard

# RHEL/CentOS/Rocky/Alma/Fedora
sudo yum clean expire-cache --disablerepo=* --enablerepo=flowguard
sudo yum update flowguard
```

### Initial setup

Run `sudo flowguard setup` without a host key to reuse the key in
`/etc/flowguard/config.json`, download the latest configuration, and repeat
interactive server discovery. Use `--config` when the configuration is stored
elsewhere.

Interactive setup also checks whether transparent upstream networking is
available, helps resolve ambiguous IPv4/IPv6 address pairs, and asks which HTTP
protocols to enable. New setups prefer transparent client-IP forwarding when
its prerequisites are ready; rediscovery defaults to the current settings.
When a running Fail2Ban installation with active jails is detected, setup also
offers to synchronize its bans. This integration is opt-in and defaults to No.
Run `sudo flowguard setup -v` to show each server-source, bind-address, and
address-pair detection decision, including why NGINX listeners or pairing
heuristics were rejected.

On a capable terminal, setup uses an interactive form: use the arrow keys (or
`j`/`k`) to move, Space to toggle checkboxes, and Enter to confirm. Address-pair
configuration always lists IPv4 addresses as the fixed bases and asks for an
unused IPv6 counterpart for each one. Set `ACCESSIBLE=1` for screen-reader
friendly prompts. Use the global `--no-tui` flag or set `FLOWGUARD_NO_TUI` to
force line-oriented prompts; FlowGuard also falls back to these prompts when
input or output is redirected or `TERM=dumb`.

## Backend client IP

FlowGuard sits in front of your existing backend and can pass the validated
client IP upstream in two ways:

- [Headers upstream client IP](#headers-upstream-client-ip) is the compatible
  configuration default and works with local or remote HTTP backends. The
  backend must be configured to trust requests received through FlowGuard.
- [Transparent upstream client IP](#transparent-upstream-client-ip) preserves
  the validated client as the backend connection's TCP source address. It is
  intended for same-host Linux deployments and has additional networking
  prerequisites.

Interactive `flowguard setup` checks both modes and prefers transparent mode
for a new setup when its prerequisites are ready. Existing installations keep
their configured mode. You can review readiness at any time with
`flowguard network inspect`.

Whichever mode you choose, keep direct backend exposure narrow and restart
FlowGuard after changing startup-only networking settings.

### Headers upstream client IP

The `headers` mode works with any HTTP backend. FlowGuard removes incoming
forwarding headers and writes canonical `X-Forwarded-For`, `X-Real-IP`,
`X-Forwarded-Host`, and `X-Forwarded-Proto` values from its validated client
identity.

The backend must trust only connections that came through FlowGuard. An attacker
can spoof forwarding headers if they can reach the backend directly from a
trusted address. FlowGuard guards its own interception ports, but you must also
restrict access to the backend.

`set_real_ip_from` matches the TCP source address of the peer that sends the
forwarding header. It does not trust every request sent to that public address.
When FlowGuard is disabled, a direct client's source address does not match the
server's own public address, so NGINX ignores client-supplied forwarding
headers. Add the address ranges of any CDN or other proxy that may connect
directly while FlowGuard is disabled.

For NGINX, replace the example addresses with every address on which FlowGuard
accepts traffic:

```nginx
real_ip_header X-Forwarded-For;
real_ip_recursive on;
set_real_ip_from <public v4 address>;
set_real_ip_from <public v6 address>;
```

Save the configuration and test it before reloading NGINX:

```bash
sudoedit /etc/nginx/conf.d/flowguard.conf
sudo nginx -t
sudo systemctl reload nginx
```

### Transparent upstream client IP

On a same-host Linux deployment, `transparent` mode uses the validated client IP
as the source address of the backend connection. NGINX, Apache, and other HTTP
servers can then use the ordinary remote address without real-IP header
configuration.

> [!WARNING]
> Transparent source preservation works within one address family. An IPv6
> client cannot be the source of an IPv4 backend connection, nor can an IPv4
> client be the source of an IPv6 connection. On a single-stack server,
> FlowGuard falls back to canonical `X-Forwarded-For` and `X-Real-IP` headers for
> opposite-family clients. The backend must trust the FlowGuard bind address
> used by that fallback. Configure IPv4 and IPv6 address pairs when both
> families must reach the backend with a transparent source address.

For a quick test, override the mode for one FlowGuard process. The other
transparent settings still come from configuration and use these defaults when
omitted:

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

Before restarting FlowGuard, inspect the selected addresses, pairings, commands,
sysctl access, and routing identifiers:

```bash
sudo flowguard network inspect
# Or inspect the same explicit bind set used by `flowguard run --bind`:
sudo flowguard network inspect --bind 192.0.2.10,2001:db8::10
```

The report covers both upstream modes and marks the configured mode. Its exit
status reflects whether the configured mode is ready.

Transparent mode:

- Requires Linux, root privileges, `ip`, `iptables`, and `ip6tables` when IPv6
  is active.
- Supports same-host HTTP and HTTPS backends. It is not a remote-backend routing
  feature.
- Creates a dedicated `FLOWGUARD_UPSTREAM` mangle chain and policy routing
  state. It adopts exact stale FlowGuard-owned resources after a crash and
  removes them on clean shutdown.
- Temporarily enables `net.ipv4.conf.all.src_valid_mark` when needed and restores
  the previous value on shutdown.
- Tests the source address before opening public listeners. Startup fails if
  interception cannot be proven.
- Uses canonical header fallback only for a single-stack family mismatch. A
  failed transparent dial or route does not fall back to headers.
- Limits per-client connection pools with an LRU. Overflow requests use
  non-persistent connections.
- Treats upstream mode, mark, table, pool, and address-pair settings as
  startup-only. Restart FlowGuard after changing them.

For dual-stack servers, FlowGuard must know which IPv4 and IPv6 addresses reach
the same backend. Explicit `address_pairs` take precedence. FlowGuard then
checks addresses listed together in one NGINX `server` block, its embedded-IPv4
heuristic, and a single unambiguous remaining pair. It refuses to start
transparent mode if more than one pairing remains possible:

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

## Fail2Ban integration

On Linux hosts, FlowGuard can mirror the addresses currently banned by every
active Fail2Ban jail and reject their HTTP requests before evaluating FlowGuard
rules or connecting upstream. This works in both headers and transparent
client-IP modes. Because all active jails are included, an address banned by an
SSH, mail, or recidivist jail is also blocked from proxied HTTP traffic.

The integration is disabled unless explicitly enabled during interactive setup
or in configuration:

```json
{
  "fail2ban": {
    "enabled": true
  }
}
```

When enabled during startup, FlowGuard waits for the initial Fail2Ban
reconciliation attempt before opening its proxy listeners. A temporarily
unavailable Fail2Ban daemon does not permanently prevent startup; FlowGuard
continues with the normal retry schedule after the first attempt finishes.

FlowGuard adds a temporary `flowguard-runtime` action to active jails so ban and
unban events normally arrive immediately. It audits active jails and runtime
actions every minute, and reloads the authoritative banned-IP lists every five
minutes to recover from missed events. Newly discovered or reattached jails are
loaded immediately. If the runtime event socket cannot be created or is later
lost, snapshot enforcement continues while FlowGuard recreates the socket and
attaches or verifies runtime actions when it becomes available. No files under
`/etc/fail2ban` are created or changed, and the runtime action is removed during
a clean FlowGuard shutdown. If the Fail2Ban daemon is confirmed unavailable,
FlowGuard clears its synchronized state and continues running.

Blocked requests receive the standard FlowGuard `403 Forbidden` response. HTML
clients see the normal block page with a Stream ID, while other clients receive
the Stream ID in the `FG-Stream` response header. Structured request logs record
response status `403`, `rule.result` as `block`, and the matching jails under
`fail2ban.jails`.

## Certificate management

FlowGuard can load certificates from any combination of these sources:

- `host.cert_path` points to a directory of combined PEM files. Each file must
  contain a certificate chain and its private key. FlowGuard reads hostnames
  from the certificate, so filenames do not need to match them.
- `host.acme_path` points to a Traefik v2 or v3 `acme.json` file. FlowGuard reads
  this file without changing it.
- `host.nginx_config_path` points to an NGINX configuration. FlowGuard follows
  its includes and loads referenced `ssl_certificate` and
  `ssl_certificate_key` pairs.

FlowGuard loads certificates at startup, skips expired certificates, and indexes
valid certificates by DNS name and wildcard. It watches the source directories
and reloads after file replacements or writes. If a Traefik renewal briefly
leaves `acme.json` unreadable or incomplete, FlowGuard keeps the last valid ACME
certificates.

Use `sudo flowguard certificates` to inspect all configured sources, or pass a
hostname to see which certificate FlowGuard will serve:

```bash
sudo flowguard certificates
sudo flowguard certificates www.example.test
```

FlowGuard accepts TLS 1.2 and TLS 1.3. TLS 1.2 is limited to ECDHE suites with
AES-GCM or ChaCha20-Poly1305; Go manages the TLS 1.3 cipher suites.

## Logging

FlowGuard can write each structured request log to multiple sinks. Configuration
reloads can add, remove, or update sinks while the proxy is running.

### Supported sinks

- Local JSON files
- Grafana Loki
- OpenObserve

Challenge activity appears in a top-level `challenge` object. `rule.result`
records the final request disposition. `challenge.outcome` records challenge
events such as `issued_html`, `issued_non_html`, `passed`, `verify_success`, and
`verify_failed`. Verification and clearance entries also identify the rule and
action stored in the challenge token.

Fail2Ban blocks add a top-level `fail2ban` object containing the matching jail
names, set `rule.result` to `block`, and record response status `403`. The Stream
ID shown to the client is also available as `stream_id` in the request log.

### Sink configuration

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

### Log entry format

Each log entry contains request and response details, client and proxy identity,
rule results, timing, and host metadata. HTTPS and HTTP/3 entries include a JA4
fingerprint when one is available.

### Sink updates

On configuration reload, FlowGuard recreates only the sinks whose settings
changed. Other sinks keep running.

## Configuration

### Main sections

FlowGuard uses a JSON configuration file. Its main sections are:

- `rules` defines matching conditions and associated actions.
- `actions` defines what happens when a rule matches.
- `ip_database` configures the MaxMind database source and refresh interval.
- `trusted_proxies` defines trusted proxy networks and optional header
  authentication.
- `server` selects protocols and the upstream client-IP mode.
- `ip_lists` defines URL-backed or local IP and CIDR lists.
- `challenges` sets proof-of-work and clearance-cookie defaults.
- `fail2ban` enables local jail synchronization.
- `logging` configures file, Loki, and OpenObserve sinks.

### JSON schema

The repository includes [config.schema.json](config.schema.json) for editor
completion, validation, and field descriptions.

Add the schema URL to your configuration:

```json
{
  "$schema": "https://raw.githubusercontent.com/chieftools/flowguard-proxy/main/config.schema.json"
}
```

### Example configuration

```json
{
  "rules": {
    "log-suspicious-agents": {
      "action": "log-action",
      "conditions": {
        "matches": [
          {
            "type": "user-agent",
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
            "type": "user-agent",
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

`trusted_proxies.header_auth` uses `FG-Trusted-Proxy-Secret` by default. The
upstream proxy must strip client-supplied copies and set its own high-entropy
value. Use `header_auth.header` only for a custom header name.

### Actions

| Action | Behavior |
| --- | --- |
| `log` | Records the match and continues to later rules. |
| `allow` | Allows the request and stops rule evaluation. |
| `block` | Returns the configured status and message. |
| `rate_limit` | Applies the configured request limit and time window. |
| `challenge` | Requires a first-party browser challenge before continuing. |

### Rule conditions

Condition groups support `AND`, `OR`, `NAND`, and `NOR`. An omitted operator
defaults to `AND`; FlowGuard rejects any other value when loading configuration.

Matcher types are grouped by the value they inspect:

- Request fields: `path`, `method`, `domain`, `registerable-domain`,
  `user-agent`, `header`, `query-param`, and `cookie`.
- Validated client identity: `ip`, `asn`, `as-name`, `as-domain`, `country`,
  `continent`, and `iplist`.
- Immediate trusted proxy identity: `proxy-ip`, `proxy-asn`, and
  `proxy-iplist`.
- TLS client identity: `fingerprint-ja4` for HTTPS and HTTP/3 requests.

String matchers support equality, substring, prefix, suffix, regular-expression,
and list operations, including their negative forms. IP matchers accept addresses
or CIDR ranges with `equals`, `not-equals`, `in`, or `not-in`. Header, query,
cookie, proxy-IP, and proxy-ASN matchers also support `exists` and `missing`.

### Bot challenge interstitials

The `challenge` action requires a browser to pass a same-origin proof-of-work
check before reaching a protected resource. FlowGuard reserves the `/fg-cgi/`
prefix for challenge endpoints. It handles unknown paths below that prefix
instead of forwarding them upstream.

A successful challenge sets the HTTP-only `fg_clearance` cookie. By default, it
lasts 30 minutes, applies to the matching rule, and binds to the client IP and
User-Agent. Non-HTML requests receive a machine-readable response with
`X-FlowGuard-Challenge-URL`; a browser can use that URL to obtain clearance.

The first matching challenge rule wins. Once that rule issues a challenge or
accepts clearance, FlowGuard skips later challenge rules. Order overlapping
rules with this behavior in mind. FlowGuard does not support nested or
cumulative challenges.

Proof-of-work defaults to calibrated PBKDF2-SHA256. Calibrated mode signs a
`work_units` target into the challenge and requires a sequential hash chain. If
`work_units` is absent, FlowGuard derives it from `difficulty_bits`. Set
`work_units` for an exact target. In `probabilistic` mode, `difficulty_bits`
controls the leading-zero requirement instead.

Challenge tokens also record when the page was issued. By default, FlowGuard
rejects verification until the page has been open for 1500 milliseconds.

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

This builds `./flowguard` with the `devtools` build tag and starts a preview at
`http://127.0.0.1:18080/`. The preview covers challenge, block, and rate-limit
responses. It uses an in-process backend and does not install firewall rules.

Normal and production builds do not include the preview command.

### JA4 fingerprints

FlowGuard logs JA4 TLS client fingerprints at `request.fingerprint.ja4` for
HTTPS and HTTP/3. Cleartext HTTP requests do not have a JA4 fingerprint.

Use JA4 alongside IP, ASN, User-Agent, path, and rate limits. Avoid blocking on a
fingerprint alone unless you have checked it against your own traffic.

Exact match:

```json
{
  "type": "fingerprint-ja4",
  "match": "equals",
  "value": "t13d1516h2_8daaf6152771_02713d6af862"
}
```

Prefix match:

```json
{
  "type": "fingerprint-ja4",
  "match": "starts-with",
  "value": "t13d1516h2_"
}
```

## IP lists

FlowGuard stores IPv4 and IPv6 prefixes in memory. A list can use a URL, a local
file, or a URL with a local-file fallback. URL lists refresh at their configured
interval and use ETags when the source provides one.

Configuration:

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

List files contain one IPv4 address, IPv6 address, or CIDR range per line:

```
192.168.1.1
10.0.0.0/24
2001:db8::/32
```

Rule usage:

```json
{
  "type": "iplist",
  "match": "in",
  "value": "blocklist"
}
```

Use `proxy-iplist` to match the immediate trusted proxy against the same lists.
For a fail-closed proxy allowlist, block when the proxy IP is absent or not in
the list:

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

Inspect a list or test an address with the CLI:

```bash
# Show list stats (load time, memory usage, entry count)
flowguard iplist blocklist

# Check if IP is in list
flowguard iplist blocklist contains 192.168.1.1
```

## Architecture

### Components

| Component | Responsibility |
| --- | --- |
| CLI | Loads commands, flags, and process lifecycle. |
| Proxy manager | Coordinates listeners, firewall rules, upstream routing, and shutdown. |
| HTTP servers | Serve HTTP/1.1, HTTP/2, and HTTP/3 and forward accepted requests. |
| Certificate manager | Loads, selects, watches, and reloads TLS certificates. |
| Configuration manager | Loads configuration, watches for changes, and refreshes remote configuration. |
| Cache | Stores external data and metadata for conditional HTTP requests. |
| IP list manager | Loads and matches IPv4 and IPv6 prefixes. |
| Logger manager | Writes structured entries to the configured sinks. |
| Middleware chain | Resolves identity, logs requests, enforces Fail2Ban, and evaluates rules. |

### Traffic flow

1. `iptables` or `ip6tables` redirects ports 80 and 443 to FlowGuard's internal
   listeners.
2. FlowGuard resolves the client and immediate proxy identities.
3. HTTPS connections use a certificate already loaded by the certificate
   manager.
4. Middleware enriches and logs the request, checks Fail2Ban, and evaluates
   configured rules.
5. FlowGuard blocks, rate-limits, challenges, or forwards the request according
   to the matching action.
6. Forwarded requests use canonical headers or a transparent client source
   address, depending on the configured upstream mode.
7. FlowGuard returns the backend response to the client.

## Development

### Run tests

```bash
go test ./...
```

On Linux, run the privileged transparent-source round-trip in an isolated network namespace:

```bash
./bin/test-transparent-upstream.sh
```

## Security vulnerabilities

Report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/chieftools/flowguard-proxy/security/advisories/new).
FlowGuard does not currently run a bug bounty program.

## License

FlowGuard Proxy is licensed under the Apache License 2.0. See
[LICENSE](LICENSE) for the license text.
