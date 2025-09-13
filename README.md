# FlowGuard

A high-performance Go-based reverse proxy with advanced security features, designed to transparently intercept and filter HTTP/HTTPS traffic with dynamic rule-based filtering and minimal disruption.

## Features

### Core Functionality
- **Transparent Traffic Interception**: Redirects traffic from ports 80 and 443 to proxy ports using iptables
- **HTTPS Decryption**: Dynamically loads and manages SSL certificates for transparent HTTPS inspection
- **Automatic Certificate Management**: Monitors and reloads certificates from the filesystem for seamless rotation
- **Graceful Shutdown**: Automatically removes iptables rules on shutdown to restore original traffic flow

### Security Middleware
- **Dynamic Rule-Based Filtering**: Flexible rule engine with conditions for path, domain, IP, ASN, user-agent, headers, and ipset matching
- **IP Database Integration**: ASN and geolocation lookups using configurable IP databases (IPInfo format)
- **IPSet Integration**: Direct integration with Linux ipset for high-performance IP blocking
- **Trusted Proxy Support**: Properly handles X-Forwarded-For headers from configurable trusted proxies
- **Real Client IP Detection**: Extracts actual client IPs through proxy chains for accurate filtering
- **Hot Configuration Reload**: Automatic configuration file monitoring and reloading without restart

### Performance Optimizations
- Efficient connection handling with minimal overhead
- Certificate caching with automatic refresh
- Optimized middleware chain processing
- Support for binding to specific network interfaces
- Response caching for external data fetches
- Compiled regex pattern caching for rule matching

## Installation

### Prerequisites
- Go 1.21 or later
- Linux system with iptables support
- Root/sudo access for port redirection
- ipset installed for IP filtering (optional)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/chieftools/flowguard.git
cd flowguard

# Build for current platform
go build -o flowguard .

# Build for Linux AMD64 (production)
./build.sh
# or manually:
GOOS=linux GOARCH=amd64 go build -o flowguard-linux-amd64 .
```

## Usage

### Basic Usage

```bash
# Start with default settings
sudo ./flowguard

# Start without iptables redirection (for testing)
./flowguard --no-redirect
```

### Command Line Options

```
--bind                 Comma-separated list of IP addresses to bind to (default: auto-detect public IPs)
--http-port            Port for HTTP proxy server (default: "11080")
--https-port           Port for HTTPS proxy server (default: "11443")
--no-redirect          Skip iptables port redirection setup
--config               Path to the configuration file (default: "config.json")
--default-hostname     The default hostname to use when a certificate is not found

Certificate Options:
--cert-path            Path to combined certificate files (default: "/opt/psa/var/certificates")
--test-certs           Test loading all certificates and exit

Behavior Options:
--verbose              Enable more verbose output
--cache-dir            Directory for caching external data (default: "/var/cache/flowguard")
--user-agent           User-Agent header value for outgoing requests (default: "FlowGuard/1.0")
```

### Examples

```bash
# Test certificate loading
./flowguard --test-certs --cert-path /path/to/certs

# Run with custom configuration
sudo ./flowguard --config /etc/flowguard/config.json

# Bind to specific IPs only
sudo ./flowguard --bind "192.168.1.100,10.0.0.50"

# Enable verbose logging with custom cache directory
sudo ./flowguard --verbose --cache-dir /tmp/flowguard-cache

# Use a default hostname for missing certificates
sudo ./flowguard --default-hostname example.com
```

## Certificate Management

The proxy expects combined certificate files (cert + key) in the specified certificate path. Files should be named by hostname and contain both the certificate chain and private key.

Certificate files are:
- Loaded on-demand when first requested
- Cached in memory for performance
- Automatically refreshed periodically to support rotation
- Validated on load to ensure proper format

## Configuration

### Configuration File

FlowGuard uses a JSON configuration file for advanced filtering rules. The configuration supports:

- **Rules**: Define matching conditions and associated actions
- **Actions**: Specify what to do when rules match (block with custom status/message)
- **IP Database**: Configure IP geolocation database source and refresh interval
- **Trusted Proxies**: Configure trusted proxy networks for proper client IP detection

#### JSON Schema Support

The repository includes a `config.schema.json` file that provides:
- **IDE Autocomplete**: IntelliSense support in VS Code, IntelliJ, and other modern IDEs
- **Validation**: Real-time error checking as you edit
- **Documentation**: Inline descriptions for all properties

To use the schema, add this line to your config.json:
```json
{
  "$schema": "./config.schema.json",
  ...
}
```

See `config.example.json` for a complete example with various rule patterns.

Example configuration structure:

```json
{
  "rules": {
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
  - `domain`/`host`: Host header matching
  - `agent`/`user-agent`: User-Agent header matching
  - `header`: Arbitrary header matching
  - `ip`: Client IP matching
  - `asn`: Autonomous System Number matching
  - `ipset`: Linux ipset membership checking
- **Match Operations**: `equals`, `contains`, `starts-with`, `ends-with`, `regex`, `in`, `not-in`, `exists`, `missing`

## Security Configuration

### IPSet Integration

Create and populate ipset lists before starting the proxy:

```bash
# Create IPv4 blocklist
sudo ipset create abuseipdb_v4 hash:net

# Create IPv6 blocklist  
sudo ipset create abuseipdb_v6 hash:net family inet6

# Add IPs to blocklist
sudo ipset add abuseipdb_v4 192.168.1.100
sudo ipset add abuseipdb_v6 2001:db8::1
```

### Dynamic Security Rules

The proxy uses a flexible rule engine defined in the configuration file. Rules can be updated without restarting the service by modifying the configuration file - FlowGuard automatically detects and reloads changes.

## Architecture

### Components

- **Main**: Entry point, command-line parsing, signal handling
- **Proxy Manager**: Coordinates proxy servers and iptables rules
- **HTTP/HTTPS Servers**: Handle incoming requests and forward to backends
- **Certificate Manager**: Dynamic SSL certificate loading and management
- **Configuration Manager**: Hot-reload configuration with rule management
- **Cache System**: Caching layer for external data fetches
- **Middleware Chain**:
  - Rules Engine: Dynamic rule-based filtering with complex conditions
  - IP Lookup: ASN and geolocation database integration
  - Client IP extraction from trusted proxy chains

### Traffic Flow

1. Original traffic to ports 80/443 is redirected via iptables to proxy ports
2. Proxy receives connection and extracts real client IP through trusted proxy chains
3. For HTTPS, appropriate certificate is loaded/retrieved from cache
4. Rules engine evaluates all configured rules against the request
5. Security checks are performed based on rule conditions
6. Valid requests are forwarded to original destination
7. Response is returned to client through proxy with appropriate headers

## Development

### Running Tests

```bash
go test ./...
```

### Project Structure

```
flowguard/
├── main.go                 # Entry point and CLI
├── build.sh               # Build script for Linux AMD64
├── config.json            # Configuration file (rules, actions, etc.)
├── go.mod                 # Go module definition
├── cache/
│   ├── cache.go           # Caching system for external data
│   └── cache_test.go      # Cache tests
├── certmanager/
│   └── certmanager.go     # SSL certificate management
├── config/
│   └── config.go          # Configuration management with hot-reload
├── proxy/
│   ├── manager.go         # Proxy orchestration and iptables
│   ├── server.go          # HTTP/HTTPS server implementation
│   └── utils.go           # Utility functions
└── middleware/
    ├── middleware.go      # Middleware interface and chain
    ├── rules.go           # Dynamic rule engine
    ├── rules_test.go      # Rule engine tests
    └── iplookup.go        # IP database and ASN lookup
```

## License

[License information to be added]

## Contributing

[Contributing guidelines to be added]
