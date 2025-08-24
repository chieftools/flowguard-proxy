# HTTP Security Proxy

A high-performance Go-based reverse proxy with advanced security features, designed to transparently intercept and filter HTTP/HTTPS traffic with minimal disruption.

## Features

### Core Functionality
- **Transparent Traffic Interception**: Redirects traffic from ports 80 and 443 to proxy ports using iptables
- **HTTPS Decryption**: Dynamically loads and manages SSL certificates for transparent HTTPS inspection
- **Automatic Certificate Management**: Monitors and reloads certificates from the filesystem for seamless rotation
- **Graceful Shutdown**: Automatically removes iptables rules on shutdown to restore original traffic flow

### Security Middleware
- **IP Filtering**: Integrates with Linux ipset to block malicious IPs (IPv4 and IPv6 support)
- **User-Agent Filtering**: Blocks requests from known malicious user agents and bots
- **Trusted Proxy Support**: Properly handles X-Forwarded-For headers from trusted proxies (e.g., Cloudflare)
- **Real Client IP Detection**: Extracts actual client IPs through proxy chains for accurate filtering

### Performance Optimizations
- Efficient connection handling with minimal overhead
- Certificate caching with automatic refresh
- Optimized middleware chain processing
- Support for binding to specific network interfaces

## Installation

### Prerequisites
- Go 1.25.0 or later
- Linux system with iptables support
- Root/sudo access for port redirection
- ipset installed for IP filtering

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/http-sec-proxy.git
cd http-sec-proxy

# Build for current platform
go build -o http-sec-proxy .

# Build for Linux AMD64 (production)
./build.sh
# or manually:
GOOS=linux GOARCH=amd64 go build -o http-sec-proxy-linux-amd64 .
```

## Usage

### Basic Usage

```bash
# Start with default settings
sudo ./http-sec-proxy

# Start without iptables redirection (for testing)
./http-sec-proxy --no-redirect
```

### Command Line Options

```
--bind                  Comma-separated list of IP addresses to bind to (default: auto-detect public IPs)
--http-port            Port for HTTP proxy server (default: "11080")
--https-port           Port for HTTPS proxy server (default: "11443")
--no-redirect          Skip iptables port redirection setup
--server               Server header value to use in responses (default: "Alboweb-Proxy/1.0")

Certificate Options:
--cert-path            Path to combined certificate files (default: "/opt/psa/var/certificates")
--test-certs           Test loading all certificates and exit

Security Options:
--ipset-v4             Name of the IPv4 ipset blocklist (default: "abuseipdb_v4")
--ipset-v6             Name of the IPv6 ipset blocklist (default: "abuseipdb_v6")

Trusted Proxy Options:
--trusted-proxy-urls   Comma-separated list of URLs to fetch trusted proxy IP ranges 
                       (default: "https://www.cloudflare.com/ips-v4,https://www.cloudflare.com/ips-v6")
--trusted-proxy-refresh Refresh interval for trusted proxy IP lists (default: 12h)
```

### Examples

```bash
# Test certificate loading
./http-sec-proxy --test-certs --cert-path /path/to/certs

# Run with custom ports and IP filtering
sudo ./http-sec-proxy --http-port 8080 --https-port 8443 --ipset-v4 my_blocklist_v4

# Bind to specific IPs only
sudo ./http-sec-proxy --bind "192.168.1.100,10.0.0.50"

# Use custom trusted proxy lists
sudo ./http-sec-proxy --trusted-proxy-urls "https://mycdn.com/ips.txt" --trusted-proxy-refresh 6h
```

## Certificate Management

The proxy expects combined certificate files (cert + key) in the specified certificate path. Files should be named by hostname and contain both the certificate chain and private key.

Certificate files are:
- Loaded on-demand when first requested
- Cached in memory for performance
- Automatically refreshed periodically to support rotation
- Validated on load to ensure proper format

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

### Blocked User Agents

The proxy automatically blocks requests from known malicious user agents and bots. The blocklist is maintained in the middleware and includes common vulnerability scanners and malicious bots.

## Architecture

### Components

- **Main**: Entry point, command-line parsing, signal handling
- **Proxy Manager**: Coordinates proxy servers and iptables rules
- **HTTP/HTTPS Servers**: Handle incoming requests and forward to backends
- **Certificate Manager**: Dynamic SSL certificate loading and management
- **Middleware Chain**:
  - Agent Filter: Blocks malicious user agents
  - IP Filter: Checks against ipset blocklists
  - Trusted Proxy Handler: Processes X-Forwarded-For headers

### Traffic Flow

1. Original traffic to ports 80/443 is redirected via iptables to proxy ports
2. Proxy receives connection and applies middleware chain
3. For HTTPS, appropriate certificate is loaded/retrieved from cache
4. Security checks are performed (IP filtering, user agent blocking)
5. Valid requests are forwarded to original destination
6. Response is returned to client through proxy

## Development

### Running Tests

```bash
go test ./...
```

### Project Structure

```
http-sec-proxy/
├── main.go                 # Entry point and CLI
├── build.sh               # Build script for Linux AMD64
├── go.mod                 # Go module definition
├── certmanager/
│   └── certmanager.go     # SSL certificate management
├── proxy/
│   ├── manager.go         # Proxy orchestration and iptables
│   ├── server.go          # HTTP/HTTPS server implementation
│   └── utils.go           # Utility functions
└── middleware/
    ├── middleware.go      # Middleware interface and chain
    ├── agentfilter.go     # User-agent filtering
    ├── ipfilter.go        # IP-based filtering with ipset
    ├── trustedproxy.go    # Trusted proxy IP handling
    └── trustedproxy_test.go # Tests for trusted proxy

```

## License

[License information to be added]

## Contributing

[Contributing guidelines to be added]
