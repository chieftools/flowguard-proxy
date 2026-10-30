# Changelog

All notable changes to FlowGuard Proxy are documented in this file.

Changes are grouped by release and type, with the newest release first. Release
dates are available from the linked GitHub releases. Add future changes to the
Unreleased section, then move them into a versioned section before tagging a
release.

## [Unreleased]

## [0.33.1]

### Added

- Added support for certbot certificates. Set `host.cert_path` to certbot's config directory (`/etc/letsencrypt`) to load `fullchain.pem` and `privkey.pem` of each certificate in `live/`, whichever web server uses them, such as Apache with certbot's Apache plugin. FlowGuard watches `live/`, so renewed and new certificates are picked up without a restart or deploy hook. `flowguard setup` offers it when no other server configuration is found. See [Certificate management](README.md#certificate-management).

### Fixed

- Fixed FlowGuard no longer noticing certificate changes in a watched directory that was removed and created again, such as a DirectAdmin user's `domains` directory or a certbot certificate deleted and requested again under the same name.

## [0.33.0]

### Added

- FlowGuard now installs and runs on servers without systemd, such as Ubuntu 14.04, Debian 8 with SysV init, and containers. The DEB and RPM packages include an `/etc/init.d/flowguard` script and pick the init system when they install, upgrade or remove FlowGuard, instead of failing on `systemctl`. The script logs to `/var/log/flowguard/flowguard.log`, through the new `flowguard run --log-file` option, and reads local options from `/etc/default/flowguard` or `/etc/sysconfig/flowguard`. Remote upgrades work without systemd as well, including on apt before 1.1, and write the package manager's output to `upgrade.log` in the cache directory. The install script sets up the repository on apt before 1.1 and falls back to HTTP where apt's TLS is too old for the repository. See [Supported systems](README.md#supported-systems).

### Fixed

- Fixed CentOS 7 and other EL7 servers failing to read the FlowGuard RPM repository with "Parsing primary.xml error: Start tag expected". The repository metadata was compressed with zstd, which the yum of EL7 cannot read, and is gzip compressed again from the next release on.

## [0.32.0]

### Added

- Added `SHA256SUMS` and its signature `SHA256SUMS.asc` to the GitHub release, so downloaded packages can be verified with the FlowGuard signing key.

### Changed

- FlowGuard now calls the control panel endpoints for proxies under `/proxy/v1` instead of `/api/v1`, which also holds the API for users and integrations. The control panel keeps serving `/api/v1` for earlier versions.
- FlowGuard now pauses its requests to the control panel when the panel asks it to. A `Retry-After` on a 429 or 503 answer pauses them for that long, and a rejected host key (401) or an unsupported FlowGuard version (426) pauses them for an hour, with a log line that says why. Before, a proxy with a revoked host key kept fetching its configuration and sending heartbeats on the regular schedule. The pause also covers IP list and IP database downloads from the control panel, which keep using their cached copy, and realtime channel authorization. Proxying continues while requests are paused, and a new host key from `flowguard setup` is tried right away.
- Limited messages from the realtime server to 1 MiB. A larger message closes the connection, which then reconnects, instead of being read into memory whole.

### Security

- FlowGuard now only sends its host key to the control panel when it authorizes its realtime channel. A realtime `auth_url` on another origin is replaced by the control panel's own endpoint.
- Made `/etc/flowguard/config.json`, which holds the host key, readable by root only. FlowGuard and the DEB and RPM packages created it readable by every user on the server, so anyone with a shell could use the host key to act as the server towards the control panel. FlowGuard now writes the file with mode 0600, and installing or upgrading the package sets 0600 on an existing file. Running `flowguard` as another user now explains that it needs root instead of only reporting "permission denied". The Caddy plugin, when Caddy runs as its own user, now suggests setting `key`, which keeps the configuration in Caddy's data directory.

### Fixed

- Fixed the default `/etc/flowguard/config.json` that the DEB and RPM packages install, which was invalid JSON because of a trailing comma. Upgrading replaces it with a valid default when it was never changed, and keeps a configuration written by `flowguard setup`. The DEB package no longer marks the file as a conffile, so dpkg never asks what to do with a changed configuration during an upgrade, even with the updater of earlier versions; the default now ships as `/usr/share/flowguard/config.json`.
- Fixed remote upgrades on Debian and Ubuntu failing when a new package ships a changed default `config.json` while the installed one was changed locally, such as by `flowguard setup`. dpkg asked which version to keep, which the updater cannot answer. The updater now keeps the local file and only takes the package's version when the local file was not changed.
- Fixed remote upgrades with dnf or yum failing when an unrelated repository is broken or unreachable. The updater now only uses the FlowGuard repository to check for and install the new version, as it already did to refresh the package cache.

## [0.31.3]

### Fixed

- Fixed `install.sh` on Ubuntu stopping at needrestart's "Pending kernel upgrade" dialog, which cannot be answered when the script is piped into bash. The installer and the updater now run apt non-interactively and skip needrestart.
- Fixed proxies that could stop receiving config updates, IP list updates and upgrade requests from the control panel without reconnecting. A failed or rejected channel subscription, or one the realtime server never confirmed within 30 seconds, left the connection open but unsubscribed until FlowGuard restarted. A failed first connection was never retried, and a connection that silently died could go unnoticed for about 15 minutes. FlowGuard now reconnects in each case, backing off from 2 seconds up to 5 minutes until a subscription succeeds, and fetches the latest configuration after every successful subscription to catch up on updates sent while it was not subscribed.

## [0.31.2]

### Changed

- Updated dependencies and Go to 1.27.3.

### Fixed

- Fixed stopping FlowGuard right after it started leaving its HTTP listener open until the listener's serve goroutine ran, so a connection could still be accepted, or reset, after shutdown had returned.

## [0.31.1]

_No source changes; this release republishes 0.31.0, whose packages were not published because the RPM build failed._

## [0.31.0]

### Added

- Added `body` and `body-truncated` rule matchers. `body` matches the first 256 KiB of the request body with any string operator, so a rule can block an exploit payload without blocking every request of its kind. `body-truncated` is `true` when the body is longer than that, so a rule can block or log bodies that were not fully inspected. The body is only read when a rule reaches a body matcher and is forwarded unchanged. See [Rule conditions](README.md#rule-conditions).
- Added `--bind` to `flowguard setup` for servers without a public IP address, such as servers behind NAT or a load balancer. Setup checks that each address is assigned to the machine and stores the addresses as `server.bind_addresses`, which `flowguard run` and `flowguard network inspect` use instead of the auto-detected public addresses. Their own `--bind` flag still takes precedence. When no public IP address is found, FlowGuard now suggests a `--bind` value from the machine's other addresses. See [Initial setup](README.md#initial-setup).
- Added IPv4-only addresses to transparent mode, for servers with more IPv4 than IPv6 addresses. Pass `--address-pair IPV4=` to `flowguard setup`, or omit `ipv6` from an `address_pairs` entry, for each IPv4 address without an IPv6 counterpart. Before, transparent mode refused to start when such an address could not be paired. IPv6 client IPs reported by a trusted proxy on an IPv4-only address use the canonical header fallback. See [Initial setup](README.md#initial-setup).

## [0.30.1]

### Added

- Added `--address-pair IPV4=IPV6` to `flowguard setup` to pair IPv4 and IPv6 bind addresses for transparent mode when they cannot be paired automatically. Repeat it for each pair. Setup checks that both addresses are bind addresses, replaces configured pairs that share an address, and makes transparent mode the default. See [Initial setup](README.md#initial-setup).

### Fixed

- Fixed `flowguard setup` and `flowguard network inspect` reporting transparent mode as unavailable on servers without the `nft` command, such as Ubuntu 22.04 and Debian 11. When iptables reports a missing chain as incompatible and `nft` is not installed, FlowGuard now checks the whole mangle table for the chain instead.

## [0.30.0]

### Added

- The install script now supports CloudLinux. It also recognizes other distributions derived from Debian, Ubuntu or RHEL, such as Linux Mint or Oracle Linux, by the parent distributions they list in `ID_LIKE` in `/etc/os-release`.
- Added support for DirectAdmin certificates. Set `host.cert_path` to the DirectAdmin installation (`/usr/local/directadmin`) to load each domain's certificate and the server hostname's certificate with its chain, whichever web server DirectAdmin runs. FlowGuard watches the users' `domains` directories, so renewed certificates and new users are picked up without a restart. `flowguard setup` offers it when DirectAdmin is installed. See [Certificate management](README.md#certificate-management).
- Transparent mode now pairs IPv4 and IPv6 bind addresses using the IPs linked in DirectAdmin when `host.cert_path` points to a DirectAdmin installation. Only links that DirectAdmin applies to the web server are used.

### Fixed

- Fixed `flowguard setup` reporting transparent mode as unavailable on EL8 systems such as CloudLinux 8 and Rocky Linux 8. Their iptables 1.8.5 reports a missing chain as "Incompatible with this kernel", which is now verified with `nft` instead.
- Fixed transparent mode refusing to start, and `flowguard setup` reporting it as unavailable, when iptables prints "# Warning: iptables-legacy tables present" while listing an existing `FLOWGUARD_UPSTREAM` chain. The warning was mistaken for an unmanaged rule.
- Fixed `flowguard setup` offering a leftover `/etc/nginx/nginx.conf` on servers that no longer run nginx, such as a DirectAdmin server switched to LiteSpeed. It is now only offered while nginx is running.
- Fixed a warning for every missing include when checking nginx listeners for transparent mode. Missing includes are skipped, as they already were when loading certificates.

## [0.29.1]

### Changed

- When FlowGuard runs behind another FlowGuard, such as the Caddy plugin at the edge in front of FlowGuard on the origin, the origin now keeps the edge's Stream ID instead of creating its own. One Stream ID identifies the request in both logs, on block pages, and in the `FG-Stream` headers of the response and the backend request, and the response carries it once. The ID is only taken from proxies trusted for forwarding headers through `trusted_proxies.ipnets` or `trusted_proxies.header_auth`. ([9646db33](https://github.com/chieftools/flowguard-proxy/commit/9646db336a80915a3f7bffc2637ed9b14debb963))

## [0.29.0]

### Added

- Added a Caddy plugin that runs FlowGuard inside Caddy instead of in front of it. Build it with `xcaddy build --with go.chief.tools/flowguard-proxy/caddy`. Caddy keeps listening, terminating TLS with its own certificates and storage, and proxying. FlowGuard evaluates rules, writes request logs, and stays connected to the control panel. Use the `flowguard` global option with a host key (`key {$FLOWGUARD_KEY}`) or a configuration file, and add the `flowguard` directive to each site. List the `flowguard` listener wrapper before `tls` to get JA4 fingerprints for HTTP/1.1 and HTTP/2. A `caddy reload` keeps rate limits, log buffers and the control panel connection. See [Run inside Caddy](README.md#run-inside-caddy). ([d84a0547](https://github.com/chieftools/flowguard-proxy/commit/d84a054727f5ac0d4c53e41aa7223bc13c8a87ba))
- Added an instance ID, so several instances can share one host key, such as the machines of a Fly.io app or the replicas of a container deployment. FlowGuard takes it from `FLOWGUARD_INSTANCE_ID`, then `FLY_MACHINE_ID`, then the hostname. It is sent to the control panel and the ingest gateway, and logged as `host.instance`. Heartbeats also report the hostname and region (`FLOWGUARD_REGION` or `FLY_REGION`), and an instance tells the control panel when it shuts down. ([d43784f4](https://github.com/chieftools/flowguard-proxy/commit/d43784f4b0ec87a0f077fdfdc783255da23ecdbb))

### Fixed

- Fixed heartbeats from the Caddy plugin sending `bind_addresses` as `null`, which the control panel rejected. An empty list is now sent. ([d43784f4](https://github.com/chieftools/flowguard-proxy/commit/d43784f4b0ec87a0f077fdfdc783255da23ecdbb))

## [0.28.2]

### Added

- Added a `skip_log` action that leaves matching requests out of the request logs, for noise such as load balancer health checks. Rule evaluation continues, so later rules still apply. A matched request is still logged if another rule logs, blocks, challenges or rate-limits it, or if its response status is 400 or higher, so failing health checks stay visible. ([162587b3](https://github.com/chieftools/flowguard-proxy/commit/162587b380c852b18a66d14f443898e08d8f56fc))

## [0.28.1]

### Security

- Fixed clients behind a layer 4 load balancer being able to set their address with `X-Forwarded-For` on HTTPS and HTTP/3. The PROXY protocol now trusts only load balancers listed in the new `trusted_proxies.proxy_protocol.ipnets`, instead of `trusted_proxies.ipnets`. On HTTPS and HTTP/3, forwarding headers on a connection from one of these load balancers are ignored when it sends no PROXY header, as on health checks or listeners without the PROXY protocol, because a load balancer that forwards TLS cannot add them. On HTTP, a load balancer that is also in `trusted_proxies.ipnets` keeps its `X-Forwarded-For` trust, so it can run port 80 in HTTP mode. After upgrading from 0.28.0, move load balancer addresses into `trusted_proxies.proxy_protocol.ipnets`; until then their PROXY headers are discarded. ([7f89ad7c](https://github.com/chieftools/flowguard-proxy/commit/7f89ad7c660b7a6a5335d0e9a946ca6dd186ca5f))

### Fixed

- Fixed requests without a `Host` header, such as HTTP/1.0 load balancer health checks, failing with 502 Bad Gateway. The upstream request now gets the bind address as its `Host`, without FlowGuard's listen port and with IPv6 addresses in brackets, so it reaches the backend's default server as it would without FlowGuard. Rules and logs still see the request as host-less, and no `X-Forwarded-Host` is sent for it. A forwarded IPv6 literal `Host` also keeps its brackets now. ([bc229186](https://github.com/chieftools/flowguard-proxy/commit/bc22918682dac3f7a8405e530b85d21aad7d3803))

## [0.28.0]

### Added

- Added PROXY protocol v1 and v2 support on the HTTP and HTTPS listeners, so FlowGuard can run behind a layer 4 load balancer such as AWS NLB or HAProxy in TCP mode. A header sets the client address only when the load balancer is in `trusted_proxies.ipnets`, and the load balancer is then logged and matched as the proxy (`proxy-ip`, `proxy-asn`, `proxy-iplist`). The header is optional, so trusted proxies that do not send one keep working, and headers from other peers are discarded. ([5c3c3782](https://github.com/chieftools/flowguard-proxy/commit/5c3c378202c4354972f22c623d7464b5927c70af))

## [0.27.0]

### Added

- Added a `--shutdown-timeout` option to `flowguard run` that sets how long in-flight requests may finish on shutdown before remaining connections are closed. It defaults to 10 seconds, replacing the previous fixed 30 seconds. ([125dad0b](https://github.com/chieftools/flowguard-proxy/commit/125dad0b30ef058e3338627afa285ae1a47634a4))

### Changed

- Rate limit actions without `partition_by` now give each client its own bucket, as if `partition_by` were `["client.ip"]`. Previously the bucket was built from the request values the rule matched (path, User-Agent, headers, query parameters, cookies) and was shared by all clients, so one client could exhaust a limit such as a login limit for everyone, while varying a value such as `//login` or the User-Agent gave a fresh bucket. Set `partition_by` to `[]` to keep one bucket per rule. ([c7a0862c](https://github.com/chieftools/flowguard-proxy/commit/c7a0862c2db61808e480d309ff4034b504a726e3))
- Grouped IPv6 clients by /64 in `client.ip` rate limit buckets, challenge attempt limits and behavior counters (including the unique clients counted per JA4 fingerprint), so rotating addresses within one allocation no longer gives a client fresh buckets or counts as many clients. ([d3f48f5c](https://github.com/chieftools/flowguard-proxy/commit/d3f48f5cf87ed894266b7783aefa2e395babf6ff), [ef201b04](https://github.com/chieftools/flowguard-proxy/commit/ef201b049fdcfea139481f1986621a2436de6c11))
- Logged `request.url.domain` as the normalized host that domain rules match, so log searches find the same requests as a rule with that value. `request.url.full` keeps the host as the client sent it. ([c7db6cd8](https://github.com/chieftools/flowguard-proxy/commit/c7db6cd84e01a5cbbd4d49615f9157d57df2a6f3))

### Fixed

- Normalized the request host before `domain` and `registerable-domain` rule matching, rate limit keys, challenge binding and behavior tracking. Hosts are lowercased, any port, IPv6 brackets and trailing dot are removed, and IP addresses are written in canonical form, so `STAGING.example.com`, `staging.example.com.` and `staging.example.com:443` no longer evade a rule for `staging.example.com` when `case_insensitive` is off. Configured domain values are normalized the same way, and domain regex matches are now case-insensitive. Domain rules that match IPv6 hosts with brackets, such as a regex for raw-IP requests, should accept the bare form. ([fd295198](https://github.com/chieftools/flowguard-proxy/commit/fd2951985e0e3de3b793e58ecf7c896390f8e1bd), [1df7bb85](https://github.com/chieftools/flowguard-proxy/commit/1df7bb8541c3240e262b75f5d55051bd1347ae47))
- Fixed `query-param` rules missing parameters that contain a `;` or an invalid percent escape. These pairs were dropped when the query was parsed, while the backend still received them, so `?q=1 union select;` or `?q=%zz' union select` evaded a rule on `q`. Rules and the logged query now parse the query like common backends do: pairs are split on `&` only and invalid escapes are kept as text. ([4952ec31](https://github.com/chieftools/flowguard-proxy/commit/4952ec31b6007f7ed56611270c56e36bb0d6eebf))
- Fixed `header` and `user-agent` rules only checking the first value of a repeated header. Every value is now checked, together with the comma-joined form backends such as nginx pass upstream. `user-agent` rules also support `exists` and `missing`. ([4952ec31](https://github.com/chieftools/flowguard-proxy/commit/4952ec31b6007f7ed56611270c56e36bb0d6eebf))
- Fixed negated operators (`not-equals`, `not-contains`, `not-in`, `not-regex` and the other `not-*` operators) matching a repeated header, query parameter or cookie when any one value satisfied them. They now match only when no value matches, so `?q=safe&q=<script>` no longer satisfies `not-contains "<"`. ([4952ec31](https://github.com/chieftools/flowguard-proxy/commit/4952ec31b6007f7ed56611270c56e36bb0d6eebf))
- Fixed `query-param` and `cookie` rules never matching when the key is absent. A missing key is now matched as an empty value, as a missing header already was, so a rule such as `token not-equals secret` can no longer be evaded by leaving `token` out. `exists` and `missing` are unchanged. ([4952ec31](https://github.com/chieftools/flowguard-proxy/commit/4952ec31b6007f7ed56611270c56e36bb0d6eebf))
- Fixed `raw_match` path rules matching the already-decoded path, so encoded sequences such as `%2e%2e`, `%2f` or `%00` could never match. Raw path rules now see the path as sent and forwarded upstream. ([00432901](https://github.com/chieftools/flowguard-proxy/commit/004329018345e646e6474d63e29ff9c962cdef24))
- Fixed `cookie` rules missing cookies whose values contain bytes such as `\`, a stray `"` or non-ASCII text, which were dropped when cookies were parsed while backends such as PHP still received them. Cookie values are now also matched percent-decoded, as PHP and common Node parsers read them, so `%3Cscript%3E` matches a rule for `<script>`. ([d0efcb10](https://github.com/chieftools/flowguard-proxy/commit/d0efcb10c95e4a88a6fbab524679d508f03413ec))
- Fixed `header` rules on `Host` never matching. They now match the `Host` header as the client sent it; use `domain` to match the normalized host. ([5d823483](https://github.com/chieftools/flowguard-proxy/commit/5d823483989e0b06be47e1a20ebef571ab330c77))
- Fixed TLS certificate selection being case-sensitive, so a mixed-case SNI name or certificate name could fall back to the default certificate. Certificate names, SNI names and `default_hostname` are now compared case-insensitively. ([fdbe3d86](https://github.com/chieftools/flowguard-proxy/commit/fdbe3d8628e8d6453f2a60b91191537a886739d1))
- Fixed `SIGHUP`, which systemd sends for `systemctl reload`, terminating the proxy without removing its port redirects. FlowGuard now reloads its configuration on `SIGHUP`, refreshing it from the API first when one is configured. ([b19e8678](https://github.com/chieftools/flowguard-proxy/commit/b19e867813fc1b767b0518691c7ba9ea9dbb4c90))
- Fixed shutdown leaving proxied WebSockets and other upgraded connections open, which `http.Server.Shutdown` neither waits for nor closes. After the drain timeout FlowGuard now cancels remaining requests and closes their connections, and it drains HTTP/3 alongside HTTP/1.1 and HTTP/2 so slow QUIC clients no longer use up the drain window. ([125dad0b](https://github.com/chieftools/flowguard-proxy/commit/125dad0b30ef058e3338627afa285ae1a47634a4))

## [0.26.1]

### Fixed

- Fixed client IP resolution behind trusted proxies when a client adds its own `X-Forwarded-For` value. A loopback, link-local or malformed entry to the left of the address added by the trusted proxy no longer makes FlowGuard record the trusted proxy as the client, which let clients evade IP-based rules and per-client counters. ([05e87ce9](https://github.com/chieftools/flowguard-proxy/commit/05e87ce901f3c840d1f061baf85ea55ccae4ded8))
- Combined repeated `X-Forwarded-For` header lines before resolving the client IP, so a client-supplied first line can no longer override the address added by a trusted proxy that appends a separate header line. Requests with more than one `X-Real-IP` value now fall back to the connecting address. ([05e87ce9](https://github.com/chieftools/flowguard-proxy/commit/05e87ce901f3c840d1f061baf85ea55ccae4ded8))

## [0.26.0]

### Added

- Added an `FG-IPCountry` header with the client's country code (or `XX` when unknown) to requests sent to the backend. ([61a3ede5](https://github.com/chieftools/flowguard-proxy/commit/61a3ede5f54f9ed47d847ad4861fdcfd7548fda9))
- Added `server.upstream.headers.stream_id` and `server.upstream.headers.ip_country` settings to turn off the `FG-Stream` and `FG-IPCountry` headers on requests sent to the backend. Both are enabled by default, and client responses always include `FG-Stream`. ([61a3ede5](https://github.com/chieftools/flowguard-proxy/commit/61a3ede5f54f9ed47d847ad4861fdcfd7548fda9))

## [0.25.2]

### Changed

- Sent a stable `X-FlowGuard-Prepared-At` time with each `flowguard_ingest` request and its retries, so the ingest gateway can deduplicate retries by content and batch inserts across requests. ([bac73636](https://github.com/chieftools/flowguard-proxy/commit/bac73636750a83028620a529af4cccbf43dfb325))

## [0.25.1]

### Changed

- Included `server/<server-id>` in managed API, realtime, and log delivery User-Agent headers, including after configuration reloads. ([3191c45e](https://github.com/chieftools/flowguard-proxy/commit/3191c45e5a47e6ea4686774cf23066a94f7886ad))

## [0.25.0]

### Added

- Added the `flowguard_ingest` log sink with authenticated HTTPS delivery, compressed batches, stable batch identities across retries, receipt validation, and heartbeat capability advertisement. ([37d2b7dd](https://github.com/chieftools/flowguard-proxy/commit/37d2b7ddeaa3f80d4c879ec1a9409ed4431a58a1))

## [0.24.0]

### Added

- Logged successful HTTP/1.1 WebSocket connections at open and close with linked request entries and final upstream telemetry. ([2af17f99](https://github.com/chieftools/flowguard-proxy/commit/2af17f99786d2e0a82de6eae3fd8939227e6fd53))

### Fixed

- Restored HTTP/1.1 WebSocket proxying by preserving writable upstream response bodies during protocol upgrades. ([2af17f99](https://github.com/chieftools/flowguard-proxy/commit/2af17f99786d2e0a82de6eae3fd8939227e6fd53))

## [0.23.0]

### Changed

- Updated the Go runtime and dependencies. ([53e0e964](https://github.com/chieftools/flowguard-proxy/commit/53e0e96412540cf2980f7e3fa6f2d676171c04df))

### Fixed

- Prevented logger memory growth during sustained sink failures or slow delivery by bounding queued and in-flight entries and bytes, limiting batch sizes, and applying controlled retries and shutdown deadlines. ([967fe8a4](https://github.com/chieftools/flowguard-proxy/commit/967fe8a4ca3c8c4f9c2549b332f13a48a53ae2fd))

## [0.22.1]

### Changed

- Renamed proxy-local domain and path behavior telemetry and matcher keys to server-scoped names, while retaining the 0.22.0 matcher keys as compatibility aliases. ([d0714137](https://github.com/chieftools/flowguard-proxy/commit/d07141375cfa8483db0e295f9315483a27ce9d80))

## [0.22.0]

### Added

- Added bounded rolling client, path, domain, and JA4 behavior counters with numeric rule matching for coordinated traffic detection. ([1fe0990f](https://github.com/chieftools/flowguard-proxy/commit/1fe0990fc32acedc35068decb3c42c050e273257))
- Added explicit rate-limit bucket partitioning by client IP, connection, JA4 fingerprint, domain, and path, including shared rule-wide buckets and backwards-compatible legacy behavior. ([1fe0990f](https://github.com/chieftools/flowguard-proxy/commit/1fe0990fc32acedc35068decb3c42c050e273257))
- Added connection concurrency, upstream timing and outcome, network-prefix, cookie-name, and header-set telemetry for incident analysis without recording cookie values. ([1fe0990f](https://github.com/chieftools/flowguard-proxy/commit/1fe0990fc32acedc35068decb3c42c050e273257))

### Fixed

- Returned HTTP 504 for upstream timeouts while retaining HTTP 502 for other upstream failures. ([1fe0990f](https://github.com/chieftools/flowguard-proxy/commit/1fe0990fc32acedc35068decb3c42c050e273257))

## [0.21.0]

### Fixed

- Prevented rate-limit memory amplification by reusing bounded sliding-window storage, capping tracked keys, reclaiming expired counters under pressure, and serializing concurrent initial requests. ([3b7b045e](https://github.com/chieftools/flowguard-proxy/commit/3b7b045eb3a7be6d808a15928428b00998218062))
- Prevented expected client disconnects from flooding challenge-response logs and rate-limited unexpected response-write failures. ([3b7b045e](https://github.com/chieftools/flowguard-proxy/commit/3b7b045eb3a7be6d808a15928428b00998218062))

## [0.20.0]

### Changed

- Restricted TLS 1.2 to ECDHE cipher suites with AES-GCM or ChaCha20-Poly1305, removing CBC and SHA-1 support. ([ccda96cb](https://github.com/chieftools/flowguard-proxy/commit/ccda96cbf20e72eadadc9eb74fc0eee30f16ef8e))

## [0.19.0]

### Changed

- Updated the Go runtime and dependencies. ([fe96a1fa](https://github.com/chieftools/flowguard-proxy/commit/fe96a1fa82b457c90f0ad7ba04a16fb4f652718b))
- Improved heartbeat and private realtime channel authorization reliability by reusing outbound connections and limiting response cleanup work. ([dc41bd08](https://github.com/chieftools/flowguard-proxy/commit/dc41bd08cc1ecfd5c8bb5aa90c651f40f0ffcd7f))
- Hardened HTTP request handling by rejecting requests with excessive header values before they reach FlowGuard middleware. ([fe96a1fa](https://github.com/chieftools/flowguard-proxy/commit/fe96a1fa82b457c90f0ad7ba04a16fb4f652718b), [2693ec74](https://github.com/chieftools/flowguard-proxy/commit/2693ec749470a380a2ceb99bc024ed66cd90c65a))

## [0.18.0]

### Added

- Added optional Linux Fail2Ban synchronization with immediate runtime ban events, authoritative snapshot reconciliation, hot-reloadable configuration, interactive setup support, standard 403 block responses with Stream IDs, and startup synchronization before proxy listeners open. ([f36cbbc2](https://github.com/chieftools/flowguard-proxy/commit/f36cbbc23b8a6008f19698966c2de6ffe064e7d8))

### Changed

- Increased the packaged systemd service stop timeout from 30 to 60 seconds so Fail2Ban runtime-action cleanup can finish during shutdown. ([3b79d341](https://github.com/chieftools/flowguard-proxy/commit/3b79d341cb5e07ee19eb2a49d835b3d62e435d2a))

## [0.17.1]

### Fixed

- Corrected source-specific transparent upstream rejection detection to preserve retries when the backend recovers or confirmation is inconclusive, while keeping canceled requests neutral to shared backend health. ([f2eafae0](https://github.com/chieftools/flowguard-proxy/commit/f2eafae0064549c0969a8babc17a1c2a75ddc808))

## [0.17.0]

### Changed

- Updated dependencies. ([7bf438e9](https://github.com/chieftools/flowguard-proxy/commit/7bf438e9287f75c2f6e12a4718c0fff61563d9d3))

### Fixed

- Prevented source-specific transparent upstream rejections from affecting shared backend health or returning a synthetic response, while logging the aborted request with status 444. ([c026fb5d](https://github.com/chieftools/flowguard-proxy/commit/c026fb5d787eefd8b943df16243a369e94c3f55f))
- Fell back to the configured default certificate when every exact or wildcard certificate matching the requested hostname has expired. ([43f7a476](https://github.com/chieftools/flowguard-proxy/commit/43f7a476dfedfca7531da9e08e9b6ae70f598390))

## [0.16.2]

### Fixed

- Fixed transparent-mode readiness on nftables-backed iptables 1.8.7 systems by verifying that missing FlowGuard mangle chains are actually available. ([a17d8998](https://github.com/chieftools/flowguard-proxy/commit/a17d8998259f029a45e3015a4bb513765f828289))

## [0.16.1]

### Fixed

- Ensured FlowGuard traffic interception takes precedence over Docker-published backend port redirects. ([3b955c91](https://github.com/chieftools/flowguard-proxy/commit/3b955c91d7930e662be00f40edf0e72e5198105b))

## [0.16.0]

### Added

- Added read-only Traefik v2/v3 `acme.json` certificate loading, renewal watching, and setup discovery. ([b9f93cb2](https://github.com/chieftools/flowguard-proxy/commit/b9f93cb2d274d99e652f8a23436e00a5e122d4f7))

## [0.15.2]

### Changed

- Cleaned up interactive setup indentation and replaced the duplicate successful network-inspection report with a concise transparent-network readiness confirmation. ([e96a3da3](https://github.com/chieftools/flowguard-proxy/commit/e96a3da3cb95338d091462d6eb4240946a19d830))

## [0.15.1]

### Added

- Added automatic transparent address-pair detection when an IPv6 address's final four hextets repeat its IPv4 counterpart's decimal octets. ([c0b89cad](https://github.com/chieftools/flowguard-proxy/commit/c0b89cad2eb9f636168ae7992b2f952fefe04e1f))
- Added verbose setup and network-inspection diagnostics explaining server-source, NGINX listener, address-pairing, and prerequisite decisions. ([48aebcae](https://github.com/chieftools/flowguard-proxy/commit/48aebcaefa3f4923ea9630b8a69edd785413700a))

### Changed

- Moved upstream client-IP mode selection before manual address pairing so header-mode setups skip unnecessary pairing prompts. ([77cdc6d4](https://github.com/chieftools/flowguard-proxy/commit/77cdc6d48268a21ca7b4e571910a798d5511a409))

## [0.15.0]

### Added

- Added transparent upstream client-IP forwarding for same-host Linux backends, including dual-stack address pairing, lifecycle-managed policy routing, readiness inspection, and CLI overrides for testing. ([85c60a1a](https://github.com/chieftools/flowguard-proxy/commit/85c60a1a13deed76fb34893f126c0498ab314edd))
- Added interactive setup for selecting the upstream client-IP mode, enabled HTTP protocols, HTTP/3 advertisement, and ambiguous IPv4/IPv6 address pairs, with accessible and line-oriented terminal fallbacks. ([f37d19c9](https://github.com/chieftools/flowguard-proxy/commit/f37d19c93fd9b0e9428ce5bc33e82fb27cf35651))
- Added post-setup guidance to start or restart FlowGuard so startup-only networking changes take effect. ([feaf4e82](https://github.com/chieftools/flowguard-proxy/commit/feaf4e822140c7774736daec2da816562f9bd5df))

### Changed

- Canonicalized upstream forwarding headers, removed spoofable forwarding values, preserved request query strings during proxy rewrites, and hardened interception ports against direct traffic. ([002cc4d5](https://github.com/chieftools/flowguard-proxy/commit/002cc4d59ba9688f938f84aab39e81da7414e2f6))
- Added canonical header fallback for opposite-family clients on single-stack transparent deployments while keeping matching-family connections transparent. ([396ff3b2](https://github.com/chieftools/flowguard-proxy/commit/396ff3b2ed075c8e3dedd758698ca93b59f89579))
- Unified trusted-proxy and IP-list loading so trusted proxy lists refresh while FlowGuard is running. ([21d8be43](https://github.com/chieftools/flowguard-proxy/commit/21d8be434699a6f1d64a791bb1def03367f5ab62))
- Improved startup logging with concise endpoint, firewall, IP-list, bind-address, and upstream-mode summaries. ([f2f720fd](https://github.com/chieftools/flowguard-proxy/commit/f2f720fd3918bbd90339c1822dab6fa84414c1fd))
- Allowed `flowguard setup` without a host key to reuse the configured key and rediscover the server configuration. ([4555c2fa](https://github.com/chieftools/flowguard-proxy/commit/4555c2fa10d940e3497b4ea1a1df06fc68899b18))
- Updated dependencies. ([e19c61c0](https://github.com/chieftools/flowguard-proxy/commit/e19c61c0b4d971f96420541dfd2b5afa4c3410ed))

### Fixed

- Started the realtime configuration client only while the proxy is running, avoiding unnecessary short-lived connections from inspection and setup commands. ([cf547c1a](https://github.com/chieftools/flowguard-proxy/commit/cf547c1aecded495313a6d9fb3194f2d02fe19c2))

## [0.14.0]

### Added

- Added proxy rule matchers for selecting requests by proxy configuration. ([d9c67cf7](https://github.com/chieftools/flowguard-proxy/commit/d9c67cf7a17b928db09e0aa1525624a3a9d1261b))

### Changed

- Made upstream connections and retry handling more resilient to transient failures. ([27f2b04b](https://github.com/chieftools/flowguard-proxy/commit/27f2b04b9992e89801bf21ea30b1b2483287203b))
- Updated dependencies. ([d3d95c01](https://github.com/chieftools/flowguard-proxy/commit/d3d95c01bf13427347aec97783926767bba31237))

## [0.13.0]

### Added

- Added request-field matchers and inline CIDR matching for client IP rules. ([dfbc2f05](https://github.com/chieftools/flowguard-proxy/commit/dfbc2f055a8979476fa5d10da389fbda20c10db0))

### Removed

- Removed the `ipset` matcher feature. ([532c7655](https://github.com/chieftools/flowguard-proxy/commit/532c765555135a0a971e6c484e22962da5e4c2c8))

### Fixed

- Compiled negative regular-expression matchers correctly. ([2cde5264](https://github.com/chieftools/flowguard-proxy/commit/2cde52640a4796c50257878eaf93c3f06a11aded))

## [0.12.1]

### Changed

- Improved interactive setup output. ([aff46f0b](https://github.com/chieftools/flowguard-proxy/commit/aff46f0bb048bfdeb710eca6e964a1db621e712c))

## [0.12.0]

### Added

- Added an interactive setup command for configuring Plesk and NGINX paths. ([9d4f50cb](https://github.com/chieftools/flowguard-proxy/commit/9d4f50cbdebfcee47427d76be69b1a8b88e50331))

## [0.11.1]

### Fixed

- Prevented dotfiles from being mistaken for file extensions when identifying resources. ([ab5ada47](https://github.com/chieftools/flowguard-proxy/commit/ab5ada4751fe00cb60cfe827dcf8112867f9b8b3))

## [0.11.0]

### Added

- Added a response resource identifier for classifying proxied content. ([65498186](https://github.com/chieftools/flowguard-proxy/commit/6549818655bb876bb962e2e7e621e88833ee148d))

## [0.10.0]

### Added

- Added the `header_auth` trusted-proxy method for authenticated forwarding headers. ([1fb83390](https://github.com/chieftools/flowguard-proxy/commit/1fb833902eb2a17d2199d400fb60b1e60433795e))

### Changed

- Updated dependencies. ([4128c031](https://github.com/chieftools/flowguard-proxy/commit/4128c031f82bab0c3aad4ff6ff85178b88040613))

## [0.9.2]

### Changed

- Updated dependencies. ([7e89b7e3](https://github.com/chieftools/flowguard-proxy/commit/7e89b7e3cee17efec84f644f5ad89dbfedddcbac))

## [0.9.1]

### Fixed

- Ensured rules with order `0` are processed before rules with higher values. ([71867ba7](https://github.com/chieftools/flowguard-proxy/commit/71867ba7ee540c4e3c10de9b473d073a8e288eaa))

## [0.9.0]

### Changed

- Improved WebSocket client connection and reconnection handling. ([b775058a](https://github.com/chieftools/flowguard-proxy/commit/b775058a4fafdcf88a346c1b5bf56a9b8aae579b))

## [0.8.0]

### Added

- Added a proof-of-work challenge action for requests selected by the rule engine. ([b304c91b](https://github.com/chieftools/flowguard-proxy/commit/b304c91b87cce92b920267650efdcfb6fd3ba292))
- Added a development command for running FlowGuard locally. ([59129815](https://github.com/chieftools/flowguard-proxy/commit/59129815eefcc9e968338435bb9cee3199ff33a6))

### Changed

- Allowed startup without loaded certificates when the configured NGINX file is readable. ([11b9e7cb](https://github.com/chieftools/flowguard-proxy/commit/11b9e7cbaa86f8dedcaee32dd7507439b07511ea))

## [0.7.1]

### Added

- Added JA4 client fingerprinting for logging and rule matching. ([9382c32f](https://github.com/chieftools/flowguard-proxy/commit/9382c32f77bbc3168ece610c0266606f8b364fba))

## [0.7.0]

### Added

- Added configuration for selecting served protocols and advertising the HTTP/3 service. ([9d8f4599](https://github.com/chieftools/flowguard-proxy/commit/9d8f459923fda267dcc4a58de9f28f21482044da), [f16dbe46](https://github.com/chieftools/flowguard-proxy/commit/f16dbe46408f96d900726a0d3efc5b84d775fd5f))

### Fixed

- Ensured HTTP/2 is configured when enabled and removed a server-shutdown race condition. ([a7a26a99](https://github.com/chieftools/flowguard-proxy/commit/a7a26a99662b1410a0d492c9697d41825d32cc59), [4291b716](https://github.com/chieftools/flowguard-proxy/commit/4291b716864e036edcd93d9bb21cffe47ce1e3ec))

## [0.6.0]

### Added

- Added HTTP/3 proxy support. ([8c523189](https://github.com/chieftools/flowguard-proxy/commit/8c523189756b6688703db02655d126c249a4aa46))

## [0.5.0]

### Added

- Added NAND and NOR operators for composing rule conditions. ([9fd79988](https://github.com/chieftools/flowguard-proxy/commit/9fd79988ff0cb913c804657ed3618481b612d1b1))

### Changed

- Split configuration management into focused components to support the expanded condition model. ([96b4efd5](https://github.com/chieftools/flowguard-proxy/commit/96b4efd5bece94d0f99c4dbd802b1fed0b4cd1a4))

### Fixed

- Corrected evaluation of mixed condition groups. ([84c02995](https://github.com/chieftools/flowguard-proxy/commit/84c029957b004b670e6c16552f432032a504361c))

## [0.4.0]

### Added

- Added automatic monitoring and repair of FlowGuard firewall configuration. ([209cba4d](https://github.com/chieftools/flowguard-proxy/commit/209cba4d9f052dc77ca11defb5a61b9a2f482899))

## [0.3.12]

### Fixed

- Prevented unrelated third-party APT repository failures from blocking FlowGuard updates. ([c461a443](https://github.com/chieftools/flowguard-proxy/commit/c461a443d74f7484a14995e1322fb95ca8b008ea))

## [0.3.11]

### Fixed

- Reported systemd readiness only after listeners start successfully. ([0ea1c9b8](https://github.com/chieftools/flowguard-proxy/commit/0ea1c9b80ee628c460097d250b5fb8afa6e7df95))

## [0.3.10]

### Changed

- Migrated generated APT repository configuration to the deb822 source format. ([581b152d](https://github.com/chieftools/flowguard-proxy/commit/581b152dea7b5812d470bc6fb5ebd778ea2bf978))

## [0.3.9]

### Removed

- Removed the Axiom logging sink. ([01127f58](https://github.com/chieftools/flowguard-proxy/commit/01127f586075d324d27f6089ad6f0115a5db6f8d))

### Changed

- Updated dependencies. ([20ceda1c](https://github.com/chieftools/flowguard-proxy/commit/20ceda1c2b0b89ec37f55a19b3f41ecf9d6a445c))

## [0.3.8]

_No source changes; this release republishes 0.3.7._

## [0.3.7]

### Fixed

- Continued an upgrade when a general `apt-get update` reported unrelated repository errors. ([df1dac25](https://github.com/chieftools/flowguard-proxy/commit/df1dac25d912e9413752265222c33e93f7a36e72))

## [0.3.6]

_No source changes; this release republishes 0.3.5._

## [0.3.5]

### Fixed

- Ran unattended upgrades in a separate systemd scope so installing the new package does not terminate the upgrade process. ([7875d228](https://github.com/chieftools/flowguard-proxy/commit/7875d2280dbc91caf1f40455662af69f2aff48e0))

## [0.3.4]

### Fixed

- Refreshed the local package cache before attempting a remote upgrade. ([d7b5ff70](https://github.com/chieftools/flowguard-proxy/commit/d7b5ff7098d89e615d8cda0132258bf4fe38c3fb))

## [0.3.3]

### Fixed

- Corrected the RPM repository metadata rebuild conditional. ([d25d7423](https://github.com/chieftools/flowguard-proxy/commit/d25d74239118cfab85abaa868c96251746eaa908))

## [0.3.2]

### Added

- Added arm64 DEB and RPM packages. ([a650ad11](https://github.com/chieftools/flowguard-proxy/commit/a650ad11c804d332282572f0030c984389d2ab77))

### Fixed

- Improved RPM package and repository generation in the release workflow. ([97a56d66](https://github.com/chieftools/flowguard-proxy/commit/97a56d6690e2eb9b770156155c291b66e8c37efb))

## [0.3.1]

### Changed

- Replaced the IP trie implementation to improve IP list matching and maintenance. ([63bc71d2](https://github.com/chieftools/flowguard-proxy/commit/63bc71d237ceaed1b761cf64a1217e38e8489d09))

## [0.3.0]

### Added

- Added optional unattended package upgrades. ([3213d7cc](https://github.com/chieftools/flowguard-proxy/commit/3213d7cc2e723ec9d76a54d98de14fafb3188950))
- Added heartbeat reporting for managed proxies. ([a11d7064](https://github.com/chieftools/flowguard-proxy/commit/a11d706475c78705cd31355c7df23dae131dc472))

## [0.2.32]

### Changed

- Adjusted OpenTelemetry versions and updated dependencies for runtime compatibility. ([73335bb9](https://github.com/chieftools/flowguard-proxy/commit/73335bb98237e28a2444b75397f5d8bd7cb99ccd), [5bd2eb34](https://github.com/chieftools/flowguard-proxy/commit/5bd2eb34b4a8657de2d29c4bb88726e391b3d213))

## [0.2.31]

### Changed

- Updated dependencies. ([0bbe500f](https://github.com/chieftools/flowguard-proxy/commit/0bbe500f9feaac90a15da3bc906e5606fb069b9d))

## [0.2.30]

### Fixed

- Refined incremental release publishing so existing package archives do not need to be downloaded. ([fde6e094](https://github.com/chieftools/flowguard-proxy/commit/fde6e0942133004d9890559e35e0616b6a37b363), [46cf9a2f](https://github.com/chieftools/flowguard-proxy/commit/46cf9a2fa68df27304f5a384c5439c25c4fc07ee), [0b68924c](https://github.com/chieftools/flowguard-proxy/commit/0b68924cfbc3b4a84c1d77c06094616b0050e43e))

## [0.2.29]

### Changed

- Reworked release publishing to avoid downloading the full existing package archive. ([0703d6a9](https://github.com/chieftools/flowguard-proxy/commit/0703d6a9a764361ee2cd32a1053fa5d923432617))

## [0.2.28]

### Changed

- Updated dependencies. ([61871a37](https://github.com/chieftools/flowguard-proxy/commit/61871a3774e22d659092a94a3257bb55e72a3182))

## [0.2.27]

### Changed

- Updated dependencies. ([19f829c5](https://github.com/chieftools/flowguard-proxy/commit/19f829c579744291baaad948ea77b0c44961bba9))

## [0.2.26]

### Added

- Restored registerable-domain logging and matching with the final `registerable_domain` field name. ([771e3266](https://github.com/chieftools/flowguard-proxy/commit/771e3266bfe20d9559af252bb9707e4da03d928c), [88e5585e](https://github.com/chieftools/flowguard-proxy/commit/88e5585ea265ec7911711d2fa39c07bbc667f5ee), [13127fad](https://github.com/chieftools/flowguard-proxy/commit/13127fadc986cf450cbfff2919e2824f5dff8bd0))

## [0.2.25]

### Fixed

- Corrected APT repository generation and publishing. ([77d9e6cc](https://github.com/chieftools/flowguard-proxy/commit/77d9e6cc01d7ad28bf322872344939ff9e8b6f88))

## [0.2.24]

### Changed

- Updated the Go toolchain and clarified upgrade instructions. ([c78b6933](https://github.com/chieftools/flowguard-proxy/commit/c78b6933559e5419a4918af81a9fbb63e7d51234), [56bb923f](https://github.com/chieftools/flowguard-proxy/commit/56bb923fcb88e40a73a28b473e58549b4fff083c))

## [0.2.23]

### Changed

- Rolled back the experimental garbage collector and dependency updates from the preceding releases. ([2aa73b9d](https://github.com/chieftools/flowguard-proxy/commit/2aa73b9db34048060d8812a2775f6f82ba14748d), [5df1610b](https://github.com/chieftools/flowguard-proxy/commit/5df1610b72010ff66c0a8416b07c9717b6622ae1), [f8f0b66d](https://github.com/chieftools/flowguard-proxy/commit/f8f0b66d47fde5e319c678e4740d8c9125c00c50))

## [0.2.22]

### Removed

- Temporarily rolled back registerable-domain logging and matching. ([3fd73416](https://github.com/chieftools/flowguard-proxy/commit/3fd7341685f2c60ccc3fc68ae26174256c0b942b), [14404951](https://github.com/chieftools/flowguard-proxy/commit/1440495180612be3d7bdc5a9859eefb0f26f5d06), [4216f237](https://github.com/chieftools/flowguard-proxy/commit/4216f237bbd7567066c0e3fe2549ba55e5e1f731))

## [0.2.21]

### Fixed

- Kept a running proxy active across package upgrades. ([464616f4](https://github.com/chieftools/flowguard-proxy/commit/464616f4aac0562334032cf2c076c7797c15cafa))

### Changed

- Downgraded the Go toolchain for compatibility. ([e7cdb668](https://github.com/chieftools/flowguard-proxy/commit/e7cdb6682ec7b3af00732749f7c27391e7527a63))

## [0.2.20]

### Changed

- Disabled the experimental Green Tea garbage collector and restored the newer Axiom client. ([693e8e9d](https://github.com/chieftools/flowguard-proxy/commit/693e8e9d8882b3c0c235d0784dcba3747c74fbdc), [db17401b](https://github.com/chieftools/flowguard-proxy/commit/db17401bc6011f8570fe41c36057959db790e98e))

## [0.2.19]

### Fixed

- Restarted the proxy after an update only when it had been running beforehand. ([480dae21](https://github.com/chieftools/flowguard-proxy/commit/480dae217d43e125ce31209209e1a3ac81eb002e))

### Changed

- Downgraded the Axiom client for compatibility. ([43c1be08](https://github.com/chieftools/flowguard-proxy/commit/43c1be08d1ec0eb3edc5c50441765917e42fd132))

## [0.2.18]

### Changed

- Included normalized domain values in logs and standardized the field name as `registerable_domain`. ([95d90c80](https://github.com/chieftools/flowguard-proxy/commit/95d90c8021594ad6e744da4f5a189e9c09c8d2a1), [0ee8adae](https://github.com/chieftools/flowguard-proxy/commit/0ee8adae053a5f455fdb25c75428ad8dd3ac83d6))

## [0.2.17]

### Changed

- Reissued safe startup without certificates and registerable-domain matching on the main release line. ([32fef81b](https://github.com/chieftools/flowguard-proxy/commit/32fef81bbfdaa9eb08dd1e179bea22967ca89ac9), [0fb7dd3a](https://github.com/chieftools/flowguard-proxy/commit/0fb7dd3a618808235fc860a9e4ab19a9d4994803))
- Updated dependencies and release tooling. ([e288ed09](https://github.com/chieftools/flowguard-proxy/commit/e288ed09b0b85c6b15bc63ef9d986c3a76ee86af), [#2](https://github.com/chieftools/flowguard-proxy/pull/2), [#3](https://github.com/chieftools/flowguard-proxy/pull/3))

## [0.2.16]

### Added

- Added registerable-domain logging and rule matching. ([20eda847](https://github.com/chieftools/flowguard-proxy/commit/20eda8478957700803ebb3e1ac1a614db88f2fa8))

### Fixed

- Prevented the proxy from starting when no certificates are available. ([706bca02](https://github.com/chieftools/flowguard-proxy/commit/706bca029a784a68b95747dea14ac0e55b1b1f4c))

### Changed

- Updated dependencies. ([37d6327e](https://github.com/chieftools/flowguard-proxy/commit/37d6327e5a34915bd61b623c12b41940896d4c99))

## [0.2.15]

### Changed

- Watched certificate files as well as NGINX configuration for live reloads. ([e2a705c5](https://github.com/chieftools/flowguard-proxy/commit/e2a705c5328c1e4a36d5ba9a8580c10196718a43))

## [0.2.14]

### Fixed

- Restored server-sent event streaming by implementing `http.Flusher` on the wrapped response writer. ([30d9cea2](https://github.com/chieftools/flowguard-proxy/commit/30d9cea2c42be20eddbddec25a3b772b63673a11))

### Changed

- Updated dependencies. ([0af62e22](https://github.com/chieftools/flowguard-proxy/commit/0af62e22358e19887128bd1808e7080c63f6c33c))

## [0.2.13]

### Changed

- Allowed remote trusted-proxy lists to contain individual IP addresses as well as CIDR ranges. ([bc1be4c9](https://github.com/chieftools/flowguard-proxy/commit/bc1be4c92f1a00a8cc56ed0d03326f9c5de9f6c9))

## [0.2.12]

### Added

- Added a command for clearing the local cache directory. ([64a28441](https://github.com/chieftools/flowguard-proxy/commit/64a28441a9692bc8a0e2ebf3c6da28b53d889866))

### Fixed

- Applied API credentials before requests that require them. ([b8047ef4](https://github.com/chieftools/flowguard-proxy/commit/b8047ef40743bfe8fe78f441b5203da8d2092536))

## [0.2.11]

### Changed

- Allowed managed IP lists to be empty. ([05c6927d](https://github.com/chieftools/flowguard-proxy/commit/05c6927d9eea16c64956f5513f36f85f3563c9b2))

### Fixed

- Correctly decoded IP list event payloads. ([ec60d117](https://github.com/chieftools/flowguard-proxy/commit/ec60d1170a009646125de9b36222d526de55aafc))

## [0.2.10]

### Added

- Added live handling for `iplist.updated` WebSocket events. ([0a8afac3](https://github.com/chieftools/flowguard-proxy/commit/0a8afac34e3452c82bdde11219177283df83eb6a))

## [0.2.9]

### Added

- Added confidence values to IP list entries. ([4d789cb7](https://github.com/chieftools/flowguard-proxy/commit/4d789cb72c56c67e737c8189a417aebae2aaaca1))

### Fixed

- Shortened cached IP list lifetimes slightly to avoid expiry races. ([515c9e82](https://github.com/chieftools/flowguard-proxy/commit/515c9e82a76d1f1905909906189597b6d8247b53))

### Changed

- Reduced verbose IP list refresh output. ([f4b5bdc3](https://github.com/chieftools/flowguard-proxy/commit/f4b5bdc35b11d16df95c21940c811c9bc8277aa1))

## [0.2.8]

### Changed

- Forwarded the `FG-Stream` tracing header to upstream backends. ([d543491f](https://github.com/chieftools/flowguard-proxy/commit/d543491fae00d87680b02555c80cf433721999cc))

## [0.2.7]

### Fixed

- Rendered blocked-request error page output as text instead of a byte slice. ([41aad698](https://github.com/chieftools/flowguard-proxy/commit/41aad698006813f38d02721c3ff3ad81406c484d))

## [0.2.6]

### Added

- Added a clearer HTML error page for blocked requests. ([eb4850d8](https://github.com/chieftools/flowguard-proxy/commit/eb4850d85a6f21c7922d73f20f0ea5724b606ed2))

## [0.2.5]

### Changed

- Updated the Go toolchain version used to build FlowGuard. ([8c7b11b6](https://github.com/chieftools/flowguard-proxy/commit/8c7b11b677270067daff700fdfe96bd41fca9aa2))

## [0.2.4]

### Added

- Added ETag-aware configuration fetching and commands for refreshing configuration. ([cd308e4f](https://github.com/chieftools/flowguard-proxy/commit/cd308e4fcf86cf7d8167caca6b0f2c5886f5d8a3))

### Changed

- Switched setup inputs to flags and improved CLI command handling and API errors. ([b3091a94](https://github.com/chieftools/flowguard-proxy/commit/b3091a944550de48f3538fe6958878ba46294fa9), [0c39fa39](https://github.com/chieftools/flowguard-proxy/commit/0c39fa39b047493a018f9f03535c1d6573efb5ff), [0ce6eb77](https://github.com/chieftools/flowguard-proxy/commit/0ce6eb77d512f7240ccca2a9f096c5900d609752))

### Fixed

- Always attempted a configuration refresh during startup. ([05e7c40f](https://github.com/chieftools/flowguard-proxy/commit/05e7c40f0921540a3a727f72b19745cb4eecaad1))
- Documented the required YUM cache refresh after adding the repository. ([4eef9822](https://github.com/chieftools/flowguard-proxy/commit/4eef9822684c17cead5008c8ab900444f4d474fd))

## [0.2.3]

### Fixed

- Corrected the service start command in RPM packages. ([8926987e](https://github.com/chieftools/flowguard-proxy/commit/8926987ed5ff28ea3f90939ed5050966888d7779))

## [0.2.2]

### Changed

- Built packages for compatibility with a broader range of supported Linux systems. ([ad68f60b](https://github.com/chieftools/flowguard-proxy/commit/ad68f60b6a0a83cc67f68503f7a8ce0e5889baa9))

## [0.2.1]

### Added

- Added the `run` command and published the configuration JSON schema. ([6e14c8b7](https://github.com/chieftools/flowguard-proxy/commit/6e14c8b7f0845733485e6d24ff547feed8ffc975), [13c24e2b](https://github.com/chieftools/flowguard-proxy/commit/13c24e2b7a6a1b1a85580fc5eb9167f2d5588ddd))

### Changed

- Refreshed the minimal and bundled configuration examples. ([d9985398](https://github.com/chieftools/flowguard-proxy/commit/d99853980abbc9ee0cd5390bfee2866141aa6a34))
- Updated dependencies. ([53e2f5cc](https://github.com/chieftools/flowguard-proxy/commit/53e2f5ccb911f34f1c85227ae6b96191503bc5a8))

### Fixed

- Corrected release bootstrapping, package builds, and Debian repository architecture metadata and publishing. ([b6884eeb](https://github.com/chieftools/flowguard-proxy/commit/b6884eeb5b8ad2bcda3760ca1feb813b719c1265), [0af25671](https://github.com/chieftools/flowguard-proxy/commit/0af256719cc4d0acffa60f36f4d0663a9c259f11), [92e68523](https://github.com/chieftools/flowguard-proxy/commit/92e68523a992c83152d857cd810ccc71e357246a), [d80d0704](https://github.com/chieftools/flowguard-proxy/commit/d80d0704e388e81331807c694352c62e6dc42f81))

## 0.2.0

_Initial release._

[Unreleased]: https://github.com/chieftools/flowguard-proxy/compare/v0.33.1...HEAD
[0.33.1]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.33.1
[0.33.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.33.0
[0.32.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.32.0
[0.31.3]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.31.3
[0.31.2]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.31.2
[0.31.1]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.31.1
[0.31.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.31.0
[0.30.1]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.30.1
[0.30.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.30.0
[0.29.1]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.29.1
[0.29.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.29.0
[0.28.2]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.28.2
[0.28.1]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.28.1
[0.28.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.28.0
[0.27.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.27.0
[0.26.1]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.26.1
[0.26.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.26.0
[0.25.2]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.25.2
[0.25.1]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.25.1
[0.25.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.25.0
[0.24.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.24.0
[0.23.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.23.0
[0.22.1]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.22.1
[0.22.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.22.0
[0.21.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.21.0
[0.20.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.20.0
[0.19.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.19.0
[0.18.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.18.0
[0.17.1]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.17.1
[0.17.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.17.0
[0.16.2]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.16.2
[0.16.1]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.16.1
[0.16.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.16.0
[0.15.2]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.15.2
[0.15.1]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.15.1
[0.15.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.15.0
[0.14.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.14.0
[0.13.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.13.0
[0.12.1]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.12.1
[0.12.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.12.0
[0.11.1]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.11.1
[0.11.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.11.0
[0.10.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.10.0
[0.9.2]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.9.2
[0.9.1]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.9.1
[0.9.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.9.0
[0.8.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.8.0
[0.7.1]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.7.1
[0.7.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.7.0
[0.6.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.6.0
[0.5.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.5.0
[0.4.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.4.0
[0.3.12]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.3.12
[0.3.11]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.3.11
[0.3.10]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.3.10
[0.3.9]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.3.9
[0.3.8]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.3.8
[0.3.7]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.3.7
[0.3.6]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.3.6
[0.3.5]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.3.5
[0.3.4]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.3.4
[0.3.3]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.3.3
[0.3.2]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.3.2
[0.3.1]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.3.1
[0.3.0]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.3.0
[0.2.32]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.32
[0.2.31]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.31
[0.2.30]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.30
[0.2.29]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.29
[0.2.28]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.28
[0.2.27]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.27
[0.2.26]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.26
[0.2.25]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.25
[0.2.24]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.24
[0.2.23]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.23
[0.2.22]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.22
[0.2.21]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.21
[0.2.20]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.20
[0.2.19]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.19
[0.2.18]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.18
[0.2.17]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.17
[0.2.16]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.16
[0.2.15]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.15
[0.2.14]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.14
[0.2.13]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.13
[0.2.12]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.12
[0.2.11]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.11
[0.2.10]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.10
[0.2.9]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.9
[0.2.8]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.8
[0.2.7]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.7
[0.2.6]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.6
[0.2.5]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.5
[0.2.4]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.4
[0.2.3]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.3
[0.2.2]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.2
[0.2.1]: https://github.com/chieftools/flowguard-proxy/releases/tag/v0.2.1
