# Changelog

All notable changes to FlowGuard Proxy are documented in this file.

Changes are grouped by release and type, with the newest release first. Release
dates are available from the linked GitHub releases. Add future changes to the
Unreleased section, then move them into a versioned section before tagging a
release.

## [Unreleased]

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

[Unreleased]: https://github.com/chieftools/flowguard-proxy/compare/v0.17.0...HEAD
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
