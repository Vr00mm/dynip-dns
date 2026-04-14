# Changelog

All notable changes are documented here.

## [Unreleased]

### Added
- Package-level doc comments on all internal packages
- `Server`, `New`, `Run` doc comments
- `CONTRIBUTING.md`
- `LICENSE`
- 100% test statement coverage across all packages

### Changed
- Removed dead code: nil guards on injectable `listenPacket`/`listen` fields and redundant stop-channel check in `serveUDP`

## [2026-04-11]

### Added
- Per-IP UDP token-bucket rate limiting (20 req/s sustained, 100 000-IP cap) to mitigate DNS amplification attacks
- EDNS0 OPT record parsing (`ParseEDNS0PayloadSize`) and TC-bit truncation for oversized UDP responses
- CI workflow for build checks on push and PR

### Fixed
- SOA serial now computed once at startup (`YYYYMMDD00`) instead of using `time.Now()` per query
- OVH delegation docs: explicit `A`/`NS` record types, removed incorrect glue record terminology
- README: use `dyn.yourdomain.com` subdomain consistently
- CI: disabled Go cache (no `go.sum`), fixed build output path
- Pages repo reference corrected to `vr00mm.github.io`
- `.gitignore` and missing `dynip-dns.conf.example` added

### Initial
- Initial commit: lightweight authoritative DNS server resolving IPs encoded in subdomain labels (`192-168-1-1.dyn.example.com → 192.168.1.1`)
- IPv4 and IPv6 support (`2001-db8--1`, `ip6-` prefix)
- Record types: `A`, `AAAA`, `NS`, `SOA`, `TXT`, `ANY`
- UDP + TCP listeners, EDNS0, glue records, configurable via env/file
- Docker image, systemd service, APT package
