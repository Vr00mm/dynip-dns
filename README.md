# dynip-dns

Lightweight authoritative DNS server that resolves hostnames to IPs encoded directly in the subdomain label. No database, no dynamic updates — just encode the IP in the name.

## How it works

The IP address is encoded in any subdomain label using dashes as separators:

| Query | Resolves to |
|---|---|
| `192-168-1-1.dyn.yourdomain.com` | `192.168.1.1` |
| `ip-10-0-0-5.dyn.yourdomain.com` | `10.0.0.5` |
| `foo.172-16-0-9.dyn.yourdomain.com` | `172.16.0.9` |
| `2001-db8--1.dyn.yourdomain.com` | `2001:db8::1` |
| `bar.ip6-2001-db8--42.dyn.yourdomain.com` | `2001:db8::42` |

IPv6 encoding: `-` → `:`, `--` → `::`

Supported record types: `A`, `AAAA`, `NS`, `SOA`, `TXT`, `ANY`

## Install

### Via APT (recommended)

```bash
curl -fsSL https://vr00mm.github.io/pubkey.gpg | \
  sudo gpg --dearmor -o /usr/share/keyrings/vr00mm.gpg

echo "deb [signed-by=/usr/share/keyrings/vr00mm.gpg] https://vr00mm.github.io/deb stable main" | \
  sudo tee /etc/apt/sources.list.d/dynip-dns.list

sudo apt update && sudo apt install dynip-dns
```

### From binary

Download the binary for your architecture from the [Releases](../../releases) page, then:

```bash
sudo install -m 755 dynip-dns_linux_amd64 /usr/bin/dynip-dns
sudo mkdir -p /etc/dynip-dns
sudo cp package/etc/dynip-dns/dynip-dns.conf.example /etc/dynip-dns/dynip-dns.conf
# edit /etc/dynip-dns/dynip-dns.conf
sudo cp package/lib/systemd/system/dynip-dns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dynip-dns
```

## Configuration

Edit `/etc/dynip-dns/dynip-dns.conf` (created automatically from the example on first APT install):

```bash
sudo nano /etc/dynip-dns/dynip-dns.conf
sudo systemctl restart dynip-dns
```

```ini
zone        = dyn.yourdomain.com
ttl         = 60
bind        = :53

ns1_host    = ns1.yourdomain.com
ns2_host    = ns2.yourdomain.com
ns1_ipv4    = 203.0.113.10
ns2_ipv4    = 203.0.113.11
# ns1_ipv6  = 2001:db8::10
# ns2_ipv6  = 2001:db8::11

hostmaster  = hostmaster.yourdomain.com
version_txt = dynip-dns
enable_glue = true
log_queries = true
```

| Option | Default | Description |
|---|---|---|
| `zone` | `yourdomain.com` | Authoritative zone |
| `ttl` | `60` | Record TTL in seconds |
| `bind` | `:53` | Listen address |
| `ns1_host` | `ns1.<zone>` | Primary nameserver hostname |
| `ns2_host` | `ns2.<zone>` | Secondary nameserver hostname |
| `ns1_ipv4` | — | NS1 IPv4 glue address |
| `ns2_ipv4` | — | NS2 IPv4 glue address |
| `ns1_ipv6` | — | NS1 IPv6 glue address (optional) |
| `ns2_ipv6` | — | NS2 IPv6 glue address (optional) |
| `hostmaster` | `hostmaster.<zone>` | SOA hostmaster address |
| `version_txt` | `dynip-dns` | TXT record at zone apex |
| `enable_glue` | `true` | Include glue records in responses |
| `log_queries` | `true` | Log each DNS query |

## Test

```bash
dig @127.0.0.1 192-168-1-1.dyn.yourdomain.com A
dig @127.0.0.1 foo.192-168-1-1.dyn.yourdomain.com A
dig @127.0.0.1 2001-db8--1.dyn.yourdomain.com AAAA
dig @127.0.0.1 dyn.yourdomain.com SOA
dig @127.0.0.1 dyn.yourdomain.com NS
dig @127.0.0.1 dyn.yourdomain.com TXT
```

## Docker

```bash
docker run -d \
  -p 53:53/udp -p 53:53/tcp \
  -e ZONE=yourdomain.com \
  -e NS1_IPV4=203.0.113.10 \
  -e NS2_IPV4=203.0.113.11 \
  ghcr.io/vr00mm/dynip-dns
```

Or with Docker Compose (edit the environment values in `docker/docker-compose.yml` first):

```bash
docker compose -f docker/docker-compose.yml up -d
```

## Production

- Expose **UDP 53** and **TCP 53**
- Use real public IPs for `NS1_IPV4` / `NS2_IPV4` glue records
- You can run a single node and point both `NS1_HOST` and `NS2_HOST` at the same server — deploying two separate nodes gives redundancy but is not required
- IPv6 glue is optional: set `NS1_IPV6` / `NS2_IPV6` only if your server has a public IPv6 address
- Set `TTL=60` initially — increase once everything is stable
- See [OVH_DELEGATION.md](OVH_DELEGATION.md) for step-by-step NS delegation
