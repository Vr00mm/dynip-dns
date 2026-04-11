# OVH NS Delegation

## Recommended setup: delegate a subdomain only

Delegate only `dyn.yourdomain.com` to your dynip-dns server, while OVH keeps managing the rest of `yourdomain.com` (MX, A records, etc.) normally.

Your dynip-dns config: `ZONE=dyn.yourdomain.com`

Your nameservers:

- `ns1.yourdomain.com` → `203.0.113.10`
- `ns2.yourdomain.com` → `203.0.113.11` (or same IP as ns1 if single node)

With optional IPv6:

- `ns1.yourdomain.com` → `2001:db8::10`
- `ns2.yourdomain.com` → `2001:db8::11`

## Steps

### 1. Deploy the DNS server(s)

On one or two VPS, start the service with the appropriate config:

- Node 1: `NS1_HOST=ns1.yourdomain.com NS1_IPV4=<public-ip> ZONE=dyn.yourdomain.com`
- Node 2 (optional): `NS2_HOST=ns2.yourdomain.com NS2_IPV4=<public-ip> ZONE=dyn.yourdomain.com`

If you only have one server, point both `NS1_HOST` and `NS2_HOST` at the same IP.

### 2. Open the firewall

Allow inbound traffic on:

- UDP 53
- TCP 53

### 3. Declare glue records at OVH

In the OVH domain management panel, create the host (glue) records:

- `ns1.yourdomain.com` → `203.0.113.10`
- `ns2.yourdomain.com` → `203.0.113.11`

Add IPv6 glue records if OVH supports it for your domain.

### 4. Add NS records for the subdomain

In the OVH DNS zone editor for `yourdomain.com`, add two NS records for the `dyn` subdomain:

```
dyn  NS  ns1.yourdomain.com.
dyn  NS  ns2.yourdomain.com.
```

Do **not** change the domain's root nameservers — OVH stays in charge of `yourdomain.com`.

### 5. Wait for propagation

Test from an external resolver:

```bash
dig NS dyn.yourdomain.com
dig SOA dyn.yourdomain.com @ns1.yourdomain.com
dig A 192-168-1-1.dyn.yourdomain.com @ns1.yourdomain.com
dig AAAA 2001-db8--1.dyn.yourdomain.com @ns1.yourdomain.com
```

## Verification

```bash
dig A ns1.yourdomain.com
dig A ns2.yourdomain.com
dig NS dyn.yourdomain.com +short
dig SOA dyn.yourdomain.com +short
dig TXT dyn.yourdomain.com +short
```

## Tips

- Start with `TTL=60` so changes propagate quickly while you're testing.
- Increase the TTL once everything is stable.
- Monitor each node's uptime and connectivity independently.
