# net-triage

[![ci](https://github.com/Arman16-1998/net-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/Arman16-1998/net-triage/actions/workflows/ci.yml)
![shell](https://img.shields.io/badge/shell-bash-4EAA25)
![license](https://img.shields.io/badge/license-MIT-blue)

One-shot network triage for a single host. Point it at a hostname, IP or URL and it checks the whole path in a few seconds:

| Check   | What it tells you |
|---------|-------------------|
| `dns`   | Does the name resolve, how fast, A/AAAA records, CNAME, which resolvers were used |
| `route` | Which gateway, interface and source IP the kernel picks, and the interface MTU |
| `ping`  | Packet loss and min/avg/max latency |
| `mtu`   | Real path MTU (binary search with DF set), catches VPN/tunnel/PPPoE black holes |
| `ports` | TCP ports open / closed (refused) / filtered (no answer) with connect time |
| `tls`   | Protocol, cipher, subject, issuer, SANs, days until expiry, chain + hostname verification |
| `trace` | Hop list and whether the destination was reached (optional, `--trace`) |

Every check returns `PASS`, `WARN`, `FAIL` or `SKIP`, so you can read it at a glance or feed the JSON into scripts and monitoring.

## Why

When something "can't connect", the cause is usually one of a handful of layers: DNS, routing, packet loss, MTU, a closed or firewalled port, or a bad certificate. Running `dig`, `ip route`, `ping`, `nc` and `openssl s_client` one by one and reading their output takes time. `net-triage` runs all of them and puts the answer in one report.

## Install

```bash
git clone https://github.com/Arman16-1998/net-triage.git
cd net-triage
sudo install -m 0755 net-triage.sh /usr/local/bin/net-triage
```

Or just run `./net-triage.sh` from the repo.

**Requirements:** bash 4.4+, coreutils (`timeout`, GNU `date`), `getent`, `iproute2`, `iputils-ping`, `openssl`. `tracepath` or `traceroute` for `--trace`. Any missing tool makes its check `SKIP` instead of crashing. No `jq`, no Python.

## Usage

```
net-triage [options] <target>

  -p, --ports LIST      TCP ports to test, comma-separated (default: 22,80,443)
  -c, --count N         ICMP echo requests for latency/loss (default: 5)
  -t, --timeout SEC     Per-probe timeout in seconds (default: 3)
      --tls-port PORT   Port for the TLS check (default: 443, or the URL's port)
      --sni NAME        SNI / hostname to verify in TLS (default: target host)
      --warn-days N     Warn if the certificate expires within N days (default: 14)
      --checks LIST     Checks to run (default: dns,route,ping,mtu,ports,tls)
      --trace           Add a traceroute to the default checks
  -j, --json            Print JSON instead of the text report
      --no-color        Disable colors
```

### Examples

```bash
net-triage example.com                          # all default checks
net-triage https://10.0.0.40:8443/login         # URL: port 8443 is probed and used for TLS
net-triage 10.0.0.40 --tls-port 8443 --sni app.internal   # TLS by IP with the right SNI
net-triage db01 -p 5432,6432 --checks dns,route,ping,ports
net-triage vpn-gw.example.com --checks mtu      # just find the path MTU
net-triage api.example.com -j | jq '.checks[] | select(.status != "PASS")'
```

### Example output

```
net-triage 0.1.0 → app.example.com

[PASS] dns    resolved in 14 ms (A: 1, AAAA: 0), using 203.0.113.10
       addresses: 203.0.113.10
       resolvers: 10.0.0.2
[PASS] route  via 10.0.0.1 dev eth0 src 10.0.0.25 (mtu 1500)
[PASS] ping   5 sent, 0% loss, rtt min/avg/max 21.4/22.1/23.0 ms
[WARN] mtu    path MTU 1420 (interface 1500): below 1500, likely a VPN/tunnel/PPPoE hop; large packets may stall
[WARN] ports  2/3 open, open: 80,443, filtered: 22
       22/tcp    filtered (no answer in 3s)
       80/tcp    open     23 ms
       443/tcp   open     22 ms
[PASS] tls    TLSv1.3, expires in 61 days (Jan 23 12:00:00 2027 GMT), verify ok
       subject: CN=app.example.com
       issuer:  CN=R11,O=Let's Encrypt,C=US
       SAN:     DNS:app.example.com
       cipher:  TLS_AES_256_GCM_SHA384

Summary: WARN  (4 pass, 2 warn, 0 fail, 0 skip) in 3.8s
```

### JSON

`--json` prints a single object, safe to pipe into `jq` or ship to a log pipeline:

```json
{
  "tool": "net-triage",
  "version": "0.1.0",
  "target": "app.example.com",
  "host": "app.example.com",
  "ip": "203.0.113.10",
  "timestamp": "2026-11-23T08:00:00Z",
  "duration_ms": 3812,
  "summary": { "status": "WARN", "pass": 4, "warn": 2, "fail": 0, "skip": 0 },
  "checks": [
    {
      "name": "ping",
      "status": "PASS",
      "message": "5 sent, 0% loss, rtt min/avg/max 21.4/22.1/23.0 ms",
      "data": { "sent": 5, "loss_pct": 0, "rtt_min_ms": 21.4, "rtt_avg_ms": 22.1, "rtt_max_ms": 23.0 }
    },
    {
      "name": "mtu",
      "status": "WARN",
      "message": "path MTU 1420 (interface 1500): below 1500, ...",
      "data": { "path_mtu": 1420, "interface_mtu": 1500, "probes": 11 }
    }
  ]
}
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | All checks passed (or were skipped) |
| 1 | At least one warning |
| 2 | At least one failure |
| 3 | Usage error |

So it drops straight into cron jobs, CI or monitoring:

```bash
net-triage -t 2 --checks dns,ports,tls -p 443 api.example.com >/dev/null || alert "api.example.com degraded"
```

## How the checks decide

- **dns:** `FAIL` if the name doesn't resolve, `WARN` if the lookup takes over 500 ms. IPv4 is preferred when both families exist.
- **ping:** `WARN` on any loss or average RTT over 150 ms, `FAIL` at 20 %+ loss. 100 % loss is only a `WARN` because many hosts drop ICMP; the port check shows whether the host is really down.
- **mtu:** sends DF-flagged pings and binary-searches between 576 (1280 for IPv6) and the interface MTU (jumbo frames supported). Under 1500 is a `WARN`.
- **ports:** uses bash `/dev/tcp`. `closed` = connection refused (host up, nothing listening), `filtered` = no answer before timeout (firewall drop). All open = `PASS`, some = `WARN`, none = `FAIL`.
- **tls:** `FAIL` if the handshake fails or the certificate is expired. `WARN` for a failed chain or hostname verification (self-signed, wrong SAN), expiry within `--warn-days`, or TLS 1.0/1.1. The check is skipped if the port check already found the TLS port closed.

## Tests

```bash
./tests/run-tests.sh
```

The suite runs fully offline. It uses stub versions of `ping`, `ip` and `tracepath` (`tests/stubs/`) to simulate loss, latency, MTU black holes, jumbo frames and unreachable routes, plus real local TCP and TLS listeners (valid, expiring and mismatched certificates) on `127.0.0.1`. CI runs ShellCheck and the suite on every push.

Needs `openssl`, `jq` and `python3`.

## License

MIT
