#!/usr/bin/env bash
#
# Test suite for net-triage.
# Uses stub ping/ip/tracepath (tests/stubs) plus real local TCP and TLS
# listeners on 127.0.0.1, so it runs anywhere without network access.
# Needs: bash, openssl, jq, python3.

set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
NT="$ROOT/net-triage.sh"
STUBS="$ROOT/tests/stubs"
WORK=$(mktemp -d)
PIDS=()

cleanup() { kill "${PIDS[@]}" 2>/dev/null; wait 2>/dev/null; }
trap cleanup EXIT

PASSED=0 FAILED=0
ok()   { PASSED=$((PASSED + 1)); printf '  \e[32mok\e[0m   %s\n' "$1"; }
fail() { FAILED=$((FAILED + 1)); printf '  \e[31mFAIL\e[0m %s\n' "$1"; [[ -n ${2:-} ]] && printf '       %s\n' "$2"; }

# run net-triage with stubs first in PATH; stores JSON in $OUT and exit code in $RC
nt() { OUT=$(PATH="$STUBS:$PATH" "$NT" --json "$@" 2>&1); RC=$?; }

# expect <description> <jq filter that must be true>
expect() {
  if jq -e "$2" >/dev/null 2>&1 <<<"$OUT"; then ok "$1"; else fail "$1" "jq: $2"; fi
}
expect_rc() { if [[ $RC == "$2" ]]; then ok "$1"; else fail "$1" "exit code $RC, wanted $2"; fi; }
check() { printf '.checks[] | select(.name == "%s")' "$1"; }

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

wait_port() {

  for _ in $(seq 50); do
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
    sleep 0.1
  done
  echo "listener on port $1 did not start" >&2; exit 1
}

tls_server() {   # tls_server <port> <days valid> <CN>
  openssl req -x509 -newkey rsa:2048 -nodes -days "$2" -subj "/CN=$3" \
    -addext "subjectAltName=DNS:$3" \
    -keyout "$WORK/$1.key" -out "$WORK/$1.crt" >/dev/null 2>&1
  openssl s_server -quiet -accept "$1" -cert "$WORK/$1.crt" -key "$WORK/$1.key" \
    </dev/null >/dev/null 2>&1 &
  PIDS+=("$!")
  wait_port "$1"
}

# ---------------------------------------------------------------- fixtures
TCP_OPEN=$(free_port)
python3 -m http.server "$TCP_OPEN" --bind 127.0.0.1 >/dev/null 2>&1 &
PIDS+=("$!")
wait_port "$TCP_OPEN"

TCP_CLOSED=$(free_port)          # nothing listens here
TLS_GOOD=$(free_port);  tls_server "$TLS_GOOD" 90 localhost
TLS_SOON=$(free_port);  tls_server "$TLS_SOON" 5  localhost
TLS_OTHER=$(free_port); tls_server "$TLS_OTHER" 90 other.example

echo "net-triage tests"

# ---------------------------------------------------------------- cli
echo "cli"
"$NT" >/dev/null 2>&1; RC=$?;                    expect_rc "no target exits 3" 3
"$NT" --bogus x >/dev/null 2>&1; RC=$?;          expect_rc "unknown option exits 3" 3
"$NT" -p 99999 x >/dev/null 2>&1; RC=$?;         expect_rc "invalid port exits 3" 3
"$NT" --checks dns,nope x >/dev/null 2>&1; RC=$?; expect_rc "unknown check exits 3" 3
[[ $("$NT" -V) == "net-triage "* ]] && ok "--version prints version" || fail "--version prints version"

# ---------------------------------------------------------------- dns
echo "dns"
nt --checks dns localhost
expect "localhost resolves"            "$(check dns) | .status == \"PASS\""
expect "ip is 127.0.0.1"               '.ip == "127.0.0.1"'
nt --checks dns 127.0.0.1
expect "IP target skips resolution"    "$(check dns) | .data.type == \"ip\""
nt --checks dns does-not-exist.invalid
expect "unresolvable host fails"       "$(check dns) | .status == \"FAIL\""
expect "ip is null when unresolved"    '.ip == null'
expect_rc "unresolvable host exits 2" 2

# ---------------------------------------------------------------- target parsing
echo "target parsing"
nt --checks dns "https://localhost:$TLS_GOOD/some/path"
expect "URL host extracted"            '.host == "localhost"'
nt --checks ports,tls "https://localhost:$TLS_GOOD/x" -p "$TCP_OPEN"
expect "URL port added to port list"   "$(check ports) | .data.ports | map(.port) | index($TLS_GOOD) != null"
expect "URL port used for TLS"         "$(check tls) | .data.port == $TLS_GOOD"

# ---------------------------------------------------------------- route
echo "route"
nt --checks route 127.0.0.1
expect "gateway parsed"                "$(check route) | .data.gateway == \"192.168.1.1\""
expect "interface mtu read"            "$(check route) | .data.interface_mtu == 1500"
STUB_ROUTE=direct nt --checks route 127.0.0.1
expect "directly connected route"      "$(check route) | (.status == \"PASS\" and .data.gateway == \"\")"
STUB_ROUTE=unreachable nt --checks route 127.0.0.1
expect "unreachable network fails"     "$(check route) | .status == \"FAIL\""

# ---------------------------------------------------------------- ping
echo "ping"
nt --checks ping 127.0.0.1
expect "clean ping passes"             "$(check ping) | (.status == \"PASS\" and .data.loss_pct == 0)"
expect "rtt parsed"                    "$(check ping) | .data.rtt_avg_ms == 0.045"
STUB_LOSS=10 nt --checks ping 127.0.0.1
expect "10% loss warns"                "$(check ping) | .status == \"WARN\""
STUB_LOSS=40 nt --checks ping 127.0.0.1
expect "40% loss fails"                "$(check ping) | .status == \"FAIL\""
STUB_LOSS=100 nt --checks ping 127.0.0.1
expect "100% loss warns (ICMP may be filtered)" "$(check ping) | .status == \"WARN\""
STUB_AVG=250.5 nt --checks ping 127.0.0.1
expect "high latency warns"            "$(check ping) | .status == \"WARN\""

# ---------------------------------------------------------------- mtu
echo "mtu"
nt --checks route,ping,mtu 127.0.0.1
expect "1500 path passes"              "$(check mtu) | (.status == \"PASS\" and .data.path_mtu == 1500)"
STUB_PMTU=1420 nt --checks route,ping,mtu 127.0.0.1
expect "1420 path found by search"     "$(check mtu) | .data.path_mtu == 1420"
expect "sub-1500 path warns"           "$(check mtu) | .status == \"WARN\""
STUB_IFMTU=9000 STUB_PMTU=9000 nt --checks route,ping,mtu 127.0.0.1
expect "jumbo frames detected"         "$(check mtu) | .data.path_mtu == 9000"
STUB_IFMTU=9000 STUB_PMTU=1500 nt --checks route,ping,mtu 127.0.0.1
expect "jumbo iface, 1500 path"        "$(check mtu) | .data.path_mtu == 1500"
STUB_LOSS=100 nt --checks ping,mtu 127.0.0.1
expect "skipped when ICMP is blocked"  "$(check mtu) | .status == \"SKIP\""
STUB_NO_M=1 nt --checks ping,mtu 127.0.0.1
expect "skipped without -M support"    "$(check mtu) | .status == \"SKIP\""

# ---------------------------------------------------------------- ports
echo "ports"
nt --checks ports -p "$TCP_OPEN" 127.0.0.1
expect "open port passes"              "$(check ports) | (.status == \"PASS\" and .data.ports[0].state == \"open\")"
nt --checks ports -p "$TCP_OPEN,$TCP_CLOSED" 127.0.0.1
expect "mixed ports warn"              "$(check ports) | .status == \"WARN\""
expect "closed port detected"          "$(check ports) | .data.ports[1].state == \"closed\""
expect_rc "warning exits 1" 1
nt --checks ports -p "$TCP_CLOSED" 127.0.0.1
expect "all closed fails"              "$(check ports) | .status == \"FAIL\""

# ---------------------------------------------------------------- tls
echo "tls"
nt --checks ports,tls -p "$TLS_GOOD" --tls-port "$TLS_GOOD" localhost
expect "cert read"                     "$(check tls) | .data.subject == \"CN=localhost\""
expect "days left ~90"                 "$(check tls) | (.data.days_left >= 88 and .data.days_left <= 90)"
expect "SAN read"                      "$(check tls) | .data.san == [\"DNS:localhost\"]"
expect "self-signed cert warns"        "$(check tls) | (.status == \"WARN\" and .data.verified == false)"
nt --checks tls --tls-port "$TLS_SOON" --warn-days 30 localhost
expect "expiring cert warns"           "$(check tls) | (.status == \"WARN\" and (.message | test(\"expires soon\")))"
nt --checks tls --tls-port "$TLS_OTHER" localhost
expect "hostname mismatch reported"    "$(check tls) | .data.verify_result | test(\"hostname mismatch|self.signed\")"
nt --checks tls --tls-port "$TCP_OPEN" localhost
expect "plain HTTP port fails TLS"     "$(check tls) | .status == \"FAIL\""
nt --checks ports,tls -p "$TCP_CLOSED" --tls-port "$TCP_CLOSED" localhost
expect "closed TLS port is skipped"    "$(check tls) | .status == \"SKIP\""

# ---------------------------------------------------------------- trace
echo "trace"
nt --checks trace 127.0.0.1
expect "trace reaches target"          "$(check trace) | (.status == \"PASS\" and .data.hop_count == 3)"
STUB_TRACE_REACHED=0 nt --checks trace 127.0.0.1
expect "unreached trace warns"         "$(check trace) | .status == \"WARN\""

# ---------------------------------------------------------------- full run
echo "full run"
nt -p "$TCP_OPEN,$TLS_GOOD" --tls-port "$TLS_GOOD" --trace localhost
expect "valid JSON with all checks"    '[.checks[].name] == ["dns","route","ping","mtu","ports","tls","trace"]'
expect "summary counts add up"         '.summary.pass + .summary.warn + .summary.fail + .summary.skip == (.checks | length)'
TEXT=$(PATH="$STUBS:$PATH" "$NT" --no-color -p "$TCP_OPEN" --checks dns,ports localhost)
[[ $TEXT == *"[PASS] ports"* && $TEXT == *"Summary: PASS"* ]] \
  && ok "text report renders" || fail "text report renders" "$TEXT"

echo
printf '%d passed, %d failed\n' "$PASSED" "$FAILED"
(( FAILED == 0 ))
