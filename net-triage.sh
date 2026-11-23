#!/usr/bin/env bash
#
# net-triage — one-shot network diagnostics for a single target.
#
# Checks DNS, routing, latency / packet loss, path MTU, TCP ports and the
# TLS certificate of a host, then prints a readable report or JSON.
#
# https://github.com/Arman16-1998/net-triage
# License: MIT

set -uo pipefail

VERSION="0.1.0"

# ---------------------------------------------------------------- defaults
TARGET=""
PORTS="22,80,443"
COUNT=5
TIMEOUT=3
TLS_PORT=""
SNI=""
WARN_DAYS=14
RTT_WARN_MS=150
DNS_WARN_MS=500
LOSS_FAIL_PCT=20
CHECKS="dns,route,ping,mtu,ports,tls"
JSON=0
COLOR=1

# ---------------------------------------------------------------- state
HOST=""          # host part of the target
IP=""            # address every check runs against
FAMILY=4         # 4 or 6
IFACE_MTU=""     # MTU of the outgoing interface (from the route check)
PING_LOSS=""     # packet loss % from the ping check
declare -A PORT_STATE=()

declare -a C_NAME=() C_STATUS=() C_MSG=() C_DATA=()

usage() {
  cat <<'EOF'
Usage: net-triage [options] <target>

Target can be a hostname, an IPv4/IPv6 address or a URL
(https://host:8443/path: the host is checked, the port is used for TLS).

Options:
  -p, --ports LIST      TCP ports to test, comma-separated (default: 22,80,443)
  -c, --count N         ICMP echo requests for latency/loss (default: 5)
  -t, --timeout SEC     Per-probe timeout in seconds (default: 3)
      --tls-port PORT   Port for the TLS check (default: 443, or the URL's port)
      --sni NAME        SNI / hostname to verify in TLS (default: target host)
      --warn-days N     Warn if the certificate expires within N days (default: 14)
      --checks LIST     Checks to run (default: dns,route,ping,mtu,ports,tls)
                        Available: dns,route,ping,mtu,ports,tls,trace
                        (dns always runs: the other checks need the address)
      --trace           Add a traceroute to the default checks
  -j, --json            Print JSON instead of the text report
      --no-color        Disable colors
  -h, --help            Show this help
  -V, --version         Show version

Exit codes:
  0  all checks passed or were skipped
  1  at least one warning
  2  at least one failure
  3  usage error
EOF
}

die() { printf 'net-triage: %s\n' "$*" >&2; exit 3; }

# ---------------------------------------------------------------- helpers
have()    { command -v "$1" >/dev/null 2>&1; }
is_int()  { [[ $1 =~ ^[0-9]+$ ]]; }
is_ipv4() { [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
is_ipv6() { [[ $1 == *:* && $1 =~ ^[0-9A-Fa-f:.]+$ ]]; }
is_ip()   { is_ipv4 "$1" || is_ipv6 "$1"; }
want()    { [[ ,$CHECKS, == *,"$1",* ]]; }

now_ms() {
  local t
  t=$(date +%s%3N)
  [[ $t == *N ]] && t=$(( $(date +%s) * 1000 ))
  printf '%s' "$t"
}

# JSON builders (no jq needed)
json_esc() {
  local s=$1
  s=${s//\\/\\\\}; s=${s//\"/\\\"}
  s=${s//$'\n'/\\n}; s=${s//$'\t'/\\t}; s=${s//$'\r'/}
  printf '%s' "$s"
}
jstr() { printf '"%s":"%s"' "$1" "$(json_esc "$2")"; }
jnum() {   # numeric value, or null when empty / not a number
  if [[ $2 =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then printf '"%s":%s' "$1" "$2"
  else printf '"%s":null' "$1"; fi
}
jbool() { [[ $2 == 1 || $2 == true ]] && printf '"%s":true' "$1" || printf '"%s":false' "$1"; }
jarr() {   # jarr key "newline separated values"
  local key=$1 out="" v
  while IFS= read -r v; do
    [[ -z $v ]] && continue
    out+="${out:+,}\"$(json_esc "$v")\""
  done <<<"$2"
  printf '"%s":[%s]' "$key" "$out"
}
join() { local IFS=,; printf '%s' "$*"; }

# float comparison: gt 12.5 10 -> true
gt() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a+0 > b+0)}'; }

# ---------------------------------------------------------------- output
setup_colors() {
  if (( COLOR )) && (( ! JSON )) && [[ -t 1 && -z ${NO_COLOR:-} ]]; then
    C_PASS=$'\e[32m'; C_WARN=$'\e[33m'; C_FAIL=$'\e[31m'; C_SKIP=$'\e[90m'
    C_BOLD=$'\e[1m'; C_DIM=$'\e[2m'; C_RST=$'\e[0m'
  else
    C_PASS=""; C_WARN=""; C_FAIL=""; C_SKIP=""; C_BOLD=""; C_DIM=""; C_RST=""
  fi
}

status_color() {
  case $1 in
    PASS) printf '%s' "$C_PASS" ;; WARN) printf '%s' "$C_WARN" ;;
    FAIL) printf '%s' "$C_FAIL" ;; *)    printf '%s' "$C_SKIP" ;;
  esac
}

# record <name> <status> <message> [json data] [detail lines]
record() {
  C_NAME+=("$1"); C_STATUS+=("$2"); C_MSG+=("$3"); C_DATA+=("${4:-}")
  (( JSON )) && return
  printf '%s[%s]%s %-6s %s\n' "$(status_color "$2")" "$2" "$C_RST" "$1" "$3"
  if [[ -n ${5:-} ]]; then
    local line
    while IFS= read -r line; do
      printf '       %s%s%s\n' "$C_DIM" "$line" "$C_RST"
    done <<<"$5"
  fi
}

# ---------------------------------------------------------------- target
parse_target() {
  local t=$1 url_port="" scheme="" rest=""
  if [[ $t == *://* ]]; then
    scheme=${t%%://*}; t=${t#*://}; t=${t%%/*}; t=${t##*@}
    if [[ $t == \[* ]]; then                       # [v6]:port
      HOST=${t#\[}; HOST=${HOST%%\]*}; rest=${t#*\]}
      [[ $rest == :* ]] && url_port=${rest#:}
    elif [[ $t == *:* ]]; then
      HOST=${t%%:*}; url_port=${t##*:}
    else
      HOST=$t
    fi
    if [[ -z $url_port ]]; then
      case $scheme in https) url_port=443 ;; http) url_port=80 ;; esac
    fi
  else
    HOST=${t#\[}; HOST=${HOST%\]}
  fi
  [[ -n $HOST ]] || die "could not parse target '$1'"
  if [[ -n $url_port ]]; then
    is_int "$url_port" || die "bad port in URL: $url_port"
    [[ ,$PORTS, == *,"$url_port",* ]] || PORTS="${PORTS:+$PORTS,}$url_port"
    [[ $scheme == https && -z $TLS_PORT ]] && TLS_PORT=$url_port
  fi
  : "${TLS_PORT:=443}"
}

# ---------------------------------------------------------------- checks
check_dns() {
  local resolvers
  resolvers=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null)

  if is_ip "$HOST"; then
    IP=$HOST
    is_ipv6 "$IP" && FAMILY=6
    local ptr=""
    have getent && ptr=$(timeout "$TIMEOUT" getent hosts "$HOST" 2>/dev/null | awk '{print $2; exit}')
    record dns PASS "target is an IP address${ptr:+ (PTR: $ptr)}" \
      "$(jstr type ip),$(jstr ptr "$ptr"),$(jarr resolvers "$resolvers")"
    return
  fi

  if ! have getent; then
    record dns SKIP "getent not installed" "$(jarr resolvers "$resolvers")"
    return
  fi

  local start out rc ms addrs v4 v6 canon
  start=$(now_ms)
  out=$(timeout "$TIMEOUT" getent ahosts "$HOST" 2>/dev/null); rc=$?
  ms=$(( $(now_ms) - start ))

  addrs=$(awk '{print $1}' <<<"$out" | awk 'NF && !seen[$0]++')
  if [[ -z $addrs ]]; then
    local why="could not resolve $HOST"
    (( rc == 124 )) && why="DNS lookup for $HOST timed out after ${TIMEOUT}s"
    record dns FAIL "$why" \
      "$(jarr resolvers "$resolvers"),$(jnum time_ms "$ms")" \
      "resolvers: $(paste -sd' ' <<<"$resolvers")"
    return
  fi

  v4=$(grep -v ':' <<<"$addrs" || true)
  v6=$(grep ':' <<<"$addrs" || true)
  canon=$(awk 'NR==1 {print $3}' <<<"$out")
  [[ $canon == "$HOST" ]] && canon=""

  if [[ -n $v4 ]]; then IP=$(head -1 <<<"$v4"); FAMILY=4
  else IP=$(head -1 <<<"$v6"); FAMILY=6; fi

  local n4 n6 status=PASS msg
  n4=$(grep -c . <<<"$v4"); n6=$(grep -c . <<<"$v6")
  msg="resolved in ${ms} ms (A: $n4, AAAA: $n6), using $IP"
  if (( ms > DNS_WARN_MS )); then status=WARN; msg="slow DNS: $msg"; fi

  local detail="addresses: $(paste -sd' ' <<<"$addrs")"
  [[ -n $canon ]] && detail+=$'\n'"canonical name: $canon"
  [[ -n $resolvers ]] && detail+=$'\n'"resolvers: $(paste -sd' ' <<<"$resolvers")"

  record dns "$status" "$msg" \
    "$(jnum time_ms "$ms"),$(jarr a "$v4"),$(jarr aaaa "$v6"),$(jstr canonical_name "$canon"),$(jarr resolvers "$resolvers")" \
    "$detail"
}

check_route() {
  if ! have ip; then record route SKIP "ip (iproute2) not installed"; return; fi
  if [[ -z $IP ]]; then record route SKIP "no address to test"; return; fi

  local out rc
  out=$(ip route get "$IP" 2>&1); rc=$?
  if (( rc != 0 )); then
    record route FAIL "no route to $IP: $(head -1 <<<"$out")"
    return
  fi

  local first type="unicast" via="" dev="" src=""
  first=$(head -1 <<<"$out")
  local -a f
  read -r -a f <<<"$first"
  case ${f[0]} in local|unreachable|blackhole|prohibit|throw) type=${f[0]} ;; esac
  local i
  for (( i = 0; i < ${#f[@]} - 1; i++ )); do
    case ${f[i]} in
      via) via=${f[i+1]} ;; dev) dev=${f[i+1]} ;; src) src=${f[i+1]} ;;
    esac
  done

  if [[ -n $dev ]]; then
    IFACE_MTU=$(ip -o link show dev "$dev" 2>/dev/null \
      | awk '{for (i=1;i<NF;i++) if ($i=="mtu") {print $(i+1); exit}}')
  fi

  local data
  data="$(jstr type "$type"),$(jstr gateway "$via"),$(jstr interface "$dev"),$(jstr source "$src"),$(jnum interface_mtu "$IFACE_MTU")"

  case $type in
    unreachable|blackhole|prohibit)
      record route FAIL "route type is '$type'" "$data"; return ;;
    local)
      record route PASS "target is a local address (dev $dev)" "$data"; return ;;
  esac

  local msg
  if [[ -n $via ]]; then msg="via $via dev $dev"
  else msg="directly connected on $dev"; fi
  [[ -n $src ]] && msg+=" src $src"
  [[ -n $IFACE_MTU ]] && msg+=" (mtu $IFACE_MTU)"
  record route PASS "$msg" "$data"
}

ping_cmd() {
  # ping -6 is supported by iputils >= 20180629; fall back to ping6
  if (( FAMILY == 6 )); then
    if have ping6; then ping6 "$@"; else ping -6 "$@"; fi
  else
    ping "$@"
  fi
}

check_ping() {
  if ! have ping; then record ping SKIP "ping not installed"; return; fi
  if [[ -z $IP ]]; then record ping SKIP "no address to test"; return; fi

  local out loss rtt min="" avg="" max=""
  out=$(LC_ALL=C ping_cmd -n -q -c "$COUNT" -i 0.2 -W "$TIMEOUT" "$IP" 2>&1)
  loss=$(sed -n 's/.* \([0-9.]*\)% packet loss.*/\1/p' <<<"$out" | head -1)
  if [[ -z $loss ]]; then
    record ping SKIP "ping failed: $(head -1 <<<"$out")"
    return
  fi
  rtt=$(sed -n 's#.*= *\([0-9.]*\)/\([0-9.]*\)/\([0-9.]*\).*#\1 \2 \3#p' <<<"$out" | head -1)
  [[ -n $rtt ]] && read -r min avg max <<<"$rtt"
  PING_LOSS=${loss%.*}

  local data status msg
  data="$(jnum sent "$COUNT"),$(jnum loss_pct "$loss"),$(jnum rtt_min_ms "$min"),$(jnum rtt_avg_ms "$avg"),$(jnum rtt_max_ms "$max")"

  if (( PING_LOSS == 100 )); then
    record ping WARN "no ICMP replies ($COUNT sent): host down or ICMP filtered" "$data"
    return
  fi

  msg="$COUNT sent, ${loss}% loss, rtt min/avg/max $min/$avg/$max ms"
  if (( PING_LOSS >= LOSS_FAIL_PCT )); then status=FAIL; msg="heavy packet loss: $msg"
  elif (( PING_LOSS > 0 )); then           status=WARN; msg="packet loss: $msg"
  elif gt "$avg" "$RTT_WARN_MS"; then      status=WARN; msg="high latency: $msg"
  else                                     status=PASS; fi
  record ping "$status" "$msg" "$data"
}

check_mtu() {
  if ! have ping; then record mtu SKIP "ping not installed"; return; fi
  if [[ -z $IP ]]; then record mtu SKIP "no address to test"; return; fi
  if [[ $PING_LOSS == 100 ]]; then
    record mtu SKIP "no ICMP replies, cannot probe path MTU"; return
  fi

  local overhead=28 min_mtu=576
  (( FAMILY == 6 )) && { overhead=48; min_mtu=1280; }

  local test
  test=$(LC_ALL=C ping_cmd -n -c 1 -W "$TIMEOUT" -M do -s 56 "$IP" 2>&1)
  if grep -qiE 'invalid|unrecognized|illegal|usage' <<<"$test"; then
    record mtu SKIP "this ping does not support -M do (needs iputils)"; return
  fi

  local probes=0
  probe() {   # probe <payload bytes>; 2 packets so one random drop doesn't count
    (( probes++ ))
    LC_ALL=C ping_cmd -n -q -c 2 -i 0.2 -W "$TIMEOUT" -M do -s "$1" "$IP" >/dev/null 2>&1
  }

  local top=1500
  [[ -n $IFACE_MTU ]] && is_int "$IFACE_MTU" && (( IFACE_MTU > 1500 )) && top=$IFACE_MTU

  local mtu=""
  if probe $(( top - overhead )); then
    mtu=$top
  elif (( top > 1500 )) && probe $(( 1500 - overhead )); then
    mtu=1500   # jumbo interface but the path only carries 1500
  else
    local lo=$(( min_mtu - overhead )) hi=$(( top - overhead )) mid
    if ! probe "$lo"; then
      record mtu WARN "path MTU below $min_mtu, or ICMP 'fragmentation needed' is blocked" \
        "$(jnum path_mtu ""),$(jnum interface_mtu "$IFACE_MTU"),$(jnum probes "$probes")"
      return
    fi
    while (( hi - lo > 1 )); do
      mid=$(( (lo + hi) / 2 ))
      if probe "$mid"; then lo=$mid; else hi=$mid; fi
    done
    mtu=$(( lo + overhead ))
  fi

  local data status=PASS msg="path MTU $mtu"
  data="$(jnum path_mtu "$mtu"),$(jnum interface_mtu "$IFACE_MTU"),$(jnum probes "$probes")"
  [[ -n $IFACE_MTU ]] && msg+=" (interface $IFACE_MTU)"
  if (( mtu < 1500 )); then
    status=WARN
    msg+=": below 1500, likely a VPN/tunnel/PPPoE hop; large packets may stall"
  fi
  record mtu "$status" "$msg" "$data"
}

check_ports() {
  if [[ -z $IP ]]; then record ports SKIP "no address to test"; return; fi
  [[ -n $PORTS ]] || { record ports SKIP "no ports given"; return; }

  local p start rc ms state items="" detail="" open=() closed=() filtered=()
  for p in ${PORTS//,/ }; do
    start=$(now_ms)
    timeout "$TIMEOUT" bash -c 'exec 3<>"/dev/tcp/$0/$1"' "$IP" "$p" 2>/dev/null; rc=$?
    ms=$(( $(now_ms) - start ))
    case $rc in
      0)   state=open;     open+=("$p") ;;
      124) state=filtered; filtered+=("$p") ;;
      *)   state=closed;   closed+=("$p") ;;
    esac
    PORT_STATE[$p]=$state
    items+="${items:+,}{$(jnum port "$p"),$(jstr state "$state"),$(jnum time_ms "$ms")}"
    if [[ $state == filtered ]]; then detail+="${detail:+$'\n'}$(printf '%-9s filtered (no answer in %ss)' "$p/tcp" "$TIMEOUT")"
    else detail+="${detail:+$'\n'}$(printf '%-9s %-8s %s ms' "$p/tcp" "$state" "$ms")"; fi
  done

  local status msg total=$(( ${#open[@]} + ${#closed[@]} + ${#filtered[@]} ))
  msg="${#open[@]}/$total open"
  (( ${#open[@]} ))     && msg+=", open: $(join "${open[@]}")"
  (( ${#closed[@]} ))   && msg+=", closed: $(join "${closed[@]}")"
  (( ${#filtered[@]} )) && msg+=", filtered: $(join "${filtered[@]}")"
  if   (( ${#open[@]} == total )); then status=PASS
  elif (( ${#open[@]} == 0 ));     then status=FAIL
  else                                  status=WARN; fi

  record ports "$status" "$msg" "\"ports\":[$items]" "$detail"
}

check_tls() {
  if ! have openssl; then record tls SKIP "openssl not installed"; return; fi
  if [[ -z $IP ]]; then record tls SKIP "no address to test"; return; fi
  local pstate=${PORT_STATE[$TLS_PORT]:-}
  if [[ -n $pstate && $pstate != open ]]; then
    record tls SKIP "port $TLS_PORT is $pstate"; return
  fi

  local sni=${SNI:-$HOST} connect="$IP:$TLS_PORT" opts=()
  (( FAMILY == 6 )) && connect="[$IP]:$TLS_PORT"
  is_ip "$sni" || opts=(-servername "$sni" -verify_hostname "$sni")

  local out cert
  out=$(timeout "$TIMEOUT" openssl s_client -connect "$connect" "${opts[@]}" </dev/null 2>&1)
  cert=$(sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' <<<"$out")
  if [[ -z $cert ]]; then
    local why
    why=$(grep -oiE 'connection refused|connection timed out|no route to host|network is unreachable|wrong version number|handshake failure|unexpected eof|tlsv1 alert [a-z ]+|sslv3 alert [a-z ]+|unsupported protocol' <<<"$out" | head -1)
    [[ -z $why && -z $out ]] && why="no response within ${TIMEOUT}s"
    record tls FAIL "TLS handshake failed on port $TLS_PORT${why:+: $why}" \
      "$(jnum port "$TLS_PORT"),$(jstr sni "$sni")"
    return
  fi

  local enddate subject issuer san proto cipher verify vcode vmsg
  enddate=$(openssl x509 -noout -enddate <<<"$cert" | cut -d= -f2-)
  subject=$(openssl x509 -noout -subject -nameopt RFC2253 <<<"$cert" | sed 's/^subject= *//')
  issuer=$(openssl x509 -noout -issuer -nameopt RFC2253 <<<"$cert" | sed 's/^issuer= *//')
  san=$(openssl x509 -noout -text <<<"$cert" \
    | awk '/Subject Alternative Name/ {getline; gsub(/ /, ""); print; exit}' | tr ',' '\n')

  # OpenSSL 3 prints "New, TLSv1.3, Cipher is X"; 1.1 prints "Protocol  : X"
  proto=$(sed -n 's/^New, \(TLSv[0-9.]*\), Cipher is .*/\1/p' <<<"$out" | head -1)
  [[ -z $proto ]] && proto=$(sed -n 's/^ *Protocol *: *//p' <<<"$out" | head -1)
  cipher=$(sed -n 's/^New, .*Cipher is \(.*\)/\1/p' <<<"$out" | head -1)
  [[ -z $cipher ]] && cipher=$(sed -n 's/^ *Cipher *: *//p' <<<"$out" | head -1)

  verify=$(sed -n 's/^ *Verify return code: \([0-9]*\) (\(.*\))/\1|\2/p' <<<"$out" | tail -1)
  vcode=${verify%%|*}; vmsg=${verify#*|}

  local exp_epoch days=""
  exp_epoch=$(date -d "$enddate" +%s 2>/dev/null) \
    && days=$(( (exp_epoch - $(date +%s)) / 86400 ))

  local data
  data="$(jnum port "$TLS_PORT"),$(jstr sni "$sni"),$(jstr protocol "$proto"),$(jstr cipher "$cipher"),$(jstr subject "$subject"),$(jstr issuer "$issuer"),$(jarr san "$san"),$(jstr not_after "$enddate"),$(jnum days_left "$days"),$(jbool verified "$([[ $vcode == 0 ]] && echo 1)"),$(jstr verify_result "$vmsg")"

  local detail="subject: $subject"$'\n'"issuer:  $issuer"
  [[ -n $san ]] && detail+=$'\n'"SAN:     $(paste -sd' ' <<<"$san")"
  detail+=$'\n'"cipher:  $cipher"

  local status=PASS msg problems=()
  if [[ -z $days ]]; then
    msg="$proto, could not parse expiry date '$enddate'"; problems+=("unknown expiry")
  elif (( days < 0 )); then
    status=FAIL; msg="certificate EXPIRED $(( -days )) days ago ($enddate)"
  else
    msg="$proto, expires in $days days ($enddate)"
    (( days < WARN_DAYS )) && problems+=("expires soon (< $WARN_DAYS days)")
  fi
  [[ -n $vcode && $vcode != 0 ]] && problems+=("verify failed: $vmsg")
  case $proto in TLSv1|TLSv1.1|SSLv3) problems+=("outdated protocol $proto") ;; esac

  if (( ${#problems[@]} )); then
    [[ $status == FAIL ]] || status=WARN
    local IFS=';'; msg+="; ${problems[*]}"; msg=${msg//;/; }; msg=${msg//;  /; }
    unset IFS
  elif [[ $status == PASS ]]; then
    msg+=", verify ok"
  fi
  record tls "$status" "$msg" "$data" "$detail"
}

check_trace() {
  if [[ -z $IP ]]; then record trace SKIP "no address to test"; return; fi
  local out hops="" n=0 reached=0 tool
  if have tracepath; then
    tool=tracepath
    out=$(timeout $(( TIMEOUT * 30 )) tracepath -n -m 30 "$IP" 2>&1)
    hops=$(awk '$1 ~ /^[0-9]+\??:$/ && $2 != "[LOCALHOST]" {
                  h = $1; sub(/\??:$/, "", h)
                  if (seen[h]++) next
                  if ($2 == "no") print h, "*"; else print h, $2, $3 }' <<<"$out")
    grep -q "Resume:.*hops" <<<"$out" && reached=1
  elif have traceroute; then
    tool=traceroute
    out=$(timeout $(( TIMEOUT * 30 )) traceroute -n -q 1 -w "$TIMEOUT" -m 30 "$IP" 2>&1)
    hops=$(awk 'NR > 1 {print $1, $2, $3 ($4 == "ms" ? "ms" : "")}' <<<"$out")
    tail -1 <<<"$out" | grep -qF " $IP " && reached=1
  else
    record trace SKIP "tracepath/traceroute not installed"; return
  fi
  n=$(grep -c . <<<"$hops")

  local status=PASS msg="$n hops via $tool, destination reached"
  if (( ! reached )); then status=WARN; msg="$n hops via $tool, destination not reached"; fi
  record trace "$status" "$msg" \
    "$(jstr tool "$tool"),$(jnum hop_count "$n"),$(jbool reached "$reached"),$(jarr hops "$hops")" \
    "$hops"
}

# ---------------------------------------------------------------- main
parse_args() {
  local extra_trace=0 checks_set=0
  while (( $# )); do
    case $1 in
      -p|--ports)    PORTS=${2:?}; shift ;;
      -c|--count)    COUNT=${2:?}; shift ;;
      -t|--timeout)  TIMEOUT=${2:?}; shift ;;
      --tls-port)    TLS_PORT=${2:?}; shift ;;
      --sni)         SNI=${2:?}; shift ;;
      --warn-days)   WARN_DAYS=${2:?}; shift ;;
      --checks)      CHECKS=${2:?}; checks_set=1; shift ;;
      --trace)       extra_trace=1 ;;
      -j|--json)     JSON=1 ;;
      --no-color)    COLOR=0 ;;
      -h|--help)     usage; exit 0 ;;
      -V|--version)  echo "net-triage $VERSION"; exit 0 ;;
      --)            shift; break ;;
      -*)            die "unknown option: $1 (see --help)" ;;
      *)             [[ -z $TARGET ]] || die "only one target allowed"; TARGET=$1 ;;
    esac
    shift
  done
  [[ -z $TARGET && $# -gt 0 ]] && TARGET=$1
  [[ -n $TARGET ]] || { usage >&2; exit 3; }
  (( extra_trace && ! checks_set )) && CHECKS+=",trace"
  (( extra_trace && checks_set )) && ! want trace && CHECKS+=",trace"

  is_int "$COUNT"     && (( COUNT > 0 ))   || die "--count must be a positive integer"
  is_int "$TIMEOUT"   && (( TIMEOUT > 0 )) || die "--timeout must be a positive integer"
  is_int "$WARN_DAYS"                      || die "--warn-days must be an integer"
  [[ -z $TLS_PORT ]] || is_int "$TLS_PORT" || die "--tls-port must be a number"
  local p c
  for p in ${PORTS//,/ }; do
    is_int "$p" && (( p >= 1 && p <= 65535 )) || die "bad port: $p"
  done
  for c in ${CHECKS//,/ }; do
    [[ $c =~ ^(dns|route|ping|mtu|ports|tls|trace)$ ]] || die "unknown check: $c"
  done
}

print_json() {
  local i checks="" ts dur=$1
  for i in "${!C_NAME[@]}"; do
    checks+="${checks:+,}{$(jstr name "${C_NAME[i]}"),$(jstr status "${C_STATUS[i]}"),$(jstr message "${C_MSG[i]}"),\"data\":{${C_DATA[i]}}}"
  done
  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  local ip_json=null
  [[ -n $IP ]] && ip_json="\"$IP\""
  printf '{%s,%s,%s,%s,"ip":%s,%s,%s,"summary":{%s,%s,%s,%s,%s},"checks":[%s]}\n' \
    "$(jstr tool net-triage)" "$(jstr version "$VERSION")" \
    "$(jstr target "$TARGET")" "$(jstr host "$HOST")" "$ip_json" \
    "$(jstr timestamp "$ts")" "$(jnum duration_ms "$dur")" \
    "$(jstr status "$OVERALL")" "$(jnum pass "$N_PASS")" "$(jnum warn "$N_WARN")" \
    "$(jnum fail "$N_FAIL")" "$(jnum skip "$N_SKIP")" "$checks"
}

main() {
  parse_args "$@"
  parse_target "$TARGET"
  setup_colors

  local t0; t0=$(now_ms)
  (( JSON )) || printf '%snet-triage %s%s → %s\n\n' "$C_BOLD" "$VERSION" "$C_RST" "$TARGET"

  # dns always runs: every other check needs the address
  check_dns
  want route && check_route
  want ping  && check_ping
  want mtu   && check_mtu
  want ports && check_ports
  want tls   && check_tls
  want trace && check_trace

  N_PASS=0 N_WARN=0 N_FAIL=0 N_SKIP=0
  local s
  for s in "${C_STATUS[@]}"; do
    case $s in PASS) ((N_PASS++)) ;; WARN) ((N_WARN++)) ;; FAIL) ((N_FAIL++)) ;; *) ((N_SKIP++)) ;; esac
  done
  local rc=0
  OVERALL=PASS
  (( N_WARN )) && { OVERALL=WARN; rc=1; }
  (( N_FAIL )) && { OVERALL=FAIL; rc=2; }

  local dur=$(( $(now_ms) - t0 ))
  if (( JSON )); then
    print_json "$dur"
  else
    printf '\n%sSummary:%s %s%s%s  (%d pass, %d warn, %d fail, %d skip) in %d.%01ds\n' \
      "$C_BOLD" "$C_RST" "$(status_color "$OVERALL")" "$OVERALL" "$C_RST" \
      "$N_PASS" "$N_WARN" "$N_FAIL" "$N_SKIP" $(( dur / 1000 )) $(( dur % 1000 / 100 ))
  fi
  exit "$rc"
}

main "$@"
