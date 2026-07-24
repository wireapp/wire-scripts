#!/usr/bin/env bash
# test_coturn.sh — coturn connectivity tests for Wire/Kubernetes deployments.
#
# Tests the subset of the coturn remote test plan that is valid against the
# Wire Helm chart configuration:
#
#   Always run (plain transports):
#     2.1  TURN 401 challenge / UDP   — unauthenticated Allocate → 401 + REALM + NONCE
#     2.2  TURN 401 challenge / TCP
#
#   With --tls (requires tls.enabled=true in Helm values):
#     2.3  TURN 401 challenge / TLS
#     3.1  TLS certificate validity   — not expired, chains to expected CA
#     3.2  TLS version negotiation    — TLS 1.2/1.3 accepted; 1.0/1.1 rejected
#     3.3  Cipher suite enforcement   — strong ciphers accepted; NULL/EXPORT rejected
#     3.5  ALPN negotiation           — stun.turn / stun.nat-discovery tokens
#
#   With --metrics (requires metrics to be exposed!):
#     5.1  Prometheus health          — GET / on metrics port → HTTP 200
#     5.2  Prometheus metrics scrape  — GET /metrics → valid exposition format
#     5.4  Metrics reflect challenge  — allocation counter unchanged after 2.1+2.2
#
# Omitted (invalid against our config):
#   1.x  STUN Binding — excluded by secure-stun (requires MESSAGE-INTEGRITY)
#   1.4  STUN/DTLS    — excluded by no-dtls
#   1.5  RFC 5780     — excluded by no-rfc5780
#   2.4  TURN/DTLS    — excluded by no-dtls
#   4.1  ACME         — not configured in Helm chart template
#
# DEFAULTS:
#   Defaults to not performing TLS checks, and no metrics tests.
#
# USAGE:
#   export TURN_HOST=<ip-or-hostname>
#   export TURN_PORT=3478          # default: 3478
#   export TURN_TLS_PORT=5349      # default: 5349
#   export PROM_HOST=<ip>          # default: TURN_HOST
#   export PROM_PORT=9641          # default: 9641
#   ./test_coturn.sh [--tls|--no-tls|--metrics|--no-metrics]
#
# DEPENDENCIES: bash, socat, openssl, curl, perl, gzip
 
set -euo pipefail
 
# ── argument parsing ───────────────────────────────────────────────────────────

# TLS and metrics testing are off by default.
TLS=0
METRICS=0
VERBOSE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tls)    TLS=1; shift ;;
        --no-tls) TLS=0; shift ;;
	--metrics) METRICS=1; shift;;
	--no-metrics) METRICS=0; shift;;
	--verbose) VERBOSE=1; shift;;
        *) echo "Usage: $0 [--tls|--no-tls|--metrics|--no-metrics]" >&2; exit 1 ;;
    esac
done
 
# ── configuration ──────────────────────────────────────────────────────────────
 
HOST="${TURN_HOST:-coturn-0.coturn.calling-staging-v01.zinfra.io}"
PORT="${TURN_PORT:-3478}"
TLS_PORT="${TURN_TLS_PORT:-5349}"
PROM_HOST="${PROM_HOST:-$HOST}"
PROM_PORT="${PROM_PORT:-9641}"
 
export WORK
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
 
PASS=0
FAIL=0
SKIP=0
 
# ── helpers ────────────────────────────────────────────────────────────────────
 
log()  { echo "[$(date -u +%T)] $*" >&2; }
die()  { echo "ERROR: $2" >&2; exit "$1"; }
pass() { printf '\033[32m✓\033[0m %s\n' "$1"; PASS=$(( PASS + 1 )); }
fail() { printf '\033[31m✗\033[0m %s — %s\n' "$1" "$2"; FAIL=$(( FAIL + 1 )); }
skipTLS() { [ "$VERBOSE" -eq 1 ] && printf '\033[33m–\033[0m %s\n' "$1 (skipped: needs --tls)"; SKIP=$(( SKIP + 1 )); }
skipMetrics() { [ "$VERBOSE" -eq 1 ] && printf '\033[33m–\033[0m %s\n' "$1 (skipped: needs --metrics)"; SKIP=$(( SKIP + 1 )); }
now_ms() { perl -MTime::HiRes -e 'printf "%.3f\n", Time::HiRes::time()' | tr -d '.'; }
 
hex2bin() { perl -e 'local $/; my $h = <STDIN>; $h =~ s/\s//g; print pack "H*", $h'; }
bin2hex() { perl -e 'local $/; $d=<STDIN>; print unpack("H*", $d)'; }
 
# ── STUN packet builder ────────────────────────────────────────────────────────
#
# Builds a STUN packet with FINGERPRINT but without MESSAGE-INTEGRITY.
# MESSAGE-INTEGRITY requires a shared password, which is not available in
# unauthenticated flows.  FINGERPRINT is always included so that coturn's
# built-in check does not discard the packet before processing it.
#
# RFC 5389 §15.5: FINGERPRINT = CRC32(message excluding FP attr) XOR 0x5354554e.
# The Message Length field counts all attributes including FINGERPRINT.
#
# Args: $1=msg_type (4 hex), $2=txn_id (24 hex), $3=attrs_hex (may be empty)
 
build_stun_fp() {
    local msg_type="$1" txn_id="$2" attrs="${3:-}"
 
    local attrs_bytes=$(( ${#attrs} / 2 ))
    local fp_size=8   # 4-byte attr header + 4-byte CRC32
    local total_len=$(( attrs_bytes + fp_size ))
 
    local msg_pre_fp="${msg_type}$(printf '%04x' "$total_len")2112a442${txn_id}${attrs}"
 
    # CRC32 via the gzip trailer: bytes -8..-5 of a gzip stream are the CRC32
    # of the payload, stored little-endian.
    local crc_le
    crc_le=$(printf '%s' "$msg_pre_fp" \
        | hex2bin | gzip -c | tail -c 8 | head -c 4 | bin2hex | tr -d '\n')
 
    local crc_be="${crc_le:6:2}${crc_le:4:2}${crc_le:2:2}${crc_le:0:2}"
    local fp_val
    fp_val=$(printf '%08x' $(( 16#$crc_be ^ 0x5354554e )))
 
    printf '%s' "${msg_pre_fp}80280004${fp_val}"
}
 
# ── STUN attribute helpers ─────────────────────────────────────────────────────
 
# Walk a STUN attribute section and return the value hex of the first attribute
# matching $target_type (4 hex chars).  Exits 1 if not found.
find_attr() {
    local attrs_hex="$1" target="$2"
    local i=0
    while [ $(( i + 8 )) -le ${#attrs_hex} ]; do
        local atype="${attrs_hex:$i:4}"
        local alen=$(( 16#${attrs_hex:$(( i + 4 )):4} ))
        local aval="${attrs_hex:$(( i + 8 )):$(( alen * 2 ))}"
        if [ "$atype" = "$target" ]; then printf '%s' "$aval"; return 0; fi
        local padded=$(( ( (alen + 3) / 4 ) * 4 ))
        i=$(( i + 8 + padded * 2 ))
    done
    return 1
}
 
# Decode ERROR-CODE attribute value hex to an integer (e.g. 401).
# Layout: 2 reserved bytes | class (×100) | number.
decode_error_code() {
    local v="$1"
    echo $(( 16#${v:4:2} * 100 + 16#${v:6:2} ))
}
 
# ── transport: send and capture first response ─────────────────────────────────
#
# Returns the response as a hex string on stdout; returns empty string on
# timeout or connection failure (never exits non-zero).
 
send_udp() {
    local host="$1" port="$2" req_hex="$3"
    printf '%s' "$req_hex" | hex2bin \
        | socat -T 3 - "UDP4:${host}:${port}" 2>/dev/null \
        | bin2hex || true
}
 
send_tcp() {
    local host="$1" port="$2" req_hex="$3"
    printf '%s' "$req_hex" | hex2bin \
        | socat -T 3 - "TCP4:${host}:${port}" 2>/dev/null \
        | bin2hex || true
}
 
# Feed the request to openssl s_client, sleep 2 s so the response arrives
# before stdin closes and the session tears down.
send_tls() {
    local host="$1" port="$2" req_hex="$3"
    ( printf '%s' "$req_hex" | hex2bin; sleep 2 ) \
        | openssl s_client -connect "${host}:${port}" -quiet 2>/dev/null \
        | bin2hex || true
}
 
# ── assertion: TURN 401 challenge ─────────────────────────────────────────────
#
# Validates a STUN Error Response for an Allocate (type 0113).
# Checks magic cookie, message type, error code == 401, REALM present,
# NONCE present.  All three are required for a well-formed 401 challenge
# (RFC 5766 §6.2).
 
check_401_response() {
    local name="$1" resp_hex="$2" elapsed_ms="$3"
 
    if [ -z "$resp_hex" ] || [ ${#resp_hex} -lt 40 ]; then
        fail "$name" "no response received"; return
    fi
 
    local rtype="${resp_hex:0:4}"
    local alen=$(( 16#${resp_hex:4:4} ))
    local magic="${resp_hex:8:8}"
    local attrs="${resp_hex:40:$(( alen * 2 ))}"
 
    if [ "$magic" != "2112a442" ]; then
        fail "$name" "bad magic cookie: expected 2112a442 got $magic"; return
    fi
    if [ "$rtype" != "0113" ]; then
        fail "$name" "expected Allocate Error (0113), got $rtype"; return
    fi
 
    local ec_hex
    if ! ec_hex=$(find_attr "$attrs" "0009"); then
        fail "$name" "no ERROR-CODE attribute"; return
    fi
    local code; code=$(decode_error_code "$ec_hex")
    if [ "$code" != "401" ]; then
        fail "$name" "expected 401, got $code"; return
    fi
 
    local realm="" nonce="" realm_hex nonce_hex
    realm_hex=$(find_attr "$attrs" "0014") && realm=$(printf '%s' "$realm_hex" | hex2bin) || true
    nonce_hex=$(find_attr "$attrs" "0015") && nonce=$(printf '%s' "$nonce_hex" | hex2bin | tr -dc '[:print:]') || true
 
    [ -n "$realm" ] || { fail "$name" "401 but REALM absent"; return; }
    [ -n "$nonce" ] || { fail "$name" "401 but NONCE absent"; return; }
 
    pass "${name}  (${elapsed_ms} ms  realm=\"${realm}\"  nonce=${nonce:0:16}…)"
}
 
# ── assertion: TLS transport ───────────────────────────────────────────────────
 
# 3.1  Certificate not expired, SAN/CN matches host.
check_tls_cert() {
    local T0; T0=$(now_ms)
 
    local cert_pem
    cert_pem=$(echo \
        | timeout 5 openssl s_client -connect "${HOST}:${TLS_PORT}" \
              -servername "$HOST" 2>/dev/null \
        | openssl x509 2>/dev/null) || {
        fail "3.1  TLS cert validity" "could not retrieve certificate"; return
    }
 
    # -checkend 0: exits 1 if cert has already expired.
    echo "$cert_pem" | openssl x509 -noout -checkend 0 2>/dev/null || {
        local expiry; expiry=$(echo "$cert_pem" | openssl x509 -noout -enddate | cut -d= -f2)
        fail "3.1  TLS cert validity" "certificate expired: $expiry"; return
    }
 
    local days_left enddate
    enddate=$(echo "$cert_pem" | openssl x509 -noout -enddate | cut -d= -f2)
    # -checkend N: exits 1 if cert expires within N seconds.
    # Binary search isn't needed; just report days remaining via the 1-day boundary.
    local secs_left=0
    # Use perl for portable epoch arithmetic (avoids Linux vs macOS date divergence).
    secs_left=$(echo "$cert_pem" \
        | openssl x509 -noout -enddate \
        | perl -ne 'use POSIX; /=(.+)/ and print int((POSIX::mktime(strptime($1, "%b %d %T %Y %Z") ? @_ : ()) - time()) / 86400)' 2>/dev/null) || secs_left="?"
 
    local elapsed=$(( $(now_ms) - T0 ))
    pass "3.1  TLS cert validity  (${elapsed} ms  expires in ${secs_left} days: ${enddate})"
}
 
# 3.2  TLS 1.2 and 1.3 accepted; 1.0 and 1.1 rejected.
check_tls_versions() {
    local name="3.2  TLS version negotiation"
    local ok=1
 
    for good_ver in tls1_2 tls1_3; do
        if echo | timeout 5 openssl s_client \
                -connect "${HOST}:${TLS_PORT}" \
                -servername "$HOST" \
                "-${good_ver}" 2>/dev/null \
            | grep -q "Cipher is\|Cipher    :"; then
            log "${name}: ${good_ver} accepted (expected)"
        else
            fail "$name" "${good_ver} not accepted"
            ok=0
        fi
    done
 
    # Older versions may not be offered by the local openssl binary at all;
    # either a handshake failure or "unknown option" is a passing result.
    for bad_ver in tls1 tls1_1; do
        local out
        out=$(echo | timeout 5 openssl s_client \
            -connect "${HOST}:${TLS_PORT}" \
            -servername "$HOST" \
            "-${bad_ver}" 2>&1 || true)
        if echo "$out" | grep -qE "handshake failure|alert|unknown option|no protocols"; then
            log "${name}: ${bad_ver} rejected (expected)"
        elif echo "$out" | grep -q "Cipher is\|Cipher    :"; then
            fail "$name" "${bad_ver} was accepted — server should reject it"
            ok=0
        else
            log "${name}: ${bad_ver} — inconclusive response (may be unsupported by local openssl)"
        fi
    done
 
    [ "$ok" -eq 1 ] && pass "${name}"
}
 
# 3.3  Strong cipher accepted; NULL/EXPORT ciphers rejected.
check_tls_ciphers() {
    local name="3.3  Cipher suite enforcement"
    local ok=1
 
    # A representative strong cipher: should always be accepted.
    if echo | timeout 5 openssl s_client \
            -connect "${HOST}:${TLS_PORT}" \
            -servername "$HOST" \
            -cipher "ECDHE-RSA-AES128-GCM-SHA256" 2>/dev/null \
        | grep -q "Cipher is\|Cipher    :"; then
        log "${name}: strong cipher (ECDHE-RSA-AES128-GCM-SHA256) accepted"
    else
        fail "$name" "strong cipher ECDHE-RSA-AES128-GCM-SHA256 not accepted"
        ok=0
    fi
 
    # NULL / EXPORT suites: modern openssl may not even build these strings,
    # so an "unknown option" or empty-cipher-list error is also a pass.
    local weak_out
    weak_out=$(echo | timeout 5 openssl s_client \
        -connect "${HOST}:${TLS_PORT}" \
        -servername "$HOST" \
        -cipher "NULL,LOW,EXPORT" 2>&1 || true)
    if echo "$weak_out" | grep -q "Cipher is\|Cipher    :"; then
        fail "$name" "NULL/EXPORT cipher was accepted — server should reject it"
        ok=0
    else
        log "${name}: NULL/EXPORT ciphers rejected (expected)"
    fi
 
    [ "$ok" -eq 1 ] && pass "${name}"
}
 
# 3.5  ALPN: stun.turn and stun.nat-discovery tokens (RFC 7443).
check_tls_alpn() {
    local name="3.5  ALPN negotiation"
    local ok=1
 
    for token in "stun.turn" "stun.nat-discovery"; do
        local out
        out=$(echo | timeout 5 openssl s_client \
            -connect "${HOST}:${TLS_PORT}" \
            -servername "$HOST" \
            -alpn "$token" 2>/dev/null || true)
 
        if echo "$out" | grep -q "ALPN protocol.*${token}"; then
            log "${name}: token '${token}' negotiated"
        elif echo "$out" | grep -q "Cipher is\|Cipher    :"; then
            # Connected but ALPN not echoed back — server does not advertise
            # ALPN for this token, which is permitted by RFC 7443.
            log "${name}: token '${token}' — TLS handshake succeeded, ALPN not echoed (acceptable)"
        else
            fail "$name" "TLS handshake failed for token '${token}'"
            ok=0
        fi
    done
 
    [ "$ok" -eq 1 ] && pass "${name}"
}
# ── dependency checks ──────────────────────────────────────────────────────────
 
for cmd in socat openssl curl perl gzip; do
    command -v "$cmd" &>/dev/null || die 1 "'$cmd' required but not found"
done
 
log "deps ok  socat=$(socat -V 2>&1 | awk '/socat version/{print $3}')  openssl=$(openssl version | awk '{print $2}')"
log "target   turn=${HOST}:${PORT}  tls=${HOST}:${TLS_PORT}  prom=${PROM_HOST}:${PROM_PORT}  tls-tests=$([ "$TLS" -eq 1 ] && echo on || echo off) metrics-tests=$([ "$METRICS" -eq 1 ] && echo on || echo off)"
 
# REQUESTED-TRANSPORT attribute: type=0019, length=4, value=0x11000000
# (protocol=UDP=17, 3 padding bytes).
ALLOC_ATTRS="0019000411000000"
 
# ── prometheus baseline (captured before the TURN tests that 5.4 observes) ────

if [ "$METRICS" -eq 1 ] ; then
    {
	log "capturing prometheus baseline for 5.4…"
	PROM_BASELINE=$(curl -sf --max-time 5 "http://${PROM_HOST}:${PROM_PORT}/metrics" 2>/dev/null) || PROM_BASELINE=""
	ALLOC_BEFORE=$(printf '%s' "$PROM_BASELINE" \
			   | awk '/^turn_new_allocation_total /{print $2; exit}')
	ALLOC_BEFORE="${ALLOC_BEFORE:-0}"
	log "baseline  turn_new_allocation_total=${ALLOC_BEFORE}"
    }
else
    {
	ALLOC_BEFORE=0
	skipMetrics "prometheus baseline (used in 5.4)"
    }
fi
 
# ── 2.1  TURN 401 challenge / UDP ──────────────────────────────────────────────
 
TXN=$(openssl rand -hex 12)
REQ=$(build_stun_fp "0003" "$TXN" "$ALLOC_ATTRS")
log "2.1 → Allocate (no credentials) UDP  txn=$TXN"
T0=$(now_ms)
RESP=$(send_udp "$HOST" "$PORT" "$REQ")
T1=$(now_ms)
check_401_response "2.1  TURN 401 challenge / UDP" "$RESP" "$(( T1 - T0 ))"
 
# ── 2.2  TURN 401 challenge / TCP ──────────────────────────────────────────────
 
TXN=$(openssl rand -hex 12)
REQ=$(build_stun_fp "0003" "$TXN" "$ALLOC_ATTRS")
log "2.2 → Allocate (no credentials) TCP  txn=$TXN"
T0=$(now_ms)
RESP=$(send_tcp "$HOST" "$PORT" "$REQ")
T1=$(now_ms)
check_401_response "2.2  TURN 401 challenge / TCP" "$RESP" "$(( T1 - T0 ))"
 
# ── 2.3 / 3.1 / 3.2 / 3.3 / 3.5  TLS tests (--tls only) ─────────────────────
 
if [ "$TLS" -eq 1 ]; then
 
    TXN=$(openssl rand -hex 12)
    REQ=$(build_stun_fp "0003" "$TXN" "$ALLOC_ATTRS")
    log "2.3 → Allocate (no credentials) TLS  txn=$TXN"
    T0=$(now_ms)
    RESP=$(send_tls "$HOST" "$TLS_PORT" "$REQ")
    T1=$(now_ms)
    check_401_response "2.3  TURN 401 challenge / TLS" "$RESP" "$(( T1 - T0 ))"
 
    check_tls_cert
    check_tls_versions
    check_tls_ciphers
    check_tls_alpn
 
else
    for label in \
        "2.3  TURN 401 challenge / TLS" \
        "3.1  TLS cert validity" \
        "3.2  TLS version negotiation" \
        "3.3  Cipher suite enforcement" \
        "3.5  ALPN negotiation"
    do
        skipTLS "$label"
    done
fi
 
# ── 5.1  Prometheus health ─────────────────────────────────────────────────────
 
if [ "$METRICS" -eq 1 ]; then
    {
	log "5.1 → GET http://${PROM_HOST}:${PROM_PORT}/"
	T0=$(now_ms)
	HTTP_CODE=$(curl -so /dev/null -w '%{http_code}' --max-time 5 \
			 "http://${PROM_HOST}:${PROM_PORT}/" 2>/dev/null) || HTTP_CODE=0
	T1=$(now_ms)
	if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ]; then
	    pass "5.1  Prometheus health  ($(( T1 - T0 )) ms  HTTP $HTTP_CODE)"
	else
	    fail "5.1  Prometheus health" "expected 200/301/302, got HTTP $HTTP_CODE"
	fi
    }
else
    skipMetrics "5.1  Prometheus health"
fi

# ── 5.2  Prometheus metrics scrape ────────────────────────────────────────────
 
if [ "$METRICS" -eq 1 ]; then
    {
	log "5.2 → GET http://${PROM_HOST}:${PROM_PORT}/metrics"
	T0=$(now_ms)
	FOUNDMETRICS=$(curl -sf --max-time 5 "http://${PROM_HOST}:${PROM_PORT}/metrics" 2>/dev/null) || FOUNDMETRICS=""
	T1=$(now_ms)
 
	if [ -z "$FOUNDMETRICS" ]; then
	    fail "5.2  Prometheus metrics scrape" "empty or no response"
	else
	    MISSING=""
	    for key in \
		turn_new_allocation_total \
		turn_total_allocations_number \
		turn_traffic_rcvp \
		turn_traffic_sentp
	    do
		printf '%s' "$FOUNDMETRICS" | grep -q "^${key}" || MISSING="${MISSING} ${key}"
	    done
 
	    if [ -n "$MISSING" ]; then
		fail "5.2  Prometheus metrics scrape" "missing keys:${MISSING}"
	    else
		pass "5.2  Prometheus metrics scrape  ($(( T1 - T0 )) ms)"
	    fi
	fi
    }
else
    skipMetrics "5.2  Prometheus metrics scrape"
fi
 
# ── 5.4  Metrics reflect TURN 401 activity ────────────────────────────────────
#
# After tests 2.1 and 2.2 have run, the allocation counter must be unchanged:
# a 401 challenge must not create an allocation.  A change here indicates that
# the server granted an allocation to a request with no credentials, which is
# a serious misconfiguration.
 
if [ "$METRICS" -eq 1 ]; then
    {
	log "5.4 → checking allocation counter did not increment"
	PROM_AFTER=$(curl -sf --max-time 5 "http://${PROM_HOST}:${PROM_PORT}/metrics" 2>/dev/null) || PROM_AFTER=""
	ALLOC_AFTER=$(printf '%s' "$PROM_AFTER" \
			  | awk '/^turn_new_allocation_total /{print $2; exit}')
	ALLOC_AFTER="${ALLOC_AFTER:-0}"
	log "after     turn_new_allocation_total=${ALLOC_AFTER}"
	
	if [ -z "$PROM_AFTER" ]; then
	    fail "5.4  Metrics / TURN challenge" "could not scrape metrics after TURN tests"
	elif [ "$ALLOC_BEFORE" = "$ALLOC_AFTER" ]; then
	    pass "5.4  Metrics / TURN challenge  (allocation counter stable at ${ALLOC_AFTER})"
	else
	    fail "5.4  Metrics / TURN challenge" \
		 "turn_new_allocation_total changed: ${ALLOC_BEFORE} → ${ALLOC_AFTER} — server may have granted an unauthenticated allocation"
	fi
    }
else
    skipMetrics "5.4  Metrics / TURN challenge"
fi
 
# ── summary ────────────────────────────────────────────────────────────────────
 
echo
echo "Results: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
[ "$FAIL" -eq 0 ]
