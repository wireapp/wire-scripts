#!/usr/bin/env bash
# test_notifications.sh — Wire notification stack connectivity + protocol probe.
#
# Beyond basic TCP reachability, this script exercises each service at the
# *protocol layer* using deliberately-invalid unauthenticated requests, and
# verifies that the responses match what the real service returns.  This lets
# you distinguish:
#
#   • A correctly routed connection (real service JSON error response)      ✓
#   • A firewall black-hole / RST                                           ✗ timeout/error
#   • A TLS-intercepting proxy (wrong certificate issuer, wrong body)       ✗
#   • A DNS override pointing at the wrong host (wrong certificate)         ✗
#
# Architecture note: cannon and gundeck are not directly reachable externally.
# All access is proxied through nginz:
#
#   nginz-https.<domain>  — REST API (HTTPS/443); routes include gundeck's
#                           /push/tokens, /notifications, etc.
#   nginz-ssl.<domain>    — WebSocket endpoint (WSS/443); proxies to cannon
#                           at /await.  May share the same LB as nginz-https,
#                           or be a separate LoadBalancer in dedicated WS setups.
#
# See: https://github.com/wireapp/wire-server/blob/develop/docs/src/how-to/install/infrastructure-configuration.md
#
# Tests performed:
#   §1  APNs         — TLS cert validity+issuer, ALPN h2, HTTP/2 protocol probe
#   §2  FCM          — TLS cert validity+issuer, v1 API protocol probe
#   §3  AWS          — SNS + SQS HTTPS reachability + AWS request-ID header
#   §4  nginz-https  — /status health check, gundeck /push/tokens 401 probe
#   §5  nginz-ssl    — WebSocket upgrade handshake to /await (--ws flag)
#
# USAGE:
#   ./test_notifications.sh [OPTIONS]
#
#   --push / --no-push       APNs + FCM checks              (default: on)
#   --ws   / --no-ws         nginz-ssl WebSocket checks     (default: off)
#   --verbose                Print skipped tests too
#
# ENVIRONMENT (all optional, but §4/§5 require at least one of these):
#   WIRE_DOMAIN        Base domain, e.g. "wire.example.com"
#                      Used to derive nginz-https/nginz-ssl hostnames if they
#                      are not set individually.
#   NGINZ_HTTPS_HOST   Override the REST API hostname
#                      (default: nginz-https.$WIRE_DOMAIN)
#   NGINZ_SSL_HOST     Override the WebSocket hostname
#                      (default: nginz-ssl.$WIRE_DOMAIN)
#   APNS_HOST          Production APNs gateway  (default: api.push.apple.com)
#   APNS_SANDBOX_HOST  Sandbox APNs gateway     (default: api.sandbox.push.apple.com)
#   FCM_HOST           FCM hostname             (default: fcm.googleapis.com)
#   AWS_REGION         Region for SNS/SQS URLs  (default: eu-central-1)
#   SNS_ENDPOINT       Override SNS endpoint URL
#   SQS_ENDPOINT       Override SQS endpoint URL
#
# DEPENDENCIES: bash ≥4, curl (with HTTP/2), openssl, socat, perl
#   GNU timeout (macOS: brew install coreutils)

set -euo pipefail

# ── default flags ─────────────────────────────────────────────────────────────
DO_PUSH=1
DO_WS=0
VERBOSE=0

# ── argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --push)       DO_PUSH=1; shift ;;
        --no-push)    DO_PUSH=0; shift ;;
        --ws)         DO_WS=1;   shift ;;
        --no-ws)      DO_WS=0;   shift ;;
        --verbose)    VERBOSE=1; shift ;;
        *)
            echo "Usage: $0 [--push|--no-push] [--ws|--no-ws] [--verbose]" >&2
            exit 1
            ;;
    esac
done

# ── environment defaults ──────────────────────────────────────────────────────
APNS_HOST="${APNS_HOST:-api.push.apple.com}"
APNS_SANDBOX_HOST="${APNS_SANDBOX_HOST:-api.sandbox.push.apple.com}"
FCM_HOST="${FCM_HOST:-fcm.googleapis.com}"

SNS_ENDPOINT="${SNS_ENDPOINT:-https://sns.${AWS_REGION:-eu-central-1}.amazonaws.com}"
SQS_ENDPOINT="${SQS_ENDPOINT:-https://sqs.${AWS_REGION:-eu-central-1}.amazonaws.com}"

# Derive nginz hostnames from WIRE_DOMAIN if not set individually.
WIRE_DOMAIN="${WIRE_DOMAIN:-wiab-dev-b.zinfradev.com}"
NGINZ_HTTPS_HOST="${NGINZ_HTTPS_HOST:-${WIRE_DOMAIN:+nginz-https.${WIRE_DOMAIN}}}"
NGINZ_SSL_HOST="${NGINZ_SSL_HOST:-${WIRE_DOMAIN:+nginz-ssl.${WIRE_DOMAIN}}}"

# A well-formed (64 lowercase hex chars) but deliberately invalid device token.
# APNs validates token format before checking auth, so we get a clean
# "BadDeviceToken"(400) or "MissingProviderToken"(403) JSON response that
# fingerprints a genuine APNs connection.
APNS_PROBE_TOKEN="0000000000000000000000000000000000000000000000000000000000000000"

# FCM HTTP v1 send endpoint.  Project ID is intentionally fake so the request
# fails immediately with a Google-format 401/403 JSON body.
FCM_V1_URL="https://${FCM_HOST}/v1/projects/wire-notification-probe/messages:send"

# ── temp dir ──────────────────────────────────────────────────────────────────
export WORK
WORK=$(mktemp -d)
trap 'rm -rf "$WORK" 2>/dev/null || true' EXIT

# ── counters ──────────────────────────────────────────────────────────────────
PASS=0; FAIL=0; SKIP=0

# ── helpers ───────────────────────────────────────────────────────────────────
log()    { echo "[$(date -u +%T)] $*" >&2; }
die()    { echo "ERROR: $2" >&2; exit "$1"; }
now_ms() { perl -MTime::HiRes -e 'printf "%d\n", Time::HiRes::time() * 1000'; }

pass() { printf '\033[32m✓\033[0m  %s\n'       "$1"; PASS=$((PASS + 1)); }
fail() { printf '\033[31m✗\033[0m  %s — %s\n'  "$1" "$2"; FAIL=$((FAIL + 1)); }
warn() { printf '\033[33m⚠\033[0m  %s\n'       "$1"; }
skip() {
    [[ "$VERBOSE" -eq 1 ]] && printf '\033[90m–\033[0m  %s (skipped)\n' "$1"
    SKIP=$((SKIP + 1))
}

# ── TLS / certificate helpers ─────────────────────────────────────────────────

# Return 0 if the server certificate on host:port is still valid (not expired).
cert_not_expired() {
    local host=$1 port=${2:-443}
    timeout 8 openssl s_client \
        -connect "${host}:${port}" -servername "$host" \
        </dev/null 2>&1 \
    | openssl x509 -noout -checkend 0 2>/dev/null
}

# Print the approximate days until the certificate on host:port expires.
cert_days_left() {
    local host=$1 port=${2:-443}
    local not_after=$(timeout 8 openssl s_client -connect "${host}:${port}" -servername "$host" </dev/null 2>/dev/null \
        | openssl x509 -noout -enddate \
        | cut -d= -f2)

    # openssl -enddate emits:  "Jun 15 12:00:00 2026 GMT"
    # Single-digit days are space-padded: "Jun  5 12:00:00 2026 GMT"
    # \s+ in the regex absorbs both forms.
    perl -MTime::Local -e '
        my %mon = (Jan=>0, Feb=>1, Mar=>2, Apr=>3, May=>4,  Jun=>5,
                   Jul=>6, Aug=>7, Sep=>8, Oct=>9, Nov=>10, Dec=>11);
        if ($ARGV[0] =~ /(\w{3})\s+(\d+)\s+(\d+):(\d+):(\d+)\s+(\d+)/) {
            my $exp = Time::Local::timegm($5, $4, $3, $2, $mon{$1}, $6 - 1900);
            printf "%d\n", ($exp - time) / 86400;
        } else {
            print "unknown\n";
        }
    ' "$not_after"
}

# Return 0 if the leaf cert's issuer contains needle (case-insensitive).
cert_issuer_contains() {
    local host=$1 port=${2:-443} needle=$3
    local issuer
    issuer=$(timeout 8 openssl s_client \
        -connect "${host}:${port}" -servername "$host" \
        </dev/null 2>&1 \
      | openssl x509 -noout -issuer 2>/dev/null || echo "")
    grep -qi "$needle" <<<"$issuer"
}

# Return 0 if ALPN negotiated h2 on host:port.
alpn_h2_ok() {
    local host=$1 port=${2:-443}
    timeout 8 openssl s_client \
        -alpn h2 \
        -connect "${host}:${port}" -servername "$host" \
        </dev/null 2>&1 \
    | grep -q "ALPN protocol: h2"
}

# ── JSON helpers ──────────────────────────────────────────────────────────────

# Return 0 if string $1 contains the literal text $2 (used to fingerprint JSON bodies).
body_contains() { grep -qF "$2" <<<"$1"; }

# ── §0  Dependency and feature detection ─────────────────────────────────────
for cmd in curl openssl socat perl; do
    command -v "$cmd" &>/dev/null || die 1 "'$cmd' is required but not found in PATH"
done

CURL_VER=$(curl --version | head -n1 | awk '{print $2}')
SSL_VER=$(openssl version | awk '{print $2}')
log "deps ok  curl=${CURL_VER}  openssl=${SSL_VER}"
 
# HTTP/2 support in curl is required for the APNs protocol probe.
if curl --version 2>&1 | grep -qiE "HTTP2|nghttp2"; then
    CURL_H2=1
    log "curl HTTP/2 support: yes"
else
    CURL_H2=0
    warn "curl was not built with HTTP/2 support; APNs protocol probe (1.5) will be skipped"
fi

# use gtimeout if it's available.
if command -v gtimeout >/dev/null; then
    alias timeout='gtimeout'
elif ! command -v timeout >/dev/null; then
    die 1 "'timeout' is required but not installed. Install coreutils (brew install coreutils)."
fi

# ── §1  APNs ──────────────────────────────────────────────────────────────────
# Wire's Gundeck routes Apple push notifications through AWS SNS, which makes
# outbound TLS connections to api.push.apple.com on behalf of Gundeck.
# Run this script from a network position with the same egress path as Gundeck.
#
# APNs HTTP/2 API: POST /3/device/<token>
#   Without auth:   403  {"reason":"MissingProviderToken"}
#   Auth OK, bad token: 400 {"reason":"BadDeviceToken"}
# The "reason" key is the fingerprint of a genuine APNs connection.

if [[ "$DO_PUSH" -eq 1 ]]; then
    log "── §1 APNs ──────────────────────────────────────────────────────────────────"

    # 1.1  Basic HTTPS reachability
    log "▶  1.1  APNs basic reachability (${APNS_HOST}:443)"
    T0=$(now_ms)
    if curl -s --max-time 6 "https://${APNS_HOST}/3/device" -o /dev/null 2>&1; then
        T1=$(now_ms)
        pass "1.1  APNs basic HTTPS reachability  ($((T1 - T0)) ms)"
    else
        fail "1.1  APNs basic HTTPS reachability" \
             "no response — check firewall egress rules and DNS for ${APNS_HOST}"
    fi

    # 1.2  TLS certificate not expired
    log "▶  1.2  APNs TLS certificate expiry"
    days=$(cert_days_left "$APNS_HOST" 443)
    if cert_not_expired "$APNS_HOST" 443; then
        pass "1.2  APNs TLS certificate valid (expires in ~${days} days)"
    else
        fail "1.2  APNs TLS certificate valid" \
             "certificate has expired or could not be retrieved"
    fi

    # 1.3  TLS certificate issuer — must be Apple
    # A TLS-intercepting proxy (corporate DLP, misconfigured middlebox) would
    # present its own certificate here instead of Apple's.
    log "▶  1.3  APNs TLS certificate issuer"
    if cert_issuer_contains "$APNS_HOST" 443 "Apple"; then
        pass "1.3  APNs TLS certificate issued by Apple (no TLS intercept detected)"
    else
        raw_issuer=$(timeout 8 openssl s_client \
            -connect "${APNS_HOST}:443" -servername "$APNS_HOST" \
            </dev/null 2>&1 \
          | openssl x509 -noout -issuer 2>/dev/null || echo "unavailable")
        fail "1.3  APNs TLS certificate issued by Apple" \
             "unexpected issuer: ${raw_issuer} — possible TLS intercept proxy or DNS override"
    fi

    # 1.4  ALPN HTTP/2 negotiation
    # APNs mandates HTTP/2; if h2 is not negotiated, push delivery will fail
    # even if basic connectivity looks fine.
    log "▶  1.4  APNs ALPN h2 negotiation"
    if alpn_h2_ok "$APNS_HOST" 443; then
        pass "1.4  APNs ALPN h2 negotiated"
    else
        fail "1.4  APNs ALPN h2 negotiated" \
             "server did not accept h2 in ALPN — APNs HTTP/2 API unavailable; check for a middlebox"
    fi

    # 1.5  HTTP/2 protocol probe (unauthenticated)
    # We POST a valid-format APNs request without auth credentials.  A genuine
    # APNs server returns a JSON body containing a "reason" field.  A firewall
    # drop, a TLS proxy, or a wrong endpoint produces something entirely different.
    if [[ "$CURL_H2" -eq 1 ]]; then
        log "▶  1.5  APNs HTTP/2 protocol probe (unauthenticated → expect Apple JSON error)"
        apns_body="$WORK/apns_probe.json"
        apns_meta=$(curl -s --max-time 10 \
            --http2 \
            -H "apns-topic: com.wire.notifications" \
            -H "apns-push-type: alert" \
            -H "content-type: application/json" \
            -d '{"aps":{"alert":"wire-notification-probe"}}' \
            -o "$apns_body" \
            -w "%{http_code} %{http_version}" \
            "https://${APNS_HOST}/3/device/${APNS_PROBE_TOKEN}" 2>/dev/null) || apns_meta="000 ?"
        apns_code=$(awk '{print $1}' <<<"$apns_meta")
        apns_hv=$(awk   '{print $2}' <<<"$apns_meta")
        apns_resp=$(cat "$apns_body" 2>/dev/null || echo "")

        if body_contains "$apns_resp" '"reason"'; then
            reason=$(grep -oE '"reason"\s*:\s*"[^"]+"' <<<"$apns_resp" | head -1 | tr -d ' ')
            if [[ "$apns_hv" == "2" ]]; then
                pass "1.5  APNs HTTP/2 protocol probe — HTTP/${apns_hv} ${apns_code} ${reason}"
            else
                warn "1.5  APNs responded with correct JSON but over HTTP/${apns_hv} not h2"
                pass "1.5  APNs HTTP/2 protocol probe — HTTP/${apns_hv} ${apns_code} ${reason}"
            fi
        else
            fail "1.5  APNs HTTP/2 protocol probe" \
                 "unexpected response: HTTP/${apns_hv} ${apns_code} body='${apns_resp:0:160}'"
        fi
    else
        skip "1.5  APNs HTTP/2 protocol probe (curl lacks HTTP/2 support)"
    fi

    # 1.6  APNs sandbox endpoint
    # Development and staging Wire clients register against the sandbox APNs
    # endpoint; missing connectivity here causes missed notifications for those.
    log "▶  1.6  APNs sandbox reachability (${APNS_SANDBOX_HOST}:443)"
    T0=$(now_ms)
    if curl -s --max-time 6 "https://${APNS_SANDBOX_HOST}/3/device" -o /dev/null 2>&1; then
        T1=$(now_ms)
        pass "1.6  APNs sandbox reachable  ($((T1 - T0)) ms)"
    else
        fail "1.6  APNs sandbox reachable" \
             "no response — development/staging Wire clients will not receive notifications"
    fi

    # 1.7  APNs legacy port 2197
    # Some corporate firewalls block outbound 443 for non-HTTP traffic; port
    # 2197 is Apple's alternative for APNs connections.
    log "▶  1.7  APNs legacy port 2197 (${APNS_HOST}:2197)"
    T0=$(now_ms)
    if timeout 6 openssl s_client -quiet \
            -connect "${APNS_HOST}:2197" -servername "$APNS_HOST" \
            </dev/null &>/dev/null; then
        T1=$(now_ms)
        pass "1.7  APNs legacy port 2197 reachable  ($((T1 - T0)) ms)"
    else
        warn "1.7  APNs port 2197 unreachable (not fatal if port 443 works)"
        SKIP=$((SKIP + 1))
    fi

else
    for n in "1.1" "1.2" "1.3" "1.4" "1.5" "1.6" "1.7"; do
        skip "${n}  APNs (--no-push)"
    done
fi

# ── §2  FCM ───────────────────────────────────────────────────────────────────
# Firebase Cloud Messaging (FCM) is used for Android push notifications.
# Wire's Gundeck routes FCM pushes through AWS SNS → fcm.googleapis.com.
#
# FCM HTTP v1 API: POST /v1/projects/<project>/messages:send
#   Without auth:  401  {"error":{"code":401,"status":"UNAUTHENTICATED",...}}
# The nested "error" + "code" structure is the Google API fingerprint.

if [[ "$DO_PUSH" -eq 1 ]]; then
    log "── §2 FCM ───────────────────────────────────────────────────────────────────"

    # 2.1  Basic HTTPS reachability
    log "▶  2.1  FCM basic reachability (${FCM_HOST}:443)"
    T0=$(now_ms)
    if curl -s --max-time 6 "https://${FCM_HOST}/" -o /dev/null 2>&1; then
        T1=$(now_ms)
        pass "2.1  FCM basic HTTPS reachability  ($((T1 - T0)) ms)"
    else
        fail "2.1  FCM basic HTTPS reachability" \
             "no response — check firewall egress rules and DNS for ${FCM_HOST}"
    fi

    # 2.2  TLS certificate not expired
    log "▶  2.2  FCM TLS certificate expiry"
    days=$(cert_days_left "$FCM_HOST" 443)
    if cert_not_expired "$FCM_HOST" 443; then
        pass "2.2  FCM TLS certificate valid (expires in ~${days} days)"
    else
        fail "2.2  FCM TLS certificate valid" \
             "certificate has expired or could not be retrieved"
    fi

    # 2.3  TLS certificate issuer — must be Google (Trust Services / GTS)
    log "▶  2.3  FCM TLS certificate issuer"
    if cert_issuer_contains "$FCM_HOST" 443 "Google"; then
        pass "2.3  FCM TLS certificate issued by Google (no TLS intercept detected)"
    else
        raw_issuer=$(timeout 8 openssl s_client \
            -connect "${FCM_HOST}:443" -servername "$FCM_HOST" \
            </dev/null 2>&1 \
          | openssl x509 -noout -issuer 2>/dev/null || echo "unavailable")
        fail "2.3  FCM TLS certificate issued by Google" \
             "unexpected issuer: ${raw_issuer} — possible TLS intercept proxy or DNS override"
    fi

    # 2.4  FCM v1 API protocol probe (unauthenticated)
    # POST to the send endpoint without auth.  Google's API gateway returns a
    # machine-readable 401 JSON body.  A firewall block or TLS proxy produces
    # something different (timeout, HTML, no nested "error.code" structure).
    log "▶  2.4  FCM v1 API protocol probe (unauthenticated → expect 401 UNAUTHENTICATED)"
    fcm_body="$WORK/fcm_probe.json"
    fcm_code=$(curl -s --max-time 10 \
        -X POST \
        -H "Content-Type: application/json" \
        -d '{"message":{"token":"wire-notification-probe"}}' \
        -o "$fcm_body" \
        -w "%{http_code}" \
        "$FCM_V1_URL" 2>/dev/null) || fcm_code="000"
    fcm_resp=$(cat "$fcm_body" 2>/dev/null || echo "")

    if [[ "$fcm_code" == "401" ]] && body_contains "$fcm_resp" "UNAUTHENTICATED"; then
        pass "2.4  FCM v1 API probe — HTTP ${fcm_code} UNAUTHENTICATED (real FCM endpoint confirmed)"
    elif [[ "$fcm_code" =~ ^(400|401|403)$ ]] && body_contains "$fcm_resp" '"error"'; then
        pass "2.4  FCM v1 API probe — HTTP ${fcm_code} with Google API error JSON (endpoint confirmed)"
    else
        fail "2.4  FCM v1 API probe" \
             "unexpected response: HTTP ${fcm_code} body='${fcm_resp:0:160}'"
    fi

else
    for n in "2.1" "2.2" "2.3" "2.4"; do
        skip "${n}  FCM (--no-push)"
    done
fi

# ── §3  AWS SNS / SQS ─────────────────────────────────────────────────────────
# Gundeck requires both SNS (to register/send push) and SQS (to receive
# APNs/FCM delivery-failure feedback and to process internal user events).
# Even in websocket-only setups a real or fake-aws SQS endpoint is mandatory.
#
# Beyond HTTPS reachability we check for the x-amzn-requestid response header,
# which AWS emits on every response.  Its absence means the request likely hit
# a proxy or a misconfigured endpoint rather than real (or LocalStack) AWS.

log "── §3 AWS SNS/SQS ───────────────────────────────────────────────────────────"

check_aws_endpoint() {
    local label=$1 url=$2
    log "▶  ${label}  (${url})"
    local hdr_file="$WORK/aws_${label//[^a-z0-9]/_}.headers"
    local http_code
 
    http_code=$(curl -Is --max-time 8 "$url" \
        -D "$hdr_file" \
        -o /dev/null \
        -w "%{http_code}" 2>/dev/null) || http_code="000"
    local hdrs
    hdrs=$(cat "$hdr_file" 2>/dev/null || echo "")
 
    if grep -qi "x-amzn-requestid\|x-amz-request-id" <<<"$hdrs"; then
        pass "${label}  HTTP ${http_code} + AWS request-ID header (real AWS / LocalStack endpoint)"
    elif [[ "$http_code" =~ ^[2345][0-9][0-9]$ ]]; then
        warn "${label}  HTTP ${http_code} but no AWS request-ID header — confirm this is the intended endpoint"
        PASS=$((PASS + 1))
    else
        fail "${label}" "HTTP ${http_code} — cannot reach ${url}"
    fi
}

check_aws_endpoint "3.1  SNS endpoint" "$SNS_ENDPOINT"
check_aws_endpoint "3.2  SQS endpoint" "$SQS_ENDPOINT"

# ── §4  nginz-https — gundeck route probe ────────────────────────────────────
# Gundeck is not directly reachable; all REST access goes via nginz-https.
# We probe two things:
#
#   /status        — Wire's unauthenticated health endpoint; always returns
#                    200 OK with an empty body.  Confirms nginz itself is up.
#
#   /push/tokens   — Gundeck's push-token registration endpoint (requires
#                    auth).  An unauthenticated request gets rejected by
#                    nginz's libzauth module with a Wire-format 401 JSON body.
#                    This response confirms both that the gundeck upstream is
#                    configured in nginz AND that libzauth is running correctly.
#                    A 502 would mean gundeck is down; a 404 would mean the
#                    upstream route is missing from the nginz config.

log "── §4 nginz-https (gundeck route) ─────────────────────────────────────────"

if [[ -z "$NGINZ_HTTPS_HOST" ]]; then
    warn "NGINZ_HTTPS_HOST is not set — set WIRE_DOMAIN or NGINZ_HTTPS_HOST to enable §4"
    for n in "4.1" "4.2" "4.3"; do skip "${n}  nginz-https (no host configured)"; done
else
    # 4.1  TLS certificate validity and issuer
    log "▶  4.1  nginz-https TLS certificate (${NGINZ_HTTPS_HOST}:443)"
    days=$(cert_days_left "$NGINZ_HTTPS_HOST" 443)
    if cert_not_expired "$NGINZ_HTTPS_HOST" 443; then
        pass "4.1  nginz-https TLS certificate valid (expires in ~${days} days)"
    else
        fail "4.1  nginz-https TLS certificate valid" \
             "certificate has expired or could not be retrieved from ${NGINZ_HTTPS_HOST}"
    fi

    # 4.2  /status health check — must return exactly HTTP 200
    # This endpoint is unauthenticated and always returns 200 OK with an empty
    # body when nginz (and its upstream brig health check) is healthy.
    log "▶  4.2  nginz-https /status health check"
    T0=$(now_ms)
    status_code=$(curl -s --max-time 8 \
        -o /dev/null -w "%{http_code}" \
        "https://${NGINZ_HTTPS_HOST}/status" 2>/dev/null) || status_code="000"
    T1=$(now_ms)

    if [[ "$status_code" == "200" ]]; then
        pass "4.2  nginz-https /status → HTTP 200 OK  ($((T1 - T0)) ms)"
    else
        fail "4.2  nginz-https /status" \
             "HTTP ${status_code} (expected 200 — nginz or brig may be unhealthy)"
    fi

    # 4.3  /push/tokens gundeck route probe (unauthenticated)
    # A 401 with a Wire-format JSON body confirms:
    #   • nginz is routing /push/tokens to the gundeck upstream
    #   • libzauth is running and rejecting unauthenticated requests correctly
    # A 502 means the gundeck upstream is unreachable.
    # A 404 means the gundeck upstream route is absent from the nginz config.
    log "▶  4.3  nginz-https /push/tokens gundeck route probe (unauthenticated → expect 401)"
    push_body="$WORK/push_tokens_probe.json"
    push_code=$(curl -s --max-time 8 \
        -H "Accept: application/json" \
        -o "$push_body" -w "%{http_code}" \
        "https://${NGINZ_HTTPS_HOST}/push/tokens" 2>/dev/null) || push_code="000"
    push_resp=$(cat "$push_body" 2>/dev/null || echo "")

    if [[ "$push_code" == "401" ]]; then
        # Wire reurns {"code":401,"message":"...","label":"..."} on auth failure
        if body_contains "$push_resp" '"code"' || body_contains "$push_resp" "Unauthorized"; then
            pass "4.3  nginz-https /push/tokens → HTTP 401 Wire auth rejection (gundeck upstream reachable)"
        else
            pass "4.3  nginz-https /push/tokens → HTTP 401 (gundeck upstream reachable)"
        fi
    elif [[ "$push_code" == "403" ]]; then
        pass "4.3  nginz-https /push/tokens → HTTP 403 (gundeck upstream reachable, auth enforced)"
    elif [[ "$push_code" == "502" ]]; then
        fail "4.3  nginz-https /push/tokens → HTTP 502" \
             "nginz route exists but gundeck upstream is unreachable (pod down or not ready?)"
    elif [[ "$push_code" == "404" ]]; then
        fail "4.3  nginz-https /push/tokens → HTTP 404" \
             "route missing from nginz config — check nginx_conf.ignored_upstreams does not include gundeck"
    else
        fail "4.3  nginz-https /push/tokens" \
             "unexpected HTTP ${push_code} body='${push_resp:0:120}'"
    fi
fi

# ── §5  nginz-ssl — cannon WebSocket probe ────────────────────────────────────
# Cannon (Wire's WebSocket hub) is accessed via nginz-ssl.  Clients connect to
# wss://nginz-ssl.<domain>/await after authenticating.  In some deployments
# nginz-ssl shares the same LoadBalancer as nginz-https; in others it has a
# dedicated LB (see separate-websocket-traffic in infrastructure-configuration.md).
#
# We perform two protocol-level checks:
#   TCP connect — confirms basic network path
#   HTTP Upgrade handshake — sends a real WebSocket upgrade request and verifies
#     an HTTP response line is returned, proving a real HTTP server is present.
#     Without a valid Wire auth token we expect 101 (if pre-auth WS accepted),
#     401 (auth enforced by nginz/libzauth), or 400 (bad request but server alive).

if [[ "$DO_WS" -eq 1 ]]; then
    log "── §5 nginz-ssl (cannon WebSocket) ─────────────────────────────────────────"

    if [[ -z "$NGINZ_SSL_HOST" ]]; then
        warn "NGINZ_SSL_HOST is not set — set WIRE_DOMAIN or NGINZ_SSL_HOST to enable §5"
        for n in "5.1" "5.2" "5.3"; do skip "${n}  nginz-ssl (no host configured)"; done
    else
        # 5.1  TLS certificate validity
        log "▶  5.1  nginz-ssl TLS certificate (${NGINZ_SSL_HOST}:443)"
        days=$(cert_days_left "$NGINZ_SSL_HOST" 443)
        if cert_not_expired "$NGINZ_SSL_HOST" 443; then
            pass "5.1  nginz-ssl TLS certificate valid (expires in ~${days} days)"
        else
            fail "5.1  nginz-ssl TLS certificate valid" \
                 "certificate has expired or could not be retrieved from ${NGINZ_SSL_HOST}"
        fi

        # 5.2  TCP reachability
        log "▶  5.2  nginz-ssl TCP connect (${NGINZ_SSL_HOST}:443)"
        T0=$(now_ms)
        if timeout 6 socat -T5 - "TCP4:${NGINZ_SSL_HOST}:443" \
                </dev/null >/dev/null 2>&1; then
            T1=$(now_ms)
            pass "5.2  nginz-ssl TCP reachable  ($((T1 - T0)) ms)"
        else
            fail "5.2  nginz-ssl TCP reachable" \
                 "cannot open TCP connection to ${NGINZ_SSL_HOST}:443"
        fi

        # 5.3  WebSocket HTTP Upgrade handshake probe
        # curl handles TLS automatically; --http1.1 forces the HTTP/1.1 Upgrade
        # flow that WebSocket requires (HTTP/2 uses a different mechanism).
        # We check both the HTTP status code and for a Sec-WebSocket-Accept
        # header to confirm a full WS handshake is possible.
        log "▶  5.3  nginz-ssl WebSocket upgrade probe (wss://${NGINZ_SSL_HOST}/await)"
        ws_body="$WORK/ws_probe.txt"
        ws_hdrs_file="$WORK/ws_headers.txt"
        ws_code=$(curl -s --max-time 10 \
            --http1.1 \
            -H "Upgrade: websocket" \
            -H "Connection: Upgrade" \
            -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
            -H "Sec-WebSocket-Version: 13" \
            -o "$ws_body" \
            -w "%{http_code}" \
            -D "$ws_hdrs_file" \
            "https://${NGINZ_SSL_HOST}/await" 2>/dev/null) || ws_code="000"
        ws_hdrs=$(cat "$ws_hdrs_file" 2>/dev/null || echo "")

        if [[ "$ws_code" == "101" ]]; then
            if grep -qi "Sec-WebSocket-Accept" <<<"$ws_hdrs"; then
                pass "5.3  nginz-ssl WebSocket upgrade → HTTP 101 + Sec-WebSocket-Accept (full WS handshake)"
            else
                pass "5.3  nginz-ssl WebSocket upgrade → HTTP 101 Switching Protocols"
            fi
        elif [[ "$ws_code" =~ ^(400|401|403)$ ]]; then
            # Auth or request rejection — server is alive and handled the WS upgrade request.
            pass "5.3  nginz-ssl WebSocket upgrade → HTTP ${ws_code} (cannon upstream reachable, auth enforced)"
        elif [[ "$ws_code" == "502" ]]; then
            fail "5.3  nginz-ssl WebSocket upgrade → HTTP 502" \
                 "nginz route exists but cannon upstream is unreachable (pod down or being drained?)"
        elif [[ "$ws_code" == "000" ]]; then
            fail "5.3  nginz-ssl WebSocket upgrade" \
                 "no response (timeout or TLS handshake failure)"
        else
            fail "5.3  nginz-ssl WebSocket upgrade" \
                 "unexpected HTTP ${ws_code}"
        fi
    fi
else
    skip "5.1  nginz-ssl TLS certificate (--ws not enabled)"
    skip "5.2  nginz-ssl TCP reachable (--ws not enabled)"
    skip "5.3  nginz-ssl WebSocket upgrade probe (--ws not enabled)"
fi

# ── summary ───────────────────────────────────────────────────────────────────
echo
echo "════════════════════════════════════════"
printf "  \033[32m✓\033[0m  passed : %d\n"  "$PASS"
printf "  \033[31m✗\033[0m  failed : %d\n"  "$FAIL"
printf "  \033[90m–\033[0m  skipped: %d\n"  "$SKIP"
echo "════════════════════════════════════════"

if [[ "$FAIL" -gt 0 ]]; then
    echo
    echo "§4/§5 require WIRE_DOMAIN (or NGINZ_HTTPS_HOST / NGINZ_SSL_HOST) to be set."
fi

[[ "$FAIL" -eq 0 ]]
