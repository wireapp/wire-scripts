#!/usr/bin/env bash
# sft_call.sh — Wire SFT client: signaling + ICE via a single UDP socket.
#
# USAGE:
#   export SFT_URL="https://sft.example.com"
#   ./sft_call.sh
#
# ARCHITECTURE:
#   After SETUP, socat opens one connected UDP socket:
#     bind  → LOCAL_IP:LOCAL_UDP_PORT  (our declared candidate)
#     peer  → REMOTE_IP:REMOTE_PORT   (SFT's candidate from SDP answer)
#   stun_dispatcher.sh runs as the socat EXEC,nofork co-process.
#   Its stdin reads datagrams arriving from the SFT; its stdout writes
#   datagrams sent to the SFT.  Both directions share the same socket,
#   so every packet — responses to SFT's checks AND our own outbound
#   Binding Request — carries source port LOCAL_UDP_PORT.
#
# NOTE: accepts a conversation ID on the command line, which is not (yet) useful.
#
# NOTE: If socat is not available, will skip the UDP portion.
#
# MACOS: This supports MacOS, but requires jq to be installed.
# I installed this via:
# ```
# sudo mkdir -p /usr/local/bin
# curl -Lo /usr/local/bin/jq https://github.com/jqlang/jq/releases/latest/download/jq-macos-amd64
# chmod +x /usr/local/bin/jq
# ```
#
# DEPENDENCIES: curl, jq, uuidgen, openssl, gzip, (ip || ipconfig), dd
 
set -euo pipefail
 
SFT_URL="${SFT_URL:-https://sftd.wiab-dev-b.zinfradev.com}"
CONV_ID="${1:-$(uuidgen | tr '[:upper:]' '[:lower:]')}"
 
export WORK
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; kill "${SOCAT_PID:-}" 2>/dev/null || true' EXIT
 
# ── helpers ────────────────────────────────────────────────────────────────────

log() { echo "[$(date -u +%T)] $*" >&2; }
die() { echo "ERROR: $2" >&2; exit $1; }
now_ms() { perl -MTime::HiRes -e 'printf "%.3f\n", Time::HiRes::time()' | tr -d '.'; }
http_post_json_timed() {
    local name="$1"
    local url="$2"
    local json="$3"
    local diecode="$4"

    local body_file headers_file meta_file curl_rc http_code
    local time_namelookup time_connect time_appconnect time_pretransfer
    local time_starttransfer time_total effective_url

    body_file="$WORK/${name}.body"
    headers_file="$WORK/${name}.headers"
    meta_file="$WORK/${name}.meta"

    log "$name → $json → $url"

    set +e
    curl -sS -L --max-time 30 \
        -H "Content-Type: application/json" \
        -D "$headers_file" \
        -o "$body_file" \
        -w $'http_code=%{http_code}\nurl_effective=%{url_effective}\ntime_namelookup=%{time_namelookup}\ntime_connect=%{time_connect}\n \
             time_appconnect=%{time_appconnect}\ntime_pretransfer=%{time_pretransfer}\ntime_starttransfer=%{time_starttransfer}\ntime_total=%{time_total}\n' \
        -d "$json" \
        "$url" > "$meta_file"
    curl_rc=$?
    set -e

    http_code=$(awk -F= '/^http_code=/{print $2}' "$meta_file")
    effective_url=$(awk -F= '/^url_effective=/{print $2}' "$meta_file")
    time_namelookup=$(awk -F= '/^time_namelookup=/{print $2}' "$meta_file")
    time_connect=$(awk -F= '/^time_connect=/{print $2}' "$meta_file")
    time_appconnect=$(awk -F= '/^time_appconnect=/{print $2}' "$meta_file")
    time_pretransfer=$(awk -F= '/^time_pretransfer=/{print $2}' "$meta_file")
    time_starttransfer=$(awk -F= '/^time_starttransfer=/{print $2}' "$meta_file")
    time_total=$(awk -F= '/^time_total=/{print $2}' "$meta_file")

    log "$name HTTP=$http_code curl_rc=$curl_rc total=${time_total}s ttfb=${time_starttransfer}s url=$effective_url"
    log "$name timing: total=${time_total}s dns=${time_namelookup}s tcp=${time_connect}s tls=${time_appconnect}s pretransfer=${time_pretransfer}s"

    if [ "$curl_rc" -ne 0 ] || [ "${http_code:-0}" -lt 200 ] || [ "${http_code:-0}" -ge 300 ]; then
        log "$name failed response headers:"
        sed 's/^/  /' "$headers_file" >&2 || true

        log "$name failed response body:"
        if jq . "$body_file" >&2 2>/dev/null; then
            :
        else
            sed 's/^/  /' "$body_file" >&2 || true
        fi

        die $diecode "$name failed: curl_rc=$curl_rc http_code=$http_code total=${time_total}s"
    fi

    cat "$body_file"
}

# ── dependency checks ──────────────────────────────────────────────────────────

# Generic dependencies.
for cmd in curl jq uuidgen openssl xxd gzip dd; do
    command -v "$cmd" &>/dev/null || die -1 "'$cmd' required but not found."
done

# things we can work around.
if command -v "ip" &>/dev/null || command -v "ipconfig" &>/dev/null ; then
    log 'deps ok (ip or ipconfig available)'
else
    die -1 "neither IP or IPCONFIG is available."
fi

log "deps ok  curl=$(curl -V | awk 'NR==1{print $2}')"

# ── ICE credentials ────────────────────────────────────────────────────────────
 
export LOCAL_ICE_UFRAG LOCAL_ICE_PWD
LOCAL_ICE_UFRAG=$(openssl rand -hex 4)
LOCAL_ICE_PWD=$( openssl rand -hex 12)
 
# ── DTLS certificate fingerprint ───────────────────────────────────────────────

openssl req -newkey rsa:2048 -nodes -x509 -days 1 \
    -out "$WORK/dtls.pem" -keyout "$WORK/dtls.key" \
    -subj "/CN=sft-client" 2>/dev/null
FINGERPRINT=$(openssl x509 -in "$WORK/dtls.pem" -fingerprint -sha256 -noout \
    | sed 's/.*=//' | tr '[:upper:]' '[:lower:]')

# ── local address ──────────────────────────────────────────────────────────────

export LOCAL_IP LOCAL_UDP_PORT
# tries IP first, from linux, thes falls back to ipconfig for MacOS.
LOCAL_IP=$(
  if command -v ip >/dev/null 2>&1; then
    ip -4 addr show $(ip route show default | awk '/default/ {print $5; exit}') | awk '/inet /{print $2}' | cut -d/ -f1
  else
    ipconfig getifaddr "$(route get 1 | awk '/interface:/ {print $2}')"
  fi
)

# Random high‑port (49152–65535) without shuf
LOCAL_UDP_PORT=$(( (0x$(openssl rand -hex 2) % (65535-49152+1)) + 49152 ))
 
# ── step 1: CONFCONN ───────────────────────────────────────────────────────────
 
USER_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
# NOTE: webapp's SFT uses '_' here.
CLIENT_ID=$(openssl rand -hex 8)
SESSION_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')

## Note: src_userid and src_clientid must not be quoted.
CONFCONN_JSON=$(jq -cn \
        --arg sessid       "$SESSION_ID" \
        --arg src_userid   "$USER_ID" \
        --arg src_clientid "$CLIENT_ID" \
        '{"version":"3.0","type":"CONFCONN", "sessid":$sessid,
          "src_userid":$src_userid, "src_clientid":$src_clientid,
          "resp":false,
          "toolver":"0.0.0", "selective_audio":false, "selective_video":false}')
 
CONFCONN_RESP=$(http_post_json_timed "CONFCONN" "${SFT_URL%/}/sft/${CONV_ID}" "$CONFCONN_JSON" -3)

REMOTE_SFT=$(echo "$CONFCONN_RESP" | jq -r '.url // empty')
[ -n "$REMOTE_SFT" ] || die -4 "No SFT in CONFCONN response."
log "found remote SFT server: $REMOTE_SFT"

# ── step 2: SETUP ──────────────────────────────────────────────────────────────
 
SSRC=$(openssl rand -hex 8)
CNAME=$(openssl rand -hex 8)
 
SDP="v=0
o=- $(date +%s) 2 IN IP4 $LOCAL_IP
s=-
t=0 0
a=group:BUNDLE audio video data
m=audio $LOCAL_UDP_PORT UDP/TLS/RTP/SAVPF 111
c=IN IP4 $LOCAL_IP
a=rtpmap:111 opus/48000/2
a=sendrecv
a=rtcp-mux
a=ice-ufrag:$LOCAL_ICE_UFRAG
a=ice-pwd:$LOCAL_ICE_PWD
a=fingerprint:sha-256 $FINGERPRINT
a=setup:active
a=mid:audio
a=candidate:1 1 udp 2122260223 $LOCAL_IP $LOCAL_UDP_PORT typ host
m=video 0 UDP/TLS/RTP/SAVPF 100
c=IN IP4 0.0.0.0
a=mid:video
m=application 0 DTLS/SCTP 5000
c=IN IP4 0.0.0.0
a=mid:data
"

SETUP_JSON=$(jq -cn \
        --arg sessid       "$SESSION_ID" \
        --arg src_userid   "$USER_ID" \
        --arg src_clientid "$CLIENT_ID" \
        --arg sdp          "$SDP" \
        '{"version":"3.0",type:"SETUP", "sessid":$sessid,
          "src_userid":$src_userid, "src_clientid":$src_clientid,
          "resp":true,
          "sdp":$sdp, "props":{"videosend":"false","screensend":"false","audiocbr":"false","muted":"true"}}')

# Test form: constructs the URL using the original URL, not the returned one. works on WIAB, unreliable in prod?
# SETUP_RESP=$(http_post_json_timed "SETUP" "${SFT_URL%/}/sft/${CONV_ID}" "$SETUP_JSON" -5)

# Real form: take the URL handed to us, and use it properly.
SETUP_RESP=$(http_post_json_timed "SETUP" "${REMOTE_SFT}/sft/${CONV_ID}" "$SETUP_JSON" -5)
 
# ── parse remote ICE from SDP answer ──────────────────────────────────────────
 
REMOTE_SDP=$(echo "$CONFCONN_RESP" | jq -r '.sdp // .sdp_msg // empty')
[ -n "$REMOTE_SDP" ] || die -6 "No SDP in SETUP response."

export REMOTE_UFRAG REMOTE_PWD REMOTE_IP REMOTE_PORT
REMOTE_UFRAG=$(echo "$REMOTE_SDP" | awk -F: '/^a=ice-ufrag:/{print $2; exit}' | tr -d '[:space:]')
REMOTE_PWD=$(  echo "$REMOTE_SDP" | awk -F: '/^a=ice-pwd:/{print $2;   exit}' | tr -d '[:space:]')
read -r REMOTE_IP REMOTE_PORT < <(echo "$REMOTE_SDP" \
    | awk '/^a=candidate:/{print $5, $6; exit}')

[ -n "$REMOTE_IP"    ] || die -7 "No candidate in SDP answer."
[ -n "$REMOTE_UFRAG" ] || die -8 "No ice-ufrag in SDP answer."
log "Remote ICE: ufrag=$REMOTE_UFRAG  $REMOTE_IP:$REMOTE_PORT"

# skip the rest of this file if we do not have socat.
if command -v "socat" &>/dev/null; then

DISPATCHER="$(cd "$(dirname "$0")" && pwd)/stun_dispatcher.sh"

log "deps ok  socat=$(socat -V 2>&1 | awk '/socat version/{print $3}')"
[ -x "$DISPATCHER" ] || die -2 "stun_dispatcher.sh not found or not executable at: $DISPATCHER"

# ── step 3: single connected UDP socket + dispatcher ──────────────────────────
#
# UDP4:REMOTE_IP:REMOTE_PORT  — connect() to the SFT's candidate.
#   bind=LOCAL_IP:LOCAL_UDP_PORT — source address matches our SDP candidate.
#
# With connect() in effect the kernel only delivers datagrams FROM the SFT's
# candidate to this socket, and all writes go TO that candidate.
#
# EXEC:stun_dispatcher.sh,nofork — dispatcher replaces socat's I/O loop with:
#   stdin  ← datagrams received from SFT  (one datagram per socat read)
#   stdout → datagrams sent to SFT        (one datagram per write call)
#
# The dispatcher sends our Binding Request immediately on startup (before
# blocking on stdin), then processes whatever arrives.

log "Opening UDP $LOCAL_IP:$LOCAL_UDP_PORT → $REMOTE_IP:$REMOTE_PORT"

ICE_START_MS=$(now_ms)

socat \
    "UDP4:${REMOTE_IP}:${REMOTE_PORT},bind=${LOCAL_IP}:${LOCAL_UDP_PORT},reuseaddr" \
    "EXEC:${DISPATCHER},nofork" &
SOCAT_PID=$!

log "Waiting for ICE success (up to 30 s)..."

ICE_OK=0
for _ in $(seq 1 300); do
    sleep 0.1
    if [ -f "$WORK/ice_success" ]; then
        ICE_END_MS=$(now_ms)
        ICE_MS=$((ICE_END_MS - ICE_START_MS))
        printf '\033[32m✓\033[0m %s'
	echo " ICE connectivity confirmed in ${ICE_MS} ms."
        ICE_OK=1
        break
    fi
done

if [ "$ICE_OK" -ne 1 ]; then
    ICE_END_MS=$(now_ms)
    ICE_MS=$((ICE_END_MS - ICE_START_MS))
    log "Terminating UDP Listener..."
    kill "$SOCAT_PID"
    die -9 "ICE did not complete within ${ICE_MS} ms."
fi
log "Terminating UDP Listener..."
kill "$SOCAT_PID"

else
    log 'socat binary not found; UDP tests were not performed.'
fi
