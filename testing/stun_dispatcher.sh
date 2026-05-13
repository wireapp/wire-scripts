#!/usr/bin/env bash
# stun_dispatcher.sh — long-running STUN send/receive handler.
#
# Run as: socat "UDP4:REMOTE:PORT,bind=LOCAL:PORT" "EXEC:./stun_dispatcher.sh,nofork"
#
# With nofork, socat wires this script directly to the connected UDP socket:
#   stdin  — one complete datagram per socat read() from the network
#   stdout — each write() call becomes one UDP sendmsg() to the peer
#
# The script first sends our Binding Request (proactive check, controlling
# agent with USE-CANDIDATE), then enters a loop reading packets from stdin.
# STUN's own length field (bytes 2-3) is used to frame datagrams out of the
# byte-stream pipe, so no external framing is needed.
#
# Required env vars (exported by sft_call.sh):
#   LOCAL_ICE_UFRAG, LOCAL_ICE_PWD   — our ICE credentials
#   REMOTE_UFRAG, REMOTE_PWD         — SFT's ICE credentials
#   REMOTE_IP, REMOTE_PORT           — SFT's candidate address
#   WORK                             — temp dir for the ice_success flag
 
set -euo pipefail
 
log() { echo "[$(date -u +%T)] stun: $*" >&2; }
 
# ── read exactly N bytes from stdin as a lowercase hex string ─────────────────
# Uses dd with iflag=fullblock (GNU coreutils) which retries short reads until
# the full count is satisfied or EOF is reached.
 
read_hex() {
    dd bs="$1" count=1 iflag=fullblock 2>/dev/null | hexdump -v -e '1/1 "%02x"' | tr -d '\n'
}

hex2bin() { perl -e 'local $/; my $h = <STDIN>; $h =~ s/\s//g; print pack "H*", $h'; }
bin2hex() { perl -e 'local $/; $d=<STDIN>; print unpack("H*", $d)'; }
 
# ── build a STUN attribute block and append MESSAGE-INTEGRITY + FINGERPRINT ───
# Args: $1 = msg_type_hex (4 chars), $2 = txn_id_hex (24 chars),
#       $3 = attrs_hex (variable), $4 = hmac_key (text string)
# Writes the complete packet hex to stdout (as a string, not binary).
 
build_stun_packet() {
    local msg_type="$1" txn_id="$2" attrs="$3" hmac_key="$4"
    local attrs_bytes mi_total fp_total len_with_mi len_with_fp
    local msg_for_mi hmac mi_attr msg_pre_fp crc_le crc_be fp_val
 
    attrs_bytes=$(( ${#attrs} / 2 ))
    mi_total=24   # 4-byte header + 20-byte HMAC-SHA1 value
    fp_total=8    # 4-byte header + 4-byte CRC32 value
 
    # MESSAGE-INTEGRITY: HMAC input uses length that includes MI but not FP
    len_with_mi=$(( attrs_bytes + mi_total ))
    msg_for_mi="${msg_type}$(printf '%04x' $len_with_mi)2112a442${txn_id}${attrs}"

    hmac=$(printf '%s' "$msg_for_mi" | hex2bin \
        | openssl dgst -sha1 -hmac "$hmac_key" -binary \
        | bin2hex | tr -d '\n')
    mi_attr="00080014${hmac}"
    # FINGERPRINT: CRC32 of message up to (not including) FP, with FP in length
    len_with_fp=$(( attrs_bytes + mi_total + fp_total ))
    msg_pre_fp="${msg_type}$(printf '%04x' $len_with_fp)2112a442${txn_id}${attrs}${mi_attr}"
 
    # gzip embeds standard CRC32 (little-endian) in its last 8 bytes
    crc_le=$(printf '%s' "$msg_pre_fp" | hex2bin \
        | gzip -c | tail -c 8 | head -c 4 | hexdump -v -e '1/1 "%02x"' | tr -d '\n')
    crc_be="${crc_le:6:2}${crc_le:4:2}${crc_le:2:2}${crc_le:0:2}"
    fp_val=$(printf '%08x' $(( 16#$crc_be ^ 0x5354554e )))
 
    printf '%s' "${msg_pre_fp}80280004${fp_val}"
}
 
# ── 1. Send our Binding Request (controlling agent, USE-CANDIDATE) ─────────────
# Writing to stdout before reading stdin is safe: socat's pipe buffers the
# outbound datagram and sends it as soon as the socket is writable, while we
# then block on stdin awaiting the SFT's response and its own checks.

TXN=$(openssl rand -hex 12)

pad_hex() {
    local n="$1"
    [ "$n" -eq 0 ] && return
    printf '%*s' "$((n * 2))" '' | tr ' ' 0
}

USERNAME="${REMOTE_UFRAG}:${LOCAL_ICE_UFRAG}"
UN_HEX=$(printf '%s' "$USERNAME" | bin2hex | tr -d '\n')
UN_LEN=${#USERNAME}
UN_PAD=$(( (4 - (UN_LEN % 4)) % 4 ))
UN_ATTR="0006$(printf '%04x' $UN_LEN)${UN_HEX}$(pad_hex "$UN_PAD")"

PRIORITY_ATTR="002400040000d401"                       # standard host priority
ICE_ROLE_ATTR="80290008$(openssl rand -hex 8)"         # ICE-CONTROLED
 
ATTRS="${UN_ATTR}${PRIORITY_ATTR}${ICE_ROLE_ATTR}"
 
REQUEST_HEX=$(build_stun_packet "0001" "$TXN" "$ATTRS" "$REMOTE_PWD")
log "→ Binding Request      txn=${TXN}"
printf '%s' "$REQUEST_HEX" | hex2bin   # one write() = one UDP datagram
 
# ── 2. Packet read loop ────────────────────────────────────────────────────────
# STUN fixed header is always 20 bytes:
#   [0-1]  message type
#   [2-3]  attribute section length  ← used for framing
#   [4-7]  magic cookie (0x2112a442)
#   [8-19] transaction ID
# We read the header first, then read exactly that many more bytes for attributes.
 
# XOR-MAPPED-ADDRESS values are constant for this session: we always
# respond to the SFT with its own address (REMOTE_IP:REMOTE_PORT).
IFS='.' read -r -a octs <<< "$REMOTE_IP"
PEER_IP_HEX=$(printf '%02x%02x%02x%02x' "${octs[@]}")
PEER_XOR_PORT=$(printf '%04x' $(( REMOTE_PORT ^ 0x2112 )))
PEER_XOR_IP=$(  printf '%08x' $(( 16#$PEER_IP_HEX ^ 0x2112a442 )))
# type=0020  len=0008  reserved=00  family=01  xor_port  xor_ip
XMA="002000080001${PEER_XOR_PORT}${PEER_XOR_IP}"
 
while true; do
    # ── read fixed header ──────────────────────────────────────────────────────
    header_hex=$(read_hex 20)
    [ ${#header_hex} -eq 40 ] || { log "short header or EOF — exiting"; break; }
 
    msg_type="${header_hex:0:4}"
    attr_bytes=$(( 16#${header_hex:4:4} ))
    magic="${header_hex:8:8}"
    rxn_id="${header_hex:16:24}"
 
    # ── read attribute section ─────────────────────────────────────────────────
    if [ "$attr_bytes" -gt 0 ]; then
        attrs_hex=$(read_hex "$attr_bytes")
    else
        attrs_hex=""
    fi
 
    [ "$magic" = "2112a442" ] || { log "bad magic $magic — dropping"; continue; }
 
    # ── dispatch ───────────────────────────────────────────────────────────────
    case "$msg_type" in
 
      0001)  # Binding Request from SFT — send Success Response
        log "← Binding Request      txn=${rxn_id}"
        RESP_HEX=$(build_stun_packet "0101" "$rxn_id" "$XMA" "$LOCAL_ICE_PWD")
        log "→ Binding Success Resp txn=${rxn_id}"
        printf '%s' "$RESP_HEX" | xxd -r -p
	## This is the last packet we want to handle.
        touch "${WORK}/ice_success"
        ;;
 
      0101)  # Binding Success Response — our outbound check was acknowledged
        log "← Binding Success Resp txn=${rxn_id}  (matches our request: $([ "$rxn_id" = "$TXN" ] && echo yes || echo no))"
	if [ "$rxn_id" != "$TXN" ]; then
          log "ignoring success response for unknown transaction: $rxn_id"
	fi
        # Stay in the loop: the SFT may send more checks, and we should keep
        # responding so it maintains the nominated candidate pair.
        ;;
 
      0111)  # Binding Error Response
        err_code="${attrs_hex:0:16}"   # first attribute likely contains the error code
        log "← Binding Error Resp   txn=${rxn_id}  attrs=${err_code}..."
        ;;
 
      *)
        log "← unknown type=${msg_type}  txn=${rxn_id} — dropping"
        ;;
    esac
done
 
