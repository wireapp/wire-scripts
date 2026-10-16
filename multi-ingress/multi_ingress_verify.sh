#!/usr/bin/env bash
set -euo pipefail

WIRE_VALUES=""
MAIN_DOMAIN=""
NGINX_VALUES=""
NAMESPACE="default"
CHECK_NGINX=false
CREATE_NGINX_VALUES=false
WRITE_WIRE_SERVER=false
DEBUG=false
MULTI_DOMAIN=""

need() { command -v "$1" >/dev/null || { echo "ERROR: missing dependency: $1"; exit 2; }; }
ok() { echo "OK: $*"; }
wire_ok() {
  if [[ "$DEBUG" == true ]]; then
    ok "$@"
  fi
}
fail() { echo "MISSING/WRONG: $*"; FAILED=$((FAILED + 1)); }
usage_error() { echo "ERROR: $*" >&2; exit 2; }

require_value() {
  [[ -n "${2-}" && "${2-}" != -* ]] \
    || usage_error "$1 requires a nonempty value, not another option"
}

set_multi_domain() {
  require_value '--multi-domain (-d)' "${1-}"
  [[ -z "$MULTI_DOMAIN" ]] || usage_error "only one multi-ingress domain is allowed per invocation"
  MULTI_DOMAIN="$1"
}

usage() {
  cat <<EOF
Usage:
  $0 --wire-server-values FILE --main-domain DOMAIN --multi-domain DOMAIN [--write] [--debug]

Wire values are checked on every invocation. Exactly one multi-ingress domain
is accepted: pass --multi-domain (-d) once, or supply one positional domain.
Repeated domain arguments are rejected, even if they name the same domain.
Omit both nginx action flags to check only Wire values for the main domain and
the selected multi-ingress domain. No nginx values file is needed in this mode.
Wire field diagnostics show only missing or wrong values by default, with the
affected path and required value. Add --debug to also display passing OK checks,
including checks performed before and after writes.

Optional Wire values update:
  --write, --write-wire-server (aliases)
Fill absent keys and missing list entries for the selected multi-ingress domain
using yq. Existing list entries are preserved. Wire checks run before each write
and after the last write. Any wrong value stops writing and requires a manual
administrator fix. Existing empty strings, explicit nulls in required fields,
and wrong data types are not treated as absent. Main-domain settings are checked
but never written; missing main-domain settings also require a manual fix.
Checks with repairable missing values print a command to rerun with --write.

Optional nginx-ingress-services action (choose at most one):
  --check-nginx --nginx-values FILE [--namespace NS]
  --create-nginx-values --nginx-values FILE

--check-nginx and --create-nginx-values are mutually exclusive.
Wire checks and both nginx actions use the same --multi-domain.
Checking validates an existing nginx file and checks the main Kubernetes ingress.
Creation only writes a missing nginx file; it does not check nginx or Kubernetes.
Existing nginx files are never overwritten. All modes require the Wire options above.

Examples:
  $0 -f values/wire-server/values.yaml -m green.example.org -d red.example.com
  $0 -f values/wire-server/values.yaml -m green.example.org -d red.example.com --debug
  $0 -f values/wire-server/values.yaml -m green.example.org -d red.example.com --write
  $0 -f values/wire-server/values.yaml -m green.example.org -d red.example.com --check-nginx --nginx-values red-values.yaml
  $0 -f values/wire-server/values.yaml -m green.example.org -d red.example.com --create-nginx-values --nginx-values red-values.yaml

Check only Wire values for multiple domains, one domain per invocation:
  printf '%s\n' 'red.example.com' 'blue.example.net' | \\
    xargs -n 1 bash "$0" -f values/wire-server/values.yaml -m green.example.org -d
To fill missing Wire values as well, insert --write before -d.
To also display passing Wire checks, insert --debug before -d.

To also check nginx, use xargs to run once per domain/values-file pair.
Each invocation still handles only one multi-ingress domain (xargs -n 2 passes
the domain and its values file together):
  printf '%s\n' 'red.example.com red-values.yaml' 'blue.example.net blue-values.yaml' | \\
    xargs -n 2 bash -c 'bash "\$0" -f values/wire-server/values.yaml -m green.example.org \\
      -d "\$1" --check-nginx --nginx-values "\$2"' "$0"
Replace --check-nginx with --create-nginx-values to create each missing file.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--wire-server-values) require_value '--wire-server-values (-f)' "${2-}"; WIRE_VALUES="$2"; shift 2 ;;
    -m|--main-domain) require_value '--main-domain (-m)' "${2-}"; MAIN_DOMAIN="$2"; shift 2 ;;
    -d|--multi-domain) set_multi_domain "${2-}"; shift 2 ;;
    --check-nginx) CHECK_NGINX=true; shift ;;
    --nginx-values) require_value "$1" "${2-}"; NGINX_VALUES="$2"; shift 2 ;;
    --create-nginx-values) CREATE_NGINX_VALUES=true; shift ;;
    --write|--write-wire-server) WRITE_WIRE_SERVER=true; shift ;;
    --debug) DEBUG=true; shift ;;
    -n|--namespace) require_value '--namespace (-n)' "${2-}"; NAMESPACE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) usage_error "unknown option: $1" ;;
    *) set_multi_domain "$1"; shift ;;
  esac
done

if [[ "$CHECK_NGINX" == true && "$CREATE_NGINX_VALUES" == true ]]; then
  usage_error "--check-nginx and --create-nginx-values are mutually exclusive"
fi

if [[ "$CHECK_NGINX" == false && "$CREATE_NGINX_VALUES" == false && -n "$NGINX_VALUES" ]]; then
  usage_error "--nginx-values requires --check-nginx or --create-nginx-values"
fi

# Every action requires Wire inputs and exactly one additional ingress domain.
[[ -f "$WIRE_VALUES" ]] || usage_error "wire-server values file not found: $WIRE_VALUES"
[[ -n "$MAIN_DOMAIN" ]] || usage_error "--main-domain is required"
[[ -n "$MULTI_DOMAIN" ]] || usage_error "pass exactly one --multi-domain"

if [[ "$CHECK_NGINX" == true || "$CREATE_NGINX_VALUES" == true ]]; then
  [[ -n "$NGINX_VALUES" ]] || usage_error "nginx actions require --nginx-values"
fi

need yq
FAILED=0

yaml_get() {
  yq -r "$1 // \"\"" "$2"
}

print_wire_write_hint() {
  if [[ ${#WIRE_PENDING_PATHS[@]} -eq 0 ]]; then
    return
  fi

  echo
  if [[ "$WIRE_WRONG" -gt 0 || "$WIRE_BLOCKED" -gt 0 ]]; then
    echo "Fix the reported manual issues first; --write will stop until they are resolved."
  fi
  echo "To fill only missing Wire values while preserving existing entries, rerun with --write (alias: --write-wire-server):"
  printf '  bash %q --wire-server-values %q --main-domain %q --multi-domain %q --write\n' \
    "$0" "$WIRE_VALUES" "$MAIN_DOMAIN" "$MULTI_DOMAIN"
}

# Key encodings can be reused; node types are reread on every Wire check.
WIRE_KEYS=()
WIRE_KEY_JSON=()

wire_wrong() {
  echo "WRONG: $*; administrator must fix this manually."
  WIRE_WRONG=$((WIRE_WRONG + 1))
}

wire_quote_key() {
  local key="$1" i
  for i in "${!WIRE_KEYS[@]}"; do
    if [[ "${WIRE_KEYS[$i]}" == "$key" ]]; then
      WIRE_QUOTED_KEY="${WIRE_KEY_JSON[$i]}"
      return
    fi
  done
  if ! WIRE_QUOTED_KEY="$(WIRE_KEY="$key" yq -n -o=json -I=0 'strenv(WIRE_KEY)')"; then
    wire_wrong "cannot encode a Wire YAML key"
    return 1
  fi
  WIRE_KEYS+=("$key")
  WIRE_KEY_JSON+=("$WIRE_QUOTED_KEY")
}

# Inspect each ancestor before the leaf. has() distinguishes an absent key from
# an existing null; no scalar, null or list may be replaced with a mapping.
wire_inspect_path() {
  local key parent i cached key_exists
  WIRE_PATH='.'
  WIRE_NODE_TYPE='!!map'
  for key in "$@"; do
    if ! wire_quote_key "$key"; then
      WIRE_NODE_TYPE=error
      return
    fi
    parent="$WIRE_PATH"
    WIRE_PATH+="[$WIRE_QUOTED_KEY]"
    if [[ "$WIRE_NODE_TYPE" == missing ]]; then
      continue
    fi
    if [[ "$WIRE_NODE_TYPE" != '!!map' ]]; then
      wire_wrong "$parent must be a mapping, found $WIRE_NODE_TYPE"
      WIRE_NODE_TYPE=error
      return
    fi

    cached=false
    for i in "${!WIRE_NODE_PATHS[@]}"; do
      if [[ "${WIRE_NODE_PATHS[$i]}" == "$WIRE_PATH" ]]; then
        WIRE_NODE_TYPE="${WIRE_NODE_TYPES[$i]}"
        cached=true
        break
      fi
    done
    if [[ "$cached" == false ]]; then
      # Keep existence and type queries separate: the former combined select
      # expression could emit both a tag and "missing" for one existing key.
      if ! key_exists="$(yq -r "$parent | has($WIRE_QUOTED_KEY)" "$WIRE_VALUES")"; then
        wire_wrong "cannot check whether $WIRE_PATH exists"
        WIRE_NODE_TYPE=error
        return
      fi
      case "$key_exists" in
        false) WIRE_NODE_TYPE=missing ;;
        true)
          if ! WIRE_NODE_TYPE="$(yq -r "$WIRE_PATH | tag" "$WIRE_VALUES")"; then
            wire_wrong "cannot read the type of $WIRE_PATH"
            WIRE_NODE_TYPE=error
            return
          fi
          if [[ -z "$WIRE_NODE_TYPE" || "$WIRE_NODE_TYPE" == *$'\n'* ]]; then
            wire_wrong "expected one YAML type for $WIRE_PATH"
            WIRE_NODE_TYPE=error
            return
          fi
          ;;
        *)
          wire_wrong "expected one true/false existence result for $WIRE_PATH"
          WIRE_NODE_TYPE=error
          return
          ;;
      esac
      WIRE_NODE_PATHS+=("$WIRE_PATH")
      WIRE_NODE_TYPES+=("$WIRE_NODE_TYPE")
    fi
  done
}

wire_missing() {
  local kind="$1" repair="$2" expected="$3"
  if [[ "$kind" == list ]]; then
    echo "MISSING: add $expected to list $WIRE_PATH; preserve existing entries."
  else
    echo "MISSING: add $WIRE_PATH = $expected"
  fi
  WIRE_MISSING=$((WIRE_MISSING + 1))
  if [[ "$repair" == true ]]; then
    WIRE_PENDING_PATHS+=("$WIRE_PATH")
    WIRE_PENDING_KINDS+=("$kind")
    WIRE_PENDING_VALUES+=("$expected")
  else
    echo "MANUAL: main-domain setting $WIRE_PATH must be supplied by the administrator."
    WIRE_BLOCKED=$((WIRE_BLOCKED + 1))
  fi
}

# The checker and writer share this specification. Only fields marked repairable
# become pending additions, and a present-but-wrong value never becomes pending.
wire_check_field() {
  local kind="$1" repair="$2" expected="$3" actual expected_json invalid members member found=false
  shift 3
  wire_inspect_path "$@"
  [[ "$WIRE_NODE_TYPE" != error ]] || return 0

  if [[ "$kind" == absent ]]; then
    if [[ "$WIRE_NODE_TYPE" == missing || "$WIRE_NODE_TYPE" == '!!null' ]]; then
      wire_ok "$WIRE_PATH is null or unset"
    else
      wire_wrong "remove $WIRE_PATH or set it to null; it conflicts with multiIngress"
    fi
    return
  fi

  if [[ "$WIRE_NODE_TYPE" == missing ]]; then
    wire_missing "$kind" "$repair" "$expected"
    return
  fi

  if [[ "$kind" == scalar ]]; then
    if [[ "$WIRE_NODE_TYPE" != '!!str' ]]; then
      wire_wrong "$WIRE_PATH must be the string $expected, found $WIRE_NODE_TYPE"
      return
    fi
    # Compare JSON strings so even trailing newlines remain significant.
    if ! actual="$(yq -o=json -I=0 "$WIRE_PATH" "$WIRE_VALUES")" \
      || ! expected_json="$(WIRE_EXPECTED="$expected" yq -n -o=json -I=0 'strenv(WIRE_EXPECTED)')"; then
      wire_wrong "cannot compare $WIRE_PATH with its expected value"
      return
    fi
    if [[ "$actual" == "$expected_json" ]]; then
      wire_ok "$WIRE_PATH = $expected"
    else
      wire_wrong "$WIRE_PATH expected $expected, found ${actual:0:160}"
    fi
    return
  fi

  if [[ "$WIRE_NODE_TYPE" != '!!seq' ]]; then
    wire_wrong "$WIRE_PATH must be a list, found $WIRE_NODE_TYPE"
    return
  fi
  if ! invalid="$(yq -r "[${WIRE_PATH}[] | select((tag != \"!!str\") or (. == \"\"))] | length" "$WIRE_VALUES")"; then
    wire_wrong "cannot inspect entries in $WIRE_PATH"
    return
  fi
  if [[ "$invalid" != 0 ]]; then
    wire_wrong "$WIRE_PATH contains non-string or empty entries"
    return
  fi
  # Read each entry as a JSON string and compare literally in Bash. This retains
  # embedded whitespace and avoids wildcard matching in yq string comparisons.
  if ! members="$(yq -o=json -I=0 "${WIRE_PATH}[]" "$WIRE_VALUES")" \
    || ! expected_json="$(WIRE_EXPECTED="$expected" yq -n -o=json -I=0 'strenv(WIRE_EXPECTED)')"; then
    wire_wrong "cannot read list membership in $WIRE_PATH"
    return
  fi
  while IFS= read -r member; do
    if [[ "$member" == "$expected_json" ]]; then
      found=true
      break
    fi
  done <<< "$members"
  if [[ "$found" == true ]]; then
    wire_ok "$WIRE_PATH contains $expected"
  else
    wire_missing list "$repair" "$expected"
  fi
}

check_wire_server() {
  local d="$MULTI_DOMAIN" root_type
  WIRE_MISSING=0
  WIRE_WRONG=0
  WIRE_BLOCKED=0
  WIRE_PENDING_PATHS=()
  WIRE_PENDING_KINDS=()
  WIRE_PENDING_VALUES=()
  WIRE_NODE_PATHS=()
  WIRE_NODE_TYPES=()

  echo "Checking Wire values: $WIRE_VALUES (main: $MAIN_DOMAIN, multi-ingress: $d)"
  if ! root_type="$(yq -r 'tag' "$WIRE_VALUES")"; then
    wire_wrong "cannot parse Wire values file $WIRE_VALUES"
    return
  fi
  if [[ "$root_type" != '!!map' ]]; then
    wire_wrong "Wire values must contain exactly one YAML mapping document"
    return
  fi

  wire_check_field scalar false "$MAIN_DOMAIN" nginz nginx_conf external_env_domain
  wire_check_field absent false '' cargohold config aws s3DownloadEndpoint
  wire_check_field absent false '' galley config settings conversationCodeURI

  wire_check_field list true "$d" nginz nginx_conf additional_external_env_domains
  wire_check_field list true "$d" cannon nginx_conf additional_external_env_domains
  wire_check_field scalar true "https://account.${d}/conversation-join/" galley config settings multiIngress "$d"
  wire_check_field scalar true "https://assets.${d}" cargohold config aws multiIngress "nginz-https.${d}"
  wire_check_field scalar true "https://nginz-https.${d}" nginz nginx_conf multi_ingress_deeplink "$d" endpoints backendURL
  wire_check_field scalar true "https://nginz-ssl.${d}" nginz nginx_conf multi_ingress_deeplink "$d" endpoints backendWSURL
  wire_check_field scalar true "https://teams.${d}" nginz nginx_conf multi_ingress_deeplink "$d" endpoints teamsURL
  wire_check_field scalar true "https://account.${d}" nginz nginx_conf multi_ingress_deeplink "$d" endpoints accountsURL
  wire_check_field scalar true "https://${d}" nginz nginx_conf multi_ingress_deeplink "$d" endpoints websiteURL

}

write_wire_server() {
  local path kind value previous_path='' additions=0 expression
  while true; do
    # Reread every checked field before each individual write. The iteration
    # after the final addition is also the required post-write verification.
    check_wire_server
    if [[ "$WIRE_WRONG" -gt 0 || "$WIRE_BLOCKED" -gt 0 ]]; then
      echo "ERROR: stopped --write-wire-server; fix the reported settings manually before retrying."
      return 1
    fi
    if [[ "$WIRE_MISSING" -eq 0 ]]; then
      echo "Wire values verified for $MULTI_DOMAIN after $additions addition(s)"
      return 0
    fi
    if [[ ${#WIRE_PENDING_PATHS[@]} -eq 0 ]]; then
      echo "ERROR: missing Wire settings cannot be filled automatically."
      return 1
    fi

    path="${WIRE_PENDING_PATHS[0]}"
    kind="${WIRE_PENDING_KINDS[0]}"
    value="${WIRE_PENDING_VALUES[0]}"
    if [[ "$path" == "$previous_path" ]]; then
      echo "ERROR: the previous write did not resolve $path; stopped without further writes."
      return 1
    fi
    if [[ "$kind" == list ]]; then
      # yq reads the current list and appends; other domains and their order stay.
      expression="$path += [strenv(WIRE_ADDITION)]"
      echo "ADDING: $value to list $path in $WIRE_VALUES"
    else
      expression="$path = strenv(WIRE_ADDITION)"
      echo "ADDING: $path = $value in $WIRE_VALUES"
    fi
    if ! WIRE_ADDITION="$value" yq -i "$expression" "$WIRE_VALUES"; then
      echo "ERROR: yq could not write $path; stopped without further writes."
      return 1
    fi
    previous_path="$path"
    additions=$((additions + 1))
  done
}

slug() {
  echo "$1" | sed 's/\..*$//' | tr -cd '[:alnum:]-' | tr '[:upper:]' '[:lower:]'
}

check_main_nginx_exists() {
  need kubectl

  echo "Checking Kubernetes ingress for main domain: $MAIN_DOMAIN"

  if kubectl get ingress -A -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{" "}{range .spec.rules[*]}{.host}{" "}{end}{"\n"}{end}' \
    | grep -F "$MAIN_DOMAIN" >/dev/null; then
    ok "main nginx-ingress-services ingress appears to exist for $MAIN_DOMAIN"
  else
    fail "main nginx-ingress-services ingress not found for $MAIN_DOMAIN"
    cat <<EOF

Deploy the main nginx-ingress-services chart first, then re-run this script, for example:

helm upgrade --install nginx-ingress-services charts/nginx-ingress-services \\
  -n ${NAMESPACE} \\
  -f values/nginx-ingress-services/values.yaml \\
  --set-file secrets.tlsWildcardCert=values/nginx-ingress-services/cert.pem \\
  --set-file secrets.tlsWildcardKey=values/nginx-ingress-services/key.pem

EOF
    exit 1
  fi
}

create_nginx_values() {
  local d="$1" file="$2" s
  if [[ -e "$file" || -L "$file" ]]; then
    fail "refusing to overwrite existing nginx values path: $file; use --check-nginx to validate an existing file"
    return
  fi
  s="$(slug "$d")"

  mkdir -p "$(dirname "$file")"

  cat > "$file" <<EOF
ingressName: ${s}
nameOverride: nginx-multi-ingress-${s}

teamSettings:
  enabled: true

accountPages:
  enabled: true

tls:
  enabled: true
  useCertManager: false

config:
  dns:
    base: ${d}
    https: nginz-https.${d}
    ssl: nginz-ssl.${d}
    webapp: webapp.${d}
    fakeS3: assets.${d}
    teamSettings: teams.${d}
    accountPages: account.${d}
  renderCSPInIngress: true
  isAdditionalIngress: true

service:
  useFakeS3: true
  s3:
    externalPort: 9000
    serviceName: minio-external
EOF

  ok "created $file"
}

check_nginx_values() {
  check_main_nginx_exists

  echo "Checking $MULTI_DOMAIN at ${NGINX_VALUES}:"

  if [[ ! -f "$NGINX_VALUES" ]]; then
    fail "nginx values file does not exist: $NGINX_VALUES"
    echo "Use --create-nginx-values instead of --check-nginx to create it."
    return
  fi

  local s
  s="$(slug "$MULTI_DOMAIN")"

  [[ "$(yaml_get '.ingressName' "$NGINX_VALUES")" ]] \
    && ok "ingressName" \
    || fail "set ingressName: someName"

  [[ "$(yaml_get '.nameOverride' "$NGINX_VALUES")" ]] \
    && ok "nameOverride" \
    || fail "set nameOverride: someNameOverride"

  [[ "$(yaml_get '.config.dns.base' "$NGINX_VALUES")" == "$MULTI_DOMAIN" ]] \
    && ok "config.dns.base" \
    || fail "set config.dns.base: $MULTI_DOMAIN"

  [[ "$(yaml_get '.config.dns.https' "$NGINX_VALUES")" == "nginz-https.${MULTI_DOMAIN}" ]] \
    && ok "config.dns.https" \
    || fail "set config.dns.https: nginz-https.${MULTI_DOMAIN}"

  [[ "$(yaml_get '.config.dns.ssl' "$NGINX_VALUES")" == "nginz-ssl.${MULTI_DOMAIN}" ]] \
    && ok "config.dns.ssl" \
    || fail "set config.dns.ssl: nginz-ssl.${MULTI_DOMAIN}"

  [[ "$(yaml_get '.config.dns.webapp' "$NGINX_VALUES")" == "webapp.${MULTI_DOMAIN}" ]] \
    && ok "config.dns.webapp" \
    || fail "set config.dns.webapp: webapp.${MULTI_DOMAIN}"

  [[ "$(yaml_get '.config.dns.fakeS3' "$NGINX_VALUES")" == "assets.${MULTI_DOMAIN}" ]] \
    && ok "config.dns.fakeS3" \
    || fail "set config.dns.fakeS3: assets.${MULTI_DOMAIN}"

  [[ "$(yaml_get '.config.dns.teamSettings' "$NGINX_VALUES")" == "teams.${MULTI_DOMAIN}" ]] \
    && ok "config.dns.teamSettings" \
    || fail "set config.dns.teamSettings: teams.${MULTI_DOMAIN}"

  [[ "$(yaml_get '.config.dns.accountPages' "$NGINX_VALUES")" == "account.${MULTI_DOMAIN}" ]] \
    && ok "config.dns.accountPages" \
    || fail "set config.dns.accountPages: account.${MULTI_DOMAIN}"

  [[ "$(yaml_get '.config.isAdditionalIngress' "$NGINX_VALUES")" == "true" ]] \
    && ok "config.isAdditionalIngress" \
    || fail "set config.isAdditionalIngress: true"

  [[ "$(yaml_get '.config.renderCSPInIngress' "$NGINX_VALUES")" == "true" ]] \
    && ok "config.renderCSPInIngress" \
    || fail "set config.renderCSPInIngress: true"

  cat <<EOF

Deploy command for this domain:

helm upgrade --install nginx-ingress-services-${s} charts/nginx-ingress-services \\
  -n ${NAMESPACE} \\
  -f ${NGINX_VALUES} \\
  --set-file secrets.tlsWildcardCert=values/nginx-ingress-services/${s}-cert.pem \\
  --set-file secrets.tlsWildcardKey=values/nginx-ingress-services/${s}-key.pem
EOF
}

if [[ "$WRITE_WIRE_SERVER" == true ]]; then
  write_wire_server || exit 1
else
  check_wire_server
  print_wire_write_hint
fi
FAILED=$((FAILED + WIRE_MISSING + WIRE_WRONG))

if [[ "$CREATE_NGINX_VALUES" == true ]]; then
  create_nginx_values "$MULTI_DOMAIN" "$NGINX_VALUES"
elif [[ "$CHECK_NGINX" == true ]]; then
  check_nginx_values
fi

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "All checks passed."
else
  echo "Some checks failed. See diagnostics above."
  exit 1
fi
