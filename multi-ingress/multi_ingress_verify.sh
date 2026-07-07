#!/usr/bin/env bash
set -euo pipefail

WIRE_VALUES=""
MAIN_DOMAIN=""
NGINX_VALUES=""
NGINX_DOMAIN=""
NAMESPACE="default"
CHECK_NGINX=false
CREATE_NGINX_VALUES=false
MULTI_DOMAINS=()

need() { command -v "$1" >/dev/null || { echo "ERROR: missing dependency: $1"; exit 2; }; }
ok() { echo "OK: $*"; }
fail() { echo "MISSING/WRONG: $*"; FAILED=1; }

usage() {
  cat <<EOF
Usage:
  $0 --wire-server-values FILE --main-domain DOMAIN --multi-domain DOMAIN [--multi-domain DOMAIN...]

Optional nginx-ingress-services check/create:
  $0 --check-nginx --main-domain DOMAIN --nginx-domain DOMAIN --nginx-values FILE [--create-nginx-values] [--namespace NS]

Examples:
  $0 -f values/wire-server/values.yaml -m green.example.org -d red.example.com -d blue.example.net
  $0 --check-nginx -m green.example.org --nginx-domain red.example.com --nginx-values values/nginx-ingress-services/red-values.yaml --create-nginx-values
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -f|--wire-server-values) WIRE_VALUES="$2"; shift 2 ;;
    -m|--main-domain) MAIN_DOMAIN="$2"; shift 2 ;;
    -d|--multi-domain) MULTI_DOMAINS+=("$2"); shift 2 ;;
    --check-nginx) CHECK_NGINX=true; shift ;;
    --nginx-values) NGINX_VALUES="$2"; shift 2 ;;
    --nginx-domain) NGINX_DOMAIN="$2"; shift 2 ;;
    --create-nginx-values) CREATE_NGINX_VALUES=true; shift ;;
    -n|--namespace) NAMESPACE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) MULTI_DOMAINS+=("$1"); shift ;;
  esac
done

need yq
FAILED=0

yaml_get() {
  yq -r "$1 // \"\"" "$2"
}

yaml_has_list_value() {
  local expr="$1" value="$2" file="$3"
  yq -e "$expr[]? == \"$value\"" "$file" >/dev/null 2>&1
}

print_wire_snippet() {
  local d="$1"
  cat <<EOF

Add/check this for ${d} in wire-server values:

galley:
  config:
    multiIngress:
      ${d}: https://account.${d}/conversation-join/

cargohold:
  config:
    aws:
      multiIngress:
        nginz-https.${d}: https://assets.${d}
      # remove s3DownloadEndpoint for multi-ingress

cannon:
  nginx_conf:
    additional_external_env_domains:
      - ${d}

nginz:
  nginx_conf:
    additional_external_env_domains:
      - ${d}
    multi_ingress_deeplink:
      ${d}:
        endpoints:
          backendURL: "https://nginz-https.${d}"
          backendWSURL: "https://nginz-ssl.${d}"
          blackListURL: "https://clientblacklist.${d}/prod"
          teamsURL: "https://teams.${d}"
          accountsURL: "https://account.${d}"
          websiteURL: "https://${d}"
        title: "Production ${d}"
EOF
}

check_wire_server() {
  [[ -f "$WIRE_VALUES" ]] || { echo "ERROR: wire-server values file not found: $WIRE_VALUES"; exit 2; }
  [[ -n "$MAIN_DOMAIN" ]] || { echo "ERROR: --main-domain is required"; exit 2; }
  [[ ${#MULTI_DOMAINS[@]} -gt 0 ]] || { echo "ERROR: pass at least one --multi-domain"; exit 2; }

  echo "Checking main domain: $MAIN_DOMAIN"

  [[ "$(yaml_get '.nginz.nginx_conf.external_env_domain' "$WIRE_VALUES")" == "$MAIN_DOMAIN" ]] \
    && ok "nginz.nginx_conf.external_env_domain = $MAIN_DOMAIN" \
    || fail "set nginz.nginx_conf.external_env_domain: $MAIN_DOMAIN"

  [[ "$(yaml_get '.nginz.nginx_conf.deeplink.endpoints.backendURL' "$WIRE_VALUES")" == "https://nginz-https.${MAIN_DOMAIN}" ]] \
    && ok "main deeplink backendURL" \
    || fail "set nginz.nginx_conf.deeplink.endpoints.backendURL to https://nginz-https.${MAIN_DOMAIN}"

  [[ "$(yaml_get '.nginz.nginx_conf.deeplink.endpoints.backendWSURL' "$WIRE_VALUES")" == "https://nginz-ssl.${MAIN_DOMAIN}" ]] \
    && ok "main deeplink backendWSURL" \
    || fail "set nginz.nginx_conf.deeplink.endpoints.backendWSURL to https://nginz-ssl.${MAIN_DOMAIN}"

  if yq -e '.cargohold.config.aws.s3DownloadEndpoint? != null' "$WIRE_VALUES" >/dev/null 2>&1; then
    fail "remove cargohold.config.aws.s3DownloadEndpoint; use cargohold.config.aws.multiIngress instead"
  else
    ok "cargohold.config.aws.s3DownloadEndpoint absent"
  fi

  for d in "${MULTI_DOMAINS[@]}"; do
    echo
    echo "Checking multi-ingress domain: $d"

    domain_failed_before="$FAILED"

    yaml_has_list_value '.nginz.nginx_conf.additional_external_env_domains' "$d" "$WIRE_VALUES" \
      && ok "nginz additional_external_env_domains contains $d" \
      || fail "add $d to nginz.nginx_conf.additional_external_env_domains"

    yaml_has_list_value '.cannon.nginx_conf.additional_external_env_domains' "$d" "$WIRE_VALUES" \
      && ok "cannon additional_external_env_domains contains $d" \
      || fail "add $d to cannon.nginx_conf.additional_external_env_domains"

    [[ "$(yaml_get ".galley.config.multiIngress.\"$d\"" "$WIRE_VALUES")" == "https://account.${d}/conversation-join/" ]] \
      && ok "galley.config.multiIngress for $d" \
      || fail "add galley.config.multiIngress.\"$d\": https://account.${d}/conversation-join/"

    [[ "$(yaml_get ".cargohold.config.aws.multiIngress.\"nginz-https.${d}\"" "$WIRE_VALUES")" == "https://assets.${d}" ]] \
      && ok "cargohold multiIngress for $d" \
      || fail "add cargohold.config.aws.multiIngress.\"nginz-https.${d}\": https://assets.${d}"

    base=".nginz.nginx_conf.multi_ingress_deeplink.\"$d\".endpoints"

    [[ "$(yaml_get "$base.backendURL" "$WIRE_VALUES")" == "https://nginz-https.${d}" ]] \
      && ok "nginz multi_ingress_deeplink $d backendURL" \
      || fail "set nginz.nginx_conf.multi_ingress_deeplink.\"$d\".endpoints.backendURL"

    [[ "$(yaml_get "$base.backendWSURL" "$WIRE_VALUES")" == "https://nginz-ssl.${d}" ]] \
      && ok "nginz multi_ingress_deeplink $d backendWSURL" \
      || fail "set nginz.nginx_conf.multi_ingress_deeplink.\"$d\".endpoints.backendWSURL"

    [[ "$(yaml_get "$base.teamsURL" "$WIRE_VALUES")" == "https://teams.${d}" ]] \
      && ok "nginz multi_ingress_deeplink $d teamsURL" \
      || fail "set nginz.nginx_conf.multi_ingress_deeplink.\"$d\".endpoints.teamsURL"

    [[ "$(yaml_get "$base.accountsURL" "$WIRE_VALUES")" == "https://account.${d}" ]] \
      && ok "nginz multi_ingress_deeplink $d accountsURL" \
      || fail "set nginz.nginx_conf.multi_ingress_deeplink.\"$d\".endpoints.accountsURL"

    [[ "$(yaml_get "$base.websiteURL" "$WIRE_VALUES")" == "https://${d}" ]] \
      && ok "nginz multi_ingress_deeplink $d websiteURL" \
      || fail "set nginz.nginx_conf.multi_ingress_deeplink.\"$d\".endpoints.websiteURL"

    if [[ "$FAILED" -ne "$domain_failed_before" ]]; then
      print_wire_snippet "$d"
    fi
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
  [[ -n "$MAIN_DOMAIN" && -n "$NGINX_DOMAIN" && -n "$NGINX_VALUES" ]] || {
    echo "ERROR: --check-nginx requires --main-domain, --nginx-domain and --nginx-values"
    exit 2
  }

  check_main_nginx_exists

  echo "Checking $NGINX_DOMAIN at ${NGINX_VALUES}:"

  if [[ ! -f "$NGINX_VALUES" ]]; then
    if [[ "$CREATE_NGINX_VALUES" == true ]]; then
      create_nginx_values "$NGINX_DOMAIN" "$NGINX_VALUES"
    else
      fail "nginx values file does not exist: $NGINX_VALUES"
      echo "Re-run with --create-nginx-values to create it."
      exit 1
    fi
  fi

  local s
  s="$(slug "$NGINX_DOMAIN")"

  [[ "$(yaml_get '.ingressName' "$NGINX_VALUES")" ]] \
    && ok "ingressName" \
    || fail "set ingressName: someName"

  [[ "$(yaml_get '.nameOverride' "$NGINX_VALUES")" ]] \
    && ok "nameOverride" \
    || fail "set nameOverride: someNameOverride"

  [[ "$(yaml_get '.config.dns.base' "$NGINX_VALUES")" == "$NGINX_DOMAIN" ]] \
    && ok "config.dns.base" \
    || fail "set config.dns.base: $NGINX_DOMAIN"

  [[ "$(yaml_get '.config.dns.https' "$NGINX_VALUES")" == "nginz-https.${NGINX_DOMAIN}" ]] \
    && ok "config.dns.https" \

  [[ "$(yaml_get '.config.dns.ssl' "$NGINX_VALUES")" == "nginz-ssl.${NGINX_DOMAIN}" ]] \
    && ok "config.dns.ssl" \
    || fail "set config.dns.ssl: nginz-ssl.${NGINX_DOMAIN}"

  [[ "$(yaml_get '.config.dns.webapp' "$NGINX_VALUES")" == "webapp.${NGINX_DOMAIN}" ]] \
    && ok "config.dns.webapp" \
    || fail "set config.dns.webapp: webapp.${NGINX_DOMAIN}"

  [[ "$(yaml_get '.config.dns.fakeS3' "$NGINX_VALUES")" == "assets.${NGINX_DOMAIN}" ]] \
    && ok "config.dns.fakeS3" \
    || fail "set config.dns.fakeS3: assets.${NGINX_DOMAIN}"

  [[ "$(yaml_get '.config.dns.teamSettings' "$NGINX_VALUES")" == "teams.${NGINX_DOMAIN}" ]] \
    && ok "config.dns.teamSettings" \
    || fail "set config.dns.teamSettings: teams.${NGINX_DOMAIN}"

  [[ "$(yaml_get '.config.dns.accountPages' "$NGINX_VALUES")" == "account.${NGINX_DOMAIN}" ]] \
    && ok "config.dns.accountPages" \
    || fail "set config.dns.accountPages: account.${NGINX_DOMAIN}"

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

if [[ "$CHECK_NGINX" == true ]]; then
  check_nginx_values
else
  check_wire_server
fi

echo
if [[ "$FAILED" -eq 0 ]]; then
  echo "All checks passed."
else
  echo "Some checks failed. See MISSING/WRONG messages above."
  exit 1
fi
