#!/usr/bin/env bash

set -o pipefail

# constants
SUCCESS=0
ERR_GENERAL=1
ERR_INVALID_ARGS=2
ERR_AUTH=3
ERR_DOMAIN_NOT_FOUND=4
ERR_IDP_NOT_FOUND=5
ERR_INVALID_IDP_FILE=6
ERR_API_ERROR=7

# SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WIRE_API_VERSION="${WIRE_API_VERSION:-v14}"
WIRE_VERIFICATION_CODE="${WIRE_VERIFICATION_CODE:-aGVsbG8}"

# NGINZ_HOST for the NGINZ service. This can be overridden by setting the NGINZ_HOST environment variable.
NGINZ_HOST="${NGINZ_HOST:-https://nginz-https.example.com}"

API_URL="$NGINZ_HOST/$WIRE_API_VERSION"
TMP_DIR="${TMP_DIR:-/tmp}"

########
# check dependencies

check_dependencies() {
  local dependencies=("curl" "jq" "base64")
  for dep in "${dependencies[@]}"; do
    if ! command -v "$dep" >/dev/null 2>&1; then
      echo "Error: $dep is not installed or not in PATH." >&2
      exit $ERR_GENERAL
    fi
  done
}

get_auth_token() {
  local team_admin="$1"
  local team_password="$2"

  # response file must be associated to the team_admin
  local file="$TMP_DIR/$team_admin-auth_response.json"

  local token

  local auth_response
  # https://staging-nginz-https.zinfra.io/v16/api/swagger-ui/#/default/login
  http_code=$(curl_to_file "$NGINZ_HOST/login" "$file" \
      -H "Content-Type: application/json" \
      -d "{\"email\":\"$team_admin\",\"password\":\"$team_password\",\"verification_code\":\"$WIRE_VERIFICATION_CODE\"}" \
      )

  #echo "HTTP Code: $http_code" >&2

  if [[ "$http_code" -ne 200 ]]; then
    echo "Error: Authentication request failed. HTTP status code: $http_code" >&2
    exit $ERR_AUTH
  fi

  token=$(cat "$file" | jq -r '.access_token')

  if [[ "$token" == "null" || -z "$token" ]]; then
    echo "Error: Authentication failed. Please check your credentials." >&2
    exit $ERR_AUTH
  fi

  echo "$token"
}

delete_team() {
  local team_admin="$1"
  local team_password="$2"
  local team_id="$3"

  token=$(get_auth_token "$team_admin" "$team_password")

  printf 'API_URL=<%s>\n' "$API_URL"
  printf 'TEAM_ID=<%s>\n' "$team_id"

  # echo "Retrieved token: $token" >&2

  http_code=$(curl_to_file "$API_URL/teams/$team_id" "$TMP_DIR/delete_team_response.json" \
      -H "Authorization: Bearer $token" \
      -H "Content-Type: application/json" \
      -X DELETE \
      -d '{"password": "'$team_password'", "verification_code": "'$WIRE_VERIFICATION_CODE'"}'
      )

  if [[ "$http_code" -ne 202 ]]; then
    echo "Error: Failed to delete team. HTTP status code: $http_code" >&2
    cat "$TMP_DIR/delete_team_response.json"
    exit $ERR_API_ERROR
  fi

  echo ""
  echo "Team $team_id deleted successfully."
}


curl_to_file() {
  # echo "Executing curl command: $@" >&2

  local url="$1"
  local file="$2"
  shift 2

  local curl_args=(
    --silent
    --show-error
    --write-out "%{http_code}"
    --output "$file"
  )

# echo $url >&2

  if [[ "$CURL_INSECURE" == "true" ]]; then
    curl_args+=(--insecure)
  fi

  if [[ -n "$CURL_HOST_HEADER" ]]; then
    curl_args+=(-H "Host: $CURL_HOST_HEADER")
  fi

  http_code=$(curl \
    "${curl_args[@]}" \
    "$url" \
    "$@"
  )

  curl_rc=$?

  if [[ $curl_rc -ne 0 ]]; then
      echo "CURL_ERROR:$curl_rc" >&2
      return "$curl_rc"
  fi

  echo "$http_code"
}

usage() {  
  echo "Usage: 
    export NGINZ_HOST=https://nginz-https.example.com
    $0 delete <team_admin> <team_password> <team_id>

    Examples:
      $0 delete teamadmin@example.com secret 8037709e-6c44-4bdf-8f89-8efe3505da3c

    NOTICE: If you run this from wire-utility pod you should expose some environment variables to make it work:
      export CURL_INSECURE=true
      export CURL_HOST_HEADER=nginz-https.domain.com
      export NGINZ_HOST=https://ingress-nginx-controller-controller

      $0 delete teamadmin@example.com secret 8037709e-6c44-4bdf-8f89-8efe3505da3c

    " >&2
  exit $ERR_INVALID_ARGS
}

main() {
  # check dependencies
  check_dependencies

  if (("$# < 1")); then
    usage
  fi

  local command="$1"
  shift

  case "$command" in
    delete )
      delete_team "$@"
      ;;

    *)
      echo "Error: Unknown command '$command'. Use 'delete'."
      exit $ERR_INVALID_ARGS
      ;;
  esac
}

main "$@"