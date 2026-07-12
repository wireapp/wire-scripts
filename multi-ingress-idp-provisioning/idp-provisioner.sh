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
# LOG_FILE="${LOG_FILE:-${SCRIPT_DIR}/multi-ingress-sso.log}"
WIRE_API_VERSION="${WIRE_API_VERSION:-v16}"
WIRE_VERIFICATION_CODE="${WIRE_VERIFICATION_CODE:-aGVsbG8}"

# NGINZ_HOST for the NGINZ service. This can be overridden by setting the NGINZ_HOST environment variable.
# This URL is used to do authentication and to retrieve the list of identity providers (IDPs) for a given team.
# In multi-ingress setups, A team's administrator can use any domain for authentication or listing Idp.
# But for adding an Idp for a team, we need to use specific domain url.
# For example, if the team is using 'https://nginz-https.example.com/sso' for SSO login,
# then the domain is 'example.com' 
# and the URL for adding Idp is 'https://nginz-https.example.com/v16/identity-providers?api_version=v2'.

NGINZ_HOST="${NGINZ_HOST:-https://nginz-https.example.com}"

# SPAR_HOST="${SPAR_HOST:-http://spar:8088}"
# GALLEY_HOST="${GALLEY_HOST:-http://galley:8088}"
# BRIG_HOST="${BRIG_HOST:-http://brig:8080}"

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

# validate idp metadata xml file
validate_idp_metadata() {
  local idp_metadata_file="$1"
  if [[ ! -f "$idp_metadata_file" ]]; then
    echo "Error: IDP metadata file '$idp_metadata_file' does not exist."
    return $ERR_INVALID_IDP_FILE
  fi

  # for future
#   if ! xmllint --noout "$idp_metadata_file" >/dev/null 2>&1; then
#     echo "Error: IDP metadata file '$idp_metadata_file' is not a valid XML file."
#     exit $ERR_INVALID_IDP_FILE
#   fi

}

get_auth_token_from_last_request() {
  local file="$1"

  if [[ -f "$file" && -s "$file" ]]; then
    local token
    token=$(cat "$file" | jq -r '.access_token')
    local expires_in
    expires_in=$(cat "$file" | jq -r '.expires_in')

    # check if the token is expired
    # get mtime of the file in seconds since last auth_request
    local mtime
    mtime=$(stat -c %Y "$file")
    
    local expires_at_ts=$((mtime + expires_in - 10))

    local now
    now=$(date +%s)

    #echo "mtime: $mtime, expires_in: $expires_at_ts, now: $now, " >&2
    
    if (( now < expires_at_ts )); then
      echo "Info: Auth token is still valid. Using cached token." >&2
      echo "$token"
      return $SUCCESS
    # else
    #   echo "Info: Auth token has expired." >&2
    fi
  fi

  return $ERR_AUTH
}

get_auth_token() {
  local team_admin="$1"
  local team_password="$2"

  # response file must be associated to the team_admin
  local file="$TMP_DIR/$team_admin-auth_response.json"

  local token
  token=$(get_auth_token_from_last_request "$file")

  if [[ $? -eq $SUCCESS ]]; then
    echo "$token"
    return $SUCCESS
  else
    echo "Info: Auth token not found or expired. Requesting new token..." >&2
    echo "Info: Using team_admin: $team_admin" >&2
  fi

  if [[ -z "$team_admin" || -z "$team_password" ]]; then
    echo "Error: Missing required arguments for authentication." >&2
    exit $ERR_INVALID_ARGS
  fi

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

get_idp() {
  local team_admin="$1"
  local team_password="$2"


  token=$(get_auth_token "$team_admin" "$team_password")

  #echo "Retrieved token: $token" >&2

  curl_idp "$token"
}

curl_idp() {
  local token="$1"
  local tmp_file="$TMP_DIR/idp.json"
  
  # empty the file before writing to it
  > "$tmp_file"

  http_code=$(curl_to_file "$API_URL/identity-providers" "$tmp_file" \
      -H "Authorization: Bearer $token" \
      -H "Accept: application/json" \
      -X GET
  )

  if [[ "$http_code" -ne 200 ]]; then
    echo "Error: Failed to retrieve IDP information. HTTP status code: $http_code" >&2
    return $ERR_API_ERROR
  fi

  # Check if the file is empty or contains an error message
  if [[ ! -s "$tmp_file" ]]; then
    echo "Error: IDP information is empty or not found." >&2
    return $ERR_IDP_NOT_FOUND
  fi

  # read the JSON content from the file
  local idp_json
  idp_json=$(cat "$tmp_file")

  print_providers "$idp_json"
}

set_idp() {

  # check if the required number of arguments is provided
  if (("$# < 1")); then
    usage
  fi

  local team_admin="$1"
  local team_password="$2"
  local domain="$3"
  local idp_metadata_file="$4"
  local idp_json="$TMP_DIR/set_idp_response.json"

  # validate the IDP metadata file
  validate_idp_metadata "$idp_metadata_file"
  result=$?
  if [[ $result -ne 0 ]]; then
    echo "Error: Invalid IDP metadata file." >&2
    exit $result
  fi

  # get auth token
  token=$(get_auth_token "$team_admin" "$team_password")

  # user domain to construct the API URL for setting the IDP
  domain="https://nginz-https.$domain/$WIRE_API_VERSION"

  http_code=$(curl_to_file "$domain/identity-providers?api_version=v2" "$idp_json" \
      -H "Authorization: Bearer $token" \
      -H "Content-Type: application/xml" \
      -H "Accept: */*" \
      -X POST \
      --data-binary "@$idp_metadata_file")

  if [[ "$http_code" -eq 409 ]]; then
    echo "Error: An identity provider for the domain '$domain' already exists." >&2
    return $ERR_IDP_NOT_FOUND
  fi

  # success code: 201 Created
  # https://staging-nginz-https.zinfra.io/v16/api/swagger-ui/#/default/idp-create
  if [[ "$http_code" -ne 201 ]]; then
    echo "Error: Failed to set IDP information. HTTP status code: $http_code" >&2
    return $ERR_API_ERROR
  fi

  if [[ ! -s "$idp_json" ]]; then
    echo "Error: IDP set response is empty or not found." >&2
    return $ERR_API_ERROR
  fi

  # 
  #if [[ "$http_code" -eq 200 ]]; then
  #  echo "Successfully updated the identity provider for domain '$domain'."
  #fi

  # 
  if [[ "$http_code" -eq 201 ]]; then
    echo "Successfully created a new identity provider for domain '$domain'."
  fi

  print_providers "$idp_json"
  return $SUCCESS
}

curl_to_file() {
  # echo "Executing curl command: $@" >&2

  local url="$1"
  local file="$2"
  shift 2

  http_code=$(curl \
        --silent \
        --show-error \
        --write-out "%{http_code}" \
        --output "$file" \
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

print_providers(){
  local providers="${1:-}"

  if [[ -z "$providers" ]]; then
    echo "Team has no configured identity providers."    
  fi

  jq -r '
  ["handle", "domain name", "issuer"],
    (
      if has("providers") then .providers[]
      else .
      end
      | [
          .extraInfo.handle,
          .extraInfo.domain,
          .metadata.issuer
        ]
    )
    | @tsv
' $providers | column -t -s $'\t'
}

usage() {  
  echo "Usage: 
    $0 get <team_admin> <team_password>
    $0 set <team_admin> <team_password> <domain> <idp_metadata_file>

    <domain> is the domain name for which the IDP is being set. <domain> does not content service name such as 'nginz-https' or 'spar'. It is the domain name that will be used for SSO login.
    For example, if your SSO login URL is 'https://nginz-https.example.com/sso', then the domain is 'example.com'.
    Examples:
      $0 get admin@example.com secret
      $0 set admin@example.com secret nginz-https.example.com ./idp.xml

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
    get)
      get_idp "$@"
      ;;
    set)
      set_idp "$@"
      ;;
    *)
      echo "Error: Unknown command '$command'. Use 'get' or 'set'."
      exit $ERR_INVALID_ARGS
      ;;
  esac
}

main "$@"