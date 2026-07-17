#!/usr/bin/env bash

set -o pipefail

get_idps() {
    local file="$1"

    if [[ -z "$file" ]]; then
        echo "Error: Missing required argument for 'get' command." >&2
        usage
        exit $ERR_INVALID_ARGS
    fi

    # echo "File: $file" 

    teams=()

    while IFS= read -r team; do
        teams+=("$team")
    done < <(jq -c '.[]' "$file")

    for team in "${teams[@]}"; do
        username=$(jq -r '.username' <<< "$team")
        password=$(jq -r '.password' <<< "$team")

        echo "Team admin: $username" >&2
        bash idp-provisioner.sh get "$username" "$password"
        echo "" >&2
        # slow down the requests to avoid rate-limiting
        sleep 0.5
    done
}

set_idps() {
    local file="$1"
    local idp_domains_location="$2"

    if [[ -z "$file" || -z "$idp_domains_location" ]]; then
        echo "Error: Missing required arguments for 'set' command." >&2
        usage
        exit $ERR_INVALID_ARGS
    fi
    # echo "File: $file" 

    teams=()

    while IFS= read -r team; do
        teams+=("$team")
    done < <(jq -c '.[]' "$file")

    for team in "${teams[@]}"; do
        username=$(jq -r '.username' <<< "$team")
        password=$(jq -r '.password' <<< "$team")

        bash domain-wrapper.sh set "$username" "$password" "$idp_domains_location"
        echo "" >&2
        # slow down the requests to avoid rate-limiting
        sleep 0.5
    done
}

usage(){
    echo "Usage: 
      export NGINZ_HOST=https://nginz-https.example.com
      $0 set <teams_json_file> <idp_domains_location>

      <teams_json_file> is a JSON file containing an array of team objects with 'username' and 'password' fields.
      <idp_domains_location> is the directory containing the IDP metadata files for each domain. Each file should be named as '<domain>.xml'.

      Example: $0 set teams.json ./idp_domains" >&2

    exit $ERR_INVALID_ARGS
}

main() {
  local command="$1"
  shift

  case "$command" in
    get)
      get_idps "$@"
      ;;
    set)
      set_idps "$@"
      ;;
    *)
      echo "Error: Unknown command '$command'." >&2
      usage
      exit $ERR_INVALID_ARGS
      ;;
  esac
}

main "$@"