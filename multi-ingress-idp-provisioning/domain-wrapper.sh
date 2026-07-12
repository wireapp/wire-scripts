#!/usr/bin/env bash

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROVISIONER_SCRIPT="${SCRIPT_DIR}/idp-provisioner.sh"

check_dependencies() {
  if [[ ! -f "$PROVISIONER_SCRIPT" ]]; then
    echo "Error: Provisioner script '$PROVISIONER_SCRIPT' not found."
    exit 1
  fi

  # check if file is readable
  if [[ ! -r "$PROVISIONER_SCRIPT" ]]; then
    echo "Error: Provisioner script '$PROVISIONER_SCRIPT' is not readable."
    exit 1
  fi
}

set_idps() {
  local team_admin="$1"
  local team_password="$2"
  local idp_domains_location=$3

  if [[ -z "$team_admin" || -z "$team_password" || -z "$idp_domains_location" ]]; then
    echo "Error: Missing required arguments for 'set' command."
    usage
    exit $ERR_INVALID_ARGS
  fi

  # iterate over all files in the directory and call the provisioner script for each file
    for idp_domain_file in "$idp_domains_location"/*.xml; do
      if [[ -f "$idp_domain_file" ]]; then
        local domain=$(basename "$idp_domain_file" .xml)
        echo "Info: Setting IDP file '$idp_domain_file' for domain '$domain'" >&2
        bash "$PROVISIONER_SCRIPT" set "$team_admin" "$team_password" "$domain" "$idp_domain_file"

        echo "" >&2
        # slow down the requests to avoid rate-limiting
        sleep 0.5
      else
        echo "Warning: 'idp_domain_file' is not a file. Skipping." >&2
      fi
    done
}

usage() {  
  echo "Usage: 
    $0 set <team_admin> <team_password> <idp_domains_location>

    <idp_domains_location> is the directory containing the IDP metadata files for each domain. Each file should be named as '<domain>.xml'.
    For example, if your SSO login URL is 'https://nginz-https.example.com/sso', then the file should be named 'example.com.xml'.
    Examples:
      $0 set"
}

main() {
  # check dependencies
  check_dependencies

  if (("$# < 1")); then
    usage
    exit $ERR_INVALID_ARGS
  fi

  local command="$1"
  shift

  case "$command" in
    set)
      set_idps "$@"
      ;;
    *)
      echo "Error: Unknown command '$command'. Use 'set'."
      exit $ERR_INVALID_ARGS
      ;;
  esac
}

main "$@"