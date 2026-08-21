#!/usr/bin/env bash
#
# BRIG service should be reachable, better to run it from inside the k8s-cluster using wire-utility pod

set -e

COUNT="1"
BRIG_HOST="http://brig:8080"
CSV="false"

USAGE="
This bash script can be used to create active team admin users and
their teams.

This is the way to create teams if you have set
'setRestrictUserCreation' to 'true' in your 'values.yaml'.

Note that this uses an internal brig endpoint.  It is not exposed over
nginz and can only be used if you have direct access to brig.

USAGE: $0
    -n <N>: Create <N> users. default: ${COUNT}
    -h <host>: Base URI of brig. default: ${BRIG_HOST}
    -c: Output as headerless CSV in format 'User-Id,Email,Password'. default: ${CSV}
    -d <domain.com> Domain for team in format 'domain.com'. REQUIRED.
"

# Option parsing:
# https://sookocheff.com/post/bash/parsing-bash-script-arguments-with-shopts/
while getopts ":d:n:h:c" opt; do
case ${opt} in
    d ) DOMAIN="$OPTARG"
      ;;    
    n ) COUNT="$OPTARG"
      ;;
    h ) BRIG_HOST="$OPTARG"
      ;;
    c ) CSV="true"
      ;;
    : ) echo "-$OPTARG" requires an argument 1>&2
        exit 1
      ;;
    \? ) echo "$USAGE" 1>&2
         exit 1
      ;;
  esac
done
shift $((OPTIND -1))

if [ "$#" -ne 0 ]; then
  echo "$USAGE" 1>&2
  exit 1
fi

if [ -z "$DOMAIN" ]; then
        echo 'Must specify team name (domain.com) with -d' >&2
        exit 1
fi

TEAM_NAME=$(echo "$DOMAIN" | cut -d'.' -f1)

# Generate users

for i in $(seq 1 "$COUNT")
do
    EMAIL="teamadmin@$DOMAIN"
    PASSWORD=$(cat /dev/urandom | env LC_CTYPE=C tr -dc a-zA-Z0-9 | head -c 16)

    CURL_OUT=$(curl -i -s --show-error \
        -XPOST "$BRIG_HOST/i/users" \
        -H'Content-type: application/json' \
        -d'{"email":"'"$EMAIL"'","password":"'"$PASSWORD"'","name":"teamadmin","team":{"name":"'"$TEAM_NAME"'","icon":"default"}}')

    UUID=$(echo "$CURL_OUT" | tail -1 | sed 's/.*\"id\":\"\([a-z0-9-]*\)\".*/\1/')
    TEAM=$(echo "$CURL_OUT" | tail -1 | sed 's/.*\"team\":\"\([a-z0-9-]*\)\".*/\1/')

    if [ "$CSV" == "false" ]
        then echo -e "Succesfully created a team admin user: $UUID on team: $TEAM with email: $EMAIL and password: $PASSWORD"
        echo -e "Create users with:\tbash create_users.sh -d $DOMAIN -c -n 2 -s 1 -a $UUID -t $TEAM"
        else echo -e "$UUID,$TEAM,$EMAIL,$PASSWORD"
    fi
done
