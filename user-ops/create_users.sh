
#!/usr/bin/env bash
#
# BRIG service should be reachable, better to run it from inside the k8s-cluster using wire-utility pod

set -e

ADMIN_UUID=""
TEAM_UUID=""
BRIG_HOST="http://brig:8080"
START="1"
COUNT="1"
CSV="false"
PREFIX=""
TARGET_EMAIL_DOMAIN=""

### SHOULDNT NEED TO MODIFY ANYTHING BELOW THIS LINE ###


USAGE="This bash script can be used to create active members in a
given team.  Every member will have an email address of the form
'w<number>@${TARGET_EMAIL_DOMAIN}', and will have to change that
(after logging in with the password provided to the user from the
output of this script).

Note that this uses internal brig endpoints.  It is not exposed over
nginz and can only be used if you have direct access to brig.

USAGE: $0 -d <email domain> [OPTIONS...]
    -d <email domain>: Domain part of the emails that the bogus
                       invitations are sent to.  No default, you need
                       to provide that.  Consider 'example.com', or an
                       internal domain you control.

                       WARNING: This may boost your reputation as a
                       spammer.  Use with care!

    -a <admin uuid>: User ID of the inviting admin.  default: ${ADMIN_UUID}
    -t <team uuid>: ID of the inviting team.  default: ${TEAM_UUID}
    -s <S>: Start at offset. default: ${START}
    -n <N>: Create <N> users. default: ${COUNT}
    -h <host>: Base URI of brig. default: ${BRIG_HOST}
    -c: Output as headerless CSV in format 'User-Id,Email,Password'. default: ${CSV}
    -d domain for username default: ${TARGET_EMAIL_DOMAIN}
    -p prefix for username default: ${PREFIX}
"

# Option parsing:
# https://sookocheff.com/post/bash/parsing-bash-script-arguments-with-shopts/
while getopts ":a:t:s:n:h:d:p:c" opt; do
  case ${opt} in
    a ) ADMIN_UUID="$OPTARG"
      ;;
    t ) TEAM_UUID="$OPTARG"
      ;;
    s ) START="$OPTARG"
      ;;
    n ) COUNT="$OPTARG"
      ;;
    h ) BRIG_HOST="$OPTARG"
      ;;
    d ) TARGET_EMAIL_DOMAIN="$OPTARG"
      ;;
    p ) PREFIX="$OPTARG"
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

# Warn about sending emails

if [ "$TARGET_EMAIL_DOMAIN" == "" ]; then
    echo -e "\n\n*** Please provide an email domain if you want to run this script.\n\n"
    echo "$USAGE" 1>&2
    exit 1
fi

# Generate users
END=$((COUNT + START - 1))
for i in $(seq "$START" "$END")
do
    FUSERNAME=${PREFIX}$(printf "%03d" "$i") ### USERNAME FORMAT (NUMBER OF DIGITS)
    EMAIL=$FUSERNAME"@$TARGET_EMAIL_DOMAIN"
    PASSWORD=$(cat /dev/urandom | env LC_CTYPE=C tr -dc a-zA-Z0-9 | head -c 12)

    # Generate the invitation

    CURL_OUT_INVITATION=$(curl -i -s --show-error \
        -XPOST "$BRIG_HOST/teams/$TEAM_UUID/invitations" \
        -H'Content-type: application/json' \
        -H'Z-User: '"$ADMIN_UUID"'' \
        -d'{"email":"'"$EMAIL"'","name":"Replace with name","inviter_name":"Team admin"}')

    INVITATION_ID=$(echo "$CURL_OUT_INVITATION" | tail -1 | sed 's/.*\"id\":\"\([a-z0-9-]*\)\".*/\1/')

    #echo "Created the invitation, sleeping 1 second..." 1>&2
    sleep 1

    if ( ( echo "$INVITATION_ID" | grep -q '"code"' ) &&
         ( echo "$INVITATION_ID" | grep -q '"label"' ) ) ; then
      echo "Got an error while creating $EMAIL, aborting: $INVITATION_ID"
      exit 1
    fi

    # Get the code
    CURL_OUT_INVITATION_CODE=$(curl -i -s --show-error \
        -XGET "$BRIG_HOST/i/teams/invitation-code?team=$TEAM_UUID&invitation_id=$INVITATION_ID")

    INVITATION_CODE=$(echo "$CURL_OUT_INVITATION_CODE" | tail -1 | sed -n -e '/"code":/ s/^.*"\(.*\)".*/\1/p')

    #echo "Got the code, sleeping 1 second..." 1>&2
    sleep 1

    # Create the user using that code
    CURL_OUT=$(curl -i -s --show-error \
            -XPOST "$BRIG_HOST/i/users" \
            -H'Content-type: application/json' \
            -d'{"email":"'"$EMAIL"'","password":"'"$PASSWORD"'","name":"'"$FUSERNAME"'","team_code":"'"$INVITATION_CODE"'"}')

    TEAM_MEMBER_UUID=$(echo "$CURL_OUT" | tail -1 | sed 's/.*\"id\":\"\([a-z0-9-]*\)\".*/\1/')
    TEAM=$(echo "$CURL_OUT" | tail -1 | sed 's/.*\"team\":\"\([a-z0-9-]*\)\".*/\1/')

    if [ "$TEAM" != "$TEAM_UUID" ]; then
        echo "unexpected error: user got assigned to no / the wrong team?!"
        echo ${CURL_OUT}
        exit 1
    fi

    if [ "$CSV" == "false" ]
        then echo -e "Succesfully created a team member: $TEAM_MEMBER_UUID on team: $TEAM_UUID with email: $EMAIL and password: $PASSWORD"
        else echo -e "$EMAIL,$PASSWORD,,,$TEAM_MEMBER_UUID"
    fi

    #echo "Sleeping 1 second..." 1>&2
    sleep 1
done
