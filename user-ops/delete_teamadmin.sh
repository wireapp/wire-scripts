#!/usr/bin/env bash
set -euo pipefail

# BRIG and galley service should be reachable, better to run it from inside the k8s-cluster using wire-utility pod


BRIG="${1:-brig:8080}"
galley="${2:-galley:8080}"
DOMAIN="${3:-example.com}"

echo "Looking up user/team for domain: teamadmin@$DOMAIN"

response="$(curl -sS -w '\n%{http_code}' -X GET \
  "http://${BRIG}/i/teams?email=$(printf '%s' "teamadmin@$DOMAIN" | jq -sRr @uri)" \
  -H 'Content-type: application/json')"

http_code="$(tail -n1 <<< "$response")"
body="$(sed '$d' <<< "$response")"

if [[ "$http_code" != "200" ]]; then
  echo "Lookup failed with HTTP $http_code"
  echo "$body"
  exit 1
fi

user_id="$(jq -r '.[0].id // empty' <<< "$body")"
team_id="$(jq -r '.[0].team // empty' <<< "$body")"

if [[ -z "$user_id" || -z "$team_id" ]]; then
  echo "Could not extract user_id or team_id from response"
  echo "$body"
  exit 1
fi

echo "Found user_id: $user_id"
echo "Found team_id: $team_id"

echo "Deleting user..."
user_delete_code="$(curl -sS -o /tmp/delete_user_response.txt -w '%{http_code}' -X DELETE \
  "http://${BRIG}/i/users/${user_id}" \
  -H 'accept: application/json;charset=utf-8')"

if [[ "$user_delete_code" != "200" ]]; then
  echo "User delete failed with HTTP $user_delete_code"
  cat /tmp/delete_user_response.txt
  exit 1
fi

echo "Team Admin for the $domain deleted successfully."

echo "Deleting team..."
team_delete_code="$(curl -sS -o /tmp/delete_team_response.txt -w '%{http_code}' -X DELETE \
  "http://${BRIG}/i/teams/${team_id}?force=true" \
  -H 'accept: application/json;charset=utf-8')"

if [[ "$team_delete_code" != "200" ]]; then
  echo "Team delete failed with HTTP $team_delete_code"
  cat /tmp/delete_team_response.txt
  exit 1
fi

echo "Team $team_id deleted successfully."
echo "Done: $EMAIL and team $team_id got deleted."
