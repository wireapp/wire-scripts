#!/usr/bin/env bash
set -euo pipefail

JSON_FILE="${1:-versions/helm_image_tree.json}"

CHARTS=(
  account-pages
  databases-ephemeral
  fake-aws
  fake-aws-sqs
  ingress-nginx-controller
  migrate-features
  nginx-ingress-controller
  postgresql-external
  reaper
  smtp
  team-settings
  webapp
  wire-server
  wire-utility
  # add more charts here
)

if [[ ! -f "$JSON_FILE" ]]; then
  echo "ERROR: JSON file not found: $JSON_FILE" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: jq is required" >&2
  exit 1
fi

images="$(
  jq -r \
    --argjson charts "$(printf '%s\n' "${CHARTS[@]}" | jq -R . | jq -s .)" \
    '.[] | select(.chart as $chart | $charts | index($chart)) | .images[]' \
    "$JSON_FILE" \
  | sort -u
)"

#echo "Images:"
#echo "$images"

#echo
#echo "Image filenames:"
while IFS= read -r image; do
  [[ -z "$image" ]] && continue
  image_filename="$(sed -r 's#[:/]#_#g' <<< "$image")"
  echo "$image_filename.tar"
done <<< "$images"
