#!/usr/bin/env bash

# run it on cassandra nodes
set -e
TAG=backup_$(date +%F_%H%M%S)
for ks in gundeck spar galley brig; do
  echo "Backing up $ks - This can disrupt cassandra operations, continue only if Wire services and node disk/cpu resources allow"
  read -r -p "Type yes to continue: " confirm

  if [[ "$confirm" != "yes" ]]; then
    echo "Aborted."
    exit 0
  fi

  echo "=== flushing $ks ==="
  nodetool flush "$ks"
  echo "=== snapshotting $ks with tag $TAG ==="
  nodetool snapshot -t "$TAG" "$ks"
done
