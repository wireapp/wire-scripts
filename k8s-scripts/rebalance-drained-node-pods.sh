#!/usr/bin/env bash
set -euo pipefail

# Run only from adminhost container i.e. source bin/offline-env.sh and then inside d bash
# rebalance-drained-node-pods.sh helps rebalance workloads after a node is drained, restarted, and uncordoned by deleting pods created after the drain so Kubernetes can reschedule them.
# Before draining, export DRAIN_NODE=<node> and DRAIN_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; alternatively use DRAIN_AGO_SECONDS=<seconds> if the exact time is unavailable.
# Run the script after the node has been uncordoned; it first shows candidate pods, current pod distribution across nodes, and runs in DRY_RUN mode by default.
# Set DRY_RUN=false to actually delete candidate pods one at a time, waiting for their controller to become healthy before proceeding.
# Use INCLUDE_SYSTEM=true to include system namespaces; by default they are excluded.
# Note: deleting pods does not guarantee they return to DRAIN_NODE—the Kubernetes scheduler decides placement based on resources and scheduling constraints.

usage() {
  cat <<EOF
Usage:
  DRAIN_NODE=kubenode1 DRAIN_TIME="2026-06-30T10:30:00Z" $0
  DRAIN_NODE=kubenode1 DRAIN_AGO_SECONDS=600 $0

Optional:
  DRY_RUN=false        Actually delete pods. Default: true
  INCLUDE_SYSTEM=true  Include kube-system and other system namespaces. Default: false
EOF
}

if [[ -z "${DRAIN_NODE:-}" ]]; then
  echo "ERROR: DRAIN_NODE is not set."
  usage
  exit 1
fi

DRY_RUN="${DRY_RUN:-true}"
INCLUDE_SYSTEM="${INCLUDE_SYSTEM:-false}"

NOW_EPOCH="$(date -u +%s)"

if [[ -n "${DRAIN_TIME:-}" ]]; then
  DRAIN_EPOCH="$(date -u -d "$DRAIN_TIME" +%s)"
  AGE_SECONDS="$((NOW_EPOCH - DRAIN_EPOCH))"
elif [[ -n "${DRAIN_AGO_SECONDS:-}" ]]; then
  DRAIN_EPOCH="$((NOW_EPOCH - DRAIN_AGO_SECONDS))"
  DRAIN_TIME="$(date -u -d "@$DRAIN_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"
  AGE_SECONDS="$DRAIN_AGO_SECONDS"
else
  echo "ERROR: set either DRAIN_TIME or DRAIN_AGO_SECONDS."
  usage
  exit 1
fi

if ! kubectl get node "$DRAIN_NODE" >/dev/null 2>&1; then
  echo "ERROR: node $DRAIN_NODE does not exist."
  exit 1
fi

UNSCHEDULABLE="$(kubectl get node "$DRAIN_NODE" -o jsonpath='{.spec.unschedulable}' 2>/dev/null || true)"

echo "DRAIN_NODE: $DRAIN_NODE"
echo "DRAIN_TIME: $DRAIN_TIME"
echo "Time passed since drain: ${AGE_SECONDS}s"
echo "DRY_RUN: $DRY_RUN"
echo

if [[ "$UNSCHEDULABLE" == "true" ]]; then
  echo "ERROR: $DRAIN_NODE is still cordoned/unschedulable."
  echo "Run: kubectl uncordon $DRAIN_NODE"
  exit 1
fi

echo "Current pod count per node:"
kubectl get pods -A -o json | jq -r '
  .items[]
  | select(.spec.nodeName != null)
  | .spec.nodeName
' | sort | uniq -c | awk '{print $2 ": " $1}'

echo
echo "Current pods on $DRAIN_NODE:"
kubectl get pods -A --field-selector spec.nodeName="$DRAIN_NODE" --no-headers 2>/dev/null | wc -l
echo


echo "Recent events mentioning $DRAIN_NODE:"
kubectl get events -A --sort-by=.lastTimestamp 2>/dev/null | grep -i "$DRAIN_NODE" | tail -20 || true
echo

JQ_FILTER='
  .items[]
  | select(.spec.nodeName != $NODE)
  | select(.metadata.creationTimestamp >= $DRAIN_TIME)
  | select(.metadata.ownerReferences != null)
  | select(.metadata.ownerReferences[0].kind != "DaemonSet")
  | select(.metadata.ownerReferences[0].kind != "Job")
  | select(.metadata.ownerReferences[0].kind != "CronJob")
'

if [[ "$INCLUDE_SYSTEM" != "true" ]]; then
  JQ_FILTER+='
  | select(.metadata.namespace != "kube-system")
  | select(.metadata.namespace != "kube-public")
  | select(.metadata.namespace != "kube-node-lease")
  | select(.metadata.namespace != "ingress-nginx")
  | select(.metadata.namespace != "monitoring")
  '
fi

JQ_FILTER+='
  | [
      .metadata.namespace,
      .metadata.name,
      .spec.nodeName,
      .metadata.creationTimestamp,
      .metadata.ownerReferences[0].kind,
      .metadata.ownerReferences[0].name
    ]
  | @tsv
'

CANDIDATES="$(kubectl get pods -A -o json | jq -r \
  --arg NODE "$DRAIN_NODE" \
  --arg DRAIN_TIME "$DRAIN_TIME" \
  "$JQ_FILTER")"

if [[ -z "$CANDIDATES" ]]; then
  echo "No candidate pods found."
  exit 0
fi

echo "Candidate pods:"
echo "$CANDIDATES"
echo

echo "This can disrupt services. Kubernetes may or may not reschedule replacements onto $DRAIN_NODE."
read -r -p "Type yes to continue: " confirm

if [[ "$confirm" != "yes" ]]; then
  echo "Aborted."
  exit 0
fi

echo "$CANDIDATES" | while IFS=$'\t' read -r ns pod current_node created owner_kind owner_name; do
  echo
  echo "Candidate: $ns/$pod"
  echo "Current node: $current_node"
  echo "Created: $created"
  echo "Owner: $owner_kind/$owner_name"

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "DRY_RUN=true, not deleting."
    continue
  fi

  before_count="$(kubectl get pods -n "$ns" --no-headers 2>/dev/null | wc -l)"

  kubectl delete pod -n "$ns" "$pod"

  case "$owner_kind" in
    ReplicaSet)
      deploy="$(kubectl get rs -n "$ns" "$owner_name" -o jsonpath='{.metadata.ownerReferences[?(@.kind=="Deployment")].name}' 2>/dev/null || true)"
      if [[ -n "$deploy" ]]; then
        echo "Waiting for deployment rollout: $ns/$deploy"
        kubectl rollout status deployment/"$deploy" -n "$ns" --timeout=300s
      else
        echo "Waiting for ReplicaSet-owned replacement pods to become Ready..."
        sleep 20
      fi
      ;;

    StatefulSet)
      echo "Waiting for StatefulSet rollout: $ns/$owner_name"
      kubectl rollout status statefulset/"$owner_name" -n "$ns" --timeout=300s
      ;;

    *)
      echo "Waiting briefly for replacement..."
      sleep 20
      ;;
  esac

  after_count="$(kubectl get pods -n "$ns" --no-headers 2>/dev/null | wc -l)"
  echo "Namespace pod count before/after: $before_count/$after_count"

  echo "Pods now running on $DRAIN_NODE:"
  kubectl get pods -A --field-selector spec.nodeName="$DRAIN_NODE" --no-headers 2>/dev/null | wc -l
done

echo "Updated pod count per node post rebalancing:"
kubectl get pods -A -o json | jq -r '
  .items[]
  | select(.spec.nodeName != null)
  | .spec.nodeName
' | sort | uniq -c | awk '{print $2 ": " $1}'
