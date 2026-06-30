
#!/usr/bin/env bash
# to be executed inside the wire-utility pod
set -euo pipefail

CQLSH="${CQLSH:-cqlsh}"
OUT_DIR="${OUT_DIR:-./cql_export}"

mkdir -p "$OUT_DIR"

$CQLSH -e "COPY gundeck.user_push (client, arn, usr) TO '$OUT_DIR/user_push.csv' WITH HEADER = true AND PAGESIZE = 100 AND NUMPROCESSES = 1;"
$CQLSH -e "COPY galley.clients (user, clients) TO '$OUT_DIR/galley_clients.csv' WITH HEADER = true AND PAGESIZE = 100 AND NUMPROCESSES = 1;"
$CQLSH -e "COPY brig.user (id, email) TO '$OUT_DIR/brig_user.csv' WITH HEADER = true AND PAGESIZE = 100 AND NUMPROCESSES = 1;"

echo "CSV files written to: $OUT_DIR"
