#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
SENSOR="clab-soc-local-sensor1"
SERVER="clab-soc-local-server1"
ZEEK_LOG="/var/log/soc/zeek/internal/conn.log"
SURICATA_LOG="/var/log/soc/suricata/eve.json"
SSHD_LOG="/var/log/soc/sshd.log"

line_count() {
  local container="$1"
  local path="$2"
  docker exec "$container" sh -c '
    if [ -f "$1" ]; then wc -l < "$1"; else printf "0\n"; fi
  ' sh "$path" | tr -d '[:space:]'
}

for container in "$SENSOR" "$SERVER"; do
  if [[ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)" != "true" ]]; then
    printf 'Required container is not running: %s\n' "$container" >&2
    exit 1
  fi
done

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="$REPO_ROOT/python/runs/$RUN_ID"
RAW_DIR="$RUN_DIR/raw"
mkdir -p "$RAW_DIR"

ZEEK_START=$(( $(line_count "$SENSOR" "$ZEEK_LOG") + 1 ))
SURICATA_START=$(( $(line_count "$SENSOR" "$SURICATA_LOG") + 1 ))
SSHD_START=$(( $(line_count "$SERVER" "$SSHD_LOG") + 1 ))
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

printf 'Collecting a bounded Phase 7 evidence run: %s\n' "$RUN_ID"
"$REPO_ROOT/tests/validate-attacks.sh" | tee "$RAW_DIR/attack-validation.txt"

docker exec "$SENSOR" tail -n +"$ZEEK_START" "$ZEEK_LOG" > "$RAW_DIR/zeek-conn.log"
docker exec "$SENSOR" tail -n +"$SURICATA_START" "$SURICATA_LOG" > "$RAW_DIR/suricata-eve.json"
docker exec "$SERVER" tail -n +"$SSHD_START" "$SSHD_LOG" > "$RAW_DIR/sshd.log"

FINISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat > "$RUN_DIR/manifest.json" <<EOF
{
  "run_id": "$RUN_ID",
  "started_at": "$STARTED_AT",
  "finished_at": "$FINISHED_AT",
  "evidence_type": "observed_lab_evidence",
  "scenarios": ["guest_port_scan", "ssh_password_guessing"]
}
EOF

printf '\nEvidence directory: %s\n' "$RUN_DIR"

