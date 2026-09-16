#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
INPUT_DIR="${1:-$REPO_ROOT/python/fixtures/observed/raw}"
OUTPUT_DIR="$REPO_ROOT/python/outputs/validation"

if [[ ! -d "$INPUT_DIR" ]]; then
  printf 'Evidence directory not found: %s\n' "$INPUT_DIR" >&2
  printf 'Pass a raw evidence directory or create the observed fixture first.\n' >&2
  exit 1
fi

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

printf '=== Python tests ===\n'
python -m pytest "$REPO_ROOT/python/tests" -q

printf '\n=== Normalize evidence ===\n'
soc-analyst normalize \
  --input "$INPUT_DIR" \
  --output "$OUTPUT_DIR/events.jsonl"

printf '\n=== Correlate incidents ===\n'
soc-analyst correlate \
  --input "$OUTPUT_DIR/events.jsonl" \
  --output "$OUTPUT_DIR/incidents.json"

printf '\n=== Generate deterministic mock reports ===\n'
soc-analyst report \
  --mode mock \
  --input "$OUTPUT_DIR/incidents.json" \
  --output "$OUTPUT_DIR/reports.json"

printf '\n=== Validate reports against evidence ===\n'
soc-analyst validate \
  --incidents "$OUTPUT_DIR/incidents.json" \
  --reports "$OUTPUT_DIR/reports.json"

printf '\nPASS: Phase 7 evidence pipeline completed successfully.\n'

