#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

TOPOLOGY="$REPO_ROOT/containerlab/local.clab.yml"
VALIDATION_SCRIPT="$REPO_ROOT/tests/validate-local.sh"
LOG_DIR="$REPO_ROOT/monitoring/logs"
ARCHIVE_ROOT="$REPO_ROOT/monitoring/data/redeploy-archives"
ARCHIVE_PATH=""

handle_error() {
  local status=$?
  trap - ERR
  printf '\nRedeployment failed while running: %s\n' "$BASH_COMMAND" >&2
  printf 'The lab has been left in its current state for troubleshooting.\n' >&2
  exit "$status"
}

trap handle_error ERR

require_file() {
  local path="$1"

  if [[ ! -f "$path" ]]; then
    printf 'Required file is missing: %s\n' "$path" >&2
    exit 1
  fi
}

require_command() {
  local command_name="$1"

  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'Required command is unavailable: %s\n' "$command_name" >&2
    exit 1
  fi
}

build_image() {
  local image_tag="$1"
  local build_context="$2"

  printf '\nBuilding %s...\n' "$image_tag"
  docker build --tag "$image_tag" "$build_context"
}

printf 'SOC lab clean redeployment\n'
printf 'Project: %s\n' "$REPO_ROOT"

require_command docker
require_command containerlab
require_file "$TOPOLOGY"
require_file "$VALIDATION_SCRIPT"
require_file "$REPO_ROOT/containerlab/images/switch/Dockerfile"
require_file "$REPO_ROOT/containerlab/images/endpoint/Dockerfile"
require_file "$REPO_ROOT/containerlab/images/router/Dockerfile"
require_file "$REPO_ROOT/containerlab/images/sensor/Dockerfile"
require_file "$REPO_ROOT/monitoring/zeek/local.zeek"
require_file "$REPO_ROOT/monitoring/suricata/local.rules"

if [[ ! -x "$VALIDATION_SCRIPT" ]]; then
  printf 'Validation script is not executable: %s\n' "$VALIDATION_SCRIPT" >&2
  exit 1
fi

printf '\nChecking access to Docker...\n'
docker info >/dev/null

if docker ps -a --format '{{.Names}}' | grep -q '^clab-soc-local-'; then
  printf '\nDestroying the existing soc-local lab...\n'
  containerlab destroy --topo "$TOPOLOGY" --cleanup
else
  printf '\nNo existing soc-local containers were found; skipping destroy.\n'
fi

if [[ -d "$LOG_DIR" ]] && [[ -n "$(find "$LOG_DIR" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
  archive_stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  ARCHIVE_PATH="$ARCHIVE_ROOT/${archive_stamp}-$$"
  mkdir -p "$ARCHIVE_PATH"
  mv "$LOG_DIR" "$ARCHIVE_PATH/logs"
  printf '\nArchived previous sensor logs at:\n%s\n' "$ARCHIVE_PATH/logs"
fi

mkdir -p \
  "$LOG_DIR/zeek/internal" \
  "$LOG_DIR/zeek/transit" \
  "$LOG_DIR/server1" \
  "$LOG_DIR/suricata"

build_image soclab-switch:0.1 "$REPO_ROOT/containerlab/images/switch"
build_image soclab-endpoint:0.1 "$REPO_ROOT/containerlab/images/endpoint"
build_image soclab-router:0.1 "$REPO_ROOT/containerlab/images/router"
build_image soclab-sensor:0.1 "$REPO_ROOT/containerlab/images/sensor"

printf '\nDeploying a fresh soc-local lab...\n'
containerlab deploy --topo "$TOPOLOGY"

printf '\nWaiting 15 seconds for the lab infrastructure to settle...\n'
sleep 15

printf '\nRunning the complete local acceptance test suite...\n'
"$VALIDATION_SCRIPT"

printf '\nClean redeployment completed successfully.\n'
printf 'The validated lab has been left running.\n'

if [[ -n "$ARCHIVE_PATH" ]]; then
  printf 'Previous logs are preserved at: %s/logs\n' "$ARCHIVE_PATH"
fi
