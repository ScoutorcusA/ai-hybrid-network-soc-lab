#!/usr/bin/env bash

set -Eeuo pipefail

GUEST="clab-soc-local-guest1"
TARGET="10.10.40.10"
PORTS="22,23,25,53,80,110,139,143,443,445,3389,8080"

if (($# != 0)); then
  printf 'Usage: %s takes no arguments.\n' "$0" >&2
  printf 'The source, destination, and ports are intentionally fixed for lab safety.\n' >&2
  exit 2
fi

if ! command -v docker >/dev/null 2>&1; then
  printf 'Docker is required but was not found.\n' >&2
  exit 1
fi

if [[ "$(docker inspect -f '{{.State.Running}}' "$GUEST" 2>/dev/null || true)" != "true" ]]; then
  printf 'The guest container is not running: %s\n' "$GUEST" >&2
  exit 1
fi

if ! docker exec "$GUEST" sh -c 'command -v nmap >/dev/null 2>&1'; then
  printf 'Nmap is not installed inside %s. Redeploy the lab first.\n' "$GUEST" >&2
  exit 1
fi

printf 'Controlled SOC lab simulation\n'
printf 'Actor: guest1 (10.10.20.10)\n'
printf 'Target: server1 (%s)\n' "$TARGET"
printf 'Ports: %s\n\n' "$PORTS"

docker exec "$GUEST" \
  nmap -Pn -n -sS -T4 --max-retries 0 \
  -p "$PORTS" \
  "$TARGET"
