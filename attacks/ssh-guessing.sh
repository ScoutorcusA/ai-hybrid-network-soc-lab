#!/usr/bin/env bash

set -Eeuo pipefail

ADMIN="clab-soc-local-admin1"
SERVER="clab-soc-local-server1"
TARGET="10.10.40.10"
USERNAME="socops"
WRONG_PASSWORD="definitely-not-the-lab-password"
ATTEMPTS=6

if (($# != 0)); then
  printf 'Usage: %s takes no arguments.\n' "$0" >&2
  printf 'The source, destination, account, and attempt count are fixed for lab safety.\n' >&2
  exit 2
fi

if ! command -v docker >/dev/null 2>&1; then
  printf 'Docker is required but was not found.\n' >&2
  exit 1
fi

for container in "$ADMIN" "$SERVER"; do
  if [[ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)" != "true" ]]; then
    printf 'Required container is not running: %s\n' "$container" >&2
    exit 1
  fi
done

if ! docker exec "$ADMIN" sh -c 'command -v sshpass >/dev/null 2>&1'; then
  printf 'sshpass is not installed inside %s. Redeploy the lab first.\n' "$ADMIN" >&2
  exit 1
fi

printf 'Controlled SOC lab SSH guessing simulation\n'
printf 'Actor: admin1 (10.10.30.10)\n'
printf 'Target: server1 (%s)\n' "$TARGET"
printf 'Account: %s\n' "$USERNAME"
printf 'Expected result: every authentication attempt fails\n\n'

for attempt in $(seq 1 "$ATTEMPTS"); do
  printf 'Attempt %s of %s\n' "$attempt" "$ATTEMPTS"

  if docker exec \
    -e SSHPASS="$WRONG_PASSWORD" \
    "$ADMIN" \
    sshpass -e ssh \
      -o ConnectTimeout=3 \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      -o NumberOfPasswordPrompts=1 \
      "$USERNAME@$TARGET" true
  then
    printf 'Unexpected successful SSH login; stopping immediately.\n' >&2
    exit 1
  fi

  sleep 1
done

printf '\nAll controlled SSH attempts failed as expected.\n'
