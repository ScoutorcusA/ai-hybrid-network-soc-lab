#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

printf 'SOC lab hybrid redeployment\n'

"$SCRIPT_DIR/redeploy-local.sh"
"$REPO_ROOT/scripts/configure-hybrid.sh"

printf '\nWaiting 10 seconds for WireGuard and OSPF to settle...\n'
sleep 10

"$SCRIPT_DIR/validate-hybrid.sh"

printf '\nHybrid redeployment completed successfully.\n'
