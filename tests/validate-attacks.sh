#!/usr/bin/env bash

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ATTACK_SCRIPT="$REPO_ROOT/attacks/guest-scan.sh"

CORE="clab-soc-local-core1"
GUEST="clab-soc-local-guest1"
SENSOR="clab-soc-local-sensor1"

ZEEK_CONN_LOG='/var/log/soc/zeek/internal/conn.log'
SURICATA_EVE_LOG='/var/log/soc/suricata/eve.json'
EXPECTED_PORT_COUNT=12

PASS_COUNT=0
FAIL_COUNT=0

pass() {
  printf 'PASS: %s\n' "$1"
  PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
  printf 'FAIL: %s\n' "$1"
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

print_summary() {
  printf '\n=== Attack validation summary ===\n'
  printf 'Passed: %d\n' "$PASS_COUNT"
  printf 'Failed: %d\n' "$FAIL_COUNT"
}

container_is_running() {
  local container="$1"

  [[ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)" == "true" ]]
}

log_line_count() {
  local file="$1"
  local count

  count=$(docker exec "$SENSOR" sh -c '
    if [ -f "$1" ]; then
      wc -l < "$1"
    else
      printf "0\n"
    fi
  ' sh "$file" 2>/dev/null || true)

  count=$(printf '%s' "$count" | tr -d '[:space:]')

  if [[ "$count" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$count"
  else
    printf '0\n'
  fi
}

fresh_json_count() {
  local file="$1"
  local start_line="$2"
  local filter="$3"

  docker exec "$SENSOR" sh -c '
    file="$1"
    start_line="$2"
    filter="$3"

    if [ ! -f "$file" ]; then
      printf "0\n"
      exit 0
    fi

    tail -n +"$start_line" "$file" |
      jq -c "$filter" 2>/dev/null |
      wc -l
  ' sh "$file" "$start_line" "$filter" | tr -d '[:space:]'
}

fresh_distinct_port_count() {
  local file="$1"
  local start_line="$2"
  local filter="$3"

  docker exec "$SENSOR" sh -c '
    file="$1"
    start_line="$2"
    filter="$3"

    if [ ! -f "$file" ]; then
      printf "0\n"
      exit 0
    fi

    tail -n +"$start_line" "$file" |
      jq -r "$filter | .\"id.resp_p\"" 2>/dev/null |
      sort -nu |
      wc -l
  ' sh "$file" "$start_line" "$filter" | tr -d '[:space:]'
}

wait_for_fresh_count() {
  local file="$1"
  local start_line="$2"
  local filter="$3"
  local minimum="$4"
  local count=0

  for attempt in $(seq 1 20); do
    count=$(fresh_json_count "$file" "$start_line" "$filter")

    if [[ "$count" =~ ^[0-9]+$ ]] && ((count >= minimum)); then
      return 0
    fi

    sleep 1
  done

  return 1
}

guest_local_counter() {
  docker exec "$CORE" nft -a list chain inet core_filter forward 2>/dev/null |
    awk '
      /NFT_CORE_GUEST_LOCAL/ {
        for (field = 1; field <= NF - 2; field++) {
          if ($field == "counter" && $(field + 1) == "packets") {
            print $(field + 2)
            exit
          }
        }
      }
    '
}

printf '=== Attack-test prerequisites ===\n'

if [[ -x "$ATTACK_SCRIPT" ]]; then
  pass "Controlled guest scan script exists and is executable"
else
  fail "Controlled guest scan script exists and is executable"
fi

for container in "$CORE" "$GUEST" "$SENSOR"; do
  if container_is_running "$container"; then
    pass "$container is running"
  else
    fail "$container is running"
  fi
done

if docker exec "$GUEST" command -v nmap >/dev/null 2>&1; then
  pass "Nmap is installed inside guest1"
else
  fail "Nmap is installed inside guest1"
fi

COUNTER_BEFORE=$(guest_local_counter)

if [[ "$COUNTER_BEFORE" =~ ^[0-9]+$ ]]; then
  pass "Guest-local firewall counter is readable"
else
  fail "Guest-local firewall counter is readable"
fi

if ((FAIL_COUNT > 0)); then
  print_summary
  printf 'Prerequisites failed; the scan was not started.\n' >&2
  exit 1
fi

ZEEK_START=$(( $(log_line_count "$ZEEK_CONN_LOG") + 1 ))
SURICATA_START=$(( $(log_line_count "$SURICATA_EVE_LOG") + 1 ))

ZEEK_SCAN_FILTER='select(."id.orig_h" == "10.10.20.10" and ."id.resp_h" == "10.10.40.10" and .proto == "tcp" and (."id.resp_p" as $port | ([22,23,25,53,80,110,139,143,443,445,3389,8080] | index($port)) != null))'
ZEEK_BLOCKED_FILTER='select(."id.orig_h" == "10.10.20.10" and ."id.resp_h" == "10.10.40.10" and .proto == "tcp" and (."id.resp_p" as $port | ([22,23,25,53,80,110,139,143,443,445,3389,8080] | index($port)) != null) and .conn_state == "S0" and .orig_pkts == 1 and .resp_pkts == 0)'
SURICATA_SCAN_FILTER='select(.event_type == "alert" and .alert.signature_id == 1000003 and .src_ip == "10.10.20.10" and .dest_ip == "10.10.40.10")'

printf '\n=== Running bounded guest scan ===\n'
ATTACK_OUTPUT=""

if ATTACK_OUTPUT=$("$ATTACK_SCRIPT" 2>&1); then
  pass "Controlled guest scan completed"
else
  fail "Controlled guest scan completed"
fi

printf '%s\n' "$ATTACK_OUTPUT"

FILTERED_PORT_COUNT=$(grep -Ec '^[0-9]+/tcp[[:space:]]+filtered([[:space:]]|$)' <<<"$ATTACK_OUTPUT")

if [[ "$FILTERED_PORT_COUNT" == "$EXPECTED_PORT_COUNT" ]]; then
  pass "Nmap reported all 12 selected ports as filtered"
else
  fail "Nmap reported all 12 selected ports as filtered"
  printf '  Expected: %d filtered ports\n' "$EXPECTED_PORT_COUNT"
  printf '  Found: %s filtered ports\n' "$FILTERED_PORT_COUNT"
fi

printf '\nWaiting for fresh Suricata and Zeek records...\n'

if wait_for_fresh_count \
  "$SURICATA_EVE_LOG" \
  "$SURICATA_START" \
  "$SURICATA_SCAN_FILTER" \
  1; then
  pass "Suricata generated a fresh SID 1000003 scan alert"
else
  fail "Suricata generated a fresh SID 1000003 scan alert"
fi

if wait_for_fresh_count \
  "$ZEEK_CONN_LOG" \
  "$ZEEK_START" \
  "$ZEEK_SCAN_FILTER" \
  "$EXPECTED_PORT_COUNT"; then
  pass "Zeek recorded all 12 fresh scan connections"
else
  fail "Zeek recorded all 12 fresh scan connections"
fi

COUNTER_AFTER=$(guest_local_counter)

if [[ "$COUNTER_AFTER" =~ ^[0-9]+$ ]]; then
  COUNTER_DELTA=$((COUNTER_AFTER - COUNTER_BEFORE))
else
  COUNTER_DELTA=0
fi

if ((COUNTER_DELTA >= EXPECTED_PORT_COUNT)); then
  pass "core1 dropped at least 12 new Guest-to-local packets"
else
  fail "core1 dropped at least 12 new Guest-to-local packets"
fi

ZEEK_SCAN_COUNT=$(fresh_json_count "$ZEEK_CONN_LOG" "$ZEEK_START" "$ZEEK_SCAN_FILTER")
ZEEK_BLOCKED_COUNT=$(fresh_json_count "$ZEEK_CONN_LOG" "$ZEEK_START" "$ZEEK_BLOCKED_FILTER")
ZEEK_DISTINCT_PORTS=$(fresh_distinct_port_count "$ZEEK_CONN_LOG" "$ZEEK_START" "$ZEEK_SCAN_FILTER")
SURICATA_ALERT_COUNT=$(fresh_json_count "$SURICATA_EVE_LOG" "$SURICATA_START" "$SURICATA_SCAN_FILTER")

if [[ "$ZEEK_DISTINCT_PORTS" == "$EXPECTED_PORT_COUNT" ]]; then
  pass "Zeek observed every selected destination port"
else
  fail "Zeek observed every selected destination port"
fi

if [[ "$ZEEK_SCAN_COUNT" == "$EXPECTED_PORT_COUNT" && "$ZEEK_BLOCKED_COUNT" == "$EXPECTED_PORT_COUNT" ]]; then
  pass "Every Zeek scan record is S0 with one SYN and no response"
else
  fail "Every Zeek scan record is S0 with one SYN and no response"
fi

printf '\n=== Fresh evidence ===\n'
printf 'Firewall counter: %s -> %s (delta: %s)\n' \
  "$COUNTER_BEFORE" "$COUNTER_AFTER" "$COUNTER_DELTA"
printf 'Suricata SID 1000003 alerts: %s\n' "$SURICATA_ALERT_COUNT"
printf 'Zeek scan records: %s\n' "$ZEEK_SCAN_COUNT"
printf 'Zeek distinct destination ports: %s\n' "$ZEEK_DISTINCT_PORTS"

print_summary

if ((FAIL_COUNT > 0)); then
  exit 1
fi

printf 'Controlled guest scan prevention and detection validated successfully.\n'
