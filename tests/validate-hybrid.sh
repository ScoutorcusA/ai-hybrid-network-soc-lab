#!/usr/bin/env bash

set -uo pipefail

if [[ -d "$HOME/.local/bin" ]]; then
  PATH="$HOME/.local/bin:$PATH"
fi
export PATH

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
TERRAFORM_DIR="$REPO_ROOT/terraform"

CORE="clab-soc-local-core1"
EDGE="clab-soc-local-edge-fw1"
USER_NODE="clab-soc-local-user1"
GUEST="clab-soc-local-guest1"
ADMIN="clab-soc-local-admin1"
SENSOR="clab-soc-local-sensor1"

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

expect_success() {
  local name="$1"
  shift
  local output

  if output=$("$@" 2>&1); then
    pass "$name"
  else
    fail "$name"
    printf '  %s\n' "$output"
  fi
}

expect_failure() {
  local name="$1"
  shift
  local output

  if output=$("$@" 2>&1); then
    fail "$name unexpectedly succeeded"
    printf '  %s\n' "$output"
  else
    pass "$name"
  fi
}

expect_output() {
  local name="$1"
  local pattern="$2"
  shift 2
  local output

  if output=$("$@" 2>&1) && grep -Eq "$pattern" <<<"$output"; then
    pass "$name"
  else
    fail "$name"
    printf '  Expected output matching: %s\n' "$pattern"
    printf '  %s\n' "$output"
  fi
}

wait_for_handshake() {
  local timestamp=0

  for attempt in $(seq 1 30); do
    timestamp=$(docker exec "$EDGE" wg show wg0 latest-handshakes 2>/dev/null | awk 'NR == 1 { print $2 }')

    if [[ "$timestamp" =~ ^[0-9]+$ ]] && ((timestamp > 0)); then
      return 0
    fi

    sleep 1
  done

  return 1
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

fresh_json_record() {
  local file="$1"
  local start_line="$2"
  local filter="$3"

  docker exec "$SENSOR" sh -c '
    file="$1"
    start_line="$2"
    filter="$3"

    if [ ! -f "$file" ]; then
      exit 1
    fi

    tail -n +"$start_line" "$file" |
      jq -c "$filter" 2>/dev/null |
      tail -n 1
  ' sh "$file" "$start_line" "$filter"
}

wait_for_fresh_json_record() {
  local file="$1"
  local start_line="$2"
  local filter="$3"
  local record=""

  for attempt in $(seq 1 20); do
    record=$(fresh_json_record "$file" "$start_line" "$filter" 2>/dev/null || true)

    if [[ -n "$record" ]]; then
      printf '%s\n' "$record"
      return 0
    fi

    sleep 1
  done

  return 1
}

printf '=== Hybrid tunnel and route state ===\n'

expect_output \
  "edge-fw1 has WireGuard interface 10.254.0.1/30" \
  '10\.254\.0\.1/30' \
  docker exec "$EDGE" ip -4 address show dev wg0

expect_success \
  "WireGuard completed a handshake" \
  wait_for_handshake

expect_output \
  "edge-fw1 has the AWS VPC route through wg0" \
  'directly connected, wg0' \
  docker exec "$EDGE" vtysh -c "show ip route 10.50.0.0/16"

expect_output \
  "core1 learned the AWS VPC route through OSPF" \
  'ospf|OSPF|10\.255\.0\.2' \
  docker exec "$CORE" vtysh -c "show ip route 10.50.0.0/16"

expect_output \
  "edge-fw1 hybrid forwarding policy is default drop" \
  'policy drop' \
  docker exec "$EDGE" nft list chain inet edge_filter forward

expect_output \
  "sensor1 is running for hybrid monitoring" \
  '^true$' \
  docker inspect -f '{{.State.Running}}' "$SENSOR"

ZEEK_TRANSIT_CONN_LOG='/var/log/soc/zeek/transit/conn.log'
ZEEK_TRANSIT_SSL_LOG='/var/log/soc/zeek/transit/ssl.log'
ZEEK_CONN_START=$(( $(log_line_count "$ZEEK_TRANSIT_CONN_LOG") + 1 ))
ZEEK_SSL_START=$(( $(log_line_count "$ZEEK_TRANSIT_SSL_LOG") + 1 ))

printf '\n=== Approved hybrid traffic ===\n'

expect_output \
  "User can reach the private AWS HTTPS application" \
  'Hybrid SOC Lab AWS Application' \
  docker exec "$USER_NODE" curl -kfsS --connect-timeout 5 --max-time 10 https://10.50.20.10

expect_success \
  "Admin can ping the private AWS application" \
  docker exec "$ADMIN" ping -c 1 -W 3 10.50.20.10

expect_success \
  "Admin can ping the AWS WireGuard gateway private address" \
  docker exec "$ADMIN" ping -c 1 -W 3 10.50.10.10

printf '\n=== Fresh hybrid monitoring evidence ===\n'

ZEEK_CONN_FILTER='select(."id.orig_h" == "10.10.10.10" and ."id.resp_h" == "10.50.20.10" and ."id.resp_p" == 443 and .proto == "tcp" and .service == "ssl" and .conn_state == "SF")'
ZEEK_SSL_FILTER='select(."id.orig_h" == "10.10.10.10" and ."id.resp_h" == "10.50.20.10" and ."id.resp_p" == 443 and .established == true)'
ZEEK_CONN_RECORD=""
ZEEK_SSL_RECORD=""

if ZEEK_CONN_RECORD=$(wait_for_fresh_json_record \
  "$ZEEK_TRANSIT_CONN_LOG" \
  "$ZEEK_CONN_START" \
  "$ZEEK_CONN_FILTER"); then
  pass "Zeek recorded the fresh User-to-AWS TLS connection"
else
  fail "Zeek recorded the fresh User-to-AWS TLS connection"
fi

if ZEEK_SSL_RECORD=$(wait_for_fresh_json_record \
  "$ZEEK_TRANSIT_SSL_LOG" \
  "$ZEEK_SSL_START" \
  "$ZEEK_SSL_FILTER"); then
  pass "Zeek recorded the fresh completed TLS session"
else
  fail "Zeek recorded the fresh completed TLS session"
fi

ZEEK_CONN_UID=$(jq -r '.uid // empty' <<<"$ZEEK_CONN_RECORD" 2>/dev/null || true)
ZEEK_SSL_UID=$(jq -r '.uid // empty' <<<"$ZEEK_SSL_RECORD" 2>/dev/null || true)

if [[ -n "$ZEEK_CONN_UID" && "$ZEEK_CONN_UID" == "$ZEEK_SSL_UID" ]]; then
  pass "Zeek connection and TLS records share the same uid"
else
  fail "Zeek connection and TLS records share the same uid"
  printf '  conn.log uid: %s\n' "${ZEEK_CONN_UID:-missing}"
  printf '  ssl.log uid: %s\n' "${ZEEK_SSL_UID:-missing}"
fi

printf '\n=== Prohibited hybrid traffic ===\n'

expect_failure \
  "Guest cannot reach the private AWS HTTPS application" \
  docker exec "$GUEST" curl -kfsS --connect-timeout 3 --max-time 5 https://10.50.20.10

expect_failure \
  "User ICMP to the private AWS application is blocked" \
  docker exec "$USER_NODE" ping -c 1 -W 2 10.50.20.10

printf '\n=== AWS exposure check ===\n'

cd "$TERRAFORM_DIR"
AWS_REGION=$(terraform output -raw aws_region)
APP_INSTANCE_ID=$(terraform output -raw private_app_instance_id)

expect_output \
  "Private AWS application has no public IPv4 address" \
  '^None$' \
  aws ec2 describe-instances \
    --region "$AWS_REGION" \
    --instance-ids "$APP_INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text

printf '\n=== Hybrid validation summary ===\n'
printf 'Passed: %d\n' "$PASS_COUNT"
printf 'Failed: %d\n' "$FAIL_COUNT"

if ((FAIL_COUNT > 0)); then
  exit 1
fi

printf 'All hybrid acceptance tests passed.\n'
