#!/usr/bin/env bash
set -uo pipefail

PASS_COUNT=0
FAIL_COUNT=0

SWITCH="clab-soc-local-sw1"
CORE="clab-soc-local-core1"
EDGE="clab-soc-local-edge-fw1"
USER_NODE="clab-soc-local-user1"
GUEST="clab-soc-local-guest1"
ADMIN="clab-soc-local-admin1"
SERVER="clab-soc-local-server1"
SENSOR="clab-soc-local-sensor1"

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

wait_for_output() {
    local name="$1"
    local pattern="$2"
    shift 2
    local output=""

    for attempt in $(seq 1 30); do
        if output=$("$@" 2>&1) && grep -Eq "$pattern" <<<"$output"; then
            pass "$name"
            return 0
        fi

        sleep 1
    done

    fail "$name"
    printf '  Expected output matching: %s\n' "$pattern"
    printf '  Last output: %s\n' "$output"
    return 1
}

log_line_count() {
    local file="$1"

    docker exec "$SENSOR" sh -c '
        if [ -f "$1" ]; then
            wc -l < "$1"
        else
            printf "0\n"
        fi
    ' sh "$file" | tr -d '[:space:]'
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

wait_for_fresh_json() {
    local name="$1"
    local file="$2"
    local start_line="$3"
    local filter="$4"
    local count=0

    for attempt in $(seq 1 20); do
        count=$(fresh_json_count "$file" "$start_line" "$filter")

        if [[ "$count" =~ ^[0-9]+$ ]] && ((count > 0)); then
            pass "$name"
            return 0
        fi

        sleep 1
    done

    fail "$name"
    return 1
}

check_single_fresh_event() {
    local name="$1"
    local file="$2"
    local start_line="$3"
    local filter="$4"
    local count

    count=$(fresh_json_count "$file" "$start_line" "$filter")

    if [[ "$count" == "1" ]]; then
        pass "$name"
    else
        fail "$name"
        printf '  Expected 1 fresh event, found %s\n' "$count"
    fi
}

capture_transit_icmp() {
    docker exec "$SENSOR" sh -c '
        timeout 8 tcpdump -U -nn -i sniff1 -c 1 \
            "icmp and host 10.255.0.2" \
            > /tmp/soc-transit-test.txt 2>&1
    ' &
    local capture_pid=$!

    sleep 1
    docker exec "$ADMIN" ping -c 1 -W 1 10.255.0.2 >/dev/null 2>&1 || true

    if wait "$capture_pid"; then
        docker exec "$SENSOR" grep -q '10.255.0.2' /tmp/soc-transit-test.txt
    else
        return 1
    fi
}

printf '=== Container health and readiness ===\n'

for node in \
    "$SWITCH" \
    "$CORE" \
    "$EDGE" \
    "$USER_NODE" \
    "$GUEST" \
    "$ADMIN" \
    "$SERVER" \
    "$SENSOR"
do
    expect_output \
        "$node is running" \
        '^true$' \
        docker inspect -f '{{.State.Running}}' "$node"
done

wait_for_output \
    "OSPF adjacency reached Full" \
    'Full' \
    docker exec "$CORE" vtysh -c "show ip ospf neighbor"

wait_for_output \
    "Zeek is monitoring sniff0" \
    'zeek.*-i sniff0' \
    docker exec "$SENSOR" pgrep -af zeek

wait_for_output \
    "Zeek is monitoring sniff1" \
    'zeek.*-i sniff1' \
    docker exec "$SENSOR" pgrep -af zeek

wait_for_output \
    "Suricata is monitoring sniff0 with VLAN tracking disabled" \
    'suricata.*-i sniff0.*vlan.use-for-tracking=false' \
    docker exec "$SENSOR" pgrep -af suricata

printf '\n=== Firewall configuration ===\n'

expect_output \
    "core1 input policy is default drop" \
    'policy drop' \
    docker exec "$CORE" nft list chain inet core_filter input

expect_output \
    "core1 forwarding policy is default drop" \
    'policy drop' \
    docker exec "$CORE" nft list chain inet core_filter forward

expect_output \
    "edge-fw1 input policy is default drop" \
    'policy drop' \
    docker exec "$EDGE" nft list chain inet edge_filter input

expect_output \
    "core1 has a Guest-local deny rule" \
    'NFT_CORE_GUEST_LOCAL' \
    docker exec "$CORE" nft list chain inet core_filter forward

expect_output \
    "core1 has a User-Management deny rule" \
    'NFT_CORE_USER_MGMT' \
    docker exec "$CORE" nft list chain inet core_filter forward

printf '\n=== Approved traffic ===\n'

expect_success \
    "User can reach approved server HTTP" \
    docker exec "$USER_NODE" curl -fsS --max-time 3 http://10.10.40.10

expect_success \
    "Admin can ping server1" \
    docker exec "$ADMIN" ping -c 1 -W 1 10.10.40.10

expect_success \
    "Admin can ping core1" \
    docker exec "$ADMIN" ping -c 1 -W 1 10.10.30.1

expect_success \
    "Admin can ping edge-fw1" \
    docker exec "$ADMIN" ping -c 1 -W 1 10.255.0.2

printf '\n=== Prohibited traffic ===\n'

expect_failure \
    "User ICMP to server1 is blocked" \
    docker exec "$USER_NODE" ping -c 1 -W 1 10.10.40.10

expect_failure \
    "User access to the Management VLAN is blocked" \
    docker exec "$USER_NODE" ping -c 1 -W 1 10.10.30.10

expect_failure \
    "Guest access to server1 is blocked" \
    docker exec "$GUEST" ping -c 1 -W 1 10.10.40.10

expect_failure \
    "Server cannot initiate toward User" \
    docker exec "$SERVER" ping -c 1 -W 1 10.10.10.10

expect_failure \
    "User cannot ping core1 directly" \
    docker exec "$USER_NODE" ping -c 1 -W 1 10.10.10.1

expect_failure \
    "core1 cannot send arbitrary ICMP to edge-fw1" \
    docker exec "$CORE" ping -c 1 -W 1 10.255.0.2

printf '\n=== Passive sensor and mirror state ===\n'

expect_success \
    "sniff0 has no IPv4 address" \
    docker exec "$SENSOR" sh -c \
    '! ip -4 -o address show dev sniff0 | grep -q " inet "'

expect_success \
    "sniff1 has no IPv4 address" \
    docker exec "$SENSOR" sh -c \
    '! ip -4 -o address show dev sniff1 | grep -q " inet "'

expect_output \
    "Sensor IP forwarding is disabled" \
    '= 0$' \
    docker exec "$SENSOR" sysctl net.ipv4.ip_forward

expect_output \
    "sniff0 is in promiscuous mode" \
    'PROMISC' \
    docker exec "$SENSOR" ip -d link show sniff0

expect_output \
    "sniff1 is in promiscuous mode" \
    'PROMISC' \
    docker exec "$SENSOR" ip -d link show sniff1

expect_output \
    "sw1 egress mirror sends copies to eth6" \
    'mirred.*eth6' \
    docker exec "$SWITCH" tc filter show dev eth5 egress

expect_success \
    "sw1 has no duplicate ingress mirror" \
    docker exec "$SWITCH" sh -c \
    '! tc filter show dev eth5 ingress | grep -q mirred'

expect_output \
    "core1 ingress mirror sends copies to eth3" \
    'mirred.*eth3' \
    docker exec "$CORE" tc filter show dev eth2 ingress

expect_output \
    "core1 egress mirror sends copies to eth3" \
    'mirred.*eth3' \
    docker exec "$CORE" tc filter show dev eth2 egress

expect_success \
    "sniff1 captures core-edge transit traffic" \
    capture_transit_icmp

printf '\n=== Fresh monitoring evidence ===\n'

ZEEK_CONN_LOG='/var/log/soc/zeek/internal/conn.log'
ZEEK_HTTP_LOG='/var/log/soc/zeek/internal/http.log'
SURICATA_EVE_LOG='/var/log/soc/suricata/eve.json'

ZEEK_CONN_START=$(( $(log_line_count "$ZEEK_CONN_LOG") + 1 ))
ZEEK_HTTP_START=$(( $(log_line_count "$ZEEK_HTTP_LOG") + 1 ))
SURICATA_EVE_START=$(( $(log_line_count "$SURICATA_EVE_LOG") + 1 ))

docker exec "$USER_NODE" \
    curl -fsS --max-time 3 http://10.10.40.10 \
    >/dev/null 2>&1 || true

docker exec "$GUEST" \
    ping -c 1 -W 1 10.10.40.10 \
    >/dev/null 2>&1 || true

ZEEK_CONN_FILTER='select(."id.orig_h" == "10.10.10.10" and ."id.resp_h" == "10.10.40.10" and ."id.resp_p" == 80 and .service == "http")'
ZEEK_HTTP_FILTER='select(."id.orig_h" == "10.10.10.10" and ."id.resp_h" == "10.10.40.10" and .method == "GET" and .status_code == 200)'
SURICATA_HTTP_FILTER='select(.event_type == "alert" and .alert.signature_id == 1000002 and .src_ip == "10.10.10.10" and .dest_ip == "10.10.40.10")'
SURICATA_GUEST_FILTER='select(.event_type == "alert" and .alert.signature_id == 1000001 and .src_ip == "10.10.20.10" and .dest_ip == "10.10.40.10")'

wait_for_fresh_json \
    "Zeek recorded the fresh User-to-server connection" \
    "$ZEEK_CONN_LOG" \
    "$ZEEK_CONN_START" \
    "$ZEEK_CONN_FILTER"

wait_for_fresh_json \
    "Zeek recorded the fresh HTTP transaction" \
    "$ZEEK_HTTP_LOG" \
    "$ZEEK_HTTP_START" \
    "$ZEEK_HTTP_FILTER"

wait_for_fresh_json \
    "Suricata alerted on the fresh approved HTTP request" \
    "$SURICATA_EVE_LOG" \
    "$SURICATA_EVE_START" \
    "$SURICATA_HTTP_FILTER"

wait_for_fresh_json \
    "Suricata alerted on the fresh Guest ICMP attempt" \
    "$SURICATA_EVE_LOG" \
    "$SURICATA_EVE_START" \
    "$SURICATA_GUEST_FILTER"

check_single_fresh_event \
    "Zeek produced one connection record for one HTTP test" \
    "$ZEEK_CONN_LOG" \
    "$ZEEK_CONN_START" \
    "$ZEEK_CONN_FILTER"

check_single_fresh_event \
    "Suricata produced one HTTP alert without mirror duplicates" \
    "$SURICATA_EVE_LOG" \
    "$SURICATA_EVE_START" \
    "$SURICATA_HTTP_FILTER"

check_single_fresh_event \
    "Suricata produced one Guest alert for one echo request" \
    "$SURICATA_EVE_LOG" \
    "$SURICATA_EVE_START" \
    "$SURICATA_GUEST_FILTER"

printf '\n=== Result ===\n'
printf '%d passed, %d failed\n' "$PASS_COUNT" "$FAIL_COUNT"

if ((FAIL_COUNT > 0)); then
    exit 1
fi

printf 'Local lab validation completed successfully.\n'
