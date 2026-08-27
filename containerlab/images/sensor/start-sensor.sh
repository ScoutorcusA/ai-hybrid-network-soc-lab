#!/usr/bin/env bash
set -euo pipefail

wait_for_interface() {
    local interface="$1"

    for attempt in $(seq 1 60); do
        if ip link show "$interface" >/dev/null 2>&1; then
            return 0
        fi

        sleep 1
    done

    echo "ERROR: interface $interface did not appear"
    return 1
}

for interface in sniff0 sniff1; do
    wait_for_interface "$interface"

    ip link set dev "$interface" up
    ip link set dev "$interface" promisc on

    # The monitoring interfaces should not have Layer-3 addresses.
    ip address flush dev "$interface"
done

mkdir -p \
    /var/log/soc/zeek/internal \
    /var/log/soc/zeek/transit \
    /var/log/soc/suricata

# Zeek instance for the internal VLAN trunk.
(
    cd /var/log/soc/zeek/internal

    exec zeek \
        -C \
        -i sniff0 \
        /opt/soc/zeek/local.zeek
) &
ZEEK_INTERNAL_PID=$!

# Zeek instance for the core-to-edge transit link.
(
    cd /var/log/soc/zeek/transit

    exec zeek \
        -C \
        -i sniff1 \
        /opt/soc/zeek/local.zeek
) &
ZEEK_TRANSIT_PID=$!

# Suricata initially watches the internal mirror.
suricata \
    -c /etc/suricata/suricata.yaml \
    -i sniff0 \
    -l /var/log/soc/suricata \
    -S /opt/soc/suricata/local.rules \
    --set vlan.use-for-tracking=false &
SURICATA_PID=$!

cleanup() {
    kill \
        "$ZEEK_INTERNAL_PID" \
        "$ZEEK_TRANSIT_PID" \
        "$SURICATA_PID" \
        2>/dev/null || true

    wait 2>/dev/null || true
}

trap cleanup EXIT INT TERM

wait -n \
    "$ZEEK_INTERNAL_PID" \
    "$ZEEK_TRANSIT_PID" \
    "$SURICATA_PID"
