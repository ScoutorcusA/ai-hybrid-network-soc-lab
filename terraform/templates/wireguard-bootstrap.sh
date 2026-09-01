#!/bin/bash
set -euxo pipefail

dnf install -y wireguard-tools

install -d -m 0700 /etc/wireguard

if [[ ! -f /etc/wireguard/privatekey ]]; then
  umask 077
  wg genkey > /etc/wireguard/privatekey
  wg pubkey < /etc/wireguard/privatekey > /etc/wireguard/publickey
fi

cat > /etc/sysctl.d/90-soclab-wireguard.conf <<'EOF'
net.ipv4.ip_forward = 1
EOF

sysctl --system
systemctl enable --now amazon-ssm-agent

touch /var/lib/soclab-wireguard-bootstrap-complete
