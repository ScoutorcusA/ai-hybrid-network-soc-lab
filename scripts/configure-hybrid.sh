#!/usr/bin/env bash

set -Eeuo pipefail

if [[ -d "$HOME/.local/bin" ]]; then
  PATH="$HOME/.local/bin:$PATH"
fi
export PATH

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
TERRAFORM_DIR="$REPO_ROOT/terraform"
EDGE_CONTAINER="clab-soc-local-edge-fw1"
EDGE_SECRET_DIR="$REPO_ROOT/containerlab/configs/edge-fw1/secrets"
LOCAL_PRIVATE_KEY="$EDGE_SECRET_DIR/privatekey"
LOCAL_PUBLIC_KEY="$EDGE_SECRET_DIR/publickey"
LOCAL_WG_CONFIG="$EDGE_SECRET_DIR/wg0.conf"

require_command() {
  local command_name="$1"

  if ! command -v "$command_name" >/dev/null 2>&1; then
    printf 'Required command is unavailable: %s\n' "$command_name" >&2
    exit 1
  fi
}

run_ssm_command() {
  local instance_id="$1"
  local region="$2"
  local comment="$3"
  local command_text="$4"
  local parameters
  local command_id
  local status
  local stdout
  local stderr

  parameters=$(jq -nc --arg command "$command_text" '{commands: [$command]}')
  command_id=$(aws ssm send-command \
    --region "$region" \
    --instance-ids "$instance_id" \
    --document-name AWS-RunShellScript \
    --comment "$comment" \
    --parameters "$parameters" \
    --query Command.CommandId \
    --output text)

  aws ssm wait command-executed \
    --region "$region" \
    --command-id "$command_id" \
    --instance-id "$instance_id"

  status=$(aws ssm get-command-invocation \
    --region "$region" \
    --command-id "$command_id" \
    --instance-id "$instance_id" \
    --query Status \
    --output text)

  stdout=$(aws ssm get-command-invocation \
    --region "$region" \
    --command-id "$command_id" \
    --instance-id "$instance_id" \
    --query StandardOutputContent \
    --output text)

  stderr=$(aws ssm get-command-invocation \
    --region "$region" \
    --command-id "$command_id" \
    --instance-id "$instance_id" \
    --query StandardErrorContent \
    --output text)

  if [[ "$status" != "Success" ]]; then
    printf 'SSM command failed with status %s.\n%s\n' "$status" "$stderr" >&2
    exit 1
  fi

  printf '%s' "$stdout"
}

for command_name in aws docker jq terraform wg; do
  require_command "$command_name"
done

if ! docker inspect "$EDGE_CONTAINER" >/dev/null 2>&1; then
  printf 'The edge container is not running: %s\n' "$EDGE_CONTAINER" >&2
  printf 'Run tests/redeploy-local.sh before configuring the hybrid tunnel.\n' >&2
  exit 1
fi

cd "$TERRAFORM_DIR"

AWS_REGION=$(terraform output -raw aws_region)
AWS_WG_INSTANCE_ID=$(terraform output -raw wireguard_instance_id)
AWS_WG_ENDPOINT=$(terraform output -raw wireguard_public_ip)
LOCAL_PUBLIC_IP_CIDR=$(sed -n 's/^[[:space:]]*local_public_ip_cidr[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' terraform.tfvars)

if [[ -z "$LOCAL_PUBLIC_IP_CIDR" ]]; then
  printf 'Could not read local_public_ip_cidr from terraform.tfvars.\n' >&2
  exit 1
fi

aws sts get-caller-identity --region "$AWS_REGION" >/dev/null

install -d -m 0700 "$EDGE_SECRET_DIR"

if [[ ! -s "$LOCAL_PRIVATE_KEY" ]]; then
  umask 077
  wg genkey > "$LOCAL_PRIVATE_KEY"
fi

wg pubkey < "$LOCAL_PRIVATE_KEY" > "$LOCAL_PUBLIC_KEY"
chmod 0600 "$LOCAL_PRIVATE_KEY" "$LOCAL_PUBLIC_KEY"

LOCAL_PUBLIC_KEY_VALUE=$(tr -d '\r\n' < "$LOCAL_PUBLIC_KEY")
AWS_PUBLIC_KEY=$(run_ssm_command \
  "$AWS_WG_INSTANCE_ID" \
  "$AWS_REGION" \
  "Read SOC lab WireGuard public key" \
  "cat /etc/wireguard/publickey")
AWS_PUBLIC_KEY=$(printf '%s' "$AWS_PUBLIC_KEY" | tr -d '\r\n')

if [[ ! "$LOCAL_PUBLIC_KEY_VALUE" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
  printf 'The generated local WireGuard public key is invalid.\n' >&2
  exit 1
fi

if [[ ! "$AWS_PUBLIC_KEY" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
  printf 'The AWS WireGuard public key returned by SSM is invalid.\n' >&2
  exit 1
fi

LOCAL_PRIVATE_KEY_VALUE=$(tr -d '\r\n' < "$LOCAL_PRIVATE_KEY")

umask 077
{
  printf '[Interface]\n'
  printf 'Address = 10.254.0.1/30\n'
  printf 'PrivateKey = %s\n' "$LOCAL_PRIVATE_KEY_VALUE"
  printf 'Table = off\n\n'
  printf '[Peer]\n'
  printf 'PublicKey = %s\n' "$AWS_PUBLIC_KEY"
  printf 'Endpoint = %s:51820\n' "$AWS_WG_ENDPOINT"
  printf 'AllowedIPs = 10.50.0.0/16, 10.254.0.2/32\n'
  printf 'PersistentKeepalive = 25\n'
} > "$LOCAL_WG_CONFIG"
chmod 0600 "$LOCAL_WG_CONFIG"

read -r -d '' AWS_CONFIG_SCRIPT <<EOF || true
set -euo pipefail

dnf install -y nftables wireguard-tools

PRIVATE_KEY=\$(tr -d '\\r\\n' < /etc/wireguard/privatekey)

cat > /etc/wireguard/wg0.conf <<WGEOF
[Interface]
Address = 10.254.0.2/30
ListenPort = 51820
PrivateKey = \$PRIVATE_KEY

[Peer]
PublicKey = $LOCAL_PUBLIC_KEY_VALUE
AllowedIPs = 10.10.0.0/16, 10.254.0.1/32
WGEOF

chmod 0600 /etc/wireguard/wg0.conf

cat > /etc/nftables/soclab-wireguard.nft <<'NFTEOF'
flush ruleset

table inet soclab_filter {
    chain input {
        type filter hook input priority 0;
        policy drop;

        ct state invalid counter drop
        ct state established,related counter accept
        iifname "lo" counter accept

        ip saddr $LOCAL_PUBLIC_IP_CIDR udp dport 51820 counter accept

        iifname "wg0" ip saddr 10.254.0.1 icmp type echo-request counter accept
        iifname "wg0" ip saddr 10.10.30.0/24 tcp dport 22 ct state new counter accept
        iifname "wg0" ip saddr 10.10.30.0/24 icmp type echo-request counter accept

        limit rate 5/second burst 10 packets log prefix "NFT_AWS_INPUT_DENY " counter drop
    }

    chain forward {
        type filter hook forward priority 0;
        policy drop;

        ct state invalid counter drop
        ct state established,related counter accept

        iifname "wg0" ip saddr 10.10.10.0/24 ip daddr 10.50.20.10 tcp dport 443 ct state new counter accept
        iifname "wg0" ip saddr 10.10.30.0/24 ip daddr 10.50.20.10 tcp dport { 22, 443 } ct state new counter accept
        iifname "wg0" ip saddr 10.10.30.0/24 ip daddr 10.50.20.10 icmp type echo-request counter accept

        ip saddr 10.50.0.0/16 ip daddr { 10.10.10.0/24, 10.10.30.0/24 } ct state new counter drop

        limit rate 5/second burst 10 packets log prefix "NFT_AWS_FORWARD_DENY " counter drop
    }
}
NFTEOF

printf 'include "/etc/nftables/soclab-wireguard.nft"\n' > /etc/sysconfig/nftables.conf

nft -c -f /etc/nftables/soclab-wireguard.nft
systemctl enable wg-quick@wg0 nftables
systemctl restart wg-quick@wg0
nft -f /etc/nftables/soclab-wireguard.nft
EOF

run_ssm_command \
  "$AWS_WG_INSTANCE_ID" \
  "$AWS_REGION" \
  "Configure SOC lab AWS WireGuard peer and firewall" \
  "$AWS_CONFIG_SCRIPT" \
  >/dev/null

docker exec "$EDGE_CONTAINER" sh -c 'wg-quick down wg0 >/dev/null 2>&1 || true; install -d -m 0700 /etc/wireguard'
docker cp "$LOCAL_WG_CONFIG" "$EDGE_CONTAINER:/etc/wireguard/wg0.conf"
docker exec "$EDGE_CONTAINER" chmod 0600 /etc/wireguard/wg0.conf
docker exec "$EDGE_CONTAINER" wg-quick up wg0
docker exec "$EDGE_CONTAINER" nft -f /etc/nftables/edge-firewall.nft
docker exec "$EDGE_CONTAINER" vtysh -f /etc/frr/frr.conf

printf 'Hybrid WireGuard configuration completed.\n'
printf 'The private keys remain outside Git in: %s\n' "$EDGE_SECRET_DIR"
