# AI-Assisted Hybrid Network SOC Lab

I built this project to practice networking, cloud security, detection engineering, and incident analysis in one lab. It combines a segmented local enterprise network with a temporary AWS VPC through WireGuard, monitors traffic with Zeek and Suricata, and turns the evidence into AI-assisted incident reports.

The AI is not the source of truth. Python calculates the facts first, the model drafts a report, a validator rejects unsupported values, and a human still reviews the final meaning.

> [Read my full build and investigation writeup in Notion](https://www.notion.so/AI-Assisted-Hybrid-Network-SOC-Lab-3bdc7041bd0a815da536c3a0462cc7a7)

## What I built

- Four local security zones using VLANs: User, Guest, Management, and Server.
- A VLAN-aware Linux switch and FRRouting routers in Containerlab.
- OSPF between the core router and edge firewall.
- Default-deny nftables policies for inter-VLAN and router traffic.
- A temporary AWS VPC with a WireGuard gateway and private application server.
- A routed tunnel that preserves the original local source address.
- A passive sensor running Zeek and Suricata on two mirrored links.
- Repeatable guest port-scan and SSH password-guessing simulations.
- A Python pipeline for normalization, correlation, AI reporting, and validation.

## Architecture

```text
 user1    VLAN 10 ----\
 guest1   VLAN 20 -----\
 admin1   VLAN 30 ------ sw1 === core1 --- OSPF --- edge-fw1
 server1  VLAN 40 -----/        FRR+nftables         FRR+nftables
                                |                         |
                         copied traffic              WireGuard
                                v                         v
                            sensor1               AWS VPN gateway
                       Zeek + Suricata                   |
                                |                        v
                                |                 private AWS app
                                v
                    normalize -> correlate -> AI draft
                                      -> validate -> human review
```

The sensor receives packet copies and is not in the forwarding path. Its capture interfaces have no IP addresses, so a sensor failure should not interrupt network traffic.

## Network plan

| Zone or link | Network | Main system |
|---|---|---|
| User VLAN 10 | `10.10.10.0/24` | `user1` — `10.10.10.10` |
| Guest VLAN 20 | `10.10.20.0/24` | `guest1` — `10.10.20.10` |
| Management VLAN 30 | `10.10.30.0/24` | `admin1` — `10.10.30.10` |
| Server VLAN 40 | `10.10.40.0/24` | `server1` — `10.10.40.10` |
| Core-to-edge transit | `10.255.0.0/30` | `core1` and `edge-fw1` |
| WireGuard tunnel | `10.254.0.0/30` | Local and AWS peers |
| AWS VPC | `10.50.0.0/16` | VPN and private app subnets |

Containerlab uses `172.30.100.0/24` for out-of-band management. I keep it separate from the simulated enterprise data plane.

## Security and monitoring

The lab uses default-deny forwarding and permits only documented paths.

| Test flow | Result |
|---|---|
| User to local server HTTP | Allowed |
| User ICMP to local server | Blocked |
| User to Management VLAN | Blocked |
| Guest to trusted local or AWS networks | Blocked |
| Management to approved infrastructure | Allowed |
| Server initiating a new connection to User | Blocked |
| User to private AWS app on HTTPS | Allowed while deployed |
| AWS app initiating toward local User or Management | Blocked |

`sensor1` observes the VLAN trunk on `sniff0` and the core-to-edge transit link on `sniff1`. Zeek records connection and protocol metadata, Suricata applies local detection rules, and nftables counters prove whether the control actually blocked the traffic.

## Controlled scenarios

All traffic stays inside systems I own and control.

### Guest TCP scan

`guest1` scans 12 selected TCP ports on `server1`.

- All 12 ports were filtered.
- The `core1` Guest-to-local counter increased by 12.
- Zeek recorded 12 `S0` connections with no response packets.
- Suricata generated local signature ID `1000003`.

### SSH password guessing

`admin1` makes six bounded SSH attempts against a disposable account on `server1` using incorrect passwords.

- Six network connections were observed.
- `sshd` recorded four failed passwords.
- OpenSSH source penalties dropped the final two connections.
- No successful authentication was observed.
- Suricata generated local signature ID `1000004`.

## AI-assisted analysis

The Python workflow is:

```text
normalize -> correlate -> report -> validate
```

It assigns stable event IDs, preserves raw references and hashes, and calculates counts, ports, and outcomes before calling an AI model. Only the structured incident is sent to OpenRouter—not the original raw logs.

The first AI report failed validation because the model changed the permitted asset from `server1` to `server1 (10.10.40.10)`. I tightened the JSON Schema to exact values and reran it successfully.

Human review still found mistakes the structural validator could not:

- `core1` was incorrectly called a perimeter firewall.
- The model suggested checking a server for traffic that never reached it.
- A Zeek event was incorrectly described as a Suricata alert.

This helped me understand that a real evidence ID can still be explained incorrectly. The AI assists the investigation, but it does not replace analyst judgment.

## Validation status

- Local network suite: **44 passed, 0 failed**.
- Python tests: **5 passed**.
- Observed analysis run: **27 events correlated into 2 incidents**.
- Mock and OpenRouter reports: **2 structurally valid reports**.
- AWS and WireGuard: deployed and tested, then intentionally destroyed.

The validation scripts cover OSPF, firewall policies, positive and negative traffic, passive monitoring, attack evidence, WireGuard, cloud routing, and AI report grounding.

## Quick start

Requirements for the local lab are Linux, Docker Engine, Containerlab, and permission to use Docker and Containerlab.

```bash
git clone https://github.com/ScoutorcusA/ai-hybrid-network-soc-lab.git
cd ai-hybrid-network-soc-lab

tests/redeploy-local.sh
```

The script builds the images, replaces any existing local lab, and runs the local validation suite.

```bash
# Repeat the local checks
tests/validate-local.sh

# Run both controlled scenarios
tests/validate-attacks.sh
```

## Run the analysis pipeline

Python 3.12 or newer is required.

```bash
python3 -m venv python/.venv
source python/.venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e './python[dev,ai]'

scripts/collect-analysis-evidence.sh

RUN_DIR="$(find python/runs -mindepth 1 -maxdepth 1 -type d | sort | tail -n 1)"
tests/validate-analysis.sh "$RUN_DIR/raw"
```

Mock mode is deterministic and does not require an API key. OpenRouter support is optional; the real key must stay in the shell environment and out of Git.

## Temporary AWS deployment

The AWS side requires Terraform, AWS CLI credentials, `jq`, WireGuard tools, an SSH public key, and the current public IPv4 address of the local peer.

```bash
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
# Replace the example address with the local public IPv4 address in /32 form.

cd terraform
terraform init
terraform plan -out=soc-lab.tfplan
terraform apply soc-lab.tfplan
cd ..

tests/redeploy-hybrid.sh
```

AWS resources can incur charges. Destroy them when testing is finished:

```bash
cd terraform
terraform destroy
```

## Repository layout

| Path | Purpose |
|---|---|
| [`containerlab/`](containerlab/) | Local topology, images, and FRR configuration |
| [`firewall/`](firewall/) | Core and edge nftables policies |
| [`monitoring/`](monitoring/) | Zeek and Suricata configuration |
| [`attacks/`](attacks/) | Bounded lab-only scenarios |
| [`terraform/`](terraform/) | AWS VPC, EC2, routing, and security groups |
| [`python/`](python/) | Normalization, correlation, reporting, and validation |
| [`scripts/`](scripts/) | Evidence collection and hybrid configuration |
| [`tests/`](tests/) | Local, hybrid, attack, redeployment, and AI checks |
| [`docs/`](docs/) | Architecture, addressing, policy, and threat model |

## Secrets and generated data

The `.gitignore` excludes API keys, private keys, Terraform state and local variables, generated Containerlab state, runtime logs, packet captures, and AI run outputs. `.env.example` contains variable names only.

## Documentation

- [Architecture](docs/architecture.md)
- [Addressing and routing](docs/addressing.md)
- [Security policy](docs/security-policy.md)
- [Threat model](docs/threat-model.md)
- [Full Notion writeup](https://www.notion.so/AI-Assisted-Hybrid-Network-SOC-Lab-3bdc7041bd0a815da536c3a0462cc7a7)

## Scope

This is a learning project, not a production SOC platform. It includes two controlled scenarios and no autonomous remediation. AWS resources are temporary, OpenRouter's free router may select different models between requests, and every AI-generated report requires human review.
