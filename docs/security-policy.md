# Network Security Policy

## Purpose

This document turns the architecture into specific allow and deny decisions. I am writing the policy before writing nftables rules so that the code can be reviewed against an understandable security goal.

My starting position is **default deny**: traffic crossing a trust boundary is blocked unless this document gives it a reason to be allowed. The policy is stateful, which means an approved connection may receive its matching return traffic without opening the same path for a new connection in the opposite direction.

This is a lab policy and not a claim that the controls are already working. Each important statement has a planned test so I can collect evidence later.

## Security objectives

- Employees can use approved local and cloud applications without receiving infrastructure-admin access.
- Guests cannot reach internal or AWS private networks.
- Only the Management VLAN can administer infrastructure.
- Servers and cloud workloads cannot begin unsolicited sessions toward employee or management devices.
- The private AWS application has no direct public application path.
- The Internet carries only WireGuard-encrypted hybrid traffic, not the original private packet.
- Denied cross-zone traffic produces useful, rate-limited evidence.
- Sensors remain passive and do not become a path around segmentation.
- The future AI analyst can recommend actions but cannot change firewall rules automatically.

## Trust zones

| Zone | CIDR | Trust level | Main concern |
|---|---|---|---|
| User | `10.10.10.0/24` | Medium | A normal workstation could become compromised. |
| Guest | `10.10.20.0/24` | Untrusted | Devices are not managed and must be treated as potentially hostile. |
| Management | `10.10.30.0/24` | High, restricted | Compromise would provide administrative reach. |
| Server | `10.10.40.0/24` | Medium-high | Services are trusted for specific ports, not for unrestricted access. |
| Core-edge transit | `10.255.0.0/30` | Infrastructure only | Must not host user workloads. |
| WireGuard tunnel | `10.254.0.0/30` | Authenticated transport | A valid peer is not automatically authorized for every inner flow. |
| AWS VPN subnet | `10.50.10.0/24` | Infrastructure only | Public exposure must be limited to the VPN service. |
| AWS application | `10.50.20.0/24` | Protected workload | Must remain private and accept only documented local sources. |
| Internet | Any non-lab address | Untrusted | Only explicitly required ingress and egress are allowed. |
| Sensor management | Containerlab management network | Restricted | Guest and User zones must not use the tool-management path. |

## Where rules are enforced

`core1` routes between local VLANs, so it enforces **east-west** policy. Sending all inter-VLAN traffic to `edge-fw1` would create an unnecessary detour and would not match the architecture.

`edge-fw1` enforces **north-south and hybrid** policy: local-to-AWS, local-to-Internet, tunnel traffic, and unsolicited inbound traffic.

AWS adds another layer:

- VPC route tables decide whether a path exists.
- Security groups restrict traffic reaching the VPN and application instances.
- VPC Flow Logs provide ACCEPT/REJECT metadata when enabled.
- CloudTrail records control-plane changes such as security-group edits.

Application authentication and HTTPS remain required even when the network permits a connection.

## Stateful processing order

The planned nftables chains follow this logic:

1. Drop malformed or `invalid` connection states.
2. Allow `established` and `related` return traffic.
3. Allow narrowly defined new connections from the matrix below.
4. Rate-limit and log denied cross-zone attempts.
5. Drop everything that did not match an allow rule.

Order matters. If a broad allow rule appears before a narrow deny rule, the deny may never be evaluated.

## Local forwarding rule matrix (`core1`)

| Rule ID | Source | Destination | Service | Action | Log? | Reason |
|---|---|---|---|---|---|---|
| `C-FWD-001` | Any local zone | Matching return path | Established/related state | Allow | Counter only | Allows replies to connections that already passed policy. |
| `C-FWD-002` | Any | Any | Invalid state | Drop | Rate-limited | Malformed or untrackable traffic should not be forwarded. |
| `C-FWD-010` | User | `server1` | TCP `80`, `443` | Allow | Counter | Employees need the approved local web application. |
| `C-FWD-011` | User | Approved server-side resolver | UDP/TCP `53` | Allow | Counter | Supports controlled DNS testing without opening all server ports. |
| `C-FWD-012` | User | Management | Any new connection | Deny | Yes | Employee devices must not administer infrastructure. |
| `C-FWD-013` | User | Guest | Any new connection | Deny | Yes | There is no business reason for a trusted user device to initiate into the untrusted zone. |
| `C-FWD-014` | User | Server | Any other new service | Deny | Yes | Trusting a web server does not mean trusting every port on it. |
| `C-FWD-015` | User | AWS private app | TCP `443` | Allow | New-connection counter | Lets approved hybrid application traffic reach `edge-fw1`, which applies a second policy check. |
| `C-FWD-020` | Guest | `10.10.0.0/16` | Any | Deny | Yes | Blocks internal discovery, exploitation, and sensor access. |
| `C-FWD-021` | Guest | `10.50.0.0/16` | Any | Deny | Yes | Stops guest traffic before it can enter WireGuard. |
| `C-FWD-030` | Management | `core1`, `edge-fw1`, `server1` | TCP `22` | Allow | Yes on new session | Only administrators may use SSH on infrastructure. |
| `C-FWD-031` | Management | Approved infrastructure | ICMP echo | Allow | Counter | Supports bounded reachability and troubleshooting tests. |
| `C-FWD-032` | Management | Other local zones | Any unlisted service | Deny | Yes | A trusted admin network is still least-privileged, not “allow any.” |
| `C-FWD-033` | Management | AWS VPN gateway and app | TCP `22` and ICMP echo | Allow | Yes on new session | Permits private administration and diagnostics through the controlled edge path. |
| `C-FWD-040` | Server | User | New connections | Deny | Yes | Prevents a compromised server from initiating lateral movement to workstations. |
| `C-FWD-041` | Server | Guest or Management | New connections | Deny | Yes | Servers have no reason to initiate into these zones in the MVP. |
| `C-FWD-099` | Any local zone | Any different local zone | Anything unmatched | Deny | Yes | Default-deny safety net. |

The rule for User-to-AWS traffic is evaluated on both `core1` and `edge-fw1`. `core1` must permit it to leave the User VLAN, and the edge must independently permit it to enter the tunnel.

## Infrastructure input rules

Traffic addressed to a router itself is handled by an input chain, not the forwarding chain.

| Rule ID | Device | Source | Service | Action | Reason |
|---|---|---|---|---|---|
| `I-IN-001` | `core1`, `edge-fw1` | Established/related | Matching return traffic | Allow | Keeps approved management and routing sessions functional. |
| `I-IN-010` | `core1`, `edge-fw1` | Management VLAN | TCP `22` | Allow | Restricts SSH administration to `admin1`'s zone. |
| `I-IN-011` | `core1`, `edge-fw1` | Management VLAN | ICMP echo | Allow | Enables diagnostic evidence. |
| `I-IN-020` | `core1` | `edge-fw1` transit address | OSPF, IP protocol `89` | Allow | OSPF must exist only on the point-to-point transit link. |
| `I-IN-021` | `edge-fw1` | `core1` transit address | OSPF, IP protocol `89` | Allow | Allows the second half of the adjacency. |
| `I-IN-030` | `edge-fw1` WAN-facing address/port | Known AWS WireGuard peer | UDP `51820` | Allow | Carries authenticated WireGuard packets only. |
| `I-IN-099` | Infrastructure | Any other source | Anything unmatched | Deny and log | Prevents endpoint zones from treating routers as general-purpose servers. |

OSPF is an IP protocol, not a TCP or UDP port. Limiting it to the transit interface prevents an endpoint from attempting to become a routing neighbor.

## Edge forwarding and egress matrix (`edge-fw1`)

| Rule ID | Source | Destination | Service | Action | Log? | Reason |
|---|---|---|---|---|---|---|
| `E-FWD-001` | Any | Matching return path | Established/related state | Allow | Counter only | Permits legitimate replies without opening reverse initiation. |
| `E-FWD-010` | User | AWS private app | TCP `443` | Allow | New-connection counter | Approved hybrid application path. |
| `E-FWD-011` | Management | AWS VPN gateway and app | TCP `22` | Allow | Yes on new session | Private administration across WireGuard; no public SSH. |
| `E-FWD-012` | Management | Approved AWS targets | ICMP echo | Allow | Counter | Supports tunnel and routing diagnostics. |
| `E-FWD-020` | Guest | AWS VPC | Any | Deny | Yes | Guest devices must never enter the private cloud network. |
| `E-FWD-021` | AWS app/VPN zones | User or Management | New connections | Deny | Yes | Cloud workloads may return approved traffic but cannot initiate toward protected local zones. |
| `E-FWD-030` | Guest | Approved external DNS resolver | UDP/TCP `53` | Allow when egress is enabled | Counter | Provides limited guest name resolution without internal DNS access. |
| `E-FWD-031` | Guest | Internet | TCP `80`, `443` | Allow when egress is enabled | Counter | Models “Internet only” guest access. Public scanning remains prohibited. |
| `E-FWD-032` | User | Internet | Required approved services only | Deny until explicitly defined | Yes | Avoids silently creating unrestricted egress during the local MVP. |
| `E-FWD-040` | Server | Internet | Any new connection | Deny | Yes | Prevents uncontrolled server egress and simple beaconing paths. Temporary updates require a documented exception. |
| `E-FWD-099` | Any | Any | Anything unmatched | Deny | Yes | Perimeter default-deny rule. |

If guest Internet egress is implemented, source NAT is allowed only for that Internet path. The local-to-AWS WireGuard path remains routed without source NAT so AWS evidence retains the original local source IP.

## AWS security-group policy

These are workload-level rules in addition to `edge-fw1` policy.

### WireGuard gateway security group

| Direction | Source/destination | Service | Action and reason |
|---|---|---|---|
| Inbound | Known local public peer address | UDP `51820` | Allow the VPN handshake and encrypted transport. Never use `0.0.0.0/0` after the local peer address is known. |
| Inbound | Management `10.10.30.0/24` over the tunnel | TCP `22` | Allow private SSH administration only. |
| Inbound | Any other source | Any | No allow rule; VPC Flow Logs should record rejects where observable. |
| Outbound | Known local public peer address | UDP `51820` | Allow tunnel responses and keepalives. |
| Outbound | AWS application subnet | Approved forwarded application traffic | Permit routing toward the private app while host nftables still applies. |

### Private application security group

| Direction | Source/destination | Service | Action and reason |
|---|---|---|---|
| Inbound | User `10.10.10.0/24` | TCP `443` | Approved employee application access. |
| Inbound | Management `10.10.30.0/24` | TCP `22` | Private administration through the tunnel. |
| Inbound | Management `10.10.30.0/24` | ICMP echo | Optional diagnostic path for lab evidence. |
| Inbound | Guest, Internet, and all unlisted sources | Any | No allow rule. The app has no public IP or direct Internet route. |
| Outbound | Required dependencies | Explicitly documented ports only | No general Internet egress in the MVP. Stateful response traffic remains possible for approved inbound sessions. |

A security group that allows `0.0.0.0/0` does not by itself make a private instance reachable; public addressing and routing also matter. I still treat the broad rule as a serious misconfiguration because another routing change could complete the exposure path.

## Logging policy

Logging every dropped packet without limits can consume storage and make a denial-of-service attack worse. I will therefore:

- Log new denied cross-zone attempts with stable prefixes such as `NFT_CORE_DENY` and `NFT_EDGE_DENY`.
- Include timestamp, input/output interface, source, destination, protocol, ports when available, and connection state.
- Apply per-rule or per-prefix rate limits while keeping packet and byte counters.
- Avoid logging passwords, tokens, cookies, WireGuard private keys, or full request bodies.
- Keep clocks synchronized so firewall, Zeek, Suricata, AWS, and application records can be correlated.
- Monitor sensor and log-pipeline health; silence is not proof that nothing happened.
- Treat VPC Flow Logs as metadata, not packet payload capture.

## Temporary exceptions

An exception is a deliberate change, not an edit made directly during troubleshooting. Each exception must record:

- Owner and reason.
- Source, destination, service, and enforcement point.
- Start and expiration time.
- Test showing the exception works.
- Test showing the rule was removed afterward.

Examples include a short server-update window or a controlled cloud-exposure simulation. Permanent “allow any” rules are not acceptable substitutes for understanding the required flow.

## Planned policy tests

All tests run only against lab-owned addresses and services.

| Test ID | From | Example action | Expected result | Expected evidence |
|---|---|---|---|---|
| `P-001` | `user1` | `curl http://10.10.40.10` | Pass | Client response, core allow counter, Zeek connection/application record. |
| `P-002` | `user1` | `curl -k https://10.10.40.10` | Pass | TLS connection metadata; payload remains encrypted to the sensor. |
| `P-003` | `user1` | `dig @10.10.40.10 example.lab` | Pass when lab DNS is enabled | DNS log and allow counter. |
| `P-004` | `user1` | `nc -zvw2 10.10.30.10 22` | Fail | `NFT_CORE_DENY`, no SSH connection. |
| `P-005` | `guest1` | Scan selected ports on `10.10.40.10` | Blocked | Rate-limited firewall drops, Zeek scan pattern if mirrored, possible Suricata alert. |
| `P-006` | `admin1` | Open SSH to `core1` and `edge-fw1` | Pass | SSH/authentication evidence and management allow counter. |
| `P-007` | `user1` | Attempt SSH to `core1` | Fail | Infrastructure input-chain deny log. |
| `P-008` | `server1` | Start a new connection to `user1` | Fail | Core deny log; established replies to `P-001` still succeed. |
| `P-009` | `user1` | `curl https://10.50.20.10` | Pass after AWS phase | Local allow counters, WireGuard transfer increase, AWS ACCEPT flow, app log. |
| `P-010` | `guest1` | Attempt the same AWS connection | Fail before tunnel | Core deny log and no matching application request. |
| `P-011` | AWS app | Start SSH toward Management VLAN | Fail | Edge deny log and no management authentication event. |
| `P-012` | Internet test point | Attempt application access by public address | Fail/no address exists | No public app path; AWS routing and security-group evidence. |
| `P-013` | `core1` | Inspect OSPF neighbor | Full only with `edge-fw1` | FRR neighbor output; no endpoint-originated adjacency. |
| `P-014` | Sensor failure test | Stop `sensor1`, then repeat approved flow | Traffic passes but monitoring-health test fails | Demonstrates passive placement and detects visibility loss. |

The final automated test scripts will print clear `PASS` or `FAIL` results and preserve sanitized evidence. A failed negative test is serious: if a connection expected to be blocked succeeds, the phase is not complete.

## Policy review checklist

- [ ] Rules match the CIDRs in [addressing.md](addressing.md).
- [ ] Default policies are drop, not accept.
- [ ] Established/related handling appears before new-connection denies.
- [ ] OSPF is limited to the transit interfaces.
- [ ] Router SSH is limited to the Management VLAN.
- [ ] Guest traffic cannot reach local or AWS private ranges.
- [ ] AWS application traffic preserves the original local source address.
- [ ] No public SSH or public application address exists in AWS.
- [ ] Deny logs are useful and rate-limited.
- [ ] Every policy statement has a positive or negative test.
- [ ] Attack simulations target only infrastructure I own and control.

## What I learned while designing this

The biggest lesson for me is that “inside” is not the same as “trusted.” A compromised employee device or server is still a realistic attacker position, so the policy controls traffic between internal zones instead of relying only on a perimeter firewall. I also learned why stateful rules matter: allowing a server's reply is different from allowing that server to begin a new connection toward a workstation.

## References

- [AWS: Control traffic using security groups](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html) — security groups are stateful and responses to allowed traffic are automatically permitted.
- [AWS: Infrastructure security in Amazon VPC](https://docs.aws.amazon.com/vpc/latest/userguide/infrastructure-security.html) — security groups, network ACLs, private subnets, and minimum-required routes.
