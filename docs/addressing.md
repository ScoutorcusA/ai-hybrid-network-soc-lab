# IP Addressing and Routing Plan

## Purpose

This document is my addressing plan for the local enterprise lab and the future AWS environment. I wrote it before building the network so that every subnet has a clear job and so that I can test routing against an expected result instead of guessing after deployment.

The most important rule is that local and AWS networks must not overlap. If both sides used the same address range, a router could not reliably decide whether a destination was local or across the WireGuard tunnel.

## Final design choice

Earlier planning notes contained more than one draft addressing scheme. For this implementation I selected the later eight-node handoff design because it matches the current architecture document:

- Local enterprise summary: `10.10.0.0/16`
- Local VLANs: `10.10.10.0/24` through `10.10.40.0/24`
- Router transit and loopbacks: `10.255.0.0/16`
- WireGuard tunnel: `10.254.0.0/30`
- AWS VPC: `10.50.0.0/16`

Only the listed subnets are assigned. The larger local summaries are route aggregates, not flat Layer-2 networks.

## How I read the notation

An address such as `10.10.10.0/24` represents a subnet. The `/24` means the first 24 bits identify the network, leaving 8 bits for host addresses. That provides 256 total addresses. In a normal IPv4 subnet, the first address identifies the network and the last is the broadcast address, so I do not assign either to a device.

I use `.1` consistently for a subnet gateway and `.10` for the first lab endpoint. This convention is not required by networking protocols, but it makes troubleshooting easier for me and for someone reviewing the repository.

## Address summary

| Zone or link | VLAN | CIDR | Gateway or endpoints | Purpose |
|---|---:|---|---|---|
| Employee users | 10 | `10.10.10.0/24` | `10.10.10.1` | Employee workstations and approved application traffic. |
| Guests | 20 | `10.10.20.0/24` | `10.10.20.1` | Untrusted clients with no path to internal or AWS private networks. |
| Management | 30 | `10.10.30.0/24` | `10.10.30.1` | Administrative access to infrastructure. |
| Local servers | 40 | `10.10.40.0/24` | `10.10.40.1` | Approved internal applications and lab services. |
| Core-to-edge transit | None | `10.255.0.0/30` | Core `.1`, edge `.2` | Point-to-point routed link and OSPF adjacency. |
| Router IDs/loopbacks | None | `10.255.255.0/24` reserved | Core `.1/32`, edge `.2/32` | Stable FRRouting router identities; not an endpoint LAN. |
| WireGuard tunnel | None | `10.254.0.0/30` | Local `.1`, AWS `.2` | Logical point-to-point tunnel addressing. |
| AWS VPC | None | `10.50.0.0/16` | AWS-provided VPC router | Non-overlapping cloud address space. |
| AWS public VPN subnet | None | `10.50.10.0/24` | AWS router `10.50.10.1` | Private interface of the public WireGuard EC2 gateway. |
| AWS private application subnet | None | `10.50.20.0/24` | AWS router `10.50.20.1` | Private application workload with no direct public address. |

## Local device assignments

| Device | Interface role | Address | Default gateway | Notes |
|---|---|---|---|---|
| `user1` | User VLAN access interface | `10.10.10.10/24` | `10.10.10.1` | Generates approved employee traffic. |
| `guest1` | Guest VLAN access interface | `10.10.20.10/24` | `10.10.20.1` | Used for controlled negative tests inside owned lab ranges. |
| `admin1` | Management VLAN access interface | `10.10.30.10/24` | `10.10.30.1` | Only endpoint intended to administer lab infrastructure. |
| `server1` | Server VLAN access interface | `10.10.40.10/24` | `10.10.40.1` | Hosts the initial local HTTP/HTTPS test service. |
| `core1` | VLAN 10 subinterface | `10.10.10.1/24` | Not applicable | Default gateway for employees. |
| `core1` | VLAN 20 subinterface | `10.10.20.1/24` | Not applicable | Default gateway for guests. |
| `core1` | VLAN 30 subinterface | `10.10.30.1/24` | Not applicable | Default gateway for management. |
| `core1` | VLAN 40 subinterface | `10.10.40.1/24` | Not applicable | Default gateway for local servers. |
| `core1` | Transit interface | `10.255.0.1/30` | Not applicable | OSPF peer link to `edge-fw1`. |
| `core1` | Loopback/router ID | `10.255.255.1/32` | Not applicable | Stable OSPF router ID. |
| `edge-fw1` | Transit interface | `10.255.0.2/30` | Not applicable | OSPF peer link to `core1`. |
| `edge-fw1` | Loopback/router ID | `10.255.255.2/32` | Not applicable | Stable OSPF router ID. |
| `edge-fw1` | WireGuard `wg0` | `10.254.0.1/30` | Peer `10.254.0.2` | Encrypts approved traffic to AWS. |
| `sensor1` | `sniff0` and `sniff1` | No IP address | None | Passive capture interfaces must not route or answer traffic. |

Containerlab also creates a tool-management interface, normally `eth0`, for container administration. That network is separate from the simulated enterprise data plane. Its exact range will be pinned in the topology file, and I will not use it to claim that a firewall or routing test passed.

## AWS assignments

| Resource | Address | Public address | Notes |
|---|---|---|---|
| AWS WireGuard gateway, VPC interface | `10.50.10.10/24` | Assigned at deployment | Public address exists only so the local peer can reach UDP `51820`. No public SSH is planned. |
| AWS WireGuard gateway, `wg0` | `10.254.0.2/30` | None | Decrypts the tunnel and routes approved packets into the VPC. |
| Private demo application | `10.50.20.10/24` | None | Reached from approved local networks through WireGuard. |

AWS reserves five addresses in every VPC subnet, including the first four and the final address. For example, I do not assign `10.50.20.0` through `10.50.20.3` or `10.50.20.255` to workloads. I chose `.10` so the planned resources stay clear of those reservations.

## Address allocation conventions

For each local `/24`, I will use the same pattern:

| Range | Intended use |
|---|---|
| `.0` | Network identifier; never assigned. |
| `.1` | Default gateway on `core1`. |
| `.2`–`.9` | Reserved for future infrastructure. |
| `.10`–`.49` | Statically assigned lab endpoints and servers. |
| `.50`–`.199` | Reserved for a future DHCP pool if DHCP is added. |
| `.200`–`.254` | Reserved for later experiments. |
| `.255` | Broadcast address; never assigned. |

The lab initially uses static addresses because they make packet captures, firewall rules, and automated tests deterministic.

## Communication intent by subnet

This table describes reachability goals. The exact port rules are defined in [security-policy.md](security-policy.md).

| Source network | Allowed communication | Blocked communication |
|---|---|---|
| User `10.10.10.0/24` | Approved DNS, HTTP, and HTTPS services on the local server; HTTPS to the AWS application; normal return traffic. | Management VLAN, guest VLAN, infrastructure administration, and unapproved server ports. |
| Guest `10.10.20.0/24` | Limited DNS and web access to external services when Internet egress is enabled. | All local enterprise subnets, router management, sensor management, and the AWS VPC. |
| Management `10.10.30.0/24` | SSH and diagnostic access to approved infrastructure and servers; approved AWS administration over the tunnel. | Unnecessary application access and any path not explicitly allowed. |
| Server `10.10.40.0/24` | Replies to approved user requests and specifically approved service dependencies. | New unsolicited sessions to users, guests, management, or the Internet. |
| Core-edge transit `10.255.0.0/30` | OSPF and routed traffic between the two routers. | Endpoint placement and general-purpose services. |
| AWS VPN subnet `10.50.10.0/24` | WireGuard from the known local public peer; routed local-to-cloud traffic; management from the Management VLAN over the tunnel. | Public SSH and unrelated inbound Internet traffic. |
| AWS app subnet `10.50.20.0/24` | HTTPS from approved local users and administration from the Management VLAN. | Direct Internet access, Guest VLAN access, and new connections toward local management or users. |

## Expected routing design

### `user1`, `guest1`, `admin1`, and `server1`

Each endpoint has only two essential route types:

| Destination | Next hop |
|---|---|
| Its own `/24` | Directly connected interface |
| Everything else | Its VLAN gateway at `10.10.<VLAN>.1` |

The presence of a route does not mean traffic is authorized. Routing chooses a path; nftables decides whether that path may be used.

### `core1`

| Destination | Expected source | Next hop/interface |
|---|---|---|
| `10.10.10.0/24` | Connected | VLAN 10 subinterface |
| `10.10.20.0/24` | Connected | VLAN 20 subinterface |
| `10.10.30.0/24` | Connected | VLAN 30 subinterface |
| `10.10.40.0/24` | Connected | VLAN 40 subinterface |
| `10.255.0.0/30` | Connected | Transit interface |
| `10.50.0.0/16` | OSPF advertisement from `edge-fw1` after VPN activation | `10.255.0.2` |
| Approved Internet/default route | OSPF or controlled static route when egress is enabled | `10.255.0.2` |

`core1` advertises the four local VLANs to `edge-fw1`. I will start with static routes during early testing, then replace the internal route exchange with OSPF so I can prove the neighbor relationship and learned routes.

### `edge-fw1`

| Destination | Expected source | Next hop/interface |
|---|---|---|
| `10.255.0.0/30` | Connected | Transit interface |
| `10.10.10.0/24` | OSPF from `core1` | `10.255.0.1` |
| `10.10.20.0/24` | OSPF from `core1` | `10.255.0.1` |
| `10.10.30.0/24` | OSPF from `core1` | `10.255.0.1` |
| `10.10.40.0/24` | OSPF from `core1` | `10.255.0.1` |
| `10.50.0.0/16` | Static/WireGuard allowed prefix | `wg0`, peer `10.254.0.2` |
| Internet destinations | Host/VM uplink when explicitly enabled | WAN/uplink gateway |

`edge-fw1` advertises reachability to `10.50.0.0/16` into local OSPF only when the cloud route is intentionally configured. The first version will not form an OSPF neighbor across WireGuard.

### AWS WireGuard gateway and VPC

| Routing location | Destination | Target |
|---|---|---|
| WireGuard gateway OS | `10.10.0.0/16` | `wg0`, local peer `10.254.0.1` |
| WireGuard gateway OS | `10.50.0.0/16` | VPC interface |
| Public VPN subnet route table | `0.0.0.0/0` | Internet Gateway, required for the public tunnel endpoint |
| Private app subnet route table | `10.10.0.0/16` | WireGuard gateway network interface/instance |
| All VPC route tables | `10.50.0.0/16` | AWS local route |

The WireGuard EC2 instance must have source/destination checking disabled because it is forwarding packets whose source or destination is another host. The private application subnet intentionally has no general `0.0.0.0/0` Internet route in the MVP.

## Example expected paths

| Test flow | Expected path | Expected result |
|---|---|---|
| User to local web server | `user1 -> sw1 -> core1 -> server1` | Allowed on the documented application ports. |
| User to management | `user1 -> sw1 -> core1` | Dropped and logged by `core1`; no packet reaches `admin1`. |
| Guest scan of server VLAN | `guest1 -> sw1 -> core1` | Dropped and logged by `core1`; sensor records visible attempts if mirroring is correct. |
| Admin SSH to `edge-fw1` | `admin1 -> sw1 -> core1 -> edge-fw1` | Allowed from Management VLAN only. |
| User to AWS application | `user1 -> core1 -> edge-fw1 -> wg0 -> AWS VPN gateway -> app` | Allowed on HTTPS after the tunnel is deployed. |
| Guest to AWS application | `guest1 -> core1` | Dropped and logged before entering WireGuard. |
| AWS app starts a session to Management | `app -> AWS VPN gateway -> edge-fw1` | Dropped and logged; only established return traffic is allowed. |

## What I will verify during implementation

This is a design, not proof that the network works. I will consider the addressing plan implemented only after I save evidence for:

- Correct addresses and VLAN membership on every endpoint.
- Each endpoint reaching its own default gateway.
- No accidental Layer-2 communication across VLANs.
- A full OSPF adjacency between `core1` and `edge-fw1`.
- The expected connected and learned routes on both routers.
- A route to `10.50.0.0/16` appearing only when the hybrid path is configured.
- The AWS private subnet returning `10.10.0.0/16` through the WireGuard gateway.
- Traceroutes matching the expected paths.
- Firewall tests proving that route availability does not bypass policy.

## What I learned while designing this

My main lesson is that routing and security are related but different. A routing table can know exactly how to reach a destination while the firewall correctly blocks the packet. I also learned that a VPN needs a working return route: successfully sending a packet into AWS is not enough if the application does not know how to send the response back to the local VLAN.

## References

- [AWS: Subnet CIDR blocks](https://docs.aws.amazon.com/vpc/latest/userguide/subnet-sizing.html) — AWS-reserved subnet addresses and valid subnet sizing.
- [AWS: Disable source/destination checks for a forwarding instance](https://docs.aws.amazon.com/vpc/latest/userguide/work-with-nat-instances.html#EIP_Disable_SrcDestCheck) — why an EC2 instance forwarding traffic for other hosts needs this setting disabled.
