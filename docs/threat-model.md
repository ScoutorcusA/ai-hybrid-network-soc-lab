# Threat Model

## Purpose

This threat model explains what I am protecting, where an attacker could start, what evidence I expect, and which controls should reduce the risk. I am using it as a set of testable security hypotheses—not as proof that the lab is secure before the controls are implemented.

The initial scope contains four required scenarios:

1. Guest-network reconnaissance.
2. Outbound beaconing from a compromised endpoint.
3. Lateral movement from a user workstation.
4. Accidental AWS cloud exposure.

All simulations must stay inside infrastructure I own and control. Public systems are never scan targets for this project.

## Method

For each threat I document:

- **Asset:** what could be harmed.
- **Attacker position:** where the activity begins.
- **Method:** what the attacker attempts.
- **Expected evidence:** records that should exist if visibility is working.
- **Detection:** how the SOC recognizes the behavior.
- **Mitigation:** controls that block or limit it.
- **Validation:** the safe lab exercise that tests the assumption.

I use a simple qualitative score to prioritize the work:

- Likelihood: `1` (unlikely) to `5` (very likely).
- Impact: `1` (minor) to `5` (severe).
- Risk score: likelihood multiplied by impact.

The numbers are deliberately simple. They help me compare scenarios, but they are not a substitute for evidence or business context.

## Scope and assumptions

### In scope

- Local VLANs, endpoints, routers, and nftables controls.
- The WireGuard hybrid path and both peers.
- AWS VPC routes, security groups, VPN gateway, and private application.
- Zeek, Suricata, firewall logs, VPC Flow Logs, CloudTrail, and application logs.
- Normalization, deterministic correlation, and evidence-grounded AI analysis.
- Configuration mistakes that can be reproduced safely with Terraform.

### Out of scope for the MVP

- Attacks against public organizations or systems not owned by me.
- Wireless security, physical access, and social engineering.
- Kubernetes, multi-cloud, automated remediation, and a production identity platform.
- Malware execution or destructive payloads.
- Breaking WireGuard or TLS cryptography.
- Treating the AI analyst as an autonomous responder.

### Assumptions that must be tested

- VLAN traffic really is separated at Layer 2.
- `core1` is the only normal router between local VLANs.
- The default-deny nftables policy loads successfully after deployment and reboot.
- Mirrored packets reach `sensor1` without making it part of the forwarding path.
- All evidence sources use synchronized clocks.
- WireGuard preserves original local addresses because the hybrid path does not use source NAT.
- The AWS application has no public IP and its subnet has no direct Internet route.

## Assets

| Asset | Why it matters | Security property |
|---|---|---|
| Management VLAN and `admin1` | Provides administrative reach to infrastructure. | Confidentiality, integrity, restricted access. |
| Router and firewall configurations | Determine network reachability and segmentation. | Integrity and availability. |
| Local server | Represents internal business services and evidence. | Availability, integrity, controlled access. |
| WireGuard private keys | Authenticate VPN peers and protect hybrid traffic. | Confidentiality and integrity. |
| AWS private application | Demonstrates protected cloud access. | Confidentiality, integrity, availability. |
| AWS network configuration | Determines whether private resources stay private. | Integrity and correct configuration. |
| Security telemetry | Supports investigation and validation. | Integrity, availability, correct timestamps. |
| Normalized event IDs and incident records | Form the evidence supplied to the AI analyst. | Integrity, traceability, reproducibility. |
| Git repository and Terraform state | Define the repeatable environment and may reference sensitive infrastructure. | Integrity; secrets must not be committed. |

## Trust boundaries

| Boundary | Why it is a boundary | Main control |
|---|---|---|
| Guest VLAN to any trusted subnet | Guest devices are unmanaged and untrusted. | VLAN separation plus `core1` default-deny forwarding. |
| User VLAN to Server/Management | Users need applications but not administrative reach. | Per-service rules on `core1`. |
| Local network to Internet/AWS | Traffic leaves the local trust domain. | `edge-fw1`, WireGuard, and explicit routes. |
| WireGuard gateway to private AWS app | A valid tunnel peer still should not reach every cloud service. | AWS route tables, security groups, and host firewalling. |
| Forwarding path to passive sensor | Sensor receives copies but must not control availability. | Out-of-band mirroring and sensor-health monitoring. |
| Raw logs to AI analyst | Model output is not inherently factual. | Normalization, deterministic facts, event-ID validation, and human review. |

## Risk summary

These are design-time scores. I will revise likelihood and residual risk after running the tests.

| ID | Threat | Likelihood | Impact | Initial score | Main preventive control | Target residual risk |
|---|---|---:|---:|---:|---|---|
| `T-01` | Guest reconnaissance | 4 | 3 | 12 — High | Guest-to-internal default deny | Low |
| `T-02` | Outbound beaconing | 3 | 4 | 12 — High | Restricted egress plus behavioral detection | Medium |
| `T-03` | Lateral movement | 4 | 5 | 20 — Critical | Inter-VLAN least privilege | Medium |
| `T-04` | Accidental cloud exposure | 3 | 5 | 15 — High | Private subnet, IaC review, and layered cloud controls | Low–Medium |

Residual risk cannot be confirmed until the implementation produces the expected negative tests and telemetry.

## T-01: Guest-network reconnaissance

### Scenario

A device on the Guest VLAN tries to identify live internal systems and open services. The first goal may only be discovery, but the information could support later exploitation.

| Field | Detail |
|---|---|
| Asset being attacked | Internal addressing, `server1`, management interfaces, routers, and sensor-management services. |
| Attacker position | `guest1` on `10.10.20.0/24`. |
| Attack method | Controlled ICMP and TCP probes against selected lab-owned addresses and ports. |
| Security objective | Guest traffic never reaches trusted local or AWS private networks. |

### Expected evidence

- `core1` nftables drops with the `NFT_CORE_DENY` prefix and Guest source address.
- Packet/byte counters increasing on `C-FWD-020` or `C-FWD-021`.
- Zeek `conn.log` entries showing repeated attempts if the mirrored capture point sees packets before the drop.
- A Suricata scan or policy alert if the configured rules and thresholds match the activity.
- No successful connection or application log on the target.

The exact sensor evidence depends on mirror placement. Firewall evidence should still exist even when Suricata does not raise a signature alert.

### Detection logic

- Group denied events by source IP in a short time window.
- Count distinct destination IPs and ports.
- Raise severity when one guest source probes multiple trusted targets or management ports.
- Correlate firewall denies with Zeek connection attempts and Suricata alerts using time, source, destination, and protocol.

### Mitigations

- Access VLAN separation on `sw1`.
- `core1` rules `C-FWD-020`, `C-FWD-021`, and default deny `C-FWD-099`.
- No Layer-3 address on sensor sniffing interfaces.
- Router input rules that allow administration only from Management.
- Rate-limited deny logging so the scan cannot overwhelm storage.

### Safe validation

From `guest1`, scan a small, documented list of addresses and ports inside `10.10.0.0/16`. Confirm that every connection fails, the firewall counters increase, and no target service records a successful session. Never expand the target list to public addresses.

### Investigation questions

- Was the source definitely in the Guest VLAN?
- How many internal destinations and ports were attempted?
- Were all attempts blocked, or did any target produce an application/authentication record?
- Did the sensor observe the same attempts, and if not, is mirror placement or sensor health the reason?
- Was this the planned simulation window or unexpected activity?

## T-02: Outbound beaconing

### Scenario

A compromised endpoint makes small, periodic outbound connections to a command-and-control destination. Encryption may hide the application payload, but timing and connection metadata can still reveal a regular pattern.

| Field | Detail |
|---|---|
| Asset being attacked | Endpoint integrity, credentials, internal data, and trust in outbound traffic. |
| Attacker position | Compromised `user1` or `server1`. |
| Attack method | Low-volume connections at a fixed interval to an owned local or AWS test service. |
| Security objective | Block unnecessary egress and detect suspicious periodic behavior on allowed paths. |

### Expected evidence

- Zeek connection records with repeated source/destination/port tuples.
- DNS records if the simulation uses an owned lab domain.
- Suricata flow or TLS metadata; a signature alert is not guaranteed.
- `edge-fw1` deny logs if the destination or service is not allowed.
- Application access logs if the controlled destination accepts the connections.
- Deterministically calculated interval statistics from the Python correlation layer.

### Detection logic

- Group connections by source, destination, and port.
- Calculate time differences between connections in code before invoking AI.
- Look for a low-variance interval across several events.
- Compare bytes sent and received and whether attempts succeeded or were blocked.
- Treat regularity as a lead, not proof: health checks and scheduled jobs can also be periodic.

### Mitigations

- Deny general Server-to-Internet initiation with `E-FWD-040`.
- Keep User Internet egress denied until specific requirements are documented (`E-FWD-032`).
- Allow only approved DNS resolvers and required service ports.
- Monitor DNS, TLS, flow timing, and endpoint/application logs.
- Investigate and isolate a suspected endpoint manually; the AI analyst cannot change firewall rules.

### Safe validation

Use a simple script or scheduled command to contact an owned lab service at a fixed, low frequency. The activity must be harmless, bounded, and stopped after evidence collection. Compare an allowed test with a blocked unapproved destination so the report distinguishes “attempted” from “successful.”

### Investigation questions

- Were the connections accepted or blocked?
- How many events occurred and how regular were the intervals?
- Is the destination owned and expected?
- Could the behavior be a health check, update service, or monitoring agent?
- What evidence supports compromise beyond timing alone?

## T-03: Lateral movement

### Scenario

An attacker who controls an employee workstation attempts to reach servers or administrative services that are not required for the employee's role. This tests why internal segmentation matters even after a user is already “inside.”

| Field | Detail |
|---|---|
| Asset being attacked | Local server, management VLAN, router/firewall administration, and credentials. |
| Attacker position | Compromised `user1` on `10.10.10.0/24`. |
| Attack method | Attempts to use SSH or other unapproved service ports; controlled authentication failures only where a service is intentionally reachable. |
| Security objective | Permit approved web/DNS use while denying administrative and unrelated lateral paths. |

### Expected evidence

- `NFT_CORE_DENY` events for User-to-Management or unapproved User-to-Server services.
- Zeek connections showing attempted service access if visible at the mirror.
- Suricata alerts for recognized scan or authentication patterns when relevant rules are enabled.
- Authentication failures on a lab service only if policy intentionally permits the traffic to reach it.
- No successful SSH session on infrastructure from the User VLAN.

### Detection logic

- Prioritize attempts from User to Management or infrastructure addresses.
- Correlate multiple service probes followed by authentication failures.
- Distinguish network prevention from host rejection: a firewall drop should not create a server authentication log because the packet never arrived.
- Escalate if an expected-deny flow is accepted or if a successful authentication follows reconnaissance.

### Mitigations

- User access limited to DNS, HTTP, and HTTPS on approved servers (`C-FWD-010`, `C-FWD-011`, `C-FWD-014`).
- User-to-Management deny (`C-FWD-012`).
- Router SSH limited to the Management VLAN (`I-IN-010`).
- Server-to-User initiation denied (`C-FWD-040`) to reduce reverse movement.
- Separate administrator endpoint and credentials.
- Application/host authentication even on allowed network paths.

### Safe validation

From `user1`, confirm that the approved local web request succeeds. Then attempt TCP `22` against `server1`, `core1`, and `admin1`. All administrative attempts must fail and produce evidence at the correct enforcement point. Controlled password failures belong in a later simulation against an intentionally selected lab service, never a real account or public host.

### Investigation questions

- Which policy boundary was crossed?
- Were attempts limited to one service or spread across several targets?
- Did any packet reach a host, or did `core1` block all attempts?
- Was there a successful authentication or only failed network connections?
- Does the source show other indicators such as beaconing or unusual DNS?

## T-04: Accidental AWS cloud exposure

### Scenario

A cloud administrator or Terraform change weakens the private application design—for example, by adding a broad security-group rule, a public address, or an Internet route. A single broad rule is dangerous, but actual public reachability normally requires several conditions to line up.

| Field | Detail |
|---|---|
| Asset being attacked | Private AWS application, application data, cloud credentials, and cost-controlled lab resources. |
| Attacker position | Misconfigured administrative workflow; if exposure is completed, an unauthenticated Internet source. |
| Attack method | Unsafe infrastructure-as-code change such as `0.0.0.0/0` application ingress, public IP assignment, or incorrect route table. |
| Security objective | The application remains private and reachable only from approved local networks through WireGuard. |

### Expected evidence

- Terraform plan showing the proposed network or security-group change.
- Static IaC/security checks flagging public ingress or addressing.
- CloudTrail event recording the security-group, route, or interface change.
- AWS configuration/state evidence showing whether a public IP and Internet route exist.
- VPC Flow Logs showing REJECT or unexpected ACCEPT traffic if a test flow reaches the interface.
- No direct public application response in the safe baseline.

### Detection logic

- Fail CI when the private application receives a public IP or a broad application-ingress rule.
- Compare Terraform plan/state with the expected private-subnet architecture.
- Alert on cloud control-plane changes to security groups, routes, Internet gateways, and network interfaces.
- Treat exposure as a path analysis problem: public source → Internet gateway → route/public target → security rule → listening service.

### Mitigations

- Private application subnet with no public IP and no general Internet route.
- Application security group limited to User HTTPS and Management SSH over WireGuard.
- Terraform review, validation, and policy/security scanning before apply.
- CloudTrail and VPC Flow Logs for change and network evidence.
- Short-lived lab deployments, budget alerts, and documented Terraform teardown.
- No automatic AWS deployment from untrusted public pull requests.

### Safe validation

Create an intentionally unsafe Terraform example in an isolated test or plan-only workflow. Confirm that review/security checks identify it before deployment. If a live change is required for evidence, use only the owned lab account, keep the application non-sensitive, time-box the change, avoid public scanning, and restore the safe configuration immediately.

### Investigation questions

- What exact resource changed, who changed it, and through which identity?
- Did the change create only a risky rule, or a complete reachable public path?
- Was the application listening, and did any flow actually reach it?
- How long did the unsafe state exist?
- Did Terraform restore the expected state, and was the restoration verified?

## Threat-to-control mapping

| Threat | Preventive controls | Detective controls | Recovery/response |
|---|---|---|---|
| `T-01` Guest reconnaissance | VLAN 20 isolation; `C-FWD-020/021`; router input default deny | nftables logs/counters, Zeek connection patterns, Suricata scan alerts | Confirm blocks, preserve evidence, disconnect the simulated guest if needed. |
| `T-02` Outbound beaconing | Restricted egress; approved resolvers/services; server egress deny | Zeek flow timing, DNS/TLS metadata, edge denies, deterministic interval calculation | Isolate endpoint manually, stop test process, review credentials and allowed egress. |
| `T-03` Lateral movement | Per-service User rules; Management-only SSH; Server-to-User deny | Core denies, Zeek/Suricata, authentication logs when traffic reaches a host | Contain source, review affected credentials, verify no successful session, retest segmentation. |
| `T-04` Cloud exposure | Private subnet, no public IP, least-privilege SGs, Terraform review | IaC checks, CloudTrail, VPC Flow Logs, configuration comparison | Revert with Terraform, remove public path, rotate exposed secrets if any, destroy temporary resources. |

## Evidence quality and limitations

I do not want the final incident report to overstate what the telemetry proves:

- A firewall deny proves an attempted network flow was blocked at that point; it does not prove the source was malicious.
- A Suricata alert is a detection rule match, not a final incident conclusion.
- Zeek can describe visible connections, but HTTPS and WireGuard hide payload content at their respective observation points.
- No host log should exist when a firewall blocks traffic before it reaches the host.
- A broad security-group rule is a dangerous condition, but public exposure also depends on routing, addressing, and a listening service.
- Missing telemetry may mean sensor failure or incorrect mirror placement, not absence of activity.
- AI output is an interpretation. Every factual claim must link back to valid event IDs, and unsupported conclusions must be rejected.

## Threat-model validation checklist

- [ ] Each simulation has a written start time, stop time, source, target, and expected result.
- [ ] Every target is owned lab infrastructure.
- [ ] Normal traffic is captured first to establish a comparison baseline.
- [ ] Preventive control evidence and detective evidence are both collected.
- [ ] Accepted and blocked attempts are labeled correctly.
- [ ] Sensor health and capture placement are checked before interpreting missing alerts.
- [ ] Logs are sanitized before being committed to GitHub.
- [ ] No passwords, tokens, private keys, public account identifiers, or sensitive payloads enter the repository.
- [ ] Temporary unsafe configuration is reverted and the safe state is tested again.
- [ ] The final AI report cites only event IDs present in the incident data.

## Future threat-model extensions

After the four initial scenarios work reliably, I can extend the model to include:

- WireGuard private-key theft or an incorrectly broad `AllowedIPs` configuration.
- Sensor outage, traffic-mirror failure, or log-pipeline backpressure.
- Log tampering and misleading data supplied to the AI analyst.
- Secret leakage in Git history or Terraform state.
- Denial of service against the firewall, VPN, sensor, or application.

These are valuable risks, but adding them now would expand the MVP before the required controls are proven.

## What I learned while designing this

My main lesson is that detection evidence has limits. A blocked scan, an alert, and a successful compromise are three different facts. The threat model forces me to say which one the data supports. I also learned that cloud exposure is rarely one checkbox: public reachability depends on the combination of addressing, routes, security rules, and a running service.
