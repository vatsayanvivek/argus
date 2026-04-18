# CHAIN-037 — VPN Downgrade to Network Intrusion

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Low · **Logic:** `ALL`

## Why this chain matters

The Azure VPN Gateway is configured to accept IKEv1 connections instead of enforcing IKEv2, Network Watcher is not provisioned in all regions where resources are deployed, and VNet peering relationships allow forwarded traffic. IKEv1 has known cryptographic weaknesses - it supports aggressive mode which exposes the pre-shared key hash, and its Phase 1 negotiation is vulnerable to offline brute-force attacks. An attacker on the network path (ISP-level or co-located facility) captures the IKEv1 aggressive-mode exchange, brute-forces the PSK offline, and establishes a rogue VPN tunnel into the Azure VNet. Once inside, the permissive peering configuration that allows forwarded traffic lets the attacker pivot from the landing VNet to every peered VNet. Network Watcher is missing in the regions involved, so no NSG flow logs, packet captures, or connection monitors detect the intrusion.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_015`](../rules/zt_net_015.md) | Trigger |
| [`zt_net_016`](../rules/zt_net_016.md) | Trigger |
| [`zt_net_020`](../rules/zt_net_020.md) | Trigger |

## Attack walkthrough

### Step 1 — Capture the IKEv1 aggressive-mode exchange between the on-premises gateway and the Azure VPN Gateway.

**Actor:** Network-positioned attacker  
**MITRE ATT&CK:** `T1040`  
**Enabled by:** [`zt_net_015`](../rules/zt_net_015.md)  

> IKEv1 aggressive mode transmits the identity and hash in the clear in the first message; tcpdump on the ISP path or a compromised on-prem device captures the exchange.

**Attacker gain:** Captured IKEv1 Phase 1 hash containing the pre-shared key material.


### Step 2 — Brute-force the pre-shared key offline using the captured hash.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1110.002`  
**Enabled by:** [`zt_net_015`](../rules/zt_net_015.md)  

> ike-scan + psk-crack or hashcat mode 5300 against the captured aggressive-mode hash; weak or short PSKs fall within hours.

**Attacker gain:** The plaintext pre-shared key for the VPN tunnel.


### Step 3 — Establish a rogue IKEv1 tunnel to the Azure VPN Gateway, impersonating the legitimate on-premises peer.

**Actor:** Attacker with PSK  
**MITRE ATT&CK:** `T1133`  
**Enabled by:** [`zt_net_015`](../rules/zt_net_015.md)  

> Configure strongSwan or libreswan with the recovered PSK and the Azure VPN Gateway's public IP; the gateway accepts the connection because IKEv1 is enabled and the PSK matches.

**Attacker gain:** Network-level access to the Azure VNet address space via the VPN tunnel.


### Step 4 — Pivot through VNet peerings that allow forwarded traffic to reach workloads in other VNets.

**Actor:** Attacker inside VNet  
**MITRE ATT&CK:** `T1021`  
**Enabled by:** [`zt_net_020`](../rules/zt_net_020.md)  

> VNet peering with allowForwardedTraffic=true and allowGatewayTransit=true; traffic from the VPN tunnel is forwarded into peered VNets without additional authentication.

**Attacker gain:** Access to every VNet in the peering mesh - database subnets, application tiers, management networks.


### Step 5 — Operate undetected because Network Watcher is not deployed in the affected regions.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_net_016`](../rules/zt_net_016.md)  

> No NSG flow logs capture the anomalous traffic; no packet capture capability exists for incident response; Connection Monitor does not flag the new tunnel establishment.

**Attacker gain:** No network-layer detection or forensic capability in the compromised regions.


## Blast radius

| | |
|---|---|
| Initial access | Rogue VPN tunnel established via brute-forced IKEv1 pre-shared key. |
| Lateral movement | VPN landing VNet → all peered VNets via forwarded traffic allowance. |
| Max privilege | Network-level access to every subnet in the peering topology. |
| Data at risk | All network-accessible services in peered VNets, Database instances on private subnets, Internal APIs and management interfaces |
| Services at risk | VPN Gateway, All VNet-peered workloads, SQL on private endpoints, Internal load balancers |
| Estimated scope | All VNets in the peering mesh |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

