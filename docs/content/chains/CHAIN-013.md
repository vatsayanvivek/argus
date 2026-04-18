# CHAIN-013 — VNet peering no firewall to east-west compromise

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Multiple VNets are peered directly to each other with AllowForwardedTraffic enabled, there is no Azure Firewall or NVA inspecting east-west traffic, and NSG Flow Logs are not configured. A compromise in any peered VNet immediately becomes a compromise of every peered VNet - production, non-production, and shared services are all one flat network as far as an attacker is concerned.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_004`](../rules/zt_net_004.md) | Trigger |
| [`zt_net_005`](../rules/zt_net_005.md) | Trigger |
| [`zt_vis_006`](../rules/zt_vis_006.md) | Trigger |

## Attack walkthrough

### Step 1 — Enumerate peered VNets via Azure Resource Graph or DNS reconnaissance.

**Actor:** Attacker in non-prod VNet  
**MITRE ATT&CK:** `T1590.004`  
**Enabled by:** [`zt_net_004`](../rules/zt_net_004.md)  

> Resources.network.virtualNetworks/peerings lists the target prod VNet and confirms allowForwardedTraffic=true.

**Attacker gain:** Full map of peering topology.


### Step 2 — Route directly to production IPs without any firewall inspection.

**Actor:** Attacker in non-prod VNet  
**MITRE ATT&CK:** `T1021`  
**Enabled by:** [`zt_net_005`](../rules/zt_net_005.md)  

> No 0.0.0.0/0 UDR pointing at Azure Firewall; no NVA in the data path; traffic flows over the peering link unfiltered.

**Attacker gain:** Direct layer-4 reach to production services.


### Step 3 — Move laterally and exfiltrate data while no flow logs are captured.

**Actor:** Attacker in prod VNet  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_vis_006`](../rules/zt_vis_006.md)  

> Flow logs v2 not enabled on the NSGs protecting target resources; east-west traffic is invisible.

**Attacker gain:** Silent lateral movement into the production tier.


## Blast radius

| | |
|---|---|
| Initial access | Any compromised workload in a peered VNet. |
| Lateral movement | Direct IP routing across all peered VNets, unfiltered. |
| Max privilege | Whatever the attacker can reach in the destination VNet(s). |
| Data at risk | All resources in peered VNets, Cross-environment data (prod/non-prod) |
| Services at risk | Every VNet-integrated service across the peering mesh |
| Estimated scope | Entire peering mesh |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

