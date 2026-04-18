# CHAIN-007 — No NSG on subnet no flow logs to invisible lateral

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A subnet has no NSG attached, NSG flow logs are not configured anywhere in the VNet, and Traffic Analytics is not enabled. An attacker who lands on any resource in that subnet can move laterally to every other resource in the same broadcast domain without any layer-4 filtering or any telemetry. Defenders see nothing because there is literally no log source.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_003`](../rules/zt_net_003.md) | Trigger |
| [`zt_vis_006`](../rules/zt_vis_006.md) | Trigger |
| [`zt_vis_009`](../rules/zt_vis_009.md) | Trigger |

## Attack walkthrough

### Step 1 — Perform internal port scanning across the subnet CIDR.

**Actor:** Attacker on foothold VM  
**MITRE ATT&CK:** `T1046`  
**Enabled by:** [`zt_net_003`](../rules/zt_net_003.md)  

> nmap -sS against the subnet's CIDR block; no NSG denies the traffic and no flow log captures it.

**Attacker gain:** Full inventory of live hosts and open services on the subnet.


### Step 2 — Move laterally to a database or file server in the same subnet.

**Actor:** Attacker on foothold VM  
**MITRE ATT&CK:** `T1021.002`  
**Enabled by:** [`zt_net_003`](../rules/zt_net_003.md)  

> Direct TCP connect to SQL/1433, SMB/445, WinRM/5985 on neighboring hosts - all allowed by the absent NSG.

**Attacker gain:** Expanded foothold to stateful services holding business data.


### Step 3 — Operate without any flow-level observation.

**Actor:** Attacker on second host  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_vis_006`](../rules/zt_vis_006.md)  

> NSG Flow Logs v2 are not enabled; no records arrive in storage or Log Analytics.

**Attacker gain:** Lateral movement leaves no east-west network audit trail.


### Step 4 — Evade behavioural detection because Traffic Analytics is not on.

**Actor:** Attacker on second host  
**MITRE ATT&CK:** `T1562.001`  
**Enabled by:** [`zt_vis_009`](../rules/zt_vis_009.md)  

> Traffic Analytics workspace not bound to the network watcher; no behavioural baselines exist to flag anomalous flows.

**Attacker gain:** Sustained unobserved dwell time in the internal network.


## Blast radius

| | |
|---|---|
| Initial access | Any compromised resource in the unfiltered subnet. |
| Lateral movement | Unrestricted east-west TCP/UDP across the subnet and peered networks. |
| Max privilege | Whatever privilege any neighbour in the subnet holds. |
| Data at risk | Internal databases, File shares, Internal web apps, Service endpoints reachable from the subnet |
| Services at risk | All VMs and PaaS-injected endpoints in the subnet |
| Estimated scope | Entire subnet + any peered network without its own NSG |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

