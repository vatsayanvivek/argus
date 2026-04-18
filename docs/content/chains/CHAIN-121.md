# CHAIN-121 — AKS private cluster with unrestricted egress

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

AKS is private (no public API server) but the cluster's egress firewall allows any outbound destination. A compromised pod can exfiltrate or call out to C2 freely, and the 'private cluster' label gives the security team a false sense of containment.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_005`](../rules/zt_wl_005.md) | Trigger |
| [`zt_net_024`](../rules/zt_net_024.md) | Trigger |

## Attack walkthrough

### Step 1 — Establish outbound C2 tunnel through unrestricted NAT.

**Actor:** Compromised pod  
**MITRE ATT&CK:** `T1071.001`  
**Enabled by:** [`zt_wl_005`](../rules/zt_wl_005.md)  

**Attacker gain:** Live C2 channel.


### Step 2 — Exfil cluster secrets, node identity tokens.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1041`  
**Enabled by:** [`zt_net_024`](../rules/zt_net_024.md)  

**Attacker gain:** Pod-level secret extraction


## Blast radius

| | |
|---|---|
| Initial access | Any pod compromise. |
| Max privilege | Egress to attacker infrastructure. |
| Data at risk | Pod memory, service account tokens |
| Services at risk | AKS cluster secrets |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

