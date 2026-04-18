# CHAIN-102 — VPN gateway with weak IKE crypto + pre-shared key leak

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A Site-to-Site VPN gateway accepts IKEv1 with DES/3DES + weak PSK. An attacker on-path captures IKE packets and offline-cracks the PSK, then establishes their own tunnel to pivot into the VNet from anywhere on the internet.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_021`](../rules/zt_net_021.md) | Trigger |
| [`zt_net_003`](../rules/zt_net_003.md) | Trigger |

## Attack walkthrough

### Step 1 — Capture IKE session; offline-crack the PSK using GPU cluster.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1040`  
**Enabled by:** [`zt_net_021`](../rules/zt_net_021.md)  

**Attacker gain:** Valid PSK.


### Step 2 — Establish attacker-side tunnel; appear as internal node in Azure VNet.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1133`  
**Enabled by:** [`zt_net_003`](../rules/zt_net_003.md)  

**Attacker gain:** Lateral movement into prod VNet.


## Blast radius

| | |
|---|---|
| Initial access | On-path IKE capture. |
| Max privilege | Any private-IP-reachable resource. |
| Data at risk | VM filesystems, Internal service traffic |
| Services at risk | Azure VNet |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

