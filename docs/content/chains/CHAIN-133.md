# CHAIN-133 — AKS cluster autoscaler unrestricted — DoS via pod spam

!!! note "Summary"
    **Severity:** :material-information-outline: Low · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Cluster autoscaler has no upper node-count limit and pod QoS has no ResourceQuota. A tenant-scoped attacker creates thousands of pending pods; cluster scales out to absorb them, generating a huge Azure bill.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_021`](../rules/zt_wl_021.md) | Trigger |
| [`zt_wl_012`](../rules/zt_wl_012.md) | Trigger |

## Attack walkthrough

### Step 1 — kubectl create -f thousand-pods.yaml.

**Actor:** Authorised tenant  
**MITRE ATT&CK:** `T1496`  
**Enabled by:** [`zt_wl_021`](../rules/zt_wl_021.md)  

**Attacker gain:** Autoscaler adds nodes.


### Step 2 — Sustain load; financial damage + noisy-neighbor DoS.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1496`  
**Enabled by:** [`zt_wl_012`](../rules/zt_wl_012.md)  

**Attacker gain:** Cost attack + legitimate tenant DoS.


## Blast radius

| | |
|---|---|
| Initial access | Any kubectl create permission. |
| Max privilege | Resource exhaustion / financial harm. |
| Data at risk | Cluster availability for others |
| Services at risk | Multi-tenant cluster |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

