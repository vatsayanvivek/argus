# CHAIN-126 — Service Fabric cluster with TLS downgrade

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Low · **Logic:** `ALL`

## Why this chain matters

A Service Fabric cluster accepts TLS 1.0 for node-to-node communication. A legacy-protocol downgrade attack on the management endpoint yields cluster admin — Service Fabric node identity is the root of trust for the entire cluster.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_027`](../rules/zt_wl_027.md) | Trigger |
| [`zt_net_002`](../rules/zt_net_002.md) | Trigger |

## Attack walkthrough

### Step 1 — Force TLS 1.0 negotiation; MITM the session.

**Actor:** On-path adversary  
**MITRE ATT&CK:** `T1557.001`  
**Enabled by:** [`zt_wl_027`](../rules/zt_wl_027.md)  

**Attacker gain:** Decrypted node-to-node traffic.


### Step 2 — Replay node auth; join attacker node as cluster member.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1606.002`  
**Enabled by:** [`zt_net_002`](../rules/zt_net_002.md)  

**Attacker gain:** Service Fabric node that controls the cluster.


## Blast radius

| | |
|---|---|
| Initial access | On-path MITM. |
| Max privilege | Cluster admin. |
| Data at risk | All app state |
| Services at risk | Service Fabric cluster |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

