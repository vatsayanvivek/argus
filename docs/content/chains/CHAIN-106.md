# CHAIN-106 — Cross-tenant VNet peering without RBAC scoping

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Low · **Logic:** `ALL`

## Why this chain matters

A VNet peering is established with a partner tenant and both ends allow 'Allow forwarded traffic' without careful firewall rules. Compromise of a partner resource yields Layer-3 reachability to your private subnets.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_003`](../rules/zt_net_003.md) | Trigger |
| [`zt_id_023`](../rules/zt_id_023.md) | Trigger |

## Attack walkthrough

### Step 1 — Compromise a partner VNet VM.

**Actor:** Partner-tenant attacker  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_id_023`](../rules/zt_id_023.md)  

**Attacker gain:** Partner VNet foothold.


### Step 2 — Route through peering into home VNet.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1021`  
**Enabled by:** [`zt_net_003`](../rules/zt_net_003.md)  

**Attacker gain:** Lateral reachability to home subnets.


## Blast radius

| | |
|---|---|
| Initial access | Partner VNet compromise. |
| Max privilege | Home VNet network reach. |
| Data at risk | Anything reachable on peered subnets |
| Services at risk | Peered subnets |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

