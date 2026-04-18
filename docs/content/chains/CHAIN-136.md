# CHAIN-136 — Container App Environment shared across dev/prod

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Dev and prod Container Apps share a single Managed Environment. Dev teams push changes without staging; a vulnerable dev app in the same VNet can reach prod services and secrets over the shared internal network.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_030`](../rules/zt_wl_030.md) | Trigger |
| [`zt_net_003`](../rules/zt_net_003.md) | Trigger |

## Attack walkthrough

### Step 1 — Compromise dev Container App (weaker controls).

**Actor:** Attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_wl_030`](../rules/zt_wl_030.md)  

**Attacker gain:** Foothold in shared env.


### Step 2 — Pivot to prod services over the shared VNet.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1021`  
**Enabled by:** [`zt_net_003`](../rules/zt_net_003.md)  

**Attacker gain:** Prod compromise via dev.


## Blast radius

| | |
|---|---|
| Initial access | Dev Container App. |
| Max privilege | Prod network reachability. |
| Data at risk | Prod secrets |
| Services at risk | Prod Container Apps |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

