# CHAIN-198 — Deployment slots without configuration isolation

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

App Service deployment slots are used for blue-green deploys but app settings are NOT marked slot-specific. A dev staging slot reads prod connection strings. Any vulnerability on the staging slot has prod data at hand.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_017`](../rules/zt_wl_017.md) | Trigger |
| [`zt_wl_028`](../rules/zt_wl_028.md) | Trigger |

## Attack walkthrough

### Step 1 — Exploit staging slot which has weaker controls.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_wl_017`](../rules/zt_wl_017.md)  

**Attacker gain:** Staging slot compromise.


### Step 2 — Read app settings; includes prod DB string.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_wl_028`](../rules/zt_wl_028.md)  

**Attacker gain:** Prod data access from staging foothold.


## Blast radius

| | |
|---|---|
| Initial access | Staging slot vuln. |
| Max privilege | Prod backend reachability. |
| Data at risk | Prod database |
| Services at risk | Prod app data |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

