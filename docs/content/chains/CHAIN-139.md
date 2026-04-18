# CHAIN-139 — Container App secret rotation miss

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Container App secrets (API keys, DB passwords) are set at deploy time and never rotated. A developer leaving the team still has access because the secret they provisioned is still live.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_030`](../rules/zt_wl_030.md) | Trigger |
| [`zt_id_001`](../rules/zt_id_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Use the unchanged secret months later.

**Actor:** Former developer  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_wl_030`](../rules/zt_wl_030.md)  

**Attacker gain:** Persistent access despite offboarding.


### Step 2 — Pivot to downstream systems.

**Actor:** Former dev  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_id_001`](../rules/zt_id_001.md)  

**Attacker gain:** Offboarding gap exploitation.


## Blast radius

| | |
|---|---|
| Initial access | Unchanged secret. |
| Max privilege | Whatever secret grants. |
| Data at risk | App-scope data |
| Services at risk | Downstream services the secret unlocks |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

