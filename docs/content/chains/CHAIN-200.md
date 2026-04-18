# CHAIN-200 — Azure DevOps variable group with unencrypted secret + no approval

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

An Azure DevOps variable group stores production secrets as plain (not locked) variables. Any user with contributor on the project reads them. There is no approval workflow to access the production variable group.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_017`](../rules/zt_wl_017.md) | Trigger |
| [`zt_id_019`](../rules/zt_id_019.md) | Trigger |

## Attack walkthrough

### Step 1 — View variable group values in the portal.

**Actor:** Project contributor  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_wl_017`](../rules/zt_wl_017.md)  

**Attacker gain:** Production secrets.


### Step 2 — Authenticate with stolen secrets to backend systems.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_id_019`](../rules/zt_id_019.md)  

**Attacker gain:** Cross-system compromise.


## Blast radius

| | |
|---|---|
| Initial access | Azure DevOps contributor. |
| Max privilege | Whatever secrets unlock. |
| Data at risk | Any backend the secrets reach |
| Services at risk | Every system referenced in the variable group |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

