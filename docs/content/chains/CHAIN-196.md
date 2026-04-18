# CHAIN-196 — Azure DevOps PAT with full access + sprawled

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

An Azure DevOps PAT is created with Full Access (every scope) and an expiration of 1 year. Developers share it across pipelines, local scripts, and browsers. Any leak is a year-long backdoor to Azure DevOps Repos, Pipelines, and Variable Groups.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_022`](../rules/zt_id_022.md) | Trigger |
| [`zt_id_001`](../rules/zt_id_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Harvest the PAT from a dotfile or build log.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_id_022`](../rules/zt_id_022.md)  

**Attacker gain:** Full-access PAT.


### Step 2 — Read secrets from variable groups; push malicious commits; trigger pipelines.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_id_001`](../rules/zt_id_001.md)  

**Attacker gain:** Full DevOps project control.


## Blast radius

| | |
|---|---|
| Initial access | Leaked PAT. |
| Max privilege | Azure DevOps organisation-wide. |
| Data at risk | Source code, Pipeline secrets, Build artifacts |
| Services at risk | Azure DevOps |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

