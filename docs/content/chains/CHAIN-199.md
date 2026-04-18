# CHAIN-199 — Bicep / ARM template storing secret as parameter

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

An ARM / Bicep template accepts a storage account key as a plain parameter. Deployment logs in Activity Log record the parameter in cleartext. Anyone with Activity Log reader for 90 days can harvest secrets from past deployments.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_001`](../rules/zt_id_001.md) | Trigger |
| [`zt_vis_008`](../rules/zt_vis_008.md) | Trigger |

## Attack walkthrough

### Step 1 — Parameter 'storageKey' passed in clear to ARM.

**Actor:** Deployment  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_id_001`](../rules/zt_id_001.md)  

**Attacker gain:** Secret written to Activity Log.


### Step 2 — Query Activity Log deployments; extract parameter values.

**Actor:** Attacker with reader  
**MITRE ATT&CK:** `T1213`  
**Enabled by:** [`zt_vis_008`](../rules/zt_vis_008.md)  

**Attacker gain:** Historical secret harvest.


## Blast radius

| | |
|---|---|
| Initial access | Activity Log read. |
| Max privilege | Every secret ever deployed. |
| Data at risk | All deployment-time secrets |
| Services at risk | Storage / SQL / whatever secrets referenced |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

