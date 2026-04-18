# CHAIN-092 — Cross-region replication to unauthorised region

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Low · **Logic:** `ALL`

## Why this chain matters

A storage account is configured for GRS to a region outside the tenant's data residency commitments. A compliance auditor flags this as a data-sovereignty breach — but operationally the data is also reachable from the secondary region, doubling the attack surface.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_009`](../rules/zt_data_009.md) | Trigger |
| [`zt_data_010`](../rules/zt_data_010.md) | Trigger |

## Attack walkthrough

### Step 1 — GRS writes continuous copies to a non-approved region.

**Actor:** Compliance failure  
**MITRE ATT&CK:** `T1537`  
**Enabled by:** [`zt_data_009`](../rules/zt_data_009.md)  

**Attacker gain:** Data residing outside contractual region.


### Step 2 — Compromise the secondary endpoint; same content as primary.

**Actor:** Regional attacker  
**MITRE ATT&CK:** `T1530`  
**Enabled by:** [`zt_data_010`](../rules/zt_data_010.md)  

**Attacker gain:** Data in a harder-to-monitor region.


## Blast radius

| | |
|---|---|
| Initial access | Secondary-region attack path. |
| Max privilege | Read on replicated blobs. |
| Data at risk | Same as primary |
| Services at risk | Cross-region storage |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

