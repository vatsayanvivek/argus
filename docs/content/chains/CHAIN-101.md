# CHAIN-101 — Lake House table with no row-level security on multi-tenant data

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A Synapse or Databricks table holds multi-tenant data with a tenant_id column but no row-level security filter. Any query user reads every tenant's rows — a classic tenant-isolation bug that audits rarely catch because 'the data is in Azure'.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_023`](../rules/zt_data_023.md) | Trigger |
| [`zt_data_017`](../rules/zt_data_017.md) | Trigger |

## Attack walkthrough

### Step 1 — SELECT * FROM shared_table WHERE 1=1.

**Actor:** Authorised tenant-A user  
**MITRE ATT&CK:** `T1213`  
**Enabled by:** [`zt_data_023`](../rules/zt_data_023.md)  

**Attacker gain:** Tenant-B + tenant-C rows.


### Step 2 — Bulk export; tenant separation violated.

**Actor:** Malicious insider  
**MITRE ATT&CK:** `T1005`  
**Enabled by:** [`zt_data_017`](../rules/zt_data_017.md)  

**Attacker gain:** Cross-tenant data breach.


## Blast radius

| | |
|---|---|
| Initial access | Authenticated analyst role. |
| Max privilege | Read all tenant rows. |
| Data at risk | Multi-tenant dataset |
| Services at risk | Any shared data asset |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

