# CHAIN-089 — Data Lake Gen2 with container-level public access

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A Data Lake Storage Gen2 account has one container set to Blob public access. Gen2's hierarchical namespace means the entire directory tree under that container is readable anonymously. Enterprises often discover this AFTER the data has been indexed by search engines.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_031`](../rules/zt_data_031.md) | Trigger |
| [`zt_data_001`](../rules/zt_data_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Discover the container name via enumeration or search indexing.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1580`  
**Enabled by:** [`zt_data_001`](../rules/zt_data_001.md)  

**Attacker gain:** Reachable ADLS path.


### Step 2 — Walk the hierarchical namespace; download entire folder trees.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1530`  
**Enabled by:** [`zt_data_031`](../rules/zt_data_031.md)  

**Attacker gain:** Bulk lake dataset exfil.


## Blast radius

| | |
|---|---|
| Initial access | Anon internet. |
| Max privilege | Read on the exposed container. |
| Data at risk | All lake data in container |
| Services at risk | ADLS Gen2, Downstream analytics consumers |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

