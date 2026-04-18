# CHAIN-087 — Purview account with public access + privileged collections

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Low · **Logic:** `ALL`

## Why this chain matters

Azure Purview catalogs data sources — reading the catalog itself leaks the table names, schemas, and classification labels of sensitive data. If Purview is publicly reachable AND audit logs aren't on, an attacker can reconnoitre the entire data estate.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_027`](../rules/zt_data_027.md) | Trigger |
| [`zt_vis_001`](../rules/zt_vis_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Probe Purview REST API with any token.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1087`  
**Enabled by:** [`zt_data_027`](../rules/zt_data_027.md)  

**Attacker gain:** Data catalog metadata.


### Step 2 — Target the highest-classification assets listed; pivot to chain exploits.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1087`  
**Enabled by:** [`zt_vis_001`](../rules/zt_vis_001.md)  

**Attacker gain:** Selective, high-value data targeting.


## Blast radius

| | |
|---|---|
| Initial access | Public Purview API. |
| Max privilege | Reconnaissance. |
| Data at risk | Catalog metadata |
| Services at risk | Every asset cataloged |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

