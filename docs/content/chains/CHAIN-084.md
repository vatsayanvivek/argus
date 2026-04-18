# CHAIN-084 — Stream Analytics input with embedded storage key

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A Stream Analytics job reads from a storage account using an embedded account key rather than managed identity. A job export leaks the key; the storage account has a loose SAS policy. One exposure chains into long-term account access.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_024`](../rules/zt_data_024.md) | Trigger |
| [`zt_data_012`](../rules/zt_data_012.md) | Trigger |

## Attack walkthrough

### Step 1 — Export ASA job definition; extract account key.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_data_024`](../rules/zt_data_024.md)  

**Attacker gain:** Storage account key.


### Step 2 — Use key to mint fresh SAS; access any container.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1530`  
**Enabled by:** [`zt_data_012`](../rules/zt_data_012.md)  

**Attacker gain:** Persistent storage access.


## Blast radius

| | |
|---|---|
| Initial access | ASA job read. |
| Max privilege | Full storage account. |
| Data at risk | Entire storage account |
| Services at risk | Storage, Downstream ASA outputs |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

