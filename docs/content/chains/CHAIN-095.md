# CHAIN-095 — Column-level encryption miss on PII table

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

A SQL table holds PII in a column without Always Encrypted. A DBA role can read the plaintext. Database role compromise turns a 'authorised DBA session' into mass PII exfil with no crypto boundary to slow the attacker.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_017`](../rules/zt_data_017.md) | Trigger |
| [`zt_data_004`](../rules/zt_data_004.md) | Trigger |

## Attack walkthrough

### Step 1 — SELECT * FROM sensitive_table.

**Actor:** Attacker with DBA  
**MITRE ATT&CK:** `T1005`  
**Enabled by:** [`zt_data_017`](../rules/zt_data_017.md)  

**Attacker gain:** Plaintext PII.


### Step 2 — Bulk export to attacker storage; no Always Encrypted to block.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1048`  
**Enabled by:** [`zt_data_004`](../rules/zt_data_004.md)  

**Attacker gain:** Massive PII breach.


## Blast radius

| | |
|---|---|
| Initial access | DBA compromise. |
| Max privilege | Mass PII read. |
| Data at risk | Sensitive column content |
| Services at risk | Any app keeping regulated PII in SQL |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

