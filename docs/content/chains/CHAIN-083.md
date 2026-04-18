# CHAIN-083 — Synapse SQL pool without TDE + public endpoint

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A Synapse dedicated SQL pool is reachable over the public endpoint AND Transparent Data Encryption is disabled. A compromised DBA session yields unencrypted BAK files, and any backup exfil to attacker storage is plaintext.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_029`](../rules/zt_data_029.md) | Trigger |
| [`zt_data_003`](../rules/zt_data_003.md) | Trigger |

## Attack walkthrough

### Step 1 — BACKUP DATABASE to URL pointing at attacker storage.

**Actor:** Attacker with DBA  
**MITRE ATT&CK:** `T1213`  
**Enabled by:** [`zt_data_003`](../rules/zt_data_003.md)  

**Attacker gain:** BAK file in attacker control.


### Step 2 — RESTORE locally; no TDE decryption needed.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552`  
**Enabled by:** [`zt_data_029`](../rules/zt_data_029.md)  

**Attacker gain:** Plaintext warehouse content.


## Blast radius

| | |
|---|---|
| Initial access | DBA role + public DB endpoint. |
| Max privilege | Warehouse dataset. |
| Data at risk | All Synapse tables |
| Services at risk | Synapse, Dependent BI |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

