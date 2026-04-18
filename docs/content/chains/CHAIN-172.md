# CHAIN-172 — Recovery Services Vault without immutability + Backup Contributor compromise

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

A Recovery Services Vault has no immutability policy AND soft-delete is shorter than the backup retention policy. A ransomware operator who escalates to Backup Contributor simply deletes recovery points before encrypting primary data — no restore path remains.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_bak_001`](../rules/zt_bak_001.md) | Trigger |
| [`zt_bak_002`](../rules/zt_bak_002.md) | Trigger |

## Attack walkthrough

### Step 1 — Delete recovery points; soft-delete expires quickly.

**Actor:** Ransomware operator  
**MITRE ATT&CK:** `T1485`  
**Enabled by:** [`zt_bak_001`](../rules/zt_bak_001.md)  

**Attacker gain:** Unrecoverable loss of backups.


### Step 2 — Encrypt primary data; victim has no backup.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1486`  
**Enabled by:** [`zt_bak_002`](../rules/zt_bak_002.md)  

**Attacker gain:** Complete ransomware leverage.


## Blast radius

| | |
|---|---|
| Initial access | Backup Contributor. |
| Max privilege | Destruction of backup state. |
| Data at risk | All backed-up workloads |
| Services at risk | Every protected VM / database |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

