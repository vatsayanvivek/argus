# CHAIN-099 — TDE with customer-managed key + Key Vault purge protection off

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Low · **Logic:** `ALL`

## Why this chain matters

A SQL server uses TDE with a customer-managed key stored in a Key Vault where purge protection is off. An attacker-admin purges the vault, permanently losing the key. TDE data is then unreadable forever — cryptographic self-destruct.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_004`](../rules/zt_data_004.md) | Trigger |
| [`zt_data_011`](../rules/zt_data_011.md) | Trigger |

## Attack walkthrough

### Step 1 — Delete the Key Vault.

**Actor:** Attacker-admin  
**MITRE ATT&CK:** `T1485`  
**Enabled by:** [`zt_data_011`](../rules/zt_data_011.md)  

**Attacker gain:** Vault soft-deleted.


### Step 2 — Purge the soft-deleted vault.

**Actor:** Attacker-admin  
**MITRE ATT&CK:** `T1485`  
**Enabled by:** [`zt_data_004`](../rules/zt_data_004.md)  

**Attacker gain:** Permanent key loss; all TDE-encrypted data unreadable.


## Blast radius

| | |
|---|---|
| Initial access | Key Vault Contributor. |
| Max privilege | Cryptographic DoS. |
| Data at risk | All TDE-encrypted DBs using this key |
| Services at risk | SQL Server, Dependent app |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

