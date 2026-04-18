# CHAIN-009 — KeyVault no protection no alerts to ransomware

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A Key Vault has purge protection disabled, soft-delete retention at a minimal window, and no action-group alerts on vault operations. An attacker - or a malicious insider - who gets Key Vault Contributor can delete and purge every secret and key. Any service encrypting data with a customer-managed key in that vault instantly loses access to the data: a cloud-native ransomware outcome with no ransom to pay because the keys are simply gone.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_004`](../rules/zt_data_004.md) | Trigger |
| [`zt_data_005`](../rules/zt_data_005.md) | Trigger |
| [`zt_vis_004`](../rules/zt_vis_004.md) | Trigger |

## Attack walkthrough

### Step 1 — Enumerate the target Key Vault and confirm purge protection is off.

**Actor:** Attacker / insider with Key Vault Contributor  
**MITRE ATT&CK:** `T1087.004`  
**Enabled by:** [`zt_data_004`](../rules/zt_data_004.md)  

> az keyvault show returns enablePurgeProtection=false and a low softDeleteRetentionInDays.

**Attacker gain:** Confirmation that delete + purge is a one-way operation.


### Step 2 — Delete every secret, key, and certificate in the vault.

**Actor:** Attacker / insider  
**MITRE ATT&CK:** `T1485`  
**Enabled by:** [`zt_data_005`](../rules/zt_data_005.md)  

> az keyvault secret delete / key delete looped across the vault inventory.

**Attacker gain:** Vault content moved to soft-delete state.


### Step 3 — Purge the soft-deleted items so recovery is impossible.

**Actor:** Attacker / insider  
**MITRE ATT&CK:** `T1485`  
**Enabled by:** [`zt_data_005`](../rules/zt_data_005.md)  

> az keyvault secret purge / key purge - succeeds because purge protection is disabled.

**Attacker gain:** Permanent destruction of cryptographic material.


### Step 4 — Operate without alerting - no action groups subscribe to vault audit events.

**Actor:** Attacker / insider  
**MITRE ATT&CK:** `T1562.006`  
**Enabled by:** [`zt_vis_004`](../rules/zt_vis_004.md)  

> No alert rule on AuditEvent category for Microsoft.KeyVault; no Logic App or email fires on bulk delete.

**Attacker gain:** Detection happens only when downstream apps start failing - hours to days later.


### Step 5 — Every service encrypting data with a customer-managed key in that vault becomes unreadable.

**Actor:** Business impact  
**MITRE ATT&CK:** `T1486`  
**Enabled by:** [`zt_data_004`](../rules/zt_data_004.md)  

> Storage / SQL / Disk encryption with CMK → cryptographic key version unresolvable → I/O fails.

**Attacker gain:** Effective ransomware outcome: data is still on disk but cryptographically inaccessible, and no attacker to pay.


## Blast radius

| | |
|---|---|
| Initial access | Any principal with Key Vault Contributor or equivalent purge rights. |
| Lateral movement | Not required - single-shot destructive operation. |
| Max privilege | Key Vault data-plane destruction with no recovery path. |
| Data at risk | All CMK-protected storage accounts, All CMK-protected SQL databases, All disk-encrypted VMs using the vault |
| Services at risk | Key Vault, Storage, SQL, VM Disk Encryption, Any service consuming the vault's CMK |
| Estimated scope | Every workload binding to the affected vault |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

