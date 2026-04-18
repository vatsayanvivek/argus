# CHAIN-030 — Storage account ransomware with no recovery

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Blob soft delete is not enabled on the storage account, blob versioning is disabled, and no Azure Backup vault protects the storage data. This combination removes every recovery mechanism for blob data. An attacker who gains access to the storage account - through a leaked account key, a compromised SAS token, or an overprivileged managed identity - can overwrite or delete every blob in every container. Without soft delete, deleted blobs are immediately gone. Without versioning, overwritten blobs lose their previous content permanently. Without Azure Backup, there is no point-in-time restore capability. The attacker can execute a complete ransomware scenario: encrypt or delete all data and demand payment, knowing that the victim has no technical path to recovery.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_013`](../rules/zt_data_013.md) | Trigger |
| [`zt_data_016`](../rules/zt_data_016.md) | Trigger |
| [`zt_data_017`](../rules/zt_data_017.md) | Trigger |

## Attack walkthrough

### Step 1 — Obtain storage account credentials through a leaked account key, overly permissive SAS token, or compromised identity.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1528`  
**Enabled by:** [`zt_data_013`](../rules/zt_data_013.md)  

> Storage account keys are static and grant full control; SAS tokens may have overly broad permissions (sp=rwdlac) and long expiry dates; managed identities with Storage Blob Data Contributor role provide full data-plane access.

**Attacker gain:** Full data-plane access to the storage account.


### Step 2 — Enumerate all containers and blobs to assess the scope of the target.

**Actor:** Attacker with storage access  
**MITRE ATT&CK:** `T1619`  
**Enabled by:** [`zt_data_013`](../rules/zt_data_013.md)  

> List containers API and list blobs API; identify containers with business-critical data, backups, application state, and media files.

**Attacker gain:** Complete inventory of all blob data in the storage account.


### Step 3 — Overwrite all blobs with encrypted versions or random data.

**Actor:** Attacker with inventory  
**MITRE ATT&CK:** `T1486`  
**Enabled by:** [`zt_data_016`](../rules/zt_data_016.md)  

> PUT Blob to overwrite each blob with attacker-encrypted content; because versioning is disabled (isVersioningEnabled=false), the previous blob content is permanently lost on overwrite.

**Attacker gain:** All original blob data is permanently destroyed and replaced with unusable content.


### Step 4 — Delete any remaining blobs and containers that were not overwritten.

**Actor:** Attacker completing ransomware  
**MITRE ATT&CK:** `T1485`  
**Enabled by:** [`zt_data_013`](../rules/zt_data_013.md)  

> DELETE Blob and DELETE Container APIs; soft delete is not enabled (deleteRetentionPolicy.enabled=false), so deleted blobs are immediately and permanently removed.

**Attacker gain:** Complete destruction of all blob data with no soft-delete recovery window.


### Step 5 — Discover that no backup or restore mechanism exists for the storage account.

**Actor:** Defenders attempting recovery  
**MITRE ATT&CK:** `T1490`  
**Enabled by:** [`zt_data_017`](../rules/zt_data_017.md)  

> No Azure Backup vault has a backup policy targeting this storage account; point-in-time restore requires both versioning and change feed, which are disabled; no third-party backup solution is configured.

**Attacker gain:** Data is unrecoverable - the attacker's ransomware demand is the only option on the table.


## Blast radius

| | |
|---|---|
| Initial access | Leaked storage account key, compromised SAS token, or overprivileged identity. |
| Lateral movement | Not required - storage account access is sufficient for complete data destruction. |
| Max privilege | Storage account key (full control) or Storage Blob Data Contributor. |
| Data at risk | All blobs in all containers, Application data, Media files, Exported reports, Backup data stored in blob storage |
| Services at risk | Azure Storage Account, All applications reading from the storage account, Analytics pipelines consuming blob data, Static websites hosted on the storage account |
| Estimated scope | 100% of data in the affected storage account(s) |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

