# CHAIN-042 — VM disk theft to offline data exfiltration

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A virtual machine's OS and data disks are not encrypted with Azure Disk Encryption or EncryptionAtHost, meaning the underlying VHD blobs store data in the clear at the platform layer. An attacker who gains even Reader + Disk Snapshot Contributor rights (commonly available to developer-role identities) can snapshot the disk, share the snapshot to an external subscription, and mount it offline to read every file on the volume - database files, credential caches, application secrets, memory dumps. Because Azure Backup is not configured for these VMs, the organisation has no independent recovery copy and cannot restore to a known-good state if the attacker also corrupts the live disk. To make matters worse, no Azure Monitor alert rules are configured, so the snapshot-and-copy operation completes silently: the ARM activity log records the API call, but nobody is watching.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_020`](../rules/zt_wl_020.md) | Trigger |
| [`zt_data_017`](../rules/zt_data_017.md) | Trigger |
| [`zt_vis_012`](../rules/zt_vis_012.md) | Trigger |

## Attack walkthrough

### Step 1 — Enumerate VM disks in the subscription and confirm they lack encryption.

**Actor:** Insider or compromised identity  
**MITRE ATT&CK:** `T1580`  
**Enabled by:** [`zt_wl_020`](../rules/zt_wl_020.md)  

> GET /subscriptions/{sub}/providers/Microsoft.Compute/disks?api-version=2023-10-02 - inspect encryptionSettings; disks show encryption.type='EncryptionAtRestWithPlatformKey' only (no customer key, no host-based encryption).

**Attacker gain:** Target list of unencrypted disks whose VHD content is readable if the raw blob is obtained.


### Step 2 — Create a snapshot of the target disk and grant access to generate a SAS URI for download.

**Actor:** Insider or compromised identity  
**MITRE ATT&CK:** `T1537`  
**Enabled by:** [`zt_wl_020`](../rules/zt_wl_020.md)  

> PUT /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/snapshots/{name} with creationData.sourceResourceId pointing to the target disk; then POST .../beginGetAccess to produce a time-limited SAS URL for the snapshot blob.

**Attacker gain:** A downloadable copy of the entire disk volume as a VHD blob, accessible via a SAS URL.


### Step 3 — Download the VHD snapshot to attacker-controlled infrastructure and mount it offline.

**Actor:** Attacker (external infrastructure)  
**MITRE ATT&CK:** `T1530`  
**Enabled by:** [`zt_wl_020`](../rules/zt_wl_020.md)  

> azcopy copy 'https://{sa}.blob.core.windows.net/{container}/{snap}.vhd?{sas}' ./disk.vhd; mount locally via qemu-nbd or Hyper-V to browse the filesystem offline.

**Attacker gain:** Full offline access to every file, registry hive, credential cache, and database file on the disk.


### Step 4 — Extract credentials, application secrets, and sensitive data from the mounted volume.

**Actor:** Attacker (offline analysis)  
**MITRE ATT&CK:** `T1005`  
**Enabled by:** [`zt_data_017`](../rules/zt_data_017.md)  

> Parse SAM/SYSTEM/SECURITY hives for local credential hashes, extract connection strings from web.config and appsettings.json, recover database .mdf files, dump DPAPI master keys.

**Attacker gain:** Plaintext credentials, application secrets, database contents, and PII extracted from the offline disk image.


### Step 5 — Confirm no alerts fired and no backup exists to enable recovery or forensic comparison.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_vis_012`](../rules/zt_vis_012.md)  

> No Azure Monitor alert rules are configured (zt_vis_012), so the Microsoft.Compute/snapshots/write activity log entry was never evaluated. No Azure Backup vault protects the VM (zt_data_017), so there is no independent recovery point to compare against or restore from.

**Attacker gain:** Complete operational stealth: the disk theft is recorded in the activity log but no human or automation is watching.


## Blast radius

| | |
|---|---|
| Initial access | Any identity with Disk Snapshot Contributor or equivalent on the target resource group. |
| Lateral movement | Offline credential extraction from the disk image provides passwords and tokens for lateral movement to other services. |
| Max privilege | Depends on credentials found on the disk; commonly includes service account passwords, managed identity certificates, and database connection strings. |
| Data at risk | VM filesystem contents, Local credential caches (SAM/LSA), Application secrets and connection strings, Database files, Customer PII on disk |
| Services at risk | Virtual Machines, Managed Disks, Any service whose credentials are stored on the VM |
| Estimated scope | All VMs without disk encryption in the subscription |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

