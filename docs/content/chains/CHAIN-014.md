# CHAIN-014 — No backup public storage to ransomware no recovery

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

Critical storage holds no geo-redundant backup or soft-delete configuration, the account permits public blob access, and outbound egress from any VM in the environment is unrestricted. An attacker encrypts or overwrites the blobs (ransomware), and because there is no backup tier and no versioning, the only copy of the data is the encrypted one. Payment becomes the only option.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_008`](../rules/zt_data_008.md) | Trigger |
| [`zt_data_001`](../rules/zt_data_001.md) | Trigger |
| [`zt_net_009`](../rules/zt_net_009.md) | Trigger |

## Attack walkthrough

### Step 1 — Discover the public storage account and identify writable containers.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1580`  
**Enabled by:** [`zt_data_001`](../rules/zt_data_001.md)  

> DNS brute-force against *.blob.core.windows.net; PUT probe reveals container-level public write or recoverable credentials.

**Attacker gain:** Confirmed writable target.


### Step 2 — Encrypt every blob in place with attacker-controlled keys.

**Actor:** Attacker with writable blob access  
**MITRE ATT&CK:** `T1486`  
**Enabled by:** [`zt_data_008`](../rules/zt_data_008.md)  

> Download, AES-encrypt, PUT back; soft-delete is either off or short enough to expire during the operation.

**Attacker gain:** Irrecoverable encryption of production data.


### Step 3 — Exfiltrate a copy via unrestricted egress for double-extortion leverage.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1048.003`  
**Enabled by:** [`zt_net_009`](../rules/zt_net_009.md)  

> Outbound NSG allows egress to attacker CDN; data is streamed out before encryption.

**Attacker gain:** Stolen copy available for sale / extortion in addition to the local encryption.


### Step 4 — Attempt recovery and fail.

**Actor:** Business  
**MITRE ATT&CK:** `T1490`  
**Enabled by:** [`zt_data_008`](../rules/zt_data_008.md)  

> No geo-redundant backup, no immutable blob policy, no snapshot history; blob versioning disabled.

**Attacker gain:** Recovery is impossible without paying the ransom.


## Blast radius

| | |
|---|---|
| Initial access | Public or weakly-authenticated blob access. |
| Lateral movement | Not required - a single storage account is the target. |
| Max privilege | Full write/delete on the storage data set. |
| Data at risk | All blobs in the exposed account(s), Backups that do not exist, Application state |
| Services at risk | Azure Storage, Every application reading from the affected containers |
| Estimated scope | 100% of the data in the affected storage account |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

