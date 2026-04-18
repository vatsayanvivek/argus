# CHAIN-005 — Public storage no diagnostics to silent exfil

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

A storage account allows public blob access, has no diagnostic settings streaming to Log Analytics, and encryption is either using platform-managed keys or disabled at the container level. An attacker who guesses or enumerates the container name can list and download every blob, and because StorageRead logs never left the resource, there is no evidence an exfiltration occurred. The breach is only noticed when the data shows up in a dump.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_001`](../rules/zt_data_001.md) | Trigger |
| [`zt_vis_001`](../rules/zt_vis_001.md) | Trigger |
| [`zt_data_006`](../rules/zt_data_006.md) | Trigger |

## Attack walkthrough

### Step 1 — Enumerate Azure storage account names via DNS brute-force against *.blob.core.windows.net.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1580`  
**Enabled by:** [`zt_data_001`](../rules/zt_data_001.md)  

> DNS resolution of candidate names reveals live accounts; anonymous GET against common container paths (backups, data, public, assets) completes the discovery.

**Attacker gain:** Confirmed reachable, anonymously-readable containers.


### Step 2 — List and download all blobs using the unauthenticated REST endpoint.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1530`  
**Enabled by:** [`zt_data_001`](../rules/zt_data_001.md)  

> GET https://{account}.blob.core.windows.net/{container}?restype=container&comp=list - returns full blob inventory; follow with GET per blob.

**Attacker gain:** Bulk copy of every blob in the container - backups, PII, source code, secrets.


### Step 3 — Operate without detection because diagnostic logs are not forwarded.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_vis_001`](../rules/zt_vis_001.md)  

> No diagnosticSettings resource attached to the storage account; StorageRead/StorageWrite logs never leave the account and are purged after the retention window.

**Attacker gain:** Zero telemetry of the attack. Defenders have no events to correlate.


### Step 4 — Decrypt any blobs that used weak or platform-default encryption where the key was accessible.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1486`  
**Enabled by:** [`zt_data_006`](../rules/zt_data_006.md)  

> Blobs encrypted with Microsoft-managed keys are transparently decrypted on read; customer-managed keys were not enforced so the attacker receives plaintext.

**Attacker gain:** Plaintext access to sensitive data without needing to compromise Key Vault.


## Blast radius

| | |
|---|---|
| Initial access | Anonymous internet access to public storage containers. |
| Lateral movement | None required - the data is directly reachable. |
| Max privilege | Read (and potentially write) on every blob in exposed containers. |
| Data at risk | Backups, Application data, Customer PII, Source code, Embedded secrets and tokens |
| Services at risk | Azure Storage, Any downstream system whose secrets were in exfiltrated blobs |
| Estimated scope | All publicly-exposed containers on affected storage accounts |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

