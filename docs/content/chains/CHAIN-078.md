# CHAIN-078 — Storage account SAS token with long TTL + URL leak

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

Storage generates SAS tokens with expiry > 90 days AND blob public access is off (private by design). A SAS token leaked into a log, browser history, or URL referrer still unlocks the storage account for three months, bypassing firewall rules.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_012`](../rules/zt_data_012.md) | Trigger |
| [`zt_data_001`](../rules/zt_data_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Find the SAS URL in a leaked HAR / web archive / log file.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_data_012`](../rules/zt_data_012.md)  

**Attacker gain:** Valid signed URL.


### Step 2 — Use the SAS to download every blob, bypassing private endpoint or firewall.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1530`  
**Enabled by:** [`zt_data_001`](../rules/zt_data_001.md)  

**Attacker gain:** Bulk data exfiltration.


## Blast radius

| | |
|---|---|
| Initial access | SAS URL in any leaked artifact. |
| Max privilege | Whatever the SAS was scoped to. |
| Data at risk | Every blob in SAS scope |
| Services at risk | Azure Storage |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

