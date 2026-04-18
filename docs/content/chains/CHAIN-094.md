# CHAIN-094 — Blob versioning off + immutability off + writable

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

A storage container has blob versioning and immutability both off AND a compromised key. A ransomware operator overwrites every blob with encrypted content. Original data gone — this is 'ransomware by API call'.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_013`](../rules/zt_data_013.md) | Trigger |
| [`zt_data_016`](../rules/zt_data_016.md) | Trigger |

## Attack walkthrough

### Step 1 — Authenticate via SAS/account key.

**Actor:** Attacker with key  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_data_013`](../rules/zt_data_013.md)  

**Attacker gain:** Write access to container.


### Step 2 — PUT encrypted content over every existing blob; previous version unreachable.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1486`  
**Enabled by:** [`zt_data_016`](../rules/zt_data_016.md)  

**Attacker gain:** Full encryption ransomware on storage.


## Blast radius

| | |
|---|---|
| Initial access | Any storage write access. |
| Max privilege | Destructive — full container encryption. |
| Data at risk | Every blob in container |
| Services at risk | Storage, Any dependent app |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

