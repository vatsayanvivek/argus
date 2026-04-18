# CHAIN-093 — Table Storage with soft-delete off + public access

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Table Storage has no soft-delete protection AND public read is enabled. A ransomware actor who reaches any RBAC writer can simply delete all rows — no undelete, no restore, full data loss.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_014`](../rules/zt_data_014.md) | Trigger |
| [`zt_data_015`](../rules/zt_data_015.md) | Trigger |

## Attack walkthrough

### Step 1 — Authenticate with a leaked SAS or compromised RBAC.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552`  
**Enabled by:** [`zt_data_015`](../rules/zt_data_015.md)  

**Attacker gain:** Table write.


### Step 2 — DELETE every partition key batch; no recovery available.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1485`  
**Enabled by:** [`zt_data_014`](../rules/zt_data_014.md)  

**Attacker gain:** Table obliteration.


## Blast radius

| | |
|---|---|
| Initial access | SAS or RBAC compromise. |
| Max privilege | Destructive — table destruction. |
| Data at risk | Table content |
| Services at risk | Any app reading the table |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

