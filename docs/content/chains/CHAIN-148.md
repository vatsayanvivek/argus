# CHAIN-148 — ML datastore with cleartext credential in datastore config

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

An Azure ML datastore references a SQL database using plaintext username/password in the datastore registration JSON. Anyone with Reader on the workspace can dump this config.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_ai_003`](../rules/zt_ai_003.md) | Trigger |
| [`zt_data_007`](../rules/zt_data_007.md) | Trigger |

## Attack walkthrough

### Step 1 — GET /datastores; read credential field.

**Actor:** Workspace Reader  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_ai_003`](../rules/zt_ai_003.md)  

**Attacker gain:** DB creds.


### Step 2 — Connect to DB directly.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_data_007`](../rules/zt_data_007.md)  

**Attacker gain:** DB-wide read.


## Blast radius

| | |
|---|---|
| Initial access | Workspace reader. |
| Max privilege | DB role. |
| Data at risk | ML training data source |
| Services at risk | DB + downstream models |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

