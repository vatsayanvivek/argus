# CHAIN-081 — Data Factory linked service with cleartext credential

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

An ADF pipeline uses a linked service that stores DB credentials inline instead of referencing Key Vault. Anyone with Data Factory Reader on the workspace can read the linked service JSON and extract the password. No vault rotation, no CA gate, no alert.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_021`](../rules/zt_data_021.md) | Trigger |
| [`zt_vis_001`](../rules/zt_vis_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Export pipeline + linked service JSON via portal or API.

**Actor:** DF Reader  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_data_021`](../rules/zt_data_021.md)  

**Attacker gain:** DB credential in plaintext.


### Step 2 — Connect directly to the referenced database.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_vis_001`](../rules/zt_vis_001.md)  

**Attacker gain:** No trace — DF audit log doesn't cover external DB sessions.


## Blast radius

| | |
|---|---|
| Initial access | Data Factory Reader. |
| Max privilege | DB role granted to the credential. |
| Data at risk | Source/sink database content |
| Services at risk | Any data store linked to this ADF |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

