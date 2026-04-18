# CHAIN-193 — Terraform state in storage account with public access

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Terraform state is stored in a blob container with allowBlobPublicAccess=true. The state file contains every resource ID, every parameter, and often plaintext secrets that Terraform had to 'see' during apply. Anyone with the URL has the entire infrastructure spec.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_001`](../rules/zt_data_001.md) | Trigger |
| [`zt_id_003`](../rules/zt_id_003.md) | Trigger |

## Attack walkthrough

### Step 1 — Discover public Terraform state; download state file.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1213`  
**Enabled by:** [`zt_data_001`](../rules/zt_data_001.md)  

**Attacker gain:** Complete infra inventory + embedded secrets.


### Step 2 — Use harvested secrets to pivot to every named resource.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_id_003`](../rules/zt_id_003.md)  

**Attacker gain:** Cross-resource takeover.


## Blast radius

| | |
|---|---|
| Initial access | Public state URL. |
| Max privilege | Whatever the embedded secrets unlock. |
| Data at risk | Entire deployed stack |
| Services at risk | Every resource in state |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

