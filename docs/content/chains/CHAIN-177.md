# CHAIN-177 — Automation Account runbook stores secrets in clear variables

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

An Azure Automation Account runbook uses plaintext variables (not encrypted variables) to store service account passwords. Anyone with Automation Operator role can read the variables.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_bak_002`](../rules/zt_bak_002.md) | Trigger |
| [`zt_wl_017`](../rules/zt_wl_017.md) | Trigger |

## Attack walkthrough

### Step 1 — GET variables via Automation API; fields are plaintext.

**Actor:** Automation Operator  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_bak_002`](../rules/zt_bak_002.md)  

**Attacker gain:** Service account passwords.


### Step 2 — Authenticate with stolen creds.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_wl_017`](../rules/zt_wl_017.md)  

**Attacker gain:** Service account access across the environment.


## Blast radius

| | |
|---|---|
| Initial access | Automation Operator role. |
| Max privilege | Service account scope. |
| Data at risk | Wherever the service account is authorised |
| Services at risk | Everything the runbook automates |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

