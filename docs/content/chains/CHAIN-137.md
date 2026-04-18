# CHAIN-137 — VM extension custom script contains embedded password

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A VM is provisioned with a custom-script extension that passes credentials as script arguments. Anyone with Reader on the VM can view the extension's settings including plaintext args. No secret rotation, no history.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_024`](../rules/zt_wl_024.md) | Trigger |
| [`zt_wl_028`](../rules/zt_wl_028.md) | Trigger |

## Attack walkthrough

### Step 1 — View VM extension settings via ARM API.

**Actor:** Reader  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_wl_024`](../rules/zt_wl_024.md)  

**Attacker gain:** Plaintext credential in extension args.


### Step 2 — Use credential to authenticate elsewhere.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_wl_028`](../rules/zt_wl_028.md)  

**Attacker gain:** Follow-on access.


## Blast radius

| | |
|---|---|
| Initial access | Reader role. |
| Max privilege | Whatever cred grants. |
| Data at risk | Downstream systems |
| Services at risk | Wherever the cred is valid |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

