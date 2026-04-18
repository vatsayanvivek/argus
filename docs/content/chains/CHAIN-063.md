# CHAIN-063 — Dynamic group rule misconfig grants role to unintended users

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A dynamic group rule (e.g. department = 'engineering') grants membership based on a user attribute. An attacker with User Admin or attribute-edit rights modifies a user's department to match, auto-joining them to the group — and inheriting whatever role the group holds.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_024`](../rules/zt_id_024.md) | Trigger |
| [`zt_id_025`](../rules/zt_id_025.md) | Trigger |

## Attack walkthrough

### Step 1 — Edit a principal's department attribute to trigger the dynamic rule.

**Actor:** Attacker with User Admin  
**MITRE ATT&CK:** `T1098`  
**Enabled by:** [`zt_id_025`](../rules/zt_id_025.md)  

**Attacker gain:** Auto-membership in privileged dynamic group.


### Step 2 — Sign in; role inherited via dynamic group.

**Actor:** Attacker principal  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_id_024`](../rules/zt_id_024.md)  

**Attacker gain:** Role granted through attribute-driven flow.


## Blast radius

| | |
|---|---|
| Initial access | User Admin. |
| Max privilege | Dynamic group's inherited role. |
| Data at risk | Whatever the role grants |
| Services at risk | Entra ID dynamic groups |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

