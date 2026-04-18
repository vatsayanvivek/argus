# CHAIN-054 — PIM eligible role activated without approval gate

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A high-privilege role (Global Admin, User Access Admin) is assigned Eligible via PIM but the activation policy requires neither an approver nor justification. Any identity that compromises the eligible principal's creds can self-activate to full admin with zero friction.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_009`](../rules/zt_id_009.md) | Trigger |
| [`zt_id_010`](../rules/zt_id_010.md) | Trigger |

## Attack walkthrough

### Step 1 — Sign in as the eligible principal.

**Actor:** Attacker with creds  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_id_009`](../rules/zt_id_009.md)  

**Attacker gain:** Base user session.


### Step 2 — POST /activate to PIM with any excuse text; activation completes without approver review.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1098.003`  
**Enabled by:** [`zt_id_010`](../rules/zt_id_010.md)  

**Attacker gain:** Active tenant-admin role for the full activation window.


## Blast radius

| | |
|---|---|
| Initial access | Stolen credentials of an eligible role-holder. |
| Max privilege | Whatever the eligible role grants — often Global Admin. |
| Data at risk | Directory data, All Azure resources under tenant |
| Services at risk | Entra ID, Azure RBAC at root MG |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

