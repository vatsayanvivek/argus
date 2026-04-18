# CHAIN-052 — Guest user with group-based admin escalation

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A guest user is invited to a group that transitively holds a privileged Entra directory role. Because group-based role assignments inherit to every direct and nested member, the guest gains tenant-wide privilege the moment the invitation is accepted. Cross-tenant access policies that don't restrict what external users can do compound this.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_023`](../rules/zt_id_023.md) | Trigger |
| [`zt_id_024`](../rules/zt_id_024.md) | Trigger |

## Attack walkthrough

### Step 1 — Accept an invitation for a guest user into the home tenant.

**Actor:** External tenant admin  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_023`](../rules/zt_id_023.md)  

**Attacker gain:** Guest foothold in the target tenant.


### Step 2 — Enumerate groups and discover one that holds User Administrator or similar via nested membership.

**Actor:** Guest user  
**MITRE ATT&CK:** `T1087.004`  
**Enabled by:** [`zt_id_024`](../rules/zt_id_024.md)  

**Attacker gain:** Privileged directory role by transitive inheritance.


### Step 3 — Create new users, reset passwords, or grant Application.ReadWrite.All to a controlled app.

**Actor:** Guest with role  
**MITRE ATT&CK:** `T1098`  
**Enabled by:** [`zt_id_024`](../rules/zt_id_024.md)  

**Attacker gain:** Persistent, tenant-wide admin control.


## Blast radius

| | |
|---|---|
| Initial access | Guest invitation accepted. |
| Max privilege | Entra directory admin role (User Admin, Application Admin, etc.). |
| Data at risk | Directory data, App secrets, Email / Teams via consent exploitation |
| Services at risk | Entra ID, Microsoft Graph |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

