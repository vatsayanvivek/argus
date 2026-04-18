# CHAIN-062 — Group owner can escalate by adding self to privileged group

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A non-admin user is set as owner of a group that holds a privileged role via role assignment. Group owners can add members, including themselves. No IAM separation-of-duties control stops this.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_024`](../rules/zt_id_024.md) | Trigger |
| [`zt_id_016`](../rules/zt_id_016.md) | Trigger |

## Attack walkthrough

### Step 1 — Use MS Graph PATCH /groups/<id>/members to add own user object.

**Actor:** Group owner  
**MITRE ATT&CK:** `T1098`  
**Enabled by:** [`zt_id_024`](../rules/zt_id_024.md)  

**Attacker gain:** Self-promoted to privileged group.


### Step 2 — Inherit the group's role; sign in to admin endpoints.

**Actor:** New group member  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_016`](../rules/zt_id_016.md)  

**Attacker gain:** Directory role via group membership.


## Blast radius

| | |
|---|---|
| Initial access | Group owner role only. |
| Max privilege | Whatever role the group carries. |
| Data at risk | Directory scope of inherited role |
| Services at risk | Entra ID |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

