# CHAIN-064 — On-prem sync admin compromises cloud

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Entra Connect server holds a synchronization account that can write to the directory. The server is domain-joined and shares local admins with other workstations. Compromise the workstation → dump LSASS → own the sync account → write to Entra directly.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_017`](../rules/zt_id_017.md) | Trigger |
| [`zt_id_018`](../rules/zt_id_018.md) | Trigger |

## Attack walkthrough

### Step 1 — Run Mimikatz to extract cached credentials of a shared local admin.

**Actor:** Attacker on workstation  
**MITRE ATT&CK:** `T1003.001`  
**Enabled by:** [`zt_id_017`](../rules/zt_id_017.md)  

**Attacker gain:** Sync-server local admin credential.


### Step 2 — Impersonate sync account; write directly to Entra via MSOL account token.

**Actor:** Attacker on Connect server  
**MITRE ATT&CK:** `T1098`  
**Enabled by:** [`zt_id_018`](../rules/zt_id_018.md)  

**Attacker gain:** Directory write access bypassing Conditional Access.


## Blast radius

| | |
|---|---|
| Initial access | Compromised on-prem workstation. |
| Max privilege | Directory write — equivalent to tenant admin. |
| Data at risk | Entire hybrid directory |
| Services at risk | Entra Connect + Entra ID |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

