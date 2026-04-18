# CHAIN-066 — Application admin grants Graph app perms without review

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A user holds Application Administrator (not Global Admin, but enough to grant admin consent for Graph application permissions). Combined with no review of consented apps, the admin can grant Directory.ReadWrite.All to a new app without detection and create a permanent backdoor.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_013`](../rules/zt_id_013.md) | Trigger |
| [`zt_id_011`](../rules/zt_id_011.md) | Trigger |

## Attack walkthrough

### Step 1 — Register a new Entra app requesting Directory.ReadWrite.All as application permission.

**Actor:** Malicious app admin  
**MITRE ATT&CK:** `T1098`  
**Enabled by:** [`zt_id_013`](../rules/zt_id_013.md)  

**Attacker gain:** App awaiting consent.


### Step 2 — Grant admin consent to the app (App Admin can).

**Actor:** Same actor  
**MITRE ATT&CK:** `T1098`  
**Enabled by:** [`zt_id_011`](../rules/zt_id_011.md)  

**Attacker gain:** Persistent tenant-wide directory write via app backdoor.


## Blast radius

| | |
|---|---|
| Initial access | Application Administrator role. |
| Max privilege | Tenant-wide directory write via planted app. |
| Data at risk | All directory objects |
| Services at risk | Entra ID |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

