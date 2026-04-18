# CHAIN-061 — Unmonitored directory role change

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

No Activity Log alert is configured for role assignment changes AND Entra audit logs are not streamed to a SIEM. An attacker who gains Global Admin (via any other chain) can create a new admin, delete logs, and exit without leaving a correlatable trail.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_vis_021`](../rules/zt_vis_021.md) | Trigger |
| [`zt_vis_008`](../rules/zt_vis_008.md) | Trigger |

## Attack walkthrough

### Step 1 — Create a second Global Admin account as persistence.

**Actor:** Attacker-admin  
**MITRE ATT&CK:** `T1098`  
**Enabled by:** [`zt_vis_021`](../rules/zt_vis_021.md)  

**Attacker gain:** Second admin account with no alert fired.


### Step 2 — Lower audit log retention or filter to hide the change.

**Actor:** Attacker-admin  
**MITRE ATT&CK:** `T1070.001`  
**Enabled by:** [`zt_vis_008`](../rules/zt_vis_008.md)  

**Attacker gain:** Forensic trail gap.


## Blast radius

| | |
|---|---|
| Initial access | Assumes prior admin escalation. |
| Max privilege | Persistence across password reset. |
| Data at risk | Directory, Audit integrity |
| Services at risk | Entra ID |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

