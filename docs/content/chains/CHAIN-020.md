# CHAIN-020 — No Sentinel no diagnostics to invisible persistence

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

There is no Microsoft Sentinel workspace ingesting Azure telemetry, resource-level diagnostic settings are missing across the environment, and Entra ID sign-in and audit logs are not exported. Any adversary that gains a foothold can establish persistence - service principals, app registrations, role assignments, resource changes - without any correlation or retention that would let defenders see it. Sooner or later this becomes somebody else's incident report.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_vis_007`](../rules/zt_vis_007.md) | Trigger |
| [`zt_vis_001`](../rules/zt_vis_001.md) | Trigger |
| [`zt_vis_005`](../rules/zt_vis_005.md) | Trigger |

## Attack walkthrough

### Step 1 — Enumerate and choose persistence techniques that leave telemetry only in places defenders are not watching.

**Actor:** Attacker with any initial access  
**MITRE ATT&CK:** `T1098`  
**Enabled by:** [`zt_vis_007`](../rules/zt_vis_007.md)  

> Service principal creation, app consent grants, role assignment changes - all emit AuditLogs events.

**Attacker gain:** Confidence that subsequent actions will not surface in any SIEM.


### Step 2 — Create persistent backdoor service principal and grant it roles.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1136.003`  
**Enabled by:** [`zt_vis_005`](../rules/zt_vis_005.md)  

> New-MgServicePrincipal + New-MgRoleAssignment - events flow into AuditLogs but go nowhere.

**Attacker gain:** Durable non-human identity in the tenant.


### Step 3 — Operate long-term across resources whose diagnostic settings are disabled.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_vis_001`](../rules/zt_vis_001.md)  

> Storage, Key Vault, SQL audit logs not enabled; even on-resource anomalies are never captured.

**Attacker gain:** Persistent hands-on-keyboard access with no forensic trail.


## Blast radius

| | |
|---|---|
| Initial access | Any initial foothold - the chain is about what happens after. |
| Lateral movement | Anywhere, because nothing watches lateral movement. |
| Max privilege | Whatever the attacker can gradually accumulate. |
| Data at risk | Everything, Retroactive investigation is impossible |
| Services at risk | All Azure and Entra services |
| Estimated scope | Unknown - no telemetry to size the blast radius |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

