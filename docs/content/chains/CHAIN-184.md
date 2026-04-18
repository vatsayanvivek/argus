# CHAIN-184 — Activity Log alerts missing on IAM writes

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

No Activity Log alert is configured for Microsoft.Authorization/roleAssignments/write. When an attacker grants themselves Owner on a resource group, SOC has no real-time alert — the change lives in the log but nobody's watching.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_vis_021`](../rules/zt_vis_021.md) | Trigger |
| [`zt_vis_001`](../rules/zt_vis_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Grant self Owner via role assignment.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1098`  
**Enabled by:** [`zt_vis_021`](../rules/zt_vis_021.md)  

**Attacker gain:** Owner role without trigger.


### Step 2 — Operate freely; evidence lives in log but never alerts.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1562`  
**Enabled by:** [`zt_vis_001`](../rules/zt_vis_001.md)  

**Attacker gain:** Silent privilege escalation.


## Blast radius

| | |
|---|---|
| Initial access | Contributor / UAA. |
| Max privilege | Owner via self-grant. |
| Data at risk | IAM integrity |
| Services at risk | Azure RBAC |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

