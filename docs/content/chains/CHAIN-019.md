# CHAIN-019 — Permanent privilege no PIM no reviews to insider threat

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

This is the identity-only variant of CHAIN-004. Every layer of the privileged-identity lifecycle is missing: permanent role assignments exist, PIM is not configured as the enforcement path, and no access reviews ever reconcile membership. A single malicious or compromised insider owns the tenant indefinitely, with no compensating control to limit blast radius or dwell time.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_003`](../rules/zt_id_003.md) | Trigger |
| [`zt_id_007`](../rules/zt_id_007.md) | Trigger |
| [`zt_id_010`](../rules/zt_id_010.md) | Trigger |

## Attack walkthrough

### Step 1 — Hold a standing Global Administrator or User Access Administrator assignment.

**Actor:** Privileged insider  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_003`](../rules/zt_id_003.md)  

> Role assignment with assignmentType=Active and no endDateTime; not brokered through PIM.

**Attacker gain:** 24/7 privilege without activation friction.


### Step 2 — Escalate further by assigning additional roles at will.

**Actor:** Privileged insider  
**MITRE ATT&CK:** `T1098.003`  
**Enabled by:** [`zt_id_007`](../rules/zt_id_007.md)  

> PIM not enforced as the only path to privilege; role assignments created directly against role definitions.

**Attacker gain:** Self-escalation to any directory or subscription role.


### Step 3 — Remain in place for quarters because no access review catches the standing privilege.

**Actor:** Privileged insider  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_010`](../rules/zt_id_010.md)  

> Access Reviews not enabled on directory roles or privileged groups.

**Attacker gain:** Indefinite dwell time.


### Step 4 — Execute the intended impact at the time of their choosing.

**Actor:** Privileged insider  
**MITRE ATT&CK:** `T1485`  
**Enabled by:** [`zt_id_003`](../rules/zt_id_003.md)  

> Bulk data export, selective destruction, credential theft - all permitted by standing privilege.

**Attacker gain:** Whatever outcome the insider has planned - there is no guardrail.


## Blast radius

| | |
|---|---|
| Initial access | Any privileged insider account. |
| Lateral movement | Not required - standing privilege already spans the tenant. |
| Max privilege | Global Administrator indefinitely. |
| Data at risk | Entire tenant, All subscriptions, All Microsoft 365 data |
| Services at risk | Entra ID, Every Azure subscription, All Microsoft 365 workloads |
| Estimated scope | 100% of the tenant |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

