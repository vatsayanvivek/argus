# CHAIN-170 — Event Hub partition key predictable — message replay

!!! note "Summary"
    **Severity:** :material-information-outline: Low · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Event Hub is used for audit trail ingestion. Partition keys are simple (user email). An attacker with any SAS can publish arbitrary events to any partition — forging 'audit' entries attributed to any user.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_int_005`](../rules/zt_int_005.md) | Trigger |
| [`zt_vis_001`](../rules/zt_vis_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Craft forged audit event with victim user's partition key.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1565.001`  
**Enabled by:** [`zt_int_005`](../rules/zt_int_005.md)  

**Attacker gain:** Forged audit entry.


### Step 2 — Trusts the audit log as-is; investigation misdirected.

**Actor:** Security team  
**MITRE ATT&CK:** `T1070.001`  
**Enabled by:** [`zt_vis_001`](../rules/zt_vis_001.md)  

**Attacker gain:** Misleading forensics.


## Blast radius

| | |
|---|---|
| Initial access | Any SAS on the hub. |
| Max privilege | Audit log forgery. |
| Data at risk | Audit integrity |
| Services at risk | SOC / IR pipelines |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

