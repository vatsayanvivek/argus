# CHAIN-163 — Front Door origin pool without health probe

!!! note "Summary"
    **Severity:** :material-information-outline: Low · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

Front Door origin pool has no health probe configured. A failed origin silently receives traffic and returns 502s. During an incident, Front Door cannot route around the failure — availability SLA is meaningless.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_int_008`](../rules/zt_int_008.md) | Trigger |
| [`zt_net_007`](../rules/zt_net_007.md) | Trigger |

## Attack walkthrough

### Step 1 — Origin returns 500s; Front Door continues to route.

**Actor:** Origin failure  
**MITRE ATT&CK:** `T1499`  
**Enabled by:** [`zt_int_008`](../rules/zt_int_008.md)  

**Attacker gain:** Availability collapse.


### Step 2 — Extended user-facing outage.

**Actor:** Business impact  
**MITRE ATT&CK:** `T1499`  
**Enabled by:** [`zt_net_007`](../rules/zt_net_007.md)  

**Attacker gain:** Downtime / SLA breach.


## Blast radius

| | |
|---|---|
| Initial access | Origin failure event. |
| Max privilege | Availability impact. |
| Data at risk | Service uptime |
| Services at risk | Front Door + backing app |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

