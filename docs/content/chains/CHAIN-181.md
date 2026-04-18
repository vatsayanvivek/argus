# CHAIN-181 — DR plan untested — silent replication failures

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

No DR test has run in 12+ months. Replication has silently broken for some workloads (schema changes, new disks unprotected). During a real failover, restoration fails for the very workloads that matter most.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_bak_005`](../rules/zt_bak_005.md) | Trigger |
| [`zt_vis_001`](../rules/zt_vis_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Configuration drift accumulates unchecked.

**Actor:** Time  
**MITRE ATT&CK:** `T1499`  
**Enabled by:** [`zt_bak_005`](../rules/zt_bak_005.md)  

**Attacker gain:** Silent DR decay.


### Step 2 — Failover reveals: critical DBs have no recent replica.

**Actor:** Disaster event  
**MITRE ATT&CK:** `T1490`  
**Enabled by:** [`zt_vis_001`](../rules/zt_vis_001.md)  

**Attacker gain:** DR failure.


## Blast radius

| | |
|---|---|
| Initial access | Disaster event. |
| Max privilege | DR failure. |
| Data at risk | Unreplicated critical workloads |
| Services at risk | All workloads depending on DR |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

