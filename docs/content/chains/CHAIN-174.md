# CHAIN-174 — Azure Backup cross-region replication disabled

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Backup vault is configured for LRS (local-redundant) only — no cross-region replication. A regional Azure outage or regional disaster means no recovery path; the entire backup estate is offline along with primary infrastructure.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_bak_003`](../rules/zt_bak_003.md) | Trigger |
| [`zt_bak_002`](../rules/zt_bak_002.md) | Trigger |

## Attack walkthrough

### Step 1 — Primary + backup region become unavailable.

**Actor:** Regional disaster  
**MITRE ATT&CK:** `T1561`  
**Enabled by:** [`zt_bak_003`](../rules/zt_bak_003.md)  

**Attacker gain:** Backup inaccessibility.


### Step 2 — Extended RTO beyond stated DR objective.

**Actor:** Business  
**MITRE ATT&CK:** `T1499`  
**Enabled by:** [`zt_bak_002`](../rules/zt_bak_002.md)  

**Attacker gain:** DR failure.


## Blast radius

| | |
|---|---|
| Initial access | Regional event. |
| Max privilege | DR failure. |
| Data at risk | Backup availability |
| Services at risk | All backed-up workloads during DR |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

