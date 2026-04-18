# CHAIN-179 — Instant Restore capacity exhausted — delayed recovery

!!! note "Summary"
    **Severity:** :material-information-outline: Low · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Azure Backup Instant Restore capacity is below the amount needed to restore prod workloads within the target RTO. During a real incident, restores queue behind capacity limits; SLA blown.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_bak_003`](../rules/zt_bak_003.md) | Trigger |
| [`zt_bak_004`](../rules/zt_bak_004.md) | Trigger |

## Attack walkthrough

### Step 1 — Initiate recovery; capacity unavailable.

**Actor:** Restore event  
**MITRE ATT&CK:** `T1499`  
**Enabled by:** [`zt_bak_003`](../rules/zt_bak_003.md)  

**Attacker gain:** Restore queued.


### Step 2 — RTO exceeded waiting for capacity.

**Actor:** Business  
**MITRE ATT&CK:** `T1499`  
**Enabled by:** [`zt_bak_004`](../rules/zt_bak_004.md)  

**Attacker gain:** Extended outage.


## Blast radius

| | |
|---|---|
| Initial access | Restore-time capacity limit. |
| Max privilege | Availability delay. |
| Data at risk | Service uptime |
| Services at risk | Workloads queued for restore |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

