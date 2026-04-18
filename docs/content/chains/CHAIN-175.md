# CHAIN-175 — Site Recovery RPO higher than business tolerance

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Azure Site Recovery RPO is 4 hours for a system whose tolerance is 15 minutes. A failover loses 4 hours of transactions; incident post-mortem reveals the mismatch and triggers a costly re-architecture.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_bak_005`](../rules/zt_bak_005.md) | Trigger |
| [`zt_bak_004`](../rules/zt_bak_004.md) | Trigger |

## Attack walkthrough

### Step 1 — Failover to Site Recovery replica.

**Actor:** Primary failure  
**MITRE ATT&CK:** `T1499`  
**Enabled by:** [`zt_bak_005`](../rules/zt_bak_005.md)  

**Attacker gain:** Service restored but with data loss.


### Step 2 — 4 hours of transactions lost; customer SLA breached.

**Actor:** Business impact  
**MITRE ATT&CK:** `T1486`  
**Enabled by:** [`zt_bak_004`](../rules/zt_bak_004.md)  

**Attacker gain:** Transactional data loss + SLA failure.


## Blast radius

| | |
|---|---|
| Initial access | Disaster event. |
| Max privilege | Data loss during failover. |
| Data at risk | Transactions in the RPO window |
| Services at risk | Any app replicated via ASR |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

