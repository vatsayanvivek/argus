# CHAIN-096 — Cosmos DB multi-region replication to wrong region

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Low · **Logic:** `ALL`

## Why this chain matters

Cosmos DB has a secondary replica in a region outside data-residency commitments. The replica is still ARM-addressable; a compromised principal targets the off-region endpoint which may have weaker VNet rules.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_018`](../rules/zt_data_018.md) | Trigger |
| [`zt_data_009`](../rules/zt_data_009.md) | Trigger |

## Attack walkthrough

### Step 1 — Enumerate Cosmos accounts; find the off-region writeable replica.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1087`  
**Enabled by:** [`zt_data_018`](../rules/zt_data_018.md)  

**Attacker gain:** Replica endpoint with looser firewall.


### Step 2 — Authenticate + read; same data as primary.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1213`  
**Enabled by:** [`zt_data_009`](../rules/zt_data_009.md)  

**Attacker gain:** Read-path circumvention of the primary's hardening.


## Blast radius

| | |
|---|---|
| Initial access | Off-region endpoint exposure. |
| Max privilege | Cosmos read/write role. |
| Data at risk | Same content as primary |
| Services at risk | Cosmos DB |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

