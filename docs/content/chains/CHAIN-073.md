# CHAIN-073 — Stale service principal with no owner

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A service principal exists with no listed owner AND a never-expiring credential. The original developer left years ago. The SP still has Contributor on a production subscription. No one will notice if its credential is used.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_022`](../rules/zt_id_022.md) | Trigger |
| [`zt_id_001`](../rules/zt_id_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Discover the SP's client secret in an old CI log or GitHub history.

**Actor:** Attacker with old leak  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_id_001`](../rules/zt_id_001.md)  

**Attacker gain:** Valid SP auth.


### Step 2 — Use SP to operate on prod; no owner gets notified of anomalous activity.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_id_022`](../rules/zt_id_022.md)  

**Attacker gain:** Stealth subscription-scope access.


## Blast radius

| | |
|---|---|
| Initial access | Ancient secret leak. |
| Max privilege | SP's RBAC assignment. |
| Data at risk | Prod subscription resources |
| Services at risk | Whatever the stale SP can touch |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

