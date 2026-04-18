# CHAIN-189 — Subscription without Activity Log export

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

The subscription's Activity Log is kept at default 90-day retention (in Azure) with no export to Log Analytics or Storage. At day 91, every control-plane action from day 1 is gone — deleted resource-group audit trail, role-assignment history, everything.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_vis_008`](../rules/zt_vis_008.md) | Trigger |
| [`zt_vis_001`](../rules/zt_vis_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Day 91: oldest Activity Log entries purge.

**Actor:** Time  
**MITRE ATT&CK:** `T1070.004`  
**Enabled by:** [`zt_vis_008`](../rules/zt_vis_008.md)  

**Attacker gain:** Control-plane history loss.


### Step 2 — Cannot reconstruct long-ago privileged operations.

**Actor:** IR / audit  
**MITRE ATT&CK:** `T1562.006`  
**Enabled by:** [`zt_vis_001`](../rules/zt_vis_001.md)  

**Attacker gain:** Audit gap.


## Blast radius

| | |
|---|---|
| Initial access | Time-based log loss. |
| Max privilege | Forensic gap. |
| Data at risk | Control-plane history |
| Services at risk | Subscription-wide audit integrity |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

