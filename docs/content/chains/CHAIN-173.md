# CHAIN-173 — Backup policy retention shorter than compliance requirement

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

A backup policy retains daily backups for 30 days but the regulatory requirement is 7 years. During an audit, the gap is revealed — or during a legal hold, historical data required for discovery cannot be produced.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_bak_004`](../rules/zt_bak_004.md) | Trigger |
| [`zt_vis_001`](../rules/zt_vis_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Backups rotate out at 30 days.

**Actor:** Time  
**MITRE ATT&CK:** `T1070.004`  
**Enabled by:** [`zt_bak_004`](../rules/zt_bak_004.md)  

**Attacker gain:** Historical data gap.


### Step 2 — Requested data unavailable.

**Actor:** Audit / legal  
**MITRE ATT&CK:** `T1491`  
**Enabled by:** [`zt_vis_001`](../rules/zt_vis_001.md)  

**Attacker gain:** Compliance finding or legal exposure.


## Blast radius

| | |
|---|---|
| Initial access | Time-driven data loss. |
| Max privilege | Audit findings. |
| Data at risk | Historical records |
| Services at risk | Audit posture |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

