# CHAIN-191 — Secure Score low + no remediation tracking

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

Defender Secure Score is below 40% for months with no remediation trend. The control plane knows what's broken but nobody's assigned to fix it. Every vulnerability the score reflects remains live.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_vis_005`](../rules/zt_vis_005.md) | Trigger |
| [`zt_vis_002`](../rules/zt_vis_002.md) | Trigger |

## Attack walkthrough

### Step 1 — Recommendations accumulate; score stays flat.

**Actor:** Time  
**MITRE ATT&CK:** `T1562`  
**Enabled by:** [`zt_vis_005`](../rules/zt_vis_005.md)  

**Attacker gain:** Stagnant risk posture.


### Step 2 — Exploit any of the documented gaps.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_vis_002`](../rules/zt_vis_002.md)  

**Attacker gain:** Easy target selection.


## Blast radius

| | |
|---|---|
| Initial access | Any exploitable recommendation. |
| Max privilege | Variable by recommendation. |
| Data at risk | Whatever the recommendations flag |
| Services at risk | Subscription-wide |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

