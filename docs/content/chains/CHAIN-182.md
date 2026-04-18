# CHAIN-182 — Log Analytics retention shorter than incident timeline

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

Log Analytics workspace retention is 30 days; the industry average incident dwell time is 180+ days. By the time an intrusion is detected, the logs covering the initial compromise are already rotated out.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_vis_010`](../rules/zt_vis_010.md) | Trigger |
| [`zt_vis_011`](../rules/zt_vis_011.md) | Trigger |

## Attack walkthrough

### Step 1 — Maintain quiet presence for 90 days before noisy activity.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1070.001`  
**Enabled by:** [`zt_vis_010`](../rules/zt_vis_010.md)  

**Attacker gain:** Initial compromise data aged out of workspace.


### Step 2 — Cannot determine patient zero or initial vector.

**Actor:** IR team  
**MITRE ATT&CK:** `T1070.001`  
**Enabled by:** [`zt_vis_011`](../rules/zt_vis_011.md)  

**Attacker gain:** Incomplete IR scope.


## Blast radius

| | |
|---|---|
| Initial access | Time-driven log loss. |
| Max privilege | Forensic blindness. |
| Data at risk | IR scoping integrity |
| Services at risk | Every system relying on this workspace for IR |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

