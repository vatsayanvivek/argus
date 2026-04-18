# CHAIN-185 — Defender for Cloud disabled + no Sentinel

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

Defender for Cloud is at Free tier and there's no Sentinel workspace. There is no behavioral detection, no anomaly scoring, no threat-intel correlation. Every other control has to work perfectly because there is no second layer.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_vis_003`](../rules/zt_vis_003.md) | Trigger |
| [`zt_vis_002`](../rules/zt_vis_002.md) | Trigger |

## Attack walkthrough

### Step 1 — Operate with no behavioral analytics running.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1562.001`  
**Enabled by:** [`zt_vis_003`](../rules/zt_vis_003.md)  

**Attacker gain:** Zero alert surface.


### Step 2 — Long dwell time; no mean-time-to-detect signal.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_vis_002`](../rules/zt_vis_002.md)  

**Attacker gain:** Maximum operational stealth.


## Blast radius

| | |
|---|---|
| Initial access | Posture decision. |
| Max privilege | Detection absence. |
| Data at risk | MTTD inflated across board |
| Services at risk | Every Azure resource |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

