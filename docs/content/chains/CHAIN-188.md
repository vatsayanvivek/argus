# CHAIN-188 — Application Insights sample rate too aggressive

!!! note "Summary"
    **Severity:** :material-information-outline: Low · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

App Insights sampling is set to 5%. Only 1 in 20 requests is logged. During an incident, the SOC cannot tell whether an anomalous request pattern is real or a sampling artefact. Sparse data forces conservative (slow) decisions.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_vis_006`](../rules/zt_vis_006.md) | Trigger |
| [`zt_vis_011`](../rules/zt_vis_011.md) | Trigger |

## Attack walkthrough

### Step 1 — Most attacker requests never land in App Insights.

**Actor:** Attack traffic  
**MITRE ATT&CK:** `T1070`  
**Enabled by:** [`zt_vis_006`](../rules/zt_vis_006.md)  

**Attacker gain:** Reduced detection signal.


### Step 2 — Cannot distinguish real attack from baseline noise.

**Actor:** SOC  
**MITRE ATT&CK:** `T1070`  
**Enabled by:** [`zt_vis_011`](../rules/zt_vis_011.md)  

**Attacker gain:** Investigation slowdown.


## Blast radius

| | |
|---|---|
| Initial access | Sampling decision. |
| Max privilege | Detection signal dilution. |
| Data at risk | App telemetry integrity |
| Services at risk | App Insights consumers |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

