# CHAIN-186 — Sentinel analytics rules disabled for cost

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

Sentinel is deployed but the high-fidelity analytics rules (brute force, impossible travel, new admin) are disabled to reduce cost. The workspace holds the data but produces no alerts — a tool without eyes.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_vis_002`](../rules/zt_vis_002.md) | Trigger |
| [`zt_vis_006`](../rules/zt_vis_006.md) | Trigger |

## Attack walkthrough

### Step 1 — Disable detection rules to drop ingest.

**Actor:** Cost-saving decision  
**MITRE ATT&CK:** `T1562.001`  
**Enabled by:** [`zt_vis_002`](../rules/zt_vis_002.md)  

**Attacker gain:** No real-time alerting.


### Step 2 — Known TTPs pass unnoticed.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1562.001`  
**Enabled by:** [`zt_vis_006`](../rules/zt_vis_006.md)  

**Attacker gain:** Operational freedom.


## Blast radius

| | |
|---|---|
| Initial access | Management decision. |
| Max privilege | Detection gap. |
| Data at risk | Detection coverage |
| Services at risk | All SIEM-fed systems |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

