# CHAIN-187 — Azure Monitor action groups inactive

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

Alerts are configured but the action groups point to mailboxes nobody reads or webhooks to decommissioned systems. The alert fires; the response never comes.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_vis_004`](../rules/zt_vis_004.md) | Trigger |
| [`zt_vis_006`](../rules/zt_vis_006.md) | Trigger |

## Attack walkthrough

### Step 1 — Fire into dead mailbox / broken webhook.

**Actor:** Alert  
**MITRE ATT&CK:** `T1499`  
**Enabled by:** [`zt_vis_004`](../rules/zt_vis_004.md)  

**Attacker gain:** Lost alert.


### Step 2 — Continue operating; alert triggered but unseen.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1562`  
**Enabled by:** [`zt_vis_006`](../rules/zt_vis_006.md)  

**Attacker gain:** Detection without response.


## Blast radius

| | |
|---|---|
| Initial access | Alert pipeline. |
| Max privilege | Detection-without-response gap. |
| Data at risk | Response SLA |
| Services at risk | IR pipeline |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

