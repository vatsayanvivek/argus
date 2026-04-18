# CHAIN-153 — Azure AI Content Safety bypassed via token replay

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Content Safety screens LLM outputs, but the moderation verdict is cached client-side for replay. An attacker captures a 'safe' verdict and replays it for different content, bypassing moderation.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_ai_006`](../rules/zt_ai_006.md) | Trigger |
| [`zt_vis_002`](../rules/zt_vis_002.md) | Trigger |

## Attack walkthrough

### Step 1 — Observe moderation verdict traffic; capture 'safe' signatures.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1557.002`  
**Enabled by:** [`zt_ai_006`](../rules/zt_ai_006.md)  

**Attacker gain:** Captured 'safe' moderation token.


### Step 2 — Submit harmful content, present cached token; app accepts.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1550.004`  
**Enabled by:** [`zt_vis_002`](../rules/zt_vis_002.md)  

**Attacker gain:** Moderation bypass.


## Blast radius

| | |
|---|---|
| Initial access | Client-side moderation cache. |
| Max privilege | Moderation bypass. |
| Data at risk | Moderation integrity |
| Services at risk | Content Safety consumers |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

