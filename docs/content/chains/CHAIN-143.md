# CHAIN-143 — Cognitive Services key sprawl via multiple account copies

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

Cognitive Services subscription keys are distributed via email, Confluence, and shared password managers to every team that wants LLM access. Keys never rotate; there's no way to trace which team leaked which key.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_ai_002`](../rules/zt_ai_002.md) | Trigger |
| [`zt_id_001`](../rules/zt_id_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Search Slack / SharePoint for 'Ocp-Apim-Subscription-Key'.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_ai_002`](../rules/zt_ai_002.md)  

**Attacker gain:** Valid Cognitive Services key.


### Step 2 — Use key for free inference — billed to the owning tenant.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_id_001`](../rules/zt_id_001.md)  

**Attacker gain:** Financial abuse + potentially prompt-trail leakage.


## Blast radius

| | |
|---|---|
| Initial access | Key harvest. |
| Max privilege | Inference calls billed to victim. |
| Data at risk | Inference quota exhaustion |
| Services at risk | Cognitive Services account |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

