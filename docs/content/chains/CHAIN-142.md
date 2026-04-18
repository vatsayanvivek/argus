# CHAIN-142 — Azure OpenAI endpoint public + prompt logged to App Insights

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

An Azure OpenAI endpoint is reachable publicly, and its consuming app streams every prompt/response to Application Insights. Anyone with Reader on the App Insights resource can read every prompt — including prompts containing customer PII, internal credentials in RAG context, or confidential business queries.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_ai_001`](../rules/zt_ai_001.md) | Trigger |
| [`zt_vis_006`](../rules/zt_vis_006.md) | Trigger |

## Attack walkthrough

### Step 1 — Send a prompt containing sensitive business data.

**Actor:** Legit user  
**MITRE ATT&CK:** `T1213`  
**Enabled by:** [`zt_ai_001`](../rules/zt_ai_001.md)  

**Attacker gain:** Prompt is processed normally.


### Step 2 — Query requests table; read every prompt / completion body.

**Actor:** Attacker with App Insights Reader  
**MITRE ATT&CK:** `T1213`  
**Enabled by:** [`zt_vis_006`](../rules/zt_vis_006.md)  

**Attacker gain:** Mass PII / secret leak from LLM traffic.


## Blast radius

| | |
|---|---|
| Initial access | App Insights reader role. |
| Max privilege | Historical prompt content. |
| Data at risk | All LLM prompts, Any data embedded in prompts |
| Services at risk | Azure OpenAI + consuming apps |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

