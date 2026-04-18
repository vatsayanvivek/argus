# CHAIN-147 — OpenAI deployment with no content filter + jailbreak leakage

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

An Azure OpenAI deployment has content filters disabled (or set to lowest) AND is publicly reachable. Attackers extract system prompts, harvest RAG context, and use the endpoint as a free LLM relay — all invoices paid by the victim.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_ai_006`](../rules/zt_ai_006.md) | Trigger |
| [`zt_ai_001`](../rules/zt_ai_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Send jailbreak prompt to extract the system prompt.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1557.003`  
**Enabled by:** [`zt_ai_006`](../rules/zt_ai_006.md)  

**Attacker gain:** Internal prompt + any RAG data embedded in context.


### Step 2 — Relay arbitrary prompts through the endpoint; bill paid by victim.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1496`  
**Enabled by:** [`zt_ai_001`](../rules/zt_ai_001.md)  

**Attacker gain:** Free LLM access + potential reputation harm from outputs.


## Blast radius

| | |
|---|---|
| Initial access | Public LLM endpoint. |
| Max privilege | System prompt + RAG leak; compute abuse. |
| Data at risk | System prompts, RAG context corpus |
| Services at risk | OpenAI deployment |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

