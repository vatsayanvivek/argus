# CHAIN-150 — Document Intelligence with public access + PII forms

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Document Intelligence ingests forms with SSN, banking details, health records. The service has public network access and a leaked API key works from anywhere. Attackers call the endpoint with victim-organisation images to process their own forms through the victim's quota.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_ai_001`](../rules/zt_ai_001.md) | Trigger |
| [`zt_ai_002`](../rules/zt_ai_002.md) | Trigger |

## Attack walkthrough

### Step 1 — Scrape API key from victim's mobile app bundle.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_ai_002`](../rules/zt_ai_002.md)  

**Attacker gain:** Valid Document Intelligence key.


### Step 2 — Process attacker-forms through victim's quota; extract model outputs.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1496`  
**Enabled by:** [`zt_ai_001`](../rules/zt_ai_001.md)  

**Attacker gain:** Free PII extraction paid by victim.


## Blast radius

| | |
|---|---|
| Initial access | Embedded key. |
| Max privilege | API quota abuse. |
| Data at risk | Victim's processing quota + any telemetry |
| Services at risk | Document Intelligence |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

