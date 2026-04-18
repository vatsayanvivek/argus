# CHAIN-154 — Translator service with embedded API key in mobile app

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

A mobile app ships with the Translator subscription key in its APK/IPA. Anyone decompiling the app obtains the key, using victim's free tier for their own translation bill.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_ai_002`](../rules/zt_ai_002.md) | Trigger |
| [`zt_ai_007`](../rules/zt_ai_007.md) | Trigger |

## Attack walkthrough

### Step 1 — Decompile the app; extract the subscription key.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_ai_002`](../rules/zt_ai_002.md)  

**Attacker gain:** Valid API key.


### Step 2 — Use key to run high-volume translation workloads.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1496`  
**Enabled by:** [`zt_ai_007`](../rules/zt_ai_007.md)  

**Attacker gain:** Free translation paid by victim.


## Blast radius

| | |
|---|---|
| Initial access | Mobile app decompilation. |
| Max privilege | API quota abuse. |
| Data at risk | Translation quota |
| Services at risk | Translator account |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

