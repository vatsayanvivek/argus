# CHAIN-167 — Notification Hub secret rotation gap

!!! note "Summary"
    **Severity:** :material-information-outline: Low · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Azure Notification Hubs access keys haven't rotated in 2+ years. Mobile apps still embed the original key. A compromised key lets an attacker push arbitrary notifications to every registered device.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_int_002`](../rules/zt_int_002.md) | Trigger |
| [`zt_id_001`](../rules/zt_id_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Extract key from decompiled mobile app.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_int_002`](../rules/zt_int_002.md)  

**Attacker gain:** Valid notification key.


### Step 2 — Push phishing notifications to every device.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1566`  
**Enabled by:** [`zt_id_001`](../rules/zt_id_001.md)  

**Attacker gain:** Mass-phishing channel.


## Blast radius

| | |
|---|---|
| Initial access | Embedded key. |
| Max privilege | Notification broadcast. |
| Data at risk | User trust + device reach |
| Services at risk | Notification Hubs consumers |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

