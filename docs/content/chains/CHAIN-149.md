# CHAIN-149 — Computer Vision endpoint without customer-managed key

!!! note "Summary"
    **Severity:** :material-information-outline: Low · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Computer Vision processes images containing PII (passports, licenses) but stores them with Microsoft-managed keys. A court order or Microsoft internal compromise could expose historical processed images.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_ai_007`](../rules/zt_ai_007.md) | Trigger |
| [`zt_data_006`](../rules/zt_data_006.md) | Trigger |

## Attack walkthrough

### Step 1 — Data processed without customer-controlled key.

**Actor:** Compliance failure  
**MITRE ATT&CK:** `T1213`  
**Enabled by:** [`zt_ai_007`](../rules/zt_ai_007.md)  

**Attacker gain:** Data residency / control boundary breached.


### Step 2 — Subpoena or insider access yields plaintext.

**Actor:** Legal event  
**MITRE ATT&CK:** `T1552.004`  
**Enabled by:** [`zt_data_006`](../rules/zt_data_006.md)  

**Attacker gain:** Regulatory exposure.


## Blast radius

| | |
|---|---|
| Initial access | Legal / infrastructure-level event. |
| Max privilege | Historical image content. |
| Data at risk | Processed image data |
| Services at risk | Computer Vision |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

