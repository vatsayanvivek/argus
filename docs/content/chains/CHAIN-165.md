# CHAIN-165 — Integration Account EDI content without encryption

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Low · **Logic:** `ALL`

## Why this chain matters

B2B EDI messages (X12, EDIFACT) flow through an Integration Account without at-rest encryption beyond Microsoft defaults. Regulated industries (healthcare, financial trading) require CMK — audit finding plus liability.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_int_008`](../rules/zt_int_008.md) | Trigger |
| [`zt_data_006`](../rules/zt_data_006.md) | Trigger |

## Attack walkthrough

### Step 1 — Auditor flags Integration Account without CMK.

**Actor:** Audit event  
**MITRE ATT&CK:** `T1213`  
**Enabled by:** [`zt_int_008`](../rules/zt_int_008.md)  

**Attacker gain:** Compliance failure.


### Step 2 — Subpoena + no customer-controlled key means no plausible deniability.

**Actor:** Legal event  
**MITRE ATT&CK:** `T1552.004`  
**Enabled by:** [`zt_data_006`](../rules/zt_data_006.md)  

**Attacker gain:** Regulatory / liability exposure.


## Blast radius

| | |
|---|---|
| Initial access | Audit / legal. |
| Max privilege | Regulatory exposure. |
| Data at risk | EDI transaction history |
| Services at risk | Integration Account |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

