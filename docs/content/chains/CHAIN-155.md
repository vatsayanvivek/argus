# CHAIN-155 — ML Workspace without encryption-at-rest CMK

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Low · **Logic:** `ALL`

## Why this chain matters

ML Workspace stores training artifacts with Microsoft-managed keys. Regulatory frameworks (FedRAMP High, HIPAA-regulated PHI) require CMK. A compliance finding turns into a mandatory remediation + potential audit failure.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_ai_003`](../rules/zt_ai_003.md) | Trigger |
| [`zt_data_006`](../rules/zt_data_006.md) | Trigger |

## Attack walkthrough

### Step 1 — Identify ML workspace without CMK.

**Actor:** Compliance audit  
**MITRE ATT&CK:** `T1213`  
**Enabled by:** [`zt_ai_003`](../rules/zt_ai_003.md)  

**Attacker gain:** Audit gap.


### Step 2 — Training data accessed via platform-level mechanism.

**Actor:** Legal discovery  
**MITRE ATT&CK:** `T1552.004`  
**Enabled by:** [`zt_data_006`](../rules/zt_data_006.md)  

**Attacker gain:** Regulatory breach.


## Blast radius

| | |
|---|---|
| Initial access | Compliance event. |
| Max privilege | Regulatory exposure. |
| Data at risk | Training datasets |
| Services at risk | ML Workspace |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

