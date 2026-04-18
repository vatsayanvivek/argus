# CHAIN-164 — API Connection with embedded creds — shared across Logic Apps

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

An API Connection object stores credentials inline and is referenced by 20+ Logic Apps. Rotating the underlying credential means coordinating edits across all 20 workflows — so it never happens. One credential leak compromises the whole portfolio of integrations.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_int_006`](../rules/zt_int_006.md) | Trigger |
| [`zt_int_002`](../rules/zt_int_002.md) | Trigger |

## Attack walkthrough

### Step 1 — Extract API Connection credential via ARM Reader.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_int_006`](../rules/zt_int_006.md)  

**Attacker gain:** Widely-used credential.


### Step 2 — Use credential; 20 Logic Apps look like legitimate callers.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_int_002`](../rules/zt_int_002.md)  

**Attacker gain:** Blending into 20 identity patterns.


## Blast radius

| | |
|---|---|
| Initial access | ARM Reader. |
| Max privilege | Shared connector scope. |
| Data at risk | Everything the connector reaches |
| Services at risk | 20+ Logic Apps |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

