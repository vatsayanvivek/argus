# CHAIN-161 — Logic Apps run history exposes secrets in trigger logs

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Logic Apps run history records every input/output of every action. An action that calls an external API with a Bearer token stores the token in the run log. Any user with Logic App Reader can replay those tokens for follow-on access.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_int_006`](../rules/zt_int_006.md) | Trigger |
| [`zt_wl_017`](../rules/zt_wl_017.md) | Trigger |

## Attack walkthrough

### Step 1 — Open Logic App run history; expand HTTP action inputs.

**Actor:** Reader  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_int_006`](../rules/zt_int_006.md)  

**Attacker gain:** Valid bearer token.


### Step 2 — Replay token against target API.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1550.001`  
**Enabled by:** [`zt_wl_017`](../rules/zt_wl_017.md)  

**Attacker gain:** API access.


## Blast radius

| | |
|---|---|
| Initial access | Logic App Reader role. |
| Max privilege | Token-scoped API. |
| Data at risk | Anything the token grants |
| Services at risk | Backend API + dependent systems |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

