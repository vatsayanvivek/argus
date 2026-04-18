# CHAIN-070 — PIM active assignments used as normal role

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

PIM roles are assigned as Active (not Eligible) so they never expire or require activation. This defeats the purpose of PIM — a compromised principal has permanent admin, not just-in-time admin.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_009`](../rules/zt_id_009.md) | Trigger |
| [`zt_id_010`](../rules/zt_id_010.md) | Trigger |

## Attack walkthrough

### Step 1 — Sign in; role already active, no activation needed.

**Actor:** Attacker with creds  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_id_009`](../rules/zt_id_009.md)  

**Attacker gain:** Persistent admin.


### Step 2 — Operate freely; no activation log to correlate on.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1562`  
**Enabled by:** [`zt_id_010`](../rules/zt_id_010.md)  

**Attacker gain:** Reduced detection surface.


## Blast radius

| | |
|---|---|
| Initial access | Stolen creds of active-role holder. |
| Max privilege | Assigned directory role, indefinitely. |
| Data at risk | Role scope |
| Services at risk | Entra ID |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

