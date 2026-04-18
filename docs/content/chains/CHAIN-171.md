# CHAIN-171 — Logic App with OAuth connection to over-privileged SP

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A Logic App uses an OAuth connection that was authorised with Global Admin consent. Every run of the Logic App executes with Global Admin scope — a scheduled trigger becomes a recurring privileged operation nobody audits.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_int_006`](../rules/zt_int_006.md) | Trigger |
| [`zt_id_011`](../rules/zt_id_011.md) | Trigger |

## Attack walkthrough

### Step 1 — Consent to OAuth connection while signed in as Global Admin.

**Actor:** Developer misconfig  
**MITRE ATT&CK:** `T1098`  
**Enabled by:** [`zt_int_006`](../rules/zt_int_006.md)  

**Attacker gain:** Connection carries GA scope indefinitely.


### Step 2 — Edit workflow to exfil directory data; run uses GA token.

**Actor:** Attacker with Logic App Contributor  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_id_011`](../rules/zt_id_011.md)  

**Attacker gain:** GA-scoped exfil via Logic App.


## Blast radius

| | |
|---|---|
| Initial access | Logic App Contributor. |
| Max privilege | Global Admin via token. |
| Data at risk | Tenant-wide data |
| Services at risk | Entra ID via Logic App |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

