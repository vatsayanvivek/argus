# CHAIN-068 — MFA fatigue against non-enforced user

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

A user has MFA configured but the Conditional Access policy is in report-only mode. An attacker with the password sprays MFA push notifications; when the policy is report-only, the attacker still gets the token even if the user denies the push (because the CA result was never enforced).

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_004`](../rules/zt_id_004.md) | Trigger |
| [`zt_id_015`](../rules/zt_id_015.md) | Trigger |

## Attack walkthrough

### Step 1 — Spray valid password + trigger dozens of push notifications.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1621`  
**Enabled by:** [`zt_id_004`](../rules/zt_id_004.md)  

**Attacker gain:** Either user approves by mistake or CA-report-only lets it through.


### Step 2 — Token issued despite denied push because policy is report-only.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1556.007`  
**Enabled by:** [`zt_id_015`](../rules/zt_id_015.md)  

**Attacker gain:** Authenticated session with full delegated scope.


## Blast radius

| | |
|---|---|
| Initial access | Known password + MFA prompt bombardment. |
| Max privilege | Target user's session. |
| Data at risk | All apps the user can access |
| Services at risk | M365, Azure portal |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

