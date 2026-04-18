# CHAIN-057 — Break-glass account without MFA or monitoring

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A break-glass Global Admin is excluded from every Conditional Access policy by design — but it is also excluded from sign-in monitoring alerts. The account credentials live in a shared password manager. Any insider with manager access can sign in silently.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_005`](../rules/zt_id_005.md) | Trigger |
| [`zt_vis_008`](../rules/zt_vis_008.md) | Trigger |

## Attack walkthrough

### Step 1 — Pull the break-glass password from the shared vault.

**Actor:** Insider  
**MITRE ATT&CK:** `T1078.002`  
**Enabled by:** [`zt_id_005`](../rules/zt_id_005.md)  

**Attacker gain:** Admin credential.


### Step 2 — Sign in from anywhere; no CA policy blocks, no alert fires.

**Actor:** Insider  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_vis_008`](../rules/zt_vis_008.md)  

**Attacker gain:** Silent Global Admin session.


## Blast radius

| | |
|---|---|
| Initial access | Insider with vault read. |
| Max privilege | Global Administrator. |
| Data at risk | Entire tenant + every subscription |
| Services at risk | All of Azure + Microsoft 365 |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

