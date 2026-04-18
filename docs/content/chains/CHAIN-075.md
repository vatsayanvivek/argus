# CHAIN-075 — Cross-tenant access without inbound trust restrictions

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Cross-tenant access settings allow any partner to authenticate into apps with inbound MFA/device claims trust — but the home tenant hasn't scoped which partner tenants qualify. Any tenant admin with a hostile user can auth to home apps with partner-claimed MFA.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_021`](../rules/zt_id_021.md) | Trigger |
| [`zt_id_007`](../rules/zt_id_007.md) | Trigger |

## Attack walkthrough

### Step 1 — Set up a tenant that claims MFA for all sign-ins.

**Actor:** Hostile external tenant  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_021`](../rules/zt_id_021.md)  

**Attacker gain:** Partner tenant with spoofed claims.


### Step 2 — Cross-tenant sign-in to home app; MFA claim satisfied externally.

**Actor:** Hostile user  
**MITRE ATT&CK:** `T1556.007`  
**Enabled by:** [`zt_id_007`](../rules/zt_id_007.md)  

**Attacker gain:** Authenticated on home app with fake MFA assurance.


## Blast radius

| | |
|---|---|
| Initial access | Open inbound cross-tenant trust. |
| Max privilege | Whatever the app grants to guests. |
| Data at risk | App-scope data |
| Services at risk | Every app published to the tenant |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

