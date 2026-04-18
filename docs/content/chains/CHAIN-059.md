# CHAIN-059 — Conditional Access gap on partner-tenant guest admin

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A B2B guest admin from a partner tenant is granted directory roles in the home tenant, but the home Conditional Access policies only target the home UPN suffix. The partner's admin authenticates under their own tenant with its own MFA story, and the home tenant has no visibility into whether that MFA is strong.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_023`](../rules/zt_id_023.md) | Trigger |
| [`zt_id_021`](../rules/zt_id_021.md) | Trigger |

## Attack walkthrough

### Step 1 — Compromise a partner admin account (weak MFA at partner side).

**Actor:** Partner tenant attacker  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_023`](../rules/zt_id_023.md)  

**Attacker gain:** Partner credential.


### Step 2 — Cross-tenant access to home; CA doesn't apply.

**Actor:** Partner attacker  
**MITRE ATT&CK:** `T1556.007`  
**Enabled by:** [`zt_id_021`](../rules/zt_id_021.md)  

**Attacker gain:** Home tenant admin role via partner auth.


## Blast radius

| | |
|---|---|
| Initial access | Partner tenant compromise. |
| Max privilege | Whatever directory role the guest holds. |
| Data at risk | Directory objects visible to guest role |
| Services at risk | Entra ID cross-tenant surface |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

