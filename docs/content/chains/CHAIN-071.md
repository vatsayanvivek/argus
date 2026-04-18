# CHAIN-071 — Access review disabled or never runs

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

No access review is configured for privileged groups AND users with roles are never required to re-justify their access. Role assignments accumulate as people change teams. Eventually the tenant has 30+ Global Admins nobody can justify.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_019`](../rules/zt_id_019.md) | Trigger |
| [`zt_id_006`](../rules/zt_id_006.md) | Trigger |

## Attack walkthrough

### Step 1 — Users change jobs but keep old roles because nobody reviews.

**Actor:** Time / organisation drift  
**MITRE ATT&CK:** `T1136.003`  
**Enabled by:** [`zt_id_019`](../rules/zt_id_019.md)  

**Attacker gain:** Stale admin inventory.


### Step 2 — Target any one of the many admins who no longer need the role.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_id_006`](../rules/zt_id_006.md)  

**Attacker gain:** High-probability attack surface.


## Blast radius

| | |
|---|---|
| Initial access | Phishing any stale admin. |
| Max privilege | Whatever that admin role grants. |
| Data at risk | Role scope |
| Services at risk | Entra ID |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

