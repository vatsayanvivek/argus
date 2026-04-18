# CHAIN-069 — Privileged authentication admin can reset any MFA

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Low · **Logic:** `ALL`

## Why this chain matters

The Privileged Authentication Administrator role is assigned to a user who does not need it. This role can reset MFA methods on any user — including Global Admins. A compromised holder can replace a Global Admin's MFA with attacker-controlled factors and then sign in as that admin.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_012`](../rules/zt_id_012.md) | Trigger |
| [`zt_id_005`](../rules/zt_id_005.md) | Trigger |

## Attack walkthrough

### Step 1 — Identify a GA user in the directory.

**Actor:** Compromised PAA  
**MITRE ATT&CK:** `T1087.004`  
**Enabled by:** [`zt_id_012`](../rules/zt_id_012.md)  

**Attacker gain:** Target admin account.


### Step 2 — Reset GA's MFA method to an attacker phone number.

**Actor:** PAA  
**MITRE ATT&CK:** `T1098.005`  
**Enabled by:** [`zt_id_012`](../rules/zt_id_012.md)  

**Attacker gain:** Control of GA's MFA.


### Step 3 — Sign in as GA; password reset flow + attacker phone completes auth.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_005`](../rules/zt_id_005.md)  

**Attacker gain:** Global Admin.


## Blast radius

| | |
|---|---|
| Initial access | Compromised PAA account. |
| Max privilege | Global Admin. |
| Data at risk | All of tenant |
| Services at risk | Entra ID |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

