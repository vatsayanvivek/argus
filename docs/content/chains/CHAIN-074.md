# CHAIN-074 — Guest user can invite more guests — supply-chain invitation

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Guest users are allowed to invite other guests (Restrict Guest Access setting is lax). Once one partner user is compromised, the attacker invites attacker-controlled identities into the home tenant and walks up the role graph from there.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_023`](../rules/zt_id_023.md) | Trigger |
| [`zt_id_021`](../rules/zt_id_021.md) | Trigger |

## Attack walkthrough

### Step 1 — Invite attacker@evil.com as guest.

**Actor:** Compromised guest  
**MITRE ATT&CK:** `T1098`  
**Enabled by:** [`zt_id_021`](../rules/zt_id_021.md)  

**Attacker gain:** Attacker has a directory object.


### Step 2 — Apply normal escalation chains (CHAIN-052, CHAIN-072).

**Actor:** Attacker guest  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_023`](../rules/zt_id_023.md)  

**Attacker gain:** Follow-on chains available.


## Blast radius

| | |
|---|---|
| Initial access | One compromised guest. |
| Max privilege | Grows with follow-on chains. |
| Data at risk | Directory read for all guests |
| Services at risk | Entra ID B2B |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

