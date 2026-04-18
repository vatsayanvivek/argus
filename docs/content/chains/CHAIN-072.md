# CHAIN-072 — Group with external owners creates persistence

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A Microsoft 365 / Entra group has an external (guest) user listed as owner. Guest owners can edit membership and — depending on group settings — modify role assignments. A partner breach turns into a home tenant persistence mechanism.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_024`](../rules/zt_id_024.md) | Trigger |
| [`zt_id_023`](../rules/zt_id_023.md) | Trigger |

## Attack walkthrough

### Step 1 — Compromise the guest owner account on the partner side.

**Actor:** Partner attacker  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_023`](../rules/zt_id_023.md)  

**Attacker gain:** Guest account with ownership.


### Step 2 — Add attacker-controlled user object to the group; role inherits.

**Actor:** Guest owner  
**MITRE ATT&CK:** `T1098`  
**Enabled by:** [`zt_id_024`](../rules/zt_id_024.md)  

**Attacker gain:** Persistent privileged membership.


## Blast radius

| | |
|---|---|
| Initial access | Partner tenant compromise. |
| Max privilege | Home tenant group role. |
| Data at risk | Home tenant directory objects reachable via the group's role |
| Services at risk | Entra ID, M365 groups |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

