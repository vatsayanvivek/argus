# CHAIN-017 — Guest unrestricted no reviews to long-term persistence

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Guest user permissions are left at the Microsoft default of 'Same as member users', no access reviews fire on guest accounts, and no alerts fire when guests are added. A guest identity added during a short consulting engagement becomes a permanent foothold: the guest can enumerate the directory, and nobody ever removes them.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_009`](../rules/zt_id_009.md) | Trigger |
| [`zt_id_010`](../rules/zt_id_010.md) | Trigger |
| [`zt_vis_004`](../rules/zt_vis_004.md) | Trigger |

## Attack walkthrough

### Step 1 — Retain guest credentials long after engagement ends.

**Actor:** Attacker (former contractor)  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_009`](../rules/zt_id_009.md)  

> Guest invitation never rescinded; no offboarding process; account still active in directory.

**Attacker gain:** Persistent authenticated identity in the victim tenant.


### Step 2 — Enumerate the directory like a member user because guest permissions are not restricted.

**Actor:** Guest attacker  
**MITRE ATT&CK:** `T1087.004`  
**Enabled by:** [`zt_id_009`](../rules/zt_id_009.md)  

> Get-MgUser, Get-MgGroup succeed because externalUserState guest can read full directory objects.

**Attacker gain:** Complete map of users, groups, and privileged role members.


### Step 3 — Avoid removal because access reviews are not configured.

**Actor:** Guest attacker  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_010`](../rules/zt_id_010.md)  

> Access Reviews for guest users are not enabled; no recertification fires.

**Attacker gain:** Indefinite persistence.


### Step 4 — Evade detection because no alerts fire on privileged operations.

**Actor:** Guest attacker  
**MITRE ATT&CK:** `T1562.006`  
**Enabled by:** [`zt_vis_004`](../rules/zt_vis_004.md)  

> No action group on AuditLog category AuditLogs for role assignments or group changes.

**Attacker gain:** Quiet escalation pathway into groups that grant resource access.


## Blast radius

| | |
|---|---|
| Initial access | Dormant guest identity from a previous engagement. |
| Lateral movement | Directory enumeration → social engineering or self-service group join → resource access. |
| Max privilege | Whatever groups / RBAC the guest is / becomes a member of. |
| Data at risk | Directory information, Any resource shared with Everyone/All Users, Data in groups the guest can join |
| Services at risk | Entra ID, SharePoint/Teams content shared with the guest |
| Estimated scope | Long-tail exposure across shared resources |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

