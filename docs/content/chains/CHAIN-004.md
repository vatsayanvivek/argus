# CHAIN-004 — Permanent privilege no PIM to insider escalation

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Privileged roles are permanently assigned instead of PIM-eligible, the tenant has no automated access reviews, and there is no alerting on role membership changes. A disgruntled insider - or an attacker who pivoted into a helpdesk account - can quietly add themselves to a Global Admin or Owner role and retain that privilege indefinitely because nothing ever reconciles the assignment list against a business owner.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_003`](../rules/zt_id_003.md) | Trigger |
| [`zt_id_007`](../rules/zt_id_007.md) | Trigger |
| [`zt_vis_008`](../rules/zt_vis_008.md) | Trigger |

## Attack walkthrough

### Step 1 — Enumerate existing permanently-assigned privileged roles to identify low-noise elevation targets.

**Actor:** Malicious insider  
**MITRE ATT&CK:** `T1087.004`  
**Enabled by:** [`zt_id_003`](../rules/zt_id_003.md)  

> Get-MgRoleManagementDirectoryRoleAssignment reveals all Active assignments including User Access Administrator at subscription scope.

**Attacker gain:** Knowledge of which privileged accounts exist and where the gaps are.


### Step 2 — Add a new permanent role assignment to self or a controlled account.

**Actor:** Malicious insider  
**MITRE ATT&CK:** `T1098.003`  
**Enabled by:** [`zt_id_007`](../rules/zt_id_007.md)  

> New-MgRoleManagementDirectoryRoleAssignment -PrincipalId {self} -RoleDefinitionId {GlobalAdmin}; no PIM approval workflow blocks this.

**Attacker gain:** Direct, permanent Global Administrator rights without eligibility review or approval.


### Step 3 — Wait out the quarter - no access review ever fires to catch the assignment.

**Actor:** Malicious insider  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_vis_008`](../rules/zt_vis_008.md)  

> Access Reviews are not configured for directory roles; no periodic recertification exists.

**Attacker gain:** Indefinite persistence. The assignment blends into the baseline because the baseline is never audited.


### Step 4 — Use the standing privilege to exfiltrate data or sabotage systems at a time of their choosing.

**Actor:** Malicious insider  
**MITRE ATT&CK:** `T1530`  
**Enabled by:** [`zt_id_003`](../rules/zt_id_003.md)  

> Subscription-wide resource export, mailbox impersonation via application access policy, or destructive operations with no alerting in place.

**Attacker gain:** Complete freedom of action across the tenant with attribution obscured by the absence of reviews.


## Blast radius

| | |
|---|---|
| Initial access | Existing insider account (employee, contractor, or compromised helpdesk). |
| Lateral movement | Self-elevation via direct role assignment; no approval gate, no time bounding. |
| Max privilege | Global Administrator / subscription Owner, permanent. |
| Data at risk | Tenant directory, All Azure subscriptions, Exchange and SharePoint data |
| Services at risk | Entra ID, All Azure resources, Microsoft 365 workloads |
| Estimated scope | 100% of the tenant over time |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

