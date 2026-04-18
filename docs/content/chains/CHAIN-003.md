# CHAIN-003 — Legacy auth bypass to privileged takeover

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

Legacy authentication protocols (POP, IMAP, SMTP AUTH, Exchange ActiveSync basic auth) are still enabled at the tenant level, and no Conditional Access policy blocks them. Attackers password-spray these endpoints because they bypass MFA entirely - the protocol pre-dates modern auth. One of the accounts that falls has a permanently-assigned Global Administrator or Privileged Role Administrator role (no PIM, no just-in-time elevation), so a single successful spray yields full tenant control without ever triggering an MFA prompt.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_005`](../rules/zt_id_005.md) | Trigger |
| [`zt_id_006`](../rules/zt_id_006.md) | Trigger |
| [`zt_id_003`](../rules/zt_id_003.md) | Trigger |

## Attack walkthrough

### Step 1 — Password-spray the Exchange Online legacy auth endpoint with a common-password list against scraped usernames.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1110.003`  
**Enabled by:** [`zt_id_005`](../rules/zt_id_005.md)  

> MSOLSpray / o365spray against https://outlook.office365.com/EWS/Exchange.asmx using Basic auth; legacy protocols accept credentials without MFA.

**Attacker gain:** One or more valid user credentials with no MFA challenge.


### Step 2 — Log in to Azure Portal with the stolen credential; no Conditional Access blocks the session.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_006`](../rules/zt_id_006.md)  

> No CA policy requiring MFA on 'All cloud apps' + 'All users'; sign-in risk evaluation is not configured as a grant control.

**Attacker gain:** Interactive tenant session as the compromised user.


### Step 3 — Discover the account holds a permanently-assigned privileged directory role.

**Actor:** Attacker as user  
**MITRE ATT&CK:** `T1087.004`  
**Enabled by:** [`zt_id_003`](../rules/zt_id_003.md)  

> Get-AzureADDirectoryRoleMember / Get-MgRoleManagementDirectoryRoleAssignment returns Global Administrator active at role scope /.

**Attacker gain:** Confirmation that the stolen account is Global Admin 24/7, not eligible-via-PIM.


### Step 4 — Create a backdoor account and a new Conditional Access exclusion covering it.

**Actor:** Attacker as Global Admin  
**MITRE ATT&CK:** `T1136.003`  
**Enabled by:** [`zt_id_003`](../rules/zt_id_003.md)  

> New-MgUser + New-MgRoleManagementDirectoryRoleAssignment + update CA policies to exclude the new identity.

**Attacker gain:** Persistent Global Administrator foothold that survives password resets on the original victim.


### Step 5 — Reset MFA and passwords on other privileged users, export audit logs, and disable security alerts.

**Actor:** Attacker as Global Admin  
**MITRE ATT&CK:** `T1562.001`  
**Enabled by:** [`zt_id_003`](../rules/zt_id_003.md)  

> Reset-MgUserAuthenticationMethod + Remove-MgAuditLogDirectoryAudit; Defender for Cloud alert rules can be silenced by a Global Admin.

**Attacker gain:** Full tenant compromise with reduced detection surface.


## Blast radius

| | |
|---|---|
| Initial access | Legacy authentication endpoint (Exchange Basic, POP, IMAP, SMTP AUTH) reachable from the internet. |
| Lateral movement | User sign-in to portal.azure.com → permanently-active privileged role → tenant-wide control plane. |
| Max privilege | Global Administrator at tenant scope. |
| Data at risk | Entra ID directory, Exchange mailboxes, Conditional Access policies, Audit logs, All Azure subscriptions in the tenant |
| Services at risk | Entra ID, Exchange Online, Azure Resource Manager, Microsoft 365 |
| Estimated scope | 100% of the tenant |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

