# CHAIN-044 — Admin credential spray to irrecoverable tenant lock

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Administrative accounts in this tenant do not require phishing-resistant authentication strength (FIDO2, certificate-based auth, or Windows Hello). Simultaneously, users are not required to register for MFA, meaning many admin accounts have only a password as their sole credential. An attacker conducts a low-and-slow password spray against the tenant's admin accounts, and because there is no authentication strength policy demanding phishing-resistant factors, a correct password is enough to sign in. Once inside a Global Administrator account, the attacker resets passwords for all other admins, disables their MFA registrations, and revokes their sessions. The fatal final condition: no break-glass emergency access accounts exist. When the legitimate administrators are locked out, there is no recovery path that does not involve a multi-week Microsoft support engagement. The attacker has days of uncontested Global Admin access to exfiltrate data, create backdoor service principals, and destroy resources.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_014`](../rules/zt_id_014.md) | Trigger |
| [`zt_id_023`](../rules/zt_id_023.md) | Trigger |
| [`zt_id_012`](../rules/zt_id_012.md) | Trigger |

## Attack walkthrough

### Step 1 — Enumerate valid admin account UPNs via tenant discovery and LinkedIn correlation.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1589.002`  
**Enabled by:** [`zt_id_014`](../rules/zt_id_014.md)  

> Probe login.microsoftonline.com/common/GetCredentialType with candidate UPNs to confirm account existence without triggering sign-in logs; cross-reference with LinkedIn to identify IT staff.

**Attacker gain:** Validated list of admin account UPNs in the target tenant.


### Step 2 — Execute a low-and-slow password spray against admin accounts, bypassing smart lockout thresholds.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1110.003`  
**Enabled by:** [`zt_id_023`](../rules/zt_id_023.md)  

> Spray one password per hour across all admin accounts from rotating residential proxies; no Conditional Access authentication strength policy blocks password-only auth, and no MFA registration means the accounts accept username+password alone.

**Attacker gain:** Valid credentials for at least one Global Administrator account.


### Step 3 — Reset credentials and revoke sessions for all other administrative accounts.

**Actor:** Attacker as Global Admin  
**MITRE ATT&CK:** `T1531`  
**Enabled by:** [`zt_id_012`](../rules/zt_id_012.md)  

> POST /users/{id}/authentication/methods to overwrite phone/email MFA methods; POST /users/{id}/revokeSignInSessions; Reset-MsolPassword for each admin; disable per-user MFA registration.

**Attacker gain:** All legitimate administrators are locked out of the tenant with no way to re-authenticate.


### Step 4 — Confirm no break-glass accounts exist and establish persistent backdoor access.

**Actor:** Attacker as sole Global Admin  
**MITRE ATT&CK:** `T1136.003`  
**Enabled by:** [`zt_id_012`](../rules/zt_id_012.md)  

> Enumerate all Global Admin role members; confirm no emergency access accounts with excluded Conditional Access policies exist (zt_id_012). Create a new service principal with Directory.ReadWrite.All and a 10-year client secret.

**Attacker gain:** Sole, uncontested Global Administrator control with a persistent backdoor credential.


### Step 5 — Exfiltrate tenant data and optionally destroy resources to inflict maximum damage.

**Actor:** Attacker with tenant control  
**MITRE ATT&CK:** `T1485`  
**Enabled by:** [`zt_id_014`](../rules/zt_id_014.md)  

> Export all mailboxes via eDiscovery compliance search; export Azure subscriptions' Key Vault secrets; optionally delete resource groups and purge Key Vaults (if purge protection is off) to cause irrecoverable data loss.

**Attacker gain:** Complete tenant compromise with no recovery path short of Microsoft support intervention taking days to weeks.


## Blast radius

| | |
|---|---|
| Initial access | Password spray against admin accounts with no phishing-resistant MFA enforcement. |
| Lateral movement | Not required - Global Admin grants immediate access to all tenant resources and all Azure subscriptions. |
| Max privilege | Global Administrator with exclusive control - all other admins locked out, no break-glass recovery. |
| Data at risk | All Entra ID directory data, All mailboxes and SharePoint content, All Azure subscription resources, Key Vault secrets across all subscriptions |
| Services at risk | Entra ID, Exchange Online, SharePoint, Azure Resource Manager, Key Vault, All Azure services in linked subscriptions |
| Estimated scope | 100% of the tenant and all linked subscriptions |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

