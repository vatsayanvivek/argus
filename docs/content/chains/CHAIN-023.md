# CHAIN-023 — Conditional access bypass to identity harvest

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

Conditional Access policies do not define named/trusted locations, no sign-in risk policy is configured, and MFA registration is not enforced for new or existing users. This trifecta means an attacker who obtains a valid password - from a breach dump, spray, or social engineering - can authenticate from any IP address on Earth without triggering any risk-based evaluation. Because MFA registration was never enforced, the target account likely has no second factor at all, or the attacker can register their own MFA method on first sign-in. The attacker then harvests the directory: user lists, group memberships, application registrations, and service principal secrets - building a map for deeper compromise.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_013`](../rules/zt_id_013.md) | Trigger |
| [`zt_id_018`](../rules/zt_id_018.md) | Trigger |
| [`zt_id_023`](../rules/zt_id_023.md) | Trigger |

## Attack walkthrough

### Step 1 — Obtain a valid user password from a credential breach database or targeted phishing.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1110.004`  
**Enabled by:** [`zt_id_013`](../rules/zt_id_013.md)  

> Credential stuffing against login.microsoftonline.com; no named locations means there is no IP-based block or grant control in Conditional Access.

**Attacker gain:** Valid username/password pair for an Entra ID user.


### Step 2 — Sign in from an anonymous VPN or Tor exit node without triggering any risk detection.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_018`](../rules/zt_id_018.md)  

> No sign-in risk policy means Identity Protection does not evaluate atypical travel, anonymous IP, or impossible travel signals; sign-in proceeds as normal.

**Attacker gain:** Authenticated session from an untrusted location with no additional challenge.


### Step 3 — Register their own MFA method since the account has none, or bypass MFA entirely.

**Actor:** Attacker with authenticated session  
**MITRE ATT&CK:** `T1556.006`  
**Enabled by:** [`zt_id_023`](../rules/zt_id_023.md)  

> MFA registration policy not enforced via Conditional Access or Identity Protection; user account has no registered authentication methods. Attacker registers a phone number or authenticator app.

**Attacker gain:** Attacker now owns the MFA registration for the account - persistence through MFA.


### Step 4 — Enumerate the Entra ID directory: users, groups, roles, applications, and service principals.

**Actor:** Attacker with persistent access  
**MITRE ATT&CK:** `T1087.004`  
**Enabled by:** [`zt_id_018`](../rules/zt_id_018.md)  

> Microsoft Graph API calls (GET /users, /groups, /applications, /servicePrincipals) with default directory reader permissions available to all authenticated users.

**Attacker gain:** Complete directory map including group memberships, role assignments, and application secrets metadata.


### Step 5 — Identify high-value targets and repeat the credential attack against privileged users.

**Actor:** Attacker with directory knowledge  
**MITRE ATT&CK:** `T1589.001`  
**Enabled by:** [`zt_id_023`](../rules/zt_id_023.md)  

> Cross-reference the harvested user list with role assignments to find Global Administrators, Application Administrators, and Privileged Role Administrators without MFA.

**Attacker gain:** Targeted attack list for privilege escalation across the tenant.


## Blast radius

| | |
|---|---|
| Initial access | Any valid user credential from a breach database or phishing. |
| Lateral movement | Directory enumeration → targeted credential attack on privileged users → tenant-wide access. |
| Max privilege | Initially standard user; rapidly escalates to whatever the weakest privileged account allows. |
| Data at risk | Full Entra ID directory contents, Email and OneDrive of compromised users, Application secrets metadata, Group membership and role assignment data |
| Services at risk | Entra ID, Microsoft Graph, Exchange Online, SharePoint Online, Any application relying on Entra ID for authentication |
| Estimated scope | All identities in the tenant are exposed to enumeration; compromised scope depends on password reuse |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

