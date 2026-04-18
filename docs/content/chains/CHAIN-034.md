# CHAIN-034 — Guest Account Lateral Movement

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Guest user accounts in the tenant have permissions that exceed what B2B collaboration requires: they can read directory objects, enumerate group memberships, and in some cases hold directory roles. Cross-tenant access settings use the default trust configuration, which honors MFA claims from the guest's home tenant - meaning a guest who satisfies MFA in their own (potentially attacker-controlled) tenant is treated as MFA-compliant in yours. No named locations are defined in Conditional Access, so there is no IP-based restriction on where guest sessions can originate. An attacker who controls a guest account - or simply creates one from a throwaway tenant - authenticates from any IP, satisfies MFA in their own tenant, and lands in your directory with read access to users, groups, applications, and any Azure RBAC roles the guest has been granted.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_016`](../rules/zt_id_016.md) | Trigger |
| [`zt_id_017`](../rules/zt_id_017.md) | Trigger |
| [`zt_id_013`](../rules/zt_id_013.md) | Trigger |

## Attack walkthrough

### Step 1 — Accept a pending guest invitation or compromise an existing guest account via the guest's home tenant.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_017`](../rules/zt_id_017.md)  

> Guest accounts are enumerated via Graph API or harvested from collaboration emails; the attacker controls the home tenant and can reset the guest's password there.

**Attacker gain:** Valid guest credential for the target tenant, with MFA satisfied in the attacker-controlled home tenant.


### Step 2 — Authenticate to the resource tenant from any IP address - no named location restriction blocks the session.

**Actor:** Attacker as guest  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_013`](../rules/zt_id_013.md)  

> Conditional Access evaluates the session: MFA claim is trusted from the home tenant via cross-tenant access defaults; no named location policy restricts guest sign-ins by IP.

**Attacker gain:** Authenticated guest session from an arbitrary location with full Conditional Access pass.


### Step 3 — Enumerate the directory: users, groups, applications, service principals, and role assignments.

**Actor:** Attacker as guest  
**MITRE ATT&CK:** `T1087.004`  
**Enabled by:** [`zt_id_016`](../rules/zt_id_016.md)  

> GET /v1.0/users, /v1.0/groups, /v1.0/applications - guest permissions are set to 'same as members' or the default which allows broad directory read.

**Attacker gain:** Complete organizational chart, group membership graph, application inventory, and RBAC mapping.


### Step 4 — Leverage any Azure RBAC roles assigned to the guest account to access subscription resources.

**Actor:** Attacker as guest  
**MITRE ATT&CK:** `T1580`  
**Enabled by:** [`zt_id_016`](../rules/zt_id_016.md)  

> Guest holds Contributor or Reader on resource groups granted during collaboration; az resource list and az keyvault secret show succeed.

**Attacker gain:** Access to Azure resources - potentially including Key Vaults, Storage Accounts, and databases - scoped to the guest's RBAC assignments.


### Step 5 — Use directory intelligence to craft targeted phishing or consent grant attacks against high-value internal users.

**Actor:** Attacker as guest  
**MITRE ATT&CK:** `T1566.002`  
**Enabled by:** [`zt_id_016`](../rules/zt_id_016.md)  

> Guest identifies Global Admins, their email addresses, group memberships, and recently registered applications; crafts spear-phish or illicit consent grant targeting those users.

**Attacker gain:** Escalation path from guest-level access to compromised internal privileged account.


## Blast radius

| | |
|---|---|
| Initial access | Guest account authenticated via attacker-controlled home tenant with MFA trust. |
| Lateral movement | Directory enumeration → targeted phishing of privileged users → RBAC-scoped resource access. |
| Max privilege | Whatever RBAC roles and directory permissions the guest holds, plus intelligence for social engineering escalation. |
| Data at risk | Directory metadata (users, groups, apps), Resources in guest RBAC scope, Phishing targets for escalation |
| Services at risk | Entra ID, Azure RBAC-scoped resources, Key Vault, Storage Accounts |
| Estimated scope | Directory-wide read + guest RBAC scope |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

