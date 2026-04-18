# CHAIN-011 — Cross-tenant unrestricted no CAP to multi-tenant breach

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Cross-tenant access settings are left at the Microsoft defaults (inbound from any tenant allowed), no Conditional Access policy scopes access by tenant or device compliance, and sign-in logs are not forwarded to a SIEM. An attacker who compromises any identity in any external tenant can B2B-collaborate into the victim tenant and - because no CA policy blocks it - access shared resources with the compromised credential. The source sign-ins look foreign but nothing is watching.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_004`](../rules/zt_id_004.md) | Trigger |
| [`zt_id_006`](../rules/zt_id_006.md) | Trigger |
| [`zt_vis_005`](../rules/zt_vis_005.md) | Trigger |

## Attack walkthrough

### Step 1 — Compromise any user in an unrelated Entra ID tenant (phishing, token theft, adversary-in-the-middle).

**Actor:** External attacker  
**MITRE ATT&CK:** `T1566.001`  
**Enabled by:** [`zt_id_004`](../rules/zt_id_004.md)  

> Evilginx-style AiTM capture against a small tenant that trusts the target via B2B.

**Attacker gain:** Valid session token in a trusted third-party tenant.


### Step 2 — Pivot to the victim tenant via unrestricted cross-tenant access.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_004`](../rules/zt_id_004.md)  

> crossTenantAccessPolicy default configuration permits inbound B2B collaboration from any tenant; attacker's external identity resolves into the target directory.

**Attacker gain:** Guest or external member access to shared resources in the victim tenant.


### Step 3 — Bypass conditional controls because no CA policy requires device compliance or tenant scoping.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1562.007`  
**Enabled by:** [`zt_id_006`](../rules/zt_id_006.md)  

> No policy with 'Include: All external users' + 'Require compliant device' or 'Block unknown tenant'.

**Attacker gain:** Token issuance without any risk-based or device-based gate.


### Step 4 — Evade detection because sign-in logs are not ingested into a SIEM for correlation.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_vis_005`](../rules/zt_vis_005.md)  

> Diagnostic setting for SignInLogs is not enabled on Azure AD; logs live for 30 days and nobody queries them.

**Attacker gain:** The anomalous foreign-tenant sign-in is never alerted on.


## Blast radius

| | |
|---|---|
| Initial access | Compromised identity in any external Entra tenant. |
| Lateral movement | B2B collaboration → shared resource access → internal data via guest permissions. |
| Max privilege | Whatever scope the guest is granted - often higher than intended because guest permissions default to full directory read. |
| Data at risk | Shared SharePoint libraries, Teams channels, Resources explicitly shared with external users |
| Services at risk | Entra ID, SharePoint Online, Teams, Any resource with external principals in its RBAC |
| Estimated scope | Every resource shared with external identities |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

