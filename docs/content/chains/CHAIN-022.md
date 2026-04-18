# CHAIN-022 — Emergency access lockout to tenant takeover

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

No break-glass (emergency access) accounts exist, admin roles are not protected by authentication strength policies, and PIM role activation requires no approval workflow. An attacker who compromises any Global Administrator account - via token theft, phishing, or credential stuffing - can immediately activate every PIM-eligible role without a second human approving the request. Because no break-glass accounts were provisioned, the legitimate tenant owners have no out-of-band recovery path once the attacker resets passwords, rotates MFA methods, and locks out the original admins. The tenant is irrecoverable without Microsoft Support intervention, and the attacker has unrestricted dwell time.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_012`](../rules/zt_id_012.md) | Trigger |
| [`zt_id_014`](../rules/zt_id_014.md) | Trigger |
| [`zt_id_021`](../rules/zt_id_021.md) | Trigger |

## Attack walkthrough

### Step 1 — Compromise a Global Administrator credential through phishing, token replay, or password spray.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_id_014`](../rules/zt_id_014.md)  

> No authentication strength policy enforces phishing-resistant MFA (FIDO2/Windows Hello) for admin roles; legacy MFA methods (SMS, voice) are accepted.

**Attacker gain:** Valid session as a Global Administrator.


### Step 2 — Activate all eligible PIM roles without any approval gate.

**Actor:** Attacker with admin session  
**MITRE ATT&CK:** `T1098.003`  
**Enabled by:** [`zt_id_021`](../rules/zt_id_021.md)  

> PIM role settings have approvalRequired=false; activation is instant and self-service for all directory roles.

**Attacker gain:** Full Global Administrator + every other directory role activated simultaneously.


### Step 3 — Reset passwords and MFA registrations for all other administrators.

**Actor:** Attacker with full privilege  
**MITRE ATT&CK:** `T1531`  
**Enabled by:** [`zt_id_021`](../rules/zt_id_021.md)  

> Reset-MgUserAuthenticationMethodPassword and Update-MgUserAuthenticationMethod for every admin UPN; existing admins locked out of their accounts.

**Attacker gain:** All legitimate administrators are locked out of the tenant.


### Step 4 — Add their own persistent credentials and federate an external IdP.

**Actor:** Attacker with sole control  
**MITRE ATT&CK:** `T1484.002`  
**Enabled by:** [`zt_id_014`](../rules/zt_id_014.md)  

> New-MgDomainFederationConfiguration pointing to an attacker-controlled ADFS/SAML IdP; golden SAML attack path is now durable.

**Attacker gain:** Persistent backdoor that survives individual credential rotation.


### Step 5 — Attempt recovery and discover no break-glass accounts exist.

**Actor:** Legitimate tenant owners  
**MITRE ATT&CK:** `T1531`  
**Enabled by:** [`zt_id_012`](../rules/zt_id_012.md)  

> No emergency access accounts with standing Global Administrator role, physical FIDO2 keys, and conditional access exclusions were provisioned per Microsoft best practice.

**Attacker gain:** Recovery is impossible without filing a Microsoft Support ticket, which takes days.


## Blast radius

| | |
|---|---|
| Initial access | Any Global Administrator credential. |
| Lateral movement | Not required - full tenant control is immediate after PIM activation. |
| Max privilege | Global Administrator with federation control - equivalent to owning the tenant. |
| Data at risk | Entire Entra ID directory, All Azure subscriptions, All Microsoft 365 data, All secrets in Key Vaults accessible via ARM |
| Services at risk | Entra ID, All Azure subscriptions, Microsoft 365, Exchange Online, SharePoint Online, Teams |
| Estimated scope | 100% of the tenant and all connected workloads |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

