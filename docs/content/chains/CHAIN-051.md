# CHAIN-051 — Token replay to persistent backdoor via unmonitored admin session

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Entra ID token lifetime policies are configured with extended access token lifetimes (or the default 1-hour refresh cycle is not paired with Continuous Access Evaluation), giving stolen tokens a long window of usability. Administrative accounts do not require phishing-resistant authentication strength, so an attacker who intercepts or steals a token (via AiTM phishing, a compromised device, or a session hijack) faces no step-up authentication challenge when performing sensitive administrative operations. The attacker uses the long-lived admin token to create a backdoor service principal, add federation trust to an external IdP, or register a new Global Admin - all operations that establish persistence beyond the lifetime of the stolen token. Because the Activity Log is not exported to a Log Analytics Workspace or Storage Account, the administrative operations that established persistence are retained for only 90 days in the built-in Activity Log and are not queryable by SIEM or automation. By the time the breach is discovered months later, the evidence of how persistence was established has been purged.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_019`](../rules/zt_id_019.md) | Trigger |
| [`zt_id_014`](../rules/zt_id_014.md) | Trigger |
| [`zt_vis_017`](../rules/zt_vis_017.md) | Trigger |

## Attack walkthrough

### Step 1 — Steal an admin user's access token via adversary-in-the-middle (AiTM) phishing or a compromised endpoint.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1557.003`  
**Enabled by:** [`zt_id_019`](../rules/zt_id_019.md)  

> Deploy an AiTM phishing proxy (Evilginx2, Modlishka) targeting the tenant's login page. The proxy captures the session cookie and access token after the user authenticates. Long token lifetime (zt_id_019) means the captured token remains valid for an extended period without requiring re-authentication.

**Attacker gain:** A valid, long-lived access token for an administrative account.


### Step 2 — Use the stolen token to perform administrative operations without encountering step-up authentication.

**Actor:** Attacker with admin token  
**MITRE ATT&CK:** `T1550.001`  
**Enabled by:** [`zt_id_014`](../rules/zt_id_014.md)  

> No authentication strength policy (zt_id_014) requires phishing-resistant MFA for admin operations. The stolen token (obtained via AiTM, bypassing standard MFA) is accepted for sensitive operations: role assignments, app registrations, and directory modifications.

**Attacker gain:** Unrestricted administrative API access for the lifetime of the stolen token.


### Step 3 — Create a backdoor service principal with long-lived credentials for persistent access.

**Actor:** Attacker with admin access  
**MITRE ATT&CK:** `T1136.003`  
**Enabled by:** [`zt_id_014`](../rules/zt_id_014.md)  

> POST /applications with a new App Registration; POST /servicePrincipals; add a client secret with endDateTime set years in the future; assign Global Administrator or Application Administrator role.

**Attacker gain:** An independent, attacker-controlled credential that does not depend on the stolen user token.


### Step 4 — Optionally add an external SAML/OIDC federation trust to the tenant for invisible backdoor access.

**Actor:** Attacker with admin access  
**MITRE ATT&CK:** `T1484.002`  
**Enabled by:** [`zt_id_019`](../rules/zt_id_019.md)  

> Add a federated identity credential to an existing App Registration pointing to an attacker-controlled IdP, or add a SAML federation domain to the tenant. This allows the attacker to generate valid tokens from their own infrastructure without touching the target tenant's auth flow.

**Attacker gain:** Token-issuance capability from attacker infrastructure, completely independent of the target tenant's authentication controls.


### Step 5 — Activity Log entries for the persistence operations age out because they are not exported to long-term storage.

**Actor:** Time (passive evidence destruction)  
**MITRE ATT&CK:** `T1070.003`  
**Enabled by:** [`zt_vis_017`](../rules/zt_vis_017.md)  

> The Activity Log is not exported to Log Analytics or Storage (zt_vis_017). Azure retains Activity Log data for 90 days in the built-in viewer. After 90 days, the evidence of app registration creation, role assignment, and federation trust establishment is permanently purged.

**Attacker gain:** The forensic trail of exactly how persistence was established is destroyed by Azure's own 90-day retention, leaving investigators unable to determine the backdoor mechanism.


### Step 6 — Return via the backdoor credential to access the tenant long after the original token has expired and the incident is forgotten.

**Actor:** Attacker (months later)  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_vis_017`](../rules/zt_vis_017.md)  

> Authenticate using the backdoor service principal secret or the federated IdP; the original stolen token is long expired, but the persistence mechanisms are unaffected. Investigation finds no Activity Log evidence of how the backdoor was created.

**Attacker gain:** Indefinite, evidence-free access to the tenant via persistence mechanisms whose creation is no longer auditable.


## Blast radius

| | |
|---|---|
| Initial access | Stolen admin token via AiTM phishing, facilitated by long token lifetime and missing auth strength policy. |
| Lateral movement | Direct to Global Admin scope via the stolen token - no lateral movement required. |
| Max privilege | Global Administrator with persistent backdoor credentials and optional federation trust. |
| Data at risk | All Entra ID directory data, All Azure subscription resources, All Microsoft 365 data (mail, files, Teams), Audit evidence itself (Activity Log not exported) |
| Services at risk | Entra ID, Azure Resource Manager, Microsoft 365, All services in linked subscriptions |
| Estimated scope | 100% of the tenant and all linked subscriptions |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

