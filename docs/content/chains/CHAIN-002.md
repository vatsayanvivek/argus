# CHAIN-002 — App Registration Graph abuse to tenant data

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

This is the scenario only red teams catch. An App Registration in the tenant holds high-privilege application-level Microsoft Graph permissions (Mail.Read.All, Files.Read.All, User.Read.All or worse - Directory.ReadWrite.All). Its client secret is stored in an internet-reachable location: a public storage blob, a committed .env file, or a workload whose outbound egress is unrestricted. An attacker who gets that secret can authenticate to Graph as the application - bypassing every user-centric control the tenant has - and read mailboxes, files, and directory objects tenant-wide. There is no user, no device, no MFA prompt, no Conditional Access policy in the path because application tokens do not honor them. Scanners that look at findings in isolation never connect the secret leak to the Graph permission grant; ARGUS does.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_011`](../rules/zt_id_011.md) | Trigger |
| [`zt_net_009`](../rules/zt_net_009.md) | Trigger |
| [`zt_wl_011`](../rules/zt_wl_011.md) | Trigger |

## Attack walkthrough

### Step 1 — Enumerate public tenant App Registrations and identify one holding application-level Graph permissions with standing consent.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1589.001`  
**Enabled by:** [`zt_id_011`](../rules/zt_id_011.md)  

> Probe /common/discovery/instance, scrape GitHub for committed appId+tenantId pairs, cross-reference with leaked secrets dumps.

**Attacker gain:** Knowledge that a single secret unlocks tenant-wide Graph read access.


### Step 2 — Harvest the App Registration client secret from an egress-unrestricted workload or exposed storage.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_net_009`](../rules/zt_net_009.md)  

> Unrestricted outbound NSG allows the compromised workload to exfil its environment variables to attacker-controlled infrastructure; alternatively a public blob hosts the .env.

**Attacker gain:** Valid clientId + clientSecret for the App Registration.


### Step 3 — Exchange the client credentials for an application Graph token.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1550.001`  
**Enabled by:** [`zt_wl_011`](../rules/zt_wl_011.md)  

> POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token with grant_type=client_credentials, scope=https://graph.microsoft.com/.default

**Attacker gain:** A bearer token authenticated as the application - no user context, no Conditional Access, no MFA.


### Step 4 — Read tenant-wide mailboxes, OneDrive/SharePoint files, and directory objects via Graph.

**Actor:** Attacker with app token  
**MITRE ATT&CK:** `T1530`  
**Enabled by:** [`zt_id_011`](../rules/zt_id_011.md)  

> GET https://graph.microsoft.com/v1.0/users/{id}/messages, /drives/{id}/root/children, /users with $select=* - all succeed against every user in the tenant.

**Attacker gain:** Bulk exfiltration of executive email, M&A documents, HR files, and the full user directory.


### Step 5 — Add a new password credential to the App Registration for durable, rotation-proof access.

**Actor:** Attacker with app token  
**MITRE ATT&CK:** `T1098.001`  
**Enabled by:** [`zt_wl_011`](../rules/zt_wl_011.md)  

> POST https://graph.microsoft.com/v1.0/applications/{id}/addPassword - application tokens with Application.ReadWrite.OwnedBy (or higher) can self-rotate credentials.

**Attacker gain:** Independent, attacker-controlled secret on the App Registration. Even rotating the original secret does not evict the attacker.


## Blast radius

| | |
|---|---|
| Initial access | Leaked App Registration client secret obtained via egress-unrestricted workload or exposed storage. |
| Lateral movement | Direct to Microsoft Graph with application token - no lateral movement required; the single token is the keys to the tenant. |
| Max privilege | Tenant-wide application-level Graph access (Mail/Files/Directory). Not scoped to a subscription - scoped to the entire Entra ID tenant. |
| Data at risk | All user mailboxes, All OneDrive/SharePoint content, Entra ID directory objects, Group memberships, Calendar and Teams chats |
| Services at risk | Exchange Online, SharePoint Online, OneDrive, Entra ID, Microsoft Teams |
| Estimated scope | 100% of the Entra ID tenant |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

