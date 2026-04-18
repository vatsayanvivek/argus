# CHAIN-038 — Front Door Exploit Chain

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Azure Front Door is deployed as the internet-facing edge but has no WAF policy attached, the subscription lacks Azure DDoS Protection Standard, and backend App Services do not require client certificates for mutual TLS. This triple gap creates a devastating attack surface: the attacker launches L7 application-layer attacks through Front Door unfiltered - SQL injection, XSS, bot scraping, credential stuffing - because no WAF rule inspects the payload. Simultaneously or as a diversion, they launch a volumetric DDoS attack that the Basic tier cannot mitigate, saturating the backend and masking the application-layer exploit. The backend App Service accepts any connection forwarded by Front Door without verifying a client certificate, so an attacker who discovers the backend FQDN directly (*.azurewebsites.net) can bypass Front Door entirely and hit the origin with no protection layer whatsoever.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_017`](../rules/zt_net_017.md) | Trigger |
| [`zt_net_013`](../rules/zt_net_013.md) | Trigger |
| [`zt_wl_019`](../rules/zt_wl_019.md) | Trigger |

## Attack walkthrough

### Step 1 — Enumerate the Front Door endpoint and identify that no WAF policy is attached.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1595.002`  
**Enabled by:** [`zt_net_017`](../rules/zt_net_017.md)  

> DNS lookup of *.azurefd.net; HTTP response headers reveal Front Door without X-Azure-FDID WAF markers; no 403 responses on common attack patterns confirm WAF absence.

**Attacker gain:** Confirmed unprotected Front Door endpoint accepting arbitrary HTTP payloads.


### Step 2 — Launch a volumetric DDoS attack against the Front Door and backend IPs to degrade availability and distract the operations team.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1498.001`  
**Enabled by:** [`zt_net_013`](../rules/zt_net_013.md)  

> UDP/TCP flood targeting the Front Door anycast IPs; DDoS Protection Basic provides only limited mitigation at volumes above ~300 Mbps, with no custom policies or alerting.

**Attacker gain:** Backend degradation, ops team focused on availability, reduced capacity for security investigation.


### Step 3 — Simultaneously deliver L7 application-layer attacks through Front Door targeting the unprotected backend.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_net_017`](../rules/zt_net_017.md)  

> SQL injection, SSRF, command injection payloads in HTTP requests; no WAF managed ruleset to detect or block OWASP Top 10 attack patterns.

**Attacker gain:** Application-layer compromise of the backend service - code execution, data access, or authentication bypass.


### Step 4 — Discover the backend App Service FQDN and connect directly, bypassing Front Door entirely.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_wl_019`](../rules/zt_wl_019.md)  

> DNS brute-force of *.azurewebsites.net; certificate transparency logs reveal the backend hostname. Direct connection succeeds because App Service does not require client certificates.

**Attacker gain:** Direct origin access with no CDN caching, no rate limiting, no WAF - even if a WAF is later added to Front Door.


### Step 5 — Exfiltrate data from the compromised backend while the DDoS attack continues to distract defenders.

**Actor:** Attacker with backend access  
**MITRE ATT&CK:** `T1041`  
**Enabled by:** [`zt_net_013`](../rules/zt_net_013.md)  

> Data extracted via HTTPS to attacker-controlled endpoints; operations team is triaging the availability incident and not monitoring data-plane exfiltration.

**Attacker gain:** Customer data, application secrets, and database contents exfiltrated under the cover of a DDoS smokescreen.


## Blast radius

| | |
|---|---|
| Initial access | Unfiltered Front Door endpoint or direct backend App Service access. |
| Lateral movement | Front Door → backend App Service → managed identity → connected data stores. |
| Max privilege | Application-level access to backend services plus whatever the App Service managed identity holds. |
| Data at risk | All data served by the backend application, Connected database contents, Application secrets and connection strings, User session tokens |
| Services at risk | Azure Front Door, App Service, Connected SQL/Cosmos databases, Storage accounts, Key Vault |
| Estimated scope | All backend services behind the Front Door profile |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

