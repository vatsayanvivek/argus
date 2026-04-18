# CHAIN-032 — Web App Exploitation with No WAF Protection

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

Application Gateway is deployed without a Web Application Firewall policy, Function Apps or App Services run on outdated runtime stacks with known CVEs, and Application Insights is not configured to provide application-level telemetry. An attacker who discovers the publicly-reachable endpoint uses standard web exploitation techniques - SQL injection, SSRF, deserialization - against the unpatched runtime. No WAF rule fires because there is no WAF. No APM alert triggers because Application Insights is absent. The attacker achieves code execution on the app service plan, harvests environment variables containing connection strings and managed identity tokens, and pivots to backend data stores without a single detection event reaching the operations team.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_014`](../rules/zt_net_014.md) | Trigger |
| [`zt_wl_017`](../rules/zt_wl_017.md) | Trigger |
| [`zt_vis_019`](../rules/zt_vis_019.md) | Trigger |

## Attack walkthrough

### Step 1 — Discover the public FQDN of the App Service or Function App behind the Application Gateway.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1595.002`  
**Enabled by:** [`zt_net_014`](../rules/zt_net_014.md)  

> DNS enumeration of *.azurewebsites.net, *.azurefd.net; Application Gateway public IP reverse-looked up to reveal backend pool members.

**Attacker gain:** Target URL and knowledge that no WAF policy protects the endpoint.


### Step 2 — Probe the application for known vulnerabilities in the outdated runtime stack.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_wl_017`](../rules/zt_wl_017.md)  

> Fingerprint the runtime version via response headers (X-Powered-By, Server); match against CVE databases for the specific .NET, Node, Python, or Java version deployed.

**Attacker gain:** Confirmed exploitable vulnerability in the runtime - e.g., deserialization RCE, path traversal, or SSRF.


### Step 3 — Exploit the vulnerability to achieve remote code execution within the App Service sandbox.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1059.004`  
**Enabled by:** [`zt_net_014`](../rules/zt_net_014.md)  

> Payload delivered via HTTP request body; WAF would have blocked common patterns (union select, ../, java.lang.Runtime) but no WAF policy is attached to the Application Gateway.

**Attacker gain:** Shell-level access inside the App Service container or Function App execution context.


### Step 4 — Harvest environment variables and query the managed identity endpoint for ARM and data-plane tokens.

**Actor:** Attacker inside App Service  
**MITRE ATT&CK:** `T1552.005`  
**Enabled by:** [`zt_wl_017`](../rules/zt_wl_017.md)  

> printenv reveals APPSETTING_* connection strings; curl $IDENTITY_ENDPOINT with $IDENTITY_HEADER yields bearer tokens for any resource the managed identity can access.

**Attacker gain:** Database connection strings, storage account keys, and a managed identity token for ARM.


### Step 5 — Access backend SQL databases and storage accounts using harvested connection strings and tokens.

**Actor:** Attacker with credentials  
**MITRE ATT&CK:** `T1530`  
**Enabled by:** [`zt_wl_017`](../rules/zt_wl_017.md)  

> sqlcmd with harvested SQL connection string; az storage blob download with managed identity token. Data exfiltrated over HTTPS egress.

**Attacker gain:** Full access to application data tier - customer PII, transaction records, secrets.


### Step 6 — Maintain persistence undetected because no Application Insights telemetry captures anomalous request patterns or exception spikes.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_vis_019`](../rules/zt_vis_019.md)  

> No Application Insights SDK or auto-instrumentation configured; request traces, dependency calls, and exception telemetry are never generated. SOC has zero application-layer visibility.

**Attacker gain:** Indefinite dwell time within the application tier with no application-level alerting.


## Blast radius

| | |
|---|---|
| Initial access | Publicly-reachable App Service or Function App behind an Application Gateway with no WAF policy. |
| Lateral movement | App Service managed identity → backend SQL, Storage, Key Vault via harvested tokens and connection strings. |
| Max privilege | Whatever role the App Service managed identity holds, plus direct database access via connection strings in environment variables. |
| Data at risk | Application databases, Storage account blobs, Key Vault secrets referenced by app settings, User session data |
| Services at risk | App Service, Function Apps, Application Gateway, SQL Database, Storage Accounts, Key Vault |
| Estimated scope | Application tier + all backend data stores the app connects to |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

