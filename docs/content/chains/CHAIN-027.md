# CHAIN-027 — App Service remote debug to internal pivot

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

An Azure App Service has remote debugging enabled in production, the delegated subnet hosting the App Service has no Network Security Group attached, and Application Insights is not configured for the application. Remote debugging exposes a debug endpoint that grants full process-level access to the running application - memory inspection, code injection, and arbitrary command execution. An attacker who discovers or brute-forces the debug port gains a foothold inside the App Service sandbox and, through VNet integration, reaches the internal subnet. Because no NSG filters traffic on the subnet, the attacker can scan and connect to any internal resource - databases, caches, other App Services, VMs - without restriction. With no Application Insights telemetry, there is no APM-level detection of anomalous requests, unusual response patterns, or unexpected outbound connections.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_018`](../rules/zt_wl_018.md) | Trigger |
| [`zt_net_019`](../rules/zt_net_019.md) | Trigger |
| [`zt_vis_019`](../rules/zt_vis_019.md) | Trigger |

## Attack walkthrough

### Step 1 — Discover and attach to the remote debug endpoint on the App Service.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_wl_018`](../rules/zt_wl_018.md)  

> Remote debugging is enabled (remoteDebuggingEnabled=true); the debug endpoint is accessible and allows attaching a debugger (e.g., Visual Studio Remote Debugger) to the w3wp or dotnet process.

**Attacker gain:** Full debug-level access to the running application process.


### Step 2 — Extract environment variables, connection strings, and managed identity tokens from the process memory.

**Actor:** Attacker with debugger access  
**MITRE ATT&CK:** `T1552.005`  
**Enabled by:** [`zt_wl_018`](../rules/zt_wl_018.md)  

> Debug session allows inspecting process environment, reading connection strings from appsettings, and calling the local IMDS endpoint for managed identity tokens.

**Attacker gain:** Database connection strings, storage keys, managed identity tokens, and application secrets.


### Step 3 — Scan the VNet-integrated subnet for adjacent resources.

**Actor:** Attacker with internal credentials  
**MITRE ATT&CK:** `T1046`  
**Enabled by:** [`zt_net_019`](../rules/zt_net_019.md)  

> App Service VNet integration places outbound traffic on the delegated subnet; no NSG restricts egress or east-west traffic. Attacker runs port scans against the subnet CIDR and adjacent subnets.

**Attacker gain:** Network map of all reachable internal resources - databases, caches, VMs, other App Services.


### Step 4 — Connect to internal databases and services using the stolen credentials.

**Actor:** Attacker with network access  
**MITRE ATT&CK:** `T1021`  
**Enabled by:** [`zt_net_019`](../rules/zt_net_019.md)  

> SQL Server, Redis, Cosmos DB, or other backends are reachable on the subnet with no NSG filtering; stolen connection strings provide authentication.

**Attacker gain:** Direct access to backend data stores and internal APIs.


### Step 5 — Exfiltrate data without triggering any application-level detection.

**Actor:** Attacker operating internally  
**MITRE ATT&CK:** `T1041`  
**Enabled by:** [`zt_vis_019`](../rules/zt_vis_019.md)  

> No Application Insights means no request tracing, no dependency tracking, no anomaly detection on response times or error rates. The attack is invisible at the APM layer.

**Attacker gain:** Sustained data exfiltration with no application monitoring to raise alerts.


## Blast radius

| | |
|---|---|
| Initial access | Remote debug endpoint on a production App Service. |
| Lateral movement | App Service sandbox → VNet-integrated subnet → all reachable internal resources. |
| Max privilege | Application managed identity + all credentials in the process environment. |
| Data at risk | Application data, Backend database contents, Cache contents (Redis), Managed identity scope, Connection strings and secrets |
| Services at risk | App Service, SQL Database, Redis Cache, Cosmos DB, Any VNet-connected service on unprotected subnets |
| Estimated scope | The App Service and all backend services it can reach through VNet integration |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

