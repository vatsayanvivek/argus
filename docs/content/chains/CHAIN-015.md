# CHAIN-015 — App Service HTTP remote debug to credential intercept

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

An App Service still accepts HTTP (httpsOnly=false), remote debugging is enabled on the production slot, and its outbound connections to a backing database are not TLS-enforced. An attacker positioned on the path (or sharing the network) captures the plaintext session, uses the remote debug channel to inject into the worker process, and steals the database connection string.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_005`](../rules/zt_wl_005.md) | Trigger |
| [`zt_wl_008`](../rules/zt_wl_008.md) | Trigger |
| [`zt_data_009`](../rules/zt_data_009.md) | Trigger |

## Attack walkthrough

### Step 1 — Intercept unencrypted requests to the App Service hostname.

**Actor:** Network-positioned attacker  
**MITRE ATT&CK:** `T1557.001`  
**Enabled by:** [`zt_wl_005`](../rules/zt_wl_005.md)  

> httpsOnly=false means HTTP is served; attacker on a transit network downgrade-attacks session cookies.

**Attacker gain:** Session cookies and app secrets in transit.


### Step 2 — Attach to the app worker via remote debugging.

**Actor:** Attacker with cookies  
**MITRE ATT&CK:** `T1612`  
**Enabled by:** [`zt_wl_008`](../rules/zt_wl_008.md)  

> Visual Studio remote debug over 4020/4022 enabled; auth is the publish profile credential which was harvested in step 1.

**Attacker gain:** Live process debugger attached to the production app.


### Step 3 — Extract the database connection string from process memory.

**Actor:** Attacker in process  
**MITRE ATT&CK:** `T1555`  
**Enabled by:** [`zt_data_009`](../rules/zt_data_009.md)  

> Dump of process environment / app settings; connection string uses SQL auth and is in the clear.

**Attacker gain:** Database credentials.


### Step 4 — Connect to the backing database over a non-TLS-enforced path and exfiltrate data.

**Actor:** Attacker with DB creds  
**MITRE ATT&CK:** `T1040`  
**Enabled by:** [`zt_data_009`](../rules/zt_data_009.md)  

> Connection policy does not require encryption; sniffed or replayed traffic to the DB tier.

**Attacker gain:** Direct read of backend data with intercepted credentials.


## Blast radius

| | |
|---|---|
| Initial access | Man-in-the-middle position on the path to the App Service. |
| Lateral movement | Process attach → app secrets → backend database. |
| Max privilege | Whatever the database login holds - commonly db_owner on the app's database. |
| Data at risk | Session cookies, App settings / connection strings, Backend database contents |
| Services at risk | App Service, Azure SQL / backing database, Any downstream API whose creds were in app settings |
| Estimated scope | App Service + any database it can reach |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

