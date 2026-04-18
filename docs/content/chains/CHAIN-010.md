# CHAIN-010 — No private endpoint SQL all IPs no audit to DB breach

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

An Azure SQL logical server has no Private Endpoint, its firewall rule allows 0.0.0.0 - 255.255.255.255, and SQL Auditing is not enabled. The server accepts TDS from anywhere, SQL authentication is allowed, and nothing logs connection attempts. A credential-stuffing attacker finds the server via SQL DNS enumeration, authenticates with leaked credentials, and exfiltrates the database - silently.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_010`](../rules/zt_net_010.md) | Trigger |
| [`zt_data_007`](../rules/zt_data_007.md) | Trigger |
| [`zt_data_003`](../rules/zt_data_003.md) | Trigger |

## Attack walkthrough

### Step 1 — Enumerate *.database.windows.net via DNS to discover reachable SQL servers.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1590.002`  
**Enabled by:** [`zt_net_010`](../rules/zt_net_010.md)  

> Wordlist brute-force against *.database.windows.net; live servers resolve.

**Attacker gain:** List of reachable Azure SQL endpoints.


### Step 2 — Connect from any internet IP to the server because the firewall allows 0.0.0.0-255.255.255.255.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1133`  
**Enabled by:** [`zt_data_007`](../rules/zt_data_007.md)  

> AllowAzureServices=true and a firewall rule StartIpAddress=0.0.0.0, EndIpAddress=255.255.255.255.

**Attacker gain:** TDS connectivity from arbitrary source IPs.


### Step 3 — Authenticate with credentials from a public leak or low-privilege helpdesk compromise.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_data_007`](../rules/zt_data_007.md)  

> SQL Authentication is enabled on the server (not Entra-only); credential stuffing against sqladmin, dbadmin, sa accounts.

**Attacker gain:** Authenticated SQL session.


### Step 4 — Exfiltrate entire tables with no trace.

**Actor:** Attacker in SQL  
**MITRE ATT&CK:** `T1530`  
**Enabled by:** [`zt_data_003`](../rules/zt_data_003.md)  

> SELECT * against PII/PCI tables; SQL Auditing is not enabled and no Extended Events are writing to storage.

**Attacker gain:** Silent bulk exfiltration of customer records.


## Blast radius

| | |
|---|---|
| Initial access | Any internet IP with credentials for the SQL server. |
| Lateral movement | Into every database on the server; cross-database queries where permitted. |
| Max privilege | Whatever role the compromised SQL login holds - potentially db_owner. |
| Data at risk | Customer PII, Transaction records, Any data in databases on the affected logical server |
| Services at risk | Azure SQL Database, Any downstream reports or analytics sourced from the database |
| Estimated scope | Every database on the affected logical server |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

