# CHAIN-029 — SQL database invisible exfiltration

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Azure SQL auditing is not enabled, the audit log retention period is set below 90 days (or effectively zero), and Transparent Data Encryption uses a service-managed key instead of a customer-managed key. An attacker who gains access to the SQL database through a compromised connection string, SQL injection, or credential reuse can execute arbitrary queries and exfiltrate the entire database. Because auditing is disabled or has minimal retention, there is no record of the queries executed, the data accessed, or the volume exfiltrated. The service-managed TDE key means the customer has no ability to revoke the encryption key to render the stolen data unreadable - Microsoft manages the key lifecycle and the attacker's copy is decrypted at rest.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_012`](../rules/zt_data_012.md) | Trigger |
| [`zt_vis_015`](../rules/zt_vis_015.md) | Trigger |
| [`zt_data_015`](../rules/zt_data_015.md) | Trigger |

## Attack walkthrough

### Step 1 — Gain access to the SQL database through a compromised connection string or SQL injection vulnerability.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_data_012`](../rules/zt_data_012.md)  

> Connection string found in a public repository, application configuration leak, or SQL injection in a web application frontend. Authentication succeeds with SQL authentication or a stolen AAD token.

**Attacker gain:** Authenticated session to the Azure SQL database.


### Step 2 — Enumerate database schemas, tables, and row counts to identify high-value data.

**Actor:** Attacker with database access  
**MITRE ATT&CK:** `T1505.001`  
**Enabled by:** [`zt_data_012`](../rules/zt_data_012.md)  

> SELECT * FROM INFORMATION_SCHEMA.TABLES; SELECT COUNT(*) FROM each table; identify PII, financial, and sensitive business data.

**Attacker gain:** Complete schema map and data inventory of the database.


### Step 3 — Bulk export sensitive data using SELECT INTO OUTFILE equivalents or BCP-style export via the compromised session.

**Actor:** Attacker with schema knowledge  
**MITRE ATT&CK:** `T1048`  
**Enabled by:** [`zt_vis_015`](../rules/zt_vis_015.md)  

> Data exfiltrated via application-layer queries, OPENROWSET to an external data source, or row-by-row extraction through the application; no audit log captures the queries.

**Attacker gain:** Complete copy of sensitive database contents exfiltrated to attacker-controlled infrastructure.


### Step 4 — Retain the data in a decrypted, usable form because TDE with service-managed keys provides no customer-side revocation.

**Actor:** Attacker with exfiltrated data  
**MITRE ATT&CK:** `T1530`  
**Enabled by:** [`zt_data_015`](../rules/zt_data_015.md)  

> TDE encrypts data at rest with a service-managed key; once data is read through the SQL engine, it is decrypted. The customer cannot rotate or revoke the key to render stolen data unreadable.

**Attacker gain:** Permanent possession of decrypted production data with no mechanism for the victim to invalidate it.


### Step 5 — Attempt forensic investigation and find no meaningful audit trail.

**Actor:** Defenders responding to breach notification  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_vis_015`](../rules/zt_vis_015.md)  

> SQL auditing was disabled or retention was below 90 days; no record of which queries were executed, what data was accessed, or the timeframe of the breach. Incident response and regulatory notification lack required details.

**Attacker gain:** Defenders cannot scope the breach, identify affected records, or meet regulatory notification requirements with specificity.


## Blast radius

| | |
|---|---|
| Initial access | Compromised SQL connection string or SQL injection. |
| Lateral movement | Database access → full schema enumeration → bulk data export. |
| Max privilege | Database owner or whatever role the compromised credential holds. |
| Data at risk | All data in the SQL database, PII and financial records, Business-critical data, Application metadata and configuration stored in the database |
| Services at risk | Azure SQL Database, Applications dependent on the database, Downstream analytics and reporting systems |
| Estimated scope | All data in the affected database(s) |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

