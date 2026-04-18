# CHAIN-048 — Cosmos DB to cross-service data theft and evidence destruction

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A Cosmos DB account is configured to accept connections from all networks, including the public internet. An attacker who obtains the account's primary key (from a leaked connection string, a compromised app, or an over-privileged identity) can connect directly from anywhere in the world and read every database and collection in the account. Cosmos DB connection strings frequently contain or reference Key Vault secret URIs for downstream services. The attacker follows these references to a Key Vault that has diagnostic logging disabled, meaning secret access operations are invisible. Worse, the Key Vault has purge protection disabled, so the attacker can permanently delete secrets and keys to destroy evidence and cause operational damage. The result is a cross-service attack: Cosmos DB is the entry, Key Vault is the pivot, and the combination of no logging and no purge protection means the attacker can steal everything and burn the evidence behind them.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_011`](../rules/zt_data_011.md) | Trigger |
| [`zt_vis_014`](../rules/zt_vis_014.md) | Trigger |
| [`zt_data_014`](../rules/zt_data_014.md) | Trigger |

## Attack walkthrough

### Step 1 — Connect to the Cosmos DB account from the public internet using a stolen primary key.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_data_011`](../rules/zt_data_011.md)  

> Cosmos DB firewall is set to 'All networks' (isVirtualNetworkFilterEnabled=false, ipRangeFilter empty). Attacker uses the Azure Cosmos DB SDK or REST API with the primary key from a leaked connection string to enumerate databases and collections.

**Attacker gain:** Full read/write access to every database, collection, and document in the Cosmos DB account.


### Step 2 — Exfiltrate all documents from high-value collections containing PII, financial records, or application state.

**Actor:** Attacker with Cosmos DB access  
**MITRE ATT&CK:** `T1530`  
**Enabled by:** [`zt_data_011`](../rules/zt_data_011.md)  

> Execute cross-partition queries with no RU limit; use the change feed to stream all historical and real-time changes; export via SELECT * FROM c across all containers.

**Attacker gain:** Complete database exfiltration including customer PII, transaction records, and application configuration documents.


### Step 3 — Extract Key Vault references from Cosmos DB configuration documents and application settings.

**Actor:** Attacker with Cosmos DB access  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_vis_014`](../rules/zt_vis_014.md)  

> Application documents and Cosmos DB stored procedures often contain Key Vault secret URIs (@Microsoft.KeyVault(SecretUri=...)) or direct references to vault names and secret names used by the application tier.

**Attacker gain:** Knowledge of Key Vault names, secret names, and the relationship between Cosmos DB and the Key Vault tier.


### Step 4 — Access the Key Vault to steal secrets, certificates, and keys with no diagnostic trail.

**Actor:** Attacker with Key Vault access  
**MITRE ATT&CK:** `T1555.006`  
**Enabled by:** [`zt_vis_014`](../rules/zt_vis_014.md)  

> Using credentials obtained from Cosmos DB or the original compromised identity, GET /secrets, /keys, /certificates from the Key Vault. Diagnostic logging is disabled (zt_vis_014), so SecretGet, KeySign, and CertificateGet operations produce no audit log entries.

**Attacker gain:** All secrets, keys, and certificates from the Key Vault - completely undetected due to missing diagnostic logs.


### Step 5 — Purge Key Vault secrets and keys to destroy evidence and cause operational damage.

**Actor:** Attacker covering tracks  
**MITRE ATT&CK:** `T1485`  
**Enabled by:** [`zt_data_014`](../rules/zt_data_014.md)  

> DELETE /secrets/{name} followed by POST /deletedsecrets/{name}/purge - because purge protection is disabled (zt_data_014), the soft-deleted secret is permanently destroyed with no recovery path. This eliminates evidence of what was stored and breaks dependent applications.

**Attacker gain:** Permanent destruction of Key Vault contents: evidence eliminated, dependent applications broken, no recovery possible.


### Step 6 — Use stolen Key Vault secrets to access additional services (SQL, Storage, third-party APIs) for maximum blast radius.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.004`  
**Enabled by:** [`zt_data_014`](../rules/zt_data_014.md)  

> Key Vault secrets typically include SQL connection strings, storage account keys, API keys for third-party services, and TLS certificates. Each secret unlocks another service in the architecture.

**Attacker gain:** Cascading access to every service whose credentials were stored in the compromised Key Vault.


## Blast radius

| | |
|---|---|
| Initial access | Publicly accessible Cosmos DB account with a leaked primary key. |
| Lateral movement | Cosmos DB → Key Vault → every service whose credentials are stored in the vault (SQL, Storage, third-party APIs). |
| Max privilege | Full read/write on Cosmos DB, full secret/key/certificate access on Key Vault, cascading access to downstream services. |
| Data at risk | All Cosmos DB documents, All Key Vault secrets and certificates, SQL databases (via stolen connection strings), Storage accounts (via stolen keys), Third-party service data (via stolen API keys) |
| Services at risk | Cosmos DB, Key Vault, SQL Database, Storage Accounts, Any third-party service with keys in the vault |
| Estimated scope | Cosmos DB account + Key Vault + all downstream services referenced by vault secrets |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

