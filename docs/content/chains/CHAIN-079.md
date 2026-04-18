# CHAIN-079 — Cosmos DB account key exposed in App Service config

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

Cosmos DB is accessed via master account key stored in App Service application settings. The key is readable by anyone with Website Contributor and grants root access to the entire Cosmos account. Managed identity would sandbox this; the developer chose the shortcut.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_007`](../rules/zt_data_007.md) | Trigger |
| [`zt_wl_017`](../rules/zt_wl_017.md) | Trigger |

## Attack walkthrough

### Step 1 — Read app settings; find CosmosDBKey value.

**Actor:** Attacker with Website Contributor  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_wl_017`](../rules/zt_wl_017.md)  

**Attacker gain:** Valid Cosmos master key.


### Step 2 — Use key via Cosmos SDK; full read + delete on every container.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1565.001`  
**Enabled by:** [`zt_data_007`](../rules/zt_data_007.md)  

**Attacker gain:** Unrestricted database access.


## Blast radius

| | |
|---|---|
| Initial access | App Service config read. |
| Max privilege | Cosmos DB root. |
| Data at risk | Every Cosmos container in the account |
| Services at risk | Cosmos DB, Dependent app state |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

