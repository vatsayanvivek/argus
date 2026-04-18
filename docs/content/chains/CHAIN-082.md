# CHAIN-082 — Databricks workspace token sprawl + public access

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Databricks workspace uses public network access for the control plane and users generate long-lived personal access tokens. A leaked token lets an attacker run arbitrary Spark jobs, which have cluster-level credentials to read any data source the workspace connects to.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_022`](../rules/zt_data_022.md) | Trigger |
| [`zt_data_001`](../rules/zt_data_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Harvest a PAT from a developer laptop or CI pipeline log.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_data_022`](../rules/zt_data_022.md)  

**Attacker gain:** Bearer token for Databricks API.


### Step 2 — Submit a Spark job that dbutils.fs reads every mounted storage.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1213`  
**Enabled by:** [`zt_data_001`](../rules/zt_data_001.md)  

**Attacker gain:** Bulk exfiltration through Spark.


## Blast radius

| | |
|---|---|
| Initial access | Leaked PAT. |
| Max privilege | Whatever the cluster IAM role grants. |
| Data at risk | All mounted storage, Metastores, Delta tables |
| Services at risk | Databricks, Downstream data lake |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

