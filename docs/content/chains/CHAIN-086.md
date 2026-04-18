# CHAIN-086 — HDInsight cluster without VNet injection

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Low · **Logic:** `ALL`

## Why this chain matters

HDInsight cluster nodes are reachable from the public internet and authenticate with cluster-local SSH keys. A weak SSH config yields a Hadoop worker shell which has credentials to every storage account the cluster writes to.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_data_026`](../rules/zt_data_026.md) | Trigger |
| [`zt_net_001`](../rules/zt_net_001.md) | Trigger |

## Attack walkthrough

### Step 1 — SSH to *-ssh.azurehdinsight.net; spray weak passwords.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1110`  
**Enabled by:** [`zt_data_026`](../rules/zt_data_026.md)  

**Attacker gain:** Hadoop shell.


### Step 2 — Use Hadoop CLI to read/write connected storage accounts.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1213`  
**Enabled by:** [`zt_net_001`](../rules/zt_net_001.md)  

**Attacker gain:** Cluster-adjacent data exfil.


## Blast radius

| | |
|---|---|
| Initial access | Public SSH + weak auth. |
| Max privilege | Cluster storage access. |
| Data at risk | Attached storage accounts |
| Services at risk | HDInsight, Storage |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

