# CHAIN-107 — Service endpoint bypass via compromised subnet

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A storage account is protected by service endpoint restrictions listing trusted subnets. Any compromised VM in those subnets can read the storage account with no further auth. Service endpoints authenticate subnets, not users.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_004`](../rules/zt_net_004.md) | Trigger |
| [`zt_data_001`](../rules/zt_data_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Call storage REST using the VM's managed identity.

**Actor:** Attacker on trusted-subnet VM  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_net_004`](../rules/zt_net_004.md)  

**Attacker gain:** Storage access from 'trusted' source.


### Step 2 — Read blobs; firewall treats request as legitimate.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1530`  
**Enabled by:** [`zt_data_001`](../rules/zt_data_001.md)  

**Attacker gain:** Data exfil via subnet trust.


## Blast radius

| | |
|---|---|
| Initial access | Any VM in trusted subnet. |
| Max privilege | Storage scope of trust rule. |
| Data at risk | Trusted storage account |
| Services at risk | Any resource protected by service endpoint |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

