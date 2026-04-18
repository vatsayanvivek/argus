# CHAIN-127 — Batch account compute pool with storage cred in init script

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Low · **Logic:** `ALL`

## Why this chain matters

Azure Batch pool startup task contains a plaintext storage account key. Every pool VM boots with this in its metadata. An attacker on any Batch node can read it and access the storage account from elsewhere.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_031`](../rules/zt_wl_031.md) | Trigger |
| [`zt_data_001`](../rules/zt_data_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Read CustomData / startup script.

**Actor:** Attacker on Batch node  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_wl_031`](../rules/zt_wl_031.md)  

**Attacker gain:** Storage account key.


### Step 2 — Authenticate from outside the Batch network.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_data_001`](../rules/zt_data_001.md)  

**Attacker gain:** Persistent storage access.


## Blast radius

| | |
|---|---|
| Initial access | Batch node compromise. |
| Max privilege | Storage account owner-equivalent. |
| Data at risk | Full storage account |
| Services at risk | Storage, Any app sharing the storage account |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

