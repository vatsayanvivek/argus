# CHAIN-141 — VM disk encryption key rotation missed

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Low · **Logic:** `ALL`

## Why this chain matters

VMs use Azure Disk Encryption but the encryption key has not been rotated in 3+ years. A former Key Vault admin with a copy of the key can still decrypt any disk snapshot made during that period.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_016`](../rules/zt_wl_016.md) | Trigger |
| [`zt_data_006`](../rules/zt_data_006.md) | Trigger |

## Attack walkthrough

### Step 1 — Obtain an old snapshot (backup archive, cold storage).

**Actor:** Former admin  
**MITRE ATT&CK:** `T1588.002`  
**Enabled by:** [`zt_wl_016`](../rules/zt_wl_016.md)  

**Attacker gain:** Historical disk VHD.


### Step 2 — Decrypt using retained key.

**Actor:** Former admin  
**MITRE ATT&CK:** `T1552.004`  
**Enabled by:** [`zt_data_006`](../rules/zt_data_006.md)  

**Attacker gain:** Historical disk contents.


## Blast radius

| | |
|---|---|
| Initial access | Retained key material. |
| Max privilege | Decrypt old snapshots. |
| Data at risk | Archived VM data |
| Services at risk | Any VM disk from the key's lifetime |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

