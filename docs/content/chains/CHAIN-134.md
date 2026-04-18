# CHAIN-134 — Spot VM + unhandled eviction exposes running data

!!! note "Summary"
    **Severity:** :material-information-outline: Low · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Spot VMs are evicted with 30-second notice; apps that don't checkpoint leave in-memory data in page files on the VHD. If disk encryption isn't enforced for ephemeral OS disks, a later attacker-controlled Spot allocation reuses the same hardware and can potentially recover residual data.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_022`](../rules/zt_wl_022.md) | Trigger |
| [`zt_data_015`](../rules/zt_data_015.md) | Trigger |

## Attack walkthrough

### Step 1 — Evict spot VM; data written to disk not fully wiped.

**Actor:** Azure infrastructure  
**MITRE ATT&CK:** `T1486`  
**Enabled by:** [`zt_wl_022`](../rules/zt_wl_022.md)  

**Attacker gain:** Residual data on ephemeral storage.


### Step 2 — Lucky-allocation yields the same underlying storage; extract residual data.

**Actor:** Attacker with new spot  
**MITRE ATT&CK:** `T1005`  
**Enabled by:** [`zt_data_015`](../rules/zt_data_015.md)  

**Attacker gain:** Cross-tenant data recovery.


## Blast radius

| | |
|---|---|
| Initial access | Luck + spot allocation. |
| Max privilege | Historical data residual. |
| Data at risk | Previous workload memory state |
| Services at risk | Spot VM consumers |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

