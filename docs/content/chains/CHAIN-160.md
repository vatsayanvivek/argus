# CHAIN-160 — Event Hub with Capture to public-access storage

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Event Hub Capture writes every stream event to a storage account that has public blob access enabled. A downstream compliance leak: sensitive event data intended for a VNet-only datalake ends up readable over the internet.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_int_005`](../rules/zt_int_005.md) | Trigger |
| [`zt_data_001`](../rules/zt_data_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Capture writes to container with allowBlobPublicAccess=true.

**Actor:** Misconfig  
**MITRE ATT&CK:** `T1213`  
**Enabled by:** [`zt_int_005`](../rules/zt_int_005.md)  

**Attacker gain:** Capture output publicly readable.


### Step 2 — Enumerate and download capture blobs; historical event stream exposed.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1530`  
**Enabled by:** [`zt_data_001`](../rules/zt_data_001.md)  

**Attacker gain:** Historical stream content.


## Blast radius

| | |
|---|---|
| Initial access | Anon internet. |
| Max privilege | Read on capture output. |
| Data at risk | Every historical event |
| Services at risk | Event Hub + downstream analytics |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

