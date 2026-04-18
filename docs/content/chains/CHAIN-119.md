# CHAIN-119 — App Service without auth + connection string in app settings

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

An App Service has Easy Auth disabled and its app settings store database + storage connection strings. An attacker hitting the unauthenticated /api routes can often trigger endpoints that inadvertently expose environment variables (error pages, debug endpoints).

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_002`](../rules/zt_wl_002.md) | Trigger |
| [`zt_wl_017`](../rules/zt_wl_017.md) | Trigger |

## Attack walkthrough

### Step 1 — Probe the unauth API for a stack trace or /env endpoint.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_wl_002`](../rules/zt_wl_002.md)  

**Attacker gain:** Environment dump.


### Step 2 — Extract connection strings; connect directly to backends.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_wl_017`](../rules/zt_wl_017.md)  

**Attacker gain:** Full backend DB / storage access.


## Blast radius

| | |
|---|---|
| Initial access | Unauth endpoint. |
| Max privilege | Whatever the connection string grants. |
| Data at risk | Backend datastore |
| Services at risk | DB / storage backing the app |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

