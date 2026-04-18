# CHAIN-012 — Function no auth system identity to serverless escalation

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

An Azure Function App is publicly reachable with Anonymous authLevel, it has a System-Assigned Managed Identity with broad RBAC, and diagnostic logging is disabled on the host. An attacker who locates the function URL calls the IMDS-equivalent from inside the function code path (or exploits an SSRF in the function logic) and steals a managed identity token that unlocks downstream services. The platform logs that would reveal the call were never captured.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_004`](../rules/zt_wl_004.md) | Trigger |
| [`zt_wl_010`](../rules/zt_wl_010.md) | Trigger |
| [`zt_vis_001`](../rules/zt_vis_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Discover the Function App URL via *.azurewebsites.net enumeration or GitHub search.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1595.002`  
**Enabled by:** [`zt_wl_004`](../rules/zt_wl_004.md)  

> Subdomain enumeration + unauthenticated GET /api/{function} returns 200.

**Attacker gain:** A reachable, unauthenticated function endpoint.


### Step 2 — Coerce the function to return its managed identity token via SSRF or dump endpoint.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1552.005`  
**Enabled by:** [`zt_wl_010`](../rules/zt_wl_010.md)  

> Many functions include a diagnostics/debug endpoint that reflects environment; IDENTITY_ENDPOINT + IDENTITY_HEADER can be invoked to fetch a token.

**Attacker gain:** Managed identity bearer token scoped to whatever the function identity holds.


### Step 3 — Enumerate and consume downstream services with the stolen token.

**Actor:** Attacker with MI token  
**MITRE ATT&CK:** `T1078.004`  
**Enabled by:** [`zt_wl_010`](../rules/zt_wl_010.md)  

> az rest calls against Storage, Key Vault, Graph - the identity often has Storage Blob Data Contributor at subscription scope.

**Attacker gain:** Unauthorised access to storage, secrets, or Graph, depending on the identity's role assignments.


### Step 4 — Operate without telemetry - Function App diagnostic settings are not enabled.

**Actor:** External attacker  
**MITRE ATT&CK:** `T1562.008`  
**Enabled by:** [`zt_vis_001`](../rules/zt_vis_001.md)  

> FunctionAppLogs not streamed to Log Analytics; request logs absent; attack is only visible in Application Insights if it was configured.

**Attacker gain:** No record of the invocation or token request.


## Blast radius

| | |
|---|---|
| Initial access | Unauthenticated HTTPS call to a public Function App endpoint. |
| Lateral movement | Stolen managed identity token → downstream Azure services. |
| Max privilege | Whatever the function's Managed Identity holds (often over-scoped: Contributor at resource group or subscription). |
| Data at risk | Storage accounts accessible to the identity, Key Vault secrets, Any service the identity has RBAC on |
| Services at risk | Azure Functions, Storage, Key Vault, Resource Manager |
| Estimated scope | Blast radius of the function's managed identity |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

