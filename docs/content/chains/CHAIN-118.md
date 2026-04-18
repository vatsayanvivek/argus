# CHAIN-118 — Container App with external ingress + managed identity overprivileged

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

A Container App accepts public HTTP ingress AND its user-assigned managed identity holds Contributor at subscription scope. Any RCE in the app yields Azure management-plane takeover.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_025`](../rules/zt_wl_025.md) | Trigger |
| [`zt_id_008`](../rules/zt_id_008.md) | Trigger |

## Attack walkthrough

### Step 1 — Exploit app-layer vuln (SSRF, deserialization) in the Container App.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_wl_025`](../rules/zt_wl_025.md)  

**Attacker gain:** RCE inside container.


### Step 2 — Call IMDS; get ARM token scoped as Contributor.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.005`  
**Enabled by:** [`zt_id_008`](../rules/zt_id_008.md)  

**Attacker gain:** Subscription-level privilege.


## Blast radius

| | |
|---|---|
| Initial access | Public Container App. |
| Max privilege | Subscription Contributor. |
| Data at risk | Every resource in the subscription |
| Services at risk | Azure RBAC plane |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

