# CHAIN-192 — ACR admin user + pipeline credential sprawl

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

Azure Container Registry has admin user enabled and the single shared credential is referenced in 15+ pipeline definitions across Azure DevOps / GitHub Actions. A leak in any one pipeline leaks registry-wide push access.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_018`](../rules/zt_wl_018.md) | Trigger |
| [`zt_wl_019`](../rules/zt_wl_019.md) | Trigger |

## Attack walkthrough

### Step 1 — Obtain the admin password from a leaked pipeline log.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_wl_018`](../rules/zt_wl_018.md)  

**Attacker gain:** Registry push rights.


### Step 2 — Push malicious images under common 'latest' tags; consumers pull.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1195.002`  
**Enabled by:** [`zt_wl_019`](../rules/zt_wl_019.md)  

**Attacker gain:** Fleet-wide supply-chain compromise.


## Blast radius

| | |
|---|---|
| Initial access | Pipeline log leak. |
| Max privilege | Registry push. |
| Data at risk | Every consumer's runtime |
| Services at risk | AKS / Container Apps / Functions |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

