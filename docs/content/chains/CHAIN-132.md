# CHAIN-132 — AKS ingress controller without WAF

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

AKS nginx-ingress is exposed to the internet without an AKS-attached WAF or Front Door in front. SQL injection, XSS, and RCE attempts hit backends directly. Traffic logging goes to ingress pod stdout only.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_020`](../rules/zt_wl_020.md) | Trigger |
| [`zt_net_007`](../rules/zt_net_007.md) | Trigger |

## Attack walkthrough

### Step 1 — Send OWASP Top-10 payloads; no WAF filters them.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1190`  
**Enabled by:** [`zt_wl_020`](../rules/zt_wl_020.md)  

**Attacker gain:** App-layer exploitation.


### Step 2 — Exploit reaches backend service.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1210`  
**Enabled by:** [`zt_net_007`](../rules/zt_net_007.md)  

**Attacker gain:** Internal compromise.


## Blast radius

| | |
|---|---|
| Initial access | Internet to ingress. |
| Max privilege | Backend app RCE. |
| Data at risk | App + DB |
| Services at risk | All apps behind ingress |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

