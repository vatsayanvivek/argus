# CHAIN-110 — CDN caching a secret-bearing response

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A CDN rule caches any GET response including responses that inadvertently carry Authorization headers in Location redirects, cookies in Set-Cookie, or secrets in HTML. Cache keys match only URL; many users share the 'same' cache entry.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_net_008`](../rules/zt_net_008.md) | Trigger |
| [`zt_data_001`](../rules/zt_data_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Response has Set-Cookie with auth token + no Vary: Cookie header.

**Actor:** Developer misconfig  
**MITRE ATT&CK:** `T1213`  
**Enabled by:** [`zt_net_008`](../rules/zt_net_008.md)  

**Attacker gain:** Token baked into CDN cache entry.


### Step 2 — Requests same URL; CDN serves cached response with another user's token.

**Actor:** Next user  
**MITRE ATT&CK:** `T1550.004`  
**Enabled by:** [`zt_data_001`](../rules/zt_data_001.md)  

**Attacker gain:** Session impersonation via shared cache.


## Blast radius

| | |
|---|---|
| Initial access | CDN cache pollution. |
| Max privilege | Cross-user session hijack. |
| Data at risk | Per-user secrets in cached responses |
| Services at risk | Any app fronted by misconfigured CDN |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

