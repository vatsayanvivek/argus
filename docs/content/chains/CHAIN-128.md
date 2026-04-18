# CHAIN-128 — App Configuration exposed without private endpoint

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Azure App Configuration is reachable publicly and some keys carry feature-flag defaults that leak roadmap info, along with secret references that can be resolved to Key Vault URLs. A token with App Config Reader reveals more than intended.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_026`](../rules/zt_wl_026.md) | Trigger |
| [`zt_data_001`](../rules/zt_data_001.md) | Trigger |

## Attack walkthrough

### Step 1 — List app config entries.

**Actor:** Attacker with any reader token  
**MITRE ATT&CK:** `T1087`  
**Enabled by:** [`zt_wl_026`](../rules/zt_wl_026.md)  

**Attacker gain:** Config key inventory + secret references.


### Step 2 — Resolve secret references; extract referenced Key Vault secrets.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552`  
**Enabled by:** [`zt_data_001`](../rules/zt_data_001.md)  

**Attacker gain:** Secret values beyond what App Config holds directly.


## Blast radius

| | |
|---|---|
| Initial access | Any App Config reader role. |
| Max privilege | Config keys + pointer-chased secrets. |
| Data at risk | App configuration surface |
| Services at risk | Any app reading this config |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

