# CHAIN-130 — Container Registry with admin user enabled

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

ACR has admin user enabled — a single shared credential that nobody rotates. CI systems and developers all use the same username/password. A single leak yields push rights into the registry, so attackers can insert malicious images.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_018`](../rules/zt_wl_018.md) | Trigger |
| [`zt_data_001`](../rules/zt_data_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Harvest the ACR admin password from a CI log or developer machine.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_wl_018`](../rules/zt_wl_018.md)  

**Attacker gain:** Registry push rights.


### Step 2 — Push a trojaned 'latest' tag; wait for pods to pull.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1195.002`  
**Enabled by:** [`zt_data_001`](../rules/zt_data_001.md)  

**Attacker gain:** Supply-chain compromise of every consumer.


## Blast radius

| | |
|---|---|
| Initial access | Leaked shared credential. |
| Max privilege | Push access to every repo in ACR. |
| Data at risk | Every consumer's runtime integrity |
| Services at risk | Every service pulling from this ACR |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

