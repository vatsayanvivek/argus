# CHAIN-151 — ML pipeline with hardcoded secret in code artifact

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

An ML training script in the workspace repo hardcodes a storage account key for dataset access. The training image built from the repo embeds this key; anyone with pull access to the container registry has the key.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_ai_003`](../rules/zt_ai_003.md) | Trigger |
| [`zt_wl_014`](../rules/zt_wl_014.md) | Trigger |

## Attack walkthrough

### Step 1 — Pull the training image; docker history reveals the key.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_ai_003`](../rules/zt_ai_003.md)  

**Attacker gain:** Key baked into image layer.


### Step 2 — Authenticate against the target storage.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_wl_014`](../rules/zt_wl_014.md)  

**Attacker gain:** Storage access.


## Blast radius

| | |
|---|---|
| Initial access | ACR pull role. |
| Max privilege | Storage account scope. |
| Data at risk | Training datasets |
| Services at risk | Storage + training pipeline |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

