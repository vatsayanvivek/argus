# CHAIN-131 — ACR anonymous pull + AKS no image policy

!!! note "Summary"
    **Severity:** :material-alert-circle-outline: Medium · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

ACR allows anonymous pull and AKS has no admission control on image source. An attacker registered in ACR as a pusher (via any other chain) can publish images the cluster will pull blindly.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_019`](../rules/zt_wl_019.md) | Trigger |
| [`zt_wl_014`](../rules/zt_wl_014.md) | Trigger |

## Attack walkthrough

### Step 1 — Push attacker-image to a commonly-pulled repo path.

**Actor:** Attacker with push  
**MITRE ATT&CK:** `T1195.002`  
**Enabled by:** [`zt_wl_019`](../rules/zt_wl_019.md)  

**Attacker gain:** Trojaned image in registry.


### Step 2 — Anonymous-pull the image; no signature check.

**Actor:** Kubelet  
**MITRE ATT&CK:** `T1554`  
**Enabled by:** [`zt_wl_014`](../rules/zt_wl_014.md)  

**Attacker gain:** In-cluster attacker execution.


## Blast radius

| | |
|---|---|
| Initial access | Any ACR push + AKS pull. |
| Max privilege | Pod-level code exec. |
| Data at risk | Cluster secrets |
| Services at risk | AKS pulling from this ACR |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

