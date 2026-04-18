# CHAIN-197 — Deployment workflow without branch protection

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

The main branch that deploys to prod has no branch protection — direct pushes allowed, no reviewer required, no status check required. A single compromised dev account can push directly to main and deploy malicious code to prod.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_003`](../rules/zt_id_003.md) | Trigger |
| [`zt_vis_001`](../rules/zt_vis_001.md) | Trigger |

## Attack walkthrough

### Step 1 — git push origin main with backdoor code.

**Actor:** Attacker with dev creds  
**MITRE ATT&CK:** `T1195.002`  
**Enabled by:** [`zt_id_003`](../rules/zt_id_003.md)  

**Attacker gain:** Backdoor code in main branch.


### Step 2 — Deploy triggered automatically; backdoor in prod.

**Actor:** CI  
**MITRE ATT&CK:** `T1554`  
**Enabled by:** [`zt_vis_001`](../rules/zt_vis_001.md)  

**Attacker gain:** Production compromise.


## Blast radius

| | |
|---|---|
| Initial access | Any developer credential. |
| Max privilege | Production deployment. |
| Data at risk | Prod workload integrity |
| Services at risk | Any service deployed from main |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

