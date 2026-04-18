# CHAIN-144 — ML Workspace compute instance with public IP + SSH

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Azure ML Workspace provisions compute instances with public IP and SSH enabled. The compute instance holds a managed identity with Contributor on the workspace — meaning any shell access yields access to every dataset, model registry, and endpoint in the workspace.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_ai_003`](../rules/zt_ai_003.md) | Trigger |
| [`zt_wl_006`](../rules/zt_wl_006.md) | Trigger |

## Attack walkthrough

### Step 1 — SSH to ML compute instance; brute-force or use leaked key.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1110`  
**Enabled by:** [`zt_ai_003`](../rules/zt_ai_003.md)  

**Attacker gain:** Shell on compute instance.


### Step 2 — Use workspace MI to read datastores + export models.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1213`  
**Enabled by:** [`zt_wl_006`](../rules/zt_wl_006.md)  

**Attacker gain:** Full ML workspace data exfiltration.


## Blast radius

| | |
|---|---|
| Initial access | Public SSH on ML compute. |
| Max privilege | Workspace Contributor. |
| Data at risk | Training datasets, Model weights, Endpoints |
| Services at risk | Azure ML Workspace |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

