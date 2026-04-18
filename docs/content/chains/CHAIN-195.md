# CHAIN-195 — GitHub Actions OIDC federation over-scoped

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A federated credential trusts any GitHub workflow in any repository under an organisation — the subject claim is too broad. Any repo in the org can assume the identity. A compromised developer's fork becomes cloud-credentialed code execution.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_011`](../rules/zt_id_011.md) | Trigger |
| [`zt_id_008`](../rules/zt_id_008.md) | Trigger |

## Attack walkthrough

### Step 1 — Push malicious workflow to a fork in the org.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1195.002`  
**Enabled by:** [`zt_id_011`](../rules/zt_id_011.md)  

**Attacker gain:** Workflow assumes federated identity.


### Step 2 — Use identity's Azure RBAC to exfiltrate.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_id_008`](../rules/zt_id_008.md)  

**Attacker gain:** Cloud compromise from fork.


## Blast radius

| | |
|---|---|
| Initial access | Any fork in the org. |
| Max privilege | Federated identity's RBAC. |
| Data at risk | Azure resources under that identity |
| Services at risk | Azure RBAC via OIDC |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

