# CHAIN-140 — Kubernetes workload identity shared across namespaces

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

Azure Workload Identity federation maps one Entra identity to a service account referenced in both dev and prod namespaces. A dev-namespace RCE yields the identity's tokens — same tokens prod uses. Namespace boundary is meaningless.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_wl_011`](../rules/zt_wl_011.md) | Trigger |
| [`zt_id_008`](../rules/zt_id_008.md) | Trigger |

## Attack walkthrough

### Step 1 — Federated token exchange for the shared Entra ID.

**Actor:** Attacker in dev pod  
**MITRE ATT&CK:** `T1552.005`  
**Enabled by:** [`zt_wl_011`](../rules/zt_wl_011.md)  

**Attacker gain:** Entra identity access.


### Step 2 — Use identity to access resources intended only for prod pods.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_id_008`](../rules/zt_id_008.md)  

**Attacker gain:** Cross-namespace privilege escalation.


## Blast radius

| | |
|---|---|
| Initial access | Dev namespace compromise. |
| Max privilege | Prod workload identity scope. |
| Data at risk | Prod resources |
| Services at risk | Any Azure resource granted to the shared ID |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

