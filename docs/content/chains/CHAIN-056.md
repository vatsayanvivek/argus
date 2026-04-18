# CHAIN-056 — Inactive privileged account with stale credentials

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A user account with an admin role has not signed in for 180+ days and still has an active password credential. Unused admin accounts are a favorite target — nobody notices anomalous activity, MFA prompts go to a forgotten device, and credentials are often recycled from breach corpora.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_006`](../rules/zt_id_006.md) | Trigger |
| [`zt_id_026`](../rules/zt_id_026.md) | Trigger |

## Attack walkthrough

### Step 1 — Match an inactive admin UPN against breached-credential dumps.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1589.001`  
**Enabled by:** [`zt_id_006`](../rules/zt_id_006.md)  

**Attacker gain:** Credential pair for a dormant admin account.


### Step 2 — Authenticate; because the account is idle, no user notices the sign-in log.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_id_026`](../rules/zt_id_026.md)  

**Attacker gain:** Active admin session.


## Blast radius

| | |
|---|---|
| Initial access | Breached credential + dormant account. |
| Max privilege | Whatever role the dormant account holds. |
| Data at risk | Entra directory, RBAC assignments, Anything that admin role grants |
| Services at risk | Entra ID, Azure RBAC |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

