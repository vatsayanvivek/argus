# CHAIN-194 — CI/CD service principal with sub-wide Contributor

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

The CI/CD deployment SP holds Contributor at subscription scope AND its secret is static. Any PR-triggered workflow has the ability to read/write any resource in the subscription — a malicious PR becomes a subscription takeover.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_008`](../rules/zt_id_008.md) | Trigger |
| [`zt_id_001`](../rules/zt_id_001.md) | Trigger |

## Attack walkthrough

### Step 1 — Open a PR that modifies workflow to run attacker code.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1195.002`  
**Enabled by:** [`zt_id_008`](../rules/zt_id_008.md)  

**Attacker gain:** Code execution with SP credential.


### Step 2 — SP has Contributor on entire subscription; exfiltrate.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_id_001`](../rules/zt_id_001.md)  

**Attacker gain:** Subscription-wide access.


## Blast radius

| | |
|---|---|
| Initial access | Any PR to CI repo. |
| Max privilege | Subscription Contributor. |
| Data at risk | Every resource in the subscription |
| Services at risk | Azure RBAC |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

