# CHAIN-067 — Certificate-based SP auth with long-lived cert

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

A service principal authenticates via a 10-year x.509 certificate. If the private key leaves the HSM once, there is no practical revocation. The SP holds Azure RBAC roles at subscription scope, making the leaked cert a decade-long backdoor.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_001`](../rules/zt_id_001.md) | Trigger |
| [`zt_id_003`](../rules/zt_id_003.md) | Trigger |

## Attack walkthrough

### Step 1 — Exfiltrate the private key from a misconfigured Key Vault or developer laptop.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1552.004`  
**Enabled by:** [`zt_id_001`](../rules/zt_id_001.md)  

**Attacker gain:** Valid certificate for SP auth.


### Step 2 — Authenticate to Azure AD using the certificate; persist access for the cert's remaining lifetime.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1078`  
**Enabled by:** [`zt_id_003`](../rules/zt_id_003.md)  

**Attacker gain:** Long-lived subscription-scope RBAC.


## Blast radius

| | |
|---|---|
| Initial access | Key material leak. |
| Max privilege | SP's RBAC roles. |
| Data at risk | Every resource the SP can reach |
| Services at risk | Azure RBAC |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

