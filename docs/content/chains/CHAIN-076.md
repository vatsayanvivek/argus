# CHAIN-076 — Federated identity provider trust compromise

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** Low · **Logic:** `ALL`

## Why this chain matters

Tenant federates authentication to a third-party IdP (ADFS, Okta, Ping). If the IdP's signing cert is stolen or the IdP itself is compromised, the attacker can mint SAML tokens claiming any UPN — Global Admin included. This is the Solorigate pattern.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_018`](../rules/zt_id_018.md) | Trigger |
| [`zt_id_007`](../rules/zt_id_007.md) | Trigger |

## Attack walkthrough

### Step 1 — Exfiltrate the SAML token-signing private key.

**Actor:** Attacker on IdP  
**MITRE ATT&CK:** `T1552.004`  
**Enabled by:** [`zt_id_018`](../rules/zt_id_018.md)  

**Attacker gain:** Ability to forge any SAML assertion.


### Step 2 — Mint a SAML token claiming the UPN of a Global Admin; present to Entra.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1606.002`  
**Enabled by:** [`zt_id_007`](../rules/zt_id_007.md)  

**Attacker gain:** Forged Global Admin session, no password needed.


## Blast radius

| | |
|---|---|
| Initial access | IdP compromise. |
| Max privilege | Any UPN — including GA. |
| Data at risk | Entire tenant |
| Services at risk | Entra ID |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

