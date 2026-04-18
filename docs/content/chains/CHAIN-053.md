# CHAIN-053 — Legacy authentication bypass of Conditional Access

!!! note "Summary"
    **Severity:** :material-alert-octagon: Critical · **Likelihood:** High · **Logic:** `ALL`

## Why this chain matters

Tenant allows legacy authentication protocols (IMAP, POP, SMTP AUTH, older EWS) that do not support interactive MFA. Conditional Access policies built for modern auth do not apply to these flows. An attacker who obtains any password hash or sprays a weak password logs in with no MFA prompt.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_id_004`](../rules/zt_id_004.md) | Trigger |
| [`zt_id_007`](../rules/zt_id_007.md) | Trigger |

## Attack walkthrough

### Step 1 — Password-spray known user principal names against the legacy auth endpoint.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1110.003`  
**Enabled by:** [`zt_id_004`](../rules/zt_id_004.md)  

**Attacker gain:** Valid password for a real account.


### Step 2 — Authenticate via IMAP / SMTP AUTH which ignores the modern-auth Conditional Access policy.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1556.007`  
**Enabled by:** [`zt_id_007`](../rules/zt_id_007.md)  

**Attacker gain:** Authenticated mailbox session without MFA challenge.


## Blast radius

| | |
|---|---|
| Initial access | Corporate credentials compromised. |
| Max privilege | Mailbox access; lateral-phishing potential. |
| Data at risk | Email, Attachments, OAuth consent grants granted from mailbox links |
| Services at risk | Exchange Online, SharePoint, Any app the user can consent to |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

