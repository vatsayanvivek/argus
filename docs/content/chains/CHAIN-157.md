# CHAIN-157 — APIM weak TLS + named value stored in cleartext

!!! note "Summary"
    **Severity:** :material-alert: High · **Likelihood:** Medium · **Logic:** `ALL`

## Why this chain matters

APIM accepts TLS 1.0 on the gateway AND stores backend credentials as cleartext named values. A downgrade-then-sniff attack on the gateway exposes traffic; reading the APIM config surface reveals backend secrets.

## Component rules

This chain fires when its trigger conditions are met by the following rules. Click any rule to see its detection logic and compliance mappings.

| Rule ID | Role |
|---|---|
| [`zt_int_001`](../rules/zt_int_001.md) | Trigger |
| [`zt_int_002`](../rules/zt_int_002.md) | Trigger |

## Attack walkthrough

### Step 1 — Force TLS 1.0; sniff gateway traffic.

**Actor:** Attacker  
**MITRE ATT&CK:** `T1557.001`  
**Enabled by:** [`zt_int_001`](../rules/zt_int_001.md)  

**Attacker gain:** Plaintext API calls.


### Step 2 — Read APIM named values; harvest backend creds.

**Actor:** Attacker with Contributor  
**MITRE ATT&CK:** `T1552.001`  
**Enabled by:** [`zt_int_002`](../rules/zt_int_002.md)  

**Attacker gain:** Direct backend access.


## Blast radius

| | |
|---|---|
| Initial access | TLS + Contributor. |
| Max privilege | Backend credentials. |
| Data at risk | Every backend API the gateway fronts |
| Services at risk | APIM + every backend |

## How the logic works

The chain fires only when **every** rule above has at least one finding in the current scan. Missing any one rule breaks the chain — so remediating any single step disrupts the attack path.

